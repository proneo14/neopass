package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// ExtensionHandler serves local-only endpoints for the browser extension
// via the native messaging host. Session state (JWT + master key) is pushed
// from the Electron app after login.
type ExtensionHandler struct {
	vaultRepo *db.VaultRepo
	secret    string // shared secret for authenticating requests from native host

	mu       sync.RWMutex
	session  *extensionSession
}

type extensionSession struct {
	Token        string // JWT token for API calls
	MasterKeyHex string // master key for decrypting vault entries
	UserID       string // extracted from JWT or pushed by Electron
}

type extensionCredential struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	Name     string `json:"name"`
}

func NewExtensionHandler(vaultRepo *db.VaultRepo, secret string) *ExtensionHandler {
	return &ExtensionHandler{
		vaultRepo: vaultRepo,
		secret:    secret,
	}
}

// verifySecret checks the Authorization header for the shared secret.
func (h *ExtensionHandler) verifySecret(r *http.Request) bool {
	if h.secret == "" {
		return true // no secret configured (dev mode)
	}
	auth := r.Header.Get("Authorization")
	return auth == "Bearer "+h.secret
}

// PushSession receives session state from the Electron app.
// POST /extension/session
// Body: { "token": "jwt...", "master_key_hex": "abc...", "user_id": "uuid" }
func (h *ExtensionHandler) PushSession(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		Token        string `json:"token"`
		MasterKeyHex string `json:"master_key_hex"`
		UserID       string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Token == "" || body.MasterKeyHex == "" || body.UserID == "" {
		writeError(w, http.StatusBadRequest, "token, master_key_hex, and user_id are required")
		return
	}

	h.mu.Lock()
	h.session = &extensionSession{
		Token:        body.Token,
		MasterKeyHex: body.MasterKeyHex,
		UserID:       body.UserID,
	}
	h.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GetStatus returns the current session status.
// GET /extension/status
func (h *ExtensionHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	h.mu.RLock()
	sess := h.session
	h.mu.RUnlock()

	if sess == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"locked":     true,
			"vaultCount": 0,
		})
		return
	}

	// Count vault entries
	entries, err := h.vaultRepo.ListEntries(r.Context(), sess.UserID, db.VaultFilters{})
	count := 0
	if err == nil {
		count = len(entries)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"locked":     false,
		"vaultCount": count,
	})
}

// GetCredentials returns decrypted login credentials matching a domain.
// GET /extension/credentials?domain=example.com
func (h *ExtensionHandler) GetCredentials(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	h.mu.RLock()
	sess := h.session
	h.mu.RUnlock()

	if sess == nil {
		writeJSON(w, http.StatusOK, []extensionCredential{})
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeJSON(w, http.StatusOK, []extensionCredential{})
		return
	}

	// Parse master key
	masterKeyBytes, err := hex.DecodeString(sess.MasterKeyHex)
	if err != nil || len(masterKeyBytes) != 32 {
		writeJSON(w, http.StatusOK, []extensionCredential{})
		return
	}
	var masterKey [32]byte
	copy(masterKey[:], masterKeyBytes)
	defer crypto.ZeroBytes(masterKey[:])

	// Fetch only login entries
	entries, err := h.vaultRepo.ListEntries(r.Context(), sess.UserID, db.VaultFilters{
		EntryType: "login",
	})
	if err != nil {
		writeJSON(w, http.StatusOK, []extensionCredential{})
		return
	}

	var results []extensionCredential

	for _, entry := range entries {
		// Decrypt
		plaintext, err := crypto.Decrypt(entry.EncryptedData, entry.Nonce, masterKey)
		if err != nil {
			continue
		}

		// Parse the login data
		var loginData struct {
			Name     string `json:"name"`
			Username string `json:"username"`
			Password string `json:"password"`
			URI      string `json:"uri"`
			Notes    string `json:"notes"`
		}
		if err := json.Unmarshal(plaintext, &loginData); err != nil {
			continue
		}
		crypto.ZeroBytes(plaintext)

		// Match domain against URI
		if !domainMatches(loginData.URI, domain) {
			continue
		}

		results = append(results, extensionCredential{
			ID:       entry.ID,
			Username: loginData.Username,
			Password: loginData.Password,
			Domain:   domain,
			Name:     loginData.Name,
		})
	}

	if results == nil {
		results = []extensionCredential{}
	}

	writeJSON(w, http.StatusOK, results)
}

// SaveCredential saves a new login credential.
// POST /extension/credentials
// Body: { "domain": "...", "username": "...", "encryptedPassword": "..." }
func (h *ExtensionHandler) SaveCredential(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	h.mu.RLock()
	sess := h.session
	h.mu.RUnlock()

	if sess == nil {
		writeError(w, http.StatusUnauthorized, "vault is locked")
		return
	}

	var body struct {
		Domain   string `json:"domain"`
		Username string `json:"username"`
		Password string `json:"encryptedPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Parse master key
	masterKeyBytes, err := hex.DecodeString(sess.MasterKeyHex)
	if err != nil || len(masterKeyBytes) != 32 {
		writeError(w, http.StatusInternalServerError, "invalid session")
		return
	}
	var masterKey [32]byte
	copy(masterKey[:], masterKeyBytes)
	defer crypto.ZeroBytes(masterKey[:])

	// Build login entry JSON
	loginData, _ := json.Marshal(map[string]string{
		"name":     body.Domain,
		"username": body.Username,
		"password": body.Password,
		"uri":      "https://" + body.Domain,
		"notes":    "",
	})

	// Encrypt
	ciphertext, nonce, err := crypto.Encrypt(loginData, masterKey)
	crypto.ZeroBytes(loginData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	entry := db.VaultEntry{
		UserID:        sess.UserID,
		EntryType:     "login",
		EncryptedData: ciphertext,
		Nonce:         nonce,
		Version:       1,
	}

	_, err = h.vaultRepo.CreateEntry(r.Context(), entry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save credential")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "saved"})
}

// Lock clears the session state.
// POST /extension/lock
func (h *ExtensionHandler) Lock(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	h.mu.Lock()
	if h.session != nil {
		// Zero the master key in memory
		for i := range h.session.MasterKeyHex {
			h.session.MasterKeyHex = h.session.MasterKeyHex[:i] + "0" + h.session.MasterKeyHex[i+1:]
		}
		h.session = nil
	}
	h.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "locked"})
}

// domainMatches checks if a URI contains the given domain.
func domainMatches(uri, domain string) bool {
	if uri == "" || domain == "" {
		return false
	}
	uri = strings.ToLower(uri)
	domain = strings.ToLower(domain)

	// Strip protocol
	if idx := strings.Index(uri, "://"); idx >= 0 {
		uri = uri[idx+3:]
	}

	// Strip path
	if idx := strings.Index(uri, "/"); idx >= 0 {
		uri = uri[:idx]
	}

	// Strip port
	if idx := strings.Index(uri, ":"); idx >= 0 {
		uri = uri[:idx]
	}

	// Exact match or subdomain match
	return uri == domain || strings.HasSuffix(uri, "."+domain)
}


