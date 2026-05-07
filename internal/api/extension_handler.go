package api

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/pbkdf2"

	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// derivePBKDF2 derives a key using PBKDF2-SHA512, matching the Electron main process KDF.
func derivePBKDF2(password string, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha512.New)
}

// ExtensionHandler serves local-only endpoints for the browser extension
// via the native messaging host. Session state (JWT + master key) is pushed
// from the Electron app after login.
type ExtensionHandler struct {
	vaultRepo db.VaultRepository
	userRepo  db.UserRepository
	secret    string // shared secret for authenticating requests from native host
	webauthn  *auth.WebAuthnService

	mu       sync.RWMutex
	session  *extensionSession
}

type extensionSession struct {
	Token        string // JWT token for API calls
	MasterKeyHex string // master key for decrypting vault entries
	UserID       string // extracted from JWT or pushed by Electron
	Email        string // user email for KDF salt derivation
}

type extensionCredential struct {
	ID         string              `json:"id"`
	Username   string              `json:"username"`
	Password   string              `json:"password"`
	Domain     string              `json:"domain"`
	Name       string              `json:"name"`
	URI        string              `json:"uri"`
	URIs       []extensionURI      `json:"uris,omitempty"`
	Notes      string              `json:"notes"`
	Matched    bool                `json:"matched"`
	IsFavorite bool                `json:"is_favorite"`
	Reprompt   int                 `json:"reprompt"`
}

type extensionURI struct {
	URI   string `json:"uri"`
	Match string `json:"match,omitempty"`
}

func NewExtensionHandler(vaultRepo db.VaultRepository, userRepo db.UserRepository, secret string, webauthn *auth.WebAuthnService) *ExtensionHandler {
	return &ExtensionHandler{
		vaultRepo: vaultRepo,
		userRepo:  userRepo,
		secret:    secret,
		webauthn:  webauthn,
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
		Email        string `json:"email"`
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
		Email:        body.Email,
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
		log.Error().Err(err).Str("user_id", sess.UserID).Msg("[extension] failed to list entries")
		writeJSON(w, http.StatusOK, []extensionCredential{})
		return
	}

	log.Debug().Str("user_id", sess.UserID).Str("domain", domain).Int("total_entries", len(entries)).Msg("[extension] fetching credentials")

	var results []extensionCredential

	for _, entry := range entries {
		// Decrypt
		plaintext, err := crypto.Decrypt(entry.EncryptedData, entry.Nonce, masterKey)
		if err != nil {
			log.Debug().Err(err).Str("entry_id", entry.ID).Msg("[extension] decrypt failed")
			continue
		}

		// Parse the login data
		var loginData struct {
			Name     string `json:"name"`
			Username string `json:"username"`
			Password string `json:"password"`
			URI      string `json:"uri"`
			URIs     []struct {
				URI   string `json:"uri"`
				Match string `json:"match,omitempty"` // base_domain, host, starts_with, regex, exact, never
			} `json:"uris"`
			Notes    string `json:"notes"`
			Reprompt int    `json:"reprompt"`
		}
		if err := json.Unmarshal(plaintext, &loginData); err != nil {
			log.Debug().Err(err).Str("entry_id", entry.ID).Msg("[extension] unmarshal failed")
			continue
		}
		crypto.ZeroBytes(plaintext)

		// Build the primary URI for display
		primaryURI := loginData.URI
		if len(loginData.URIs) > 0 {
			primaryURI = loginData.URIs[0].URI
		}

		// Domain matching: check legacy uri field and uris array
		matched := false
		if domain != "" {
			if len(loginData.URIs) > 0 {
				for _, u := range loginData.URIs {
					mode := u.Match
					if mode == "" {
						mode = "base_domain"
					}
					if mode == "never" {
						continue
					}
					if uriMatchesMode(u.URI, domain, mode) {
						matched = true
						break
					}
				}
			} else {
				matched = domainMatches(loginData.URI, domain)
			}
		}
		entryDomain := extractDomainFromURI(primaryURI)

		// Convert uris to extension format
		var extURIs []extensionURI
		for _, u := range loginData.URIs {
			extURIs = append(extURIs, extensionURI{URI: u.URI, Match: u.Match})
		}

		results = append(results, extensionCredential{
			ID:         entry.ID,
			Username:   loginData.Username,
			Password:   loginData.Password,
			Domain:     entryDomain,
			Name:       loginData.Name,
			URI:        primaryURI,
			URIs:       extURIs,
			Notes:      loginData.Notes,
			Matched:    matched,
			IsFavorite: entry.IsFavorite,
			Reprompt:   loginData.Reprompt,
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

	// Check for duplicate: same domain + username
	existingEntries, listErr := h.vaultRepo.ListEntries(r.Context(), sess.UserID, db.VaultFilters{
		EntryType: "login",
	})
	if listErr == nil {
		for _, existing := range existingEntries {
			plaintext, decErr := crypto.Decrypt(existing.EncryptedData, existing.Nonce, masterKey)
			if decErr != nil {
				continue
			}
			var loginEntry struct {
				Username string `json:"username"`
				URI      string `json:"uri"`
			}
			if json.Unmarshal(plaintext, &loginEntry) == nil {
				if loginEntry.Username == body.Username && domainMatches(loginEntry.URI, body.Domain) {
					crypto.ZeroBytes(plaintext)
					writeJSON(w, http.StatusConflict, map[string]string{
						"status": "duplicate",
						"error":  "credential already exists for this user and domain",
					})
					return
				}
			}
			crypto.ZeroBytes(plaintext)
		}
	}

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

// UpdateCredential updates an existing login credential.
// PUT /extension/credentials/{id}
// Body: { "name": "...", "username": "...", "password": "...", "uri": "...", "notes": "..." }
func (h *ExtensionHandler) UpdateCredential(w http.ResponseWriter, r *http.Request) {
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

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	var body struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Password string `json:"password"`
		URI      string `json:"uri"`
		Notes    string `json:"notes"`
		TOTP     string `json:"totp"`
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
		"name":     body.Name,
		"username": body.Username,
		"password": body.Password,
		"uri":      body.URI,
		"notes":    body.Notes,
		"totp":     body.TOTP,
	})

	// Encrypt
	ciphertext, nonce, err := crypto.Encrypt(loginData, masterKey)
	crypto.ZeroBytes(loginData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	entry := db.VaultEntry{
		ID:            entryID,
		UserID:        sess.UserID,
		EntryType:     "login",
		EncryptedData: ciphertext,
		Nonce:         nonce,
	}

	_, err = h.vaultRepo.UpdateEntry(r.Context(), entry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update credential")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// VerifyPassword verifies the user's master password for re-prompt.
// The extension sends the password and the server derives keys using the same
// KDF and compares against the stored session master key.
// POST /extension/verify-password
// Body: { "email": "...", "password": "..." }
// Rate-limited: 5 attempts per minute (handled by caller).
func (h *ExtensionHandler) VerifyPassword(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	h.mu.RLock()
	sess := h.session
	h.mu.RUnlock()

	if sess == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"verified": false, "error": "vault is locked"})
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Password == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"verified": false, "error": "password is required"})
		return
	}

	// Resolve email: request → session → database lookup
	email := body.Email
	if email == "" {
		email = sess.Email
	}
	if email == "" && h.userRepo != nil && sess.UserID != "" {
		if u, err := h.userRepo.GetUserByID(r.Context(), sess.UserID); err == nil {
			email = u.Email
		}
	}
	if email == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"verified": false, "error": "unable to determine account email"})
		return
	}

	// Derive master key using the same KDF as the Electron main process:
	// salt = SHA-256(email), derived = PBKDF2(password, salt, 100000, 64, sha512)
	// masterKeyHex = first 32 bytes as hex
	emailHash := sha256.Sum256([]byte(email))
	// Use Go's PBKDF2 to derive keys
	dk := derivePBKDF2(body.Password, emailHash[:], 100000, 64)
	derivedMasterKeyHex := hex.EncodeToString(dk[:32])

	// Constant-time comparison
	verified := len(derivedMasterKeyHex) == len(sess.MasterKeyHex)
	if verified {
		for i := 0; i < len(derivedMasterKeyHex) && i < len(sess.MasterKeyHex); i++ {
			if derivedMasterKeyHex[i] != sess.MasterKeyHex[i] {
				verified = false
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"verified": verified})
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

	// Signal the Electron parent process to lock the desktop vault too
	_, _ = fmt.Fprintln(os.Stdout, "EXTENSION_LOCK_REQUESTED")
	// Also write a signal file that Electron watches (more reliable than stdout)
	writeLockSignalFile()

	writeJSON(w, http.StatusOK, map[string]string{"status": "locked"})
}

// writeLockSignalFile writes a timestamp to a signal file that the Electron app watches.
func writeLockSignalFile() {
	dir := getExtAppDataDir()
	signalPath := filepath.Join(dir, "lock-signal")
	_ = os.MkdirAll(dir, 0700)
	_ = os.WriteFile(signalPath, []byte(fmt.Sprintf("%d", time.Now().UnixNano())), 0600)
}

func getExtAppDataDir() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
		return filepath.Join(appData, "QuantumPasswordManager")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "QuantumPasswordManager")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "QuantumPasswordManager")
	}
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

// uriMatchesMode checks if a URI matches the given domain using the specified match mode.
func uriMatchesMode(uri, domain, mode string) bool {
	if uri == "" || domain == "" {
		return false
	}
	switch mode {
	case "base_domain":
		return domainMatches(uri, domain)
	case "host":
		host := extractDomainFromURI(uri)
		return strings.EqualFold(host, domain)
	case "starts_with":
		return strings.HasPrefix(strings.ToLower(uri), "https://"+strings.ToLower(domain)) ||
			strings.HasPrefix(strings.ToLower(uri), "http://"+strings.ToLower(domain))
	case "regex":
		// Compile the URI as a regex pattern and test against the full URL
		re, err := regexp.Compile(uri)
		if err != nil {
			return false
		}
		return re.MatchString("https://" + domain)
	case "exact":
		return strings.EqualFold(uri, "https://"+domain) || strings.EqualFold(uri, "http://"+domain)
	case "never":
		return false
	default:
		return domainMatches(uri, domain)
	}
}

// extractDomainFromURI pulls the hostname from a URI string.
func extractDomainFromURI(uri string) string {
	if uri == "" {
		return ""
	}
	u := strings.ToLower(uri)
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	if idx := strings.Index(u, "/"); idx >= 0 {
		u = u[:idx]
	}
	if idx := strings.Index(u, ":"); idx >= 0 {
		u = u[:idx]
	}
	return u
}

// ── Extension Passkey endpoints ──────────────────────────────────────────────

// ExtListPasskeys handles GET /extension/passkeys?rp_id=...
func (h *ExtensionHandler) ExtListPasskeys(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sess := h.getSession()
	if sess == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}

	rpID := r.URL.Query().Get("rp_id")
	passkeys, err := h.webauthn.ListPasskeys(r.Context(), sess.UserID, rpID)
	if err != nil {
		log.Error().Err(err).Msg("[extension] list passkeys failed")
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}

	type passkeyInfo struct {
		CredentialID string `json:"credentialId"`
		RPID         string `json:"rpId"`
		RPName       string `json:"rpName"`
		Username     string `json:"username"`
		DisplayName  string `json:"displayName"`
		CreatedAt    string `json:"createdAt"`
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)
	var result []passkeyInfo
	for _, p := range passkeys {
		result = append(result, passkeyInfo{
			CredentialID: b64.EncodeToString(p.CredentialID),
			RPID:         p.RPID,
			RPName:       p.RPName,
			Username:     p.Username,
			DisplayName:  p.DisplayName,
			CreatedAt:    p.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	if result == nil {
		result = []passkeyInfo{}
	}
	writeJSON(w, http.StatusOK, result)
}

// ExtGetPasskeys handles POST /extension/passkeys/get
func (h *ExtensionHandler) ExtGetPasskeys(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sess := h.getSession()
	if sess == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}

	var req struct {
		RPID             string   `json:"rp_id"`
		AllowCredentials []string `json:"allow_credentials"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	passkeys, err := h.webauthn.ListPasskeys(r.Context(), sess.UserID, req.RPID)
	if err != nil {
		log.Error().Err(err).Msg("[extension] get passkeys failed")
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)
	type passkeyInfo struct {
		CredentialID string `json:"credentialId"`
		RPID         string `json:"rpId"`
		RPName       string `json:"rpName"`
		Username     string `json:"username"`
		DisplayName  string `json:"displayName"`
		CreatedAt    string `json:"createdAt"`
	}

	var result []passkeyInfo
	for _, p := range passkeys {
		credID := b64.EncodeToString(p.CredentialID)

		// If allowCredentials is specified, filter
		if len(req.AllowCredentials) > 0 {
			found := false
			for _, ac := range req.AllowCredentials {
				if ac == credID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		result = append(result, passkeyInfo{
			CredentialID: credID,
			RPID:         p.RPID,
			RPName:       p.RPName,
			Username:     p.Username,
			DisplayName:  p.DisplayName,
			CreatedAt:    p.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	if result == nil {
		result = []passkeyInfo{}
	}
	writeJSON(w, http.StatusOK, result)
}

// ExtCreatePasskey handles POST /extension/passkeys/create
// Combines begin + finish in one call using the extension session's master key.
func (h *ExtensionHandler) ExtCreatePasskey(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sess := h.getSession()
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "vault is locked")
		return
	}

	var req struct {
		RPID        string `json:"rp_id"`
		RPName      string `json:"rp_name"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Algorithm   int    `json:"algorithm"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		UserIDB64   string `json:"user_id_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RPID == "" {
		writeError(w, http.StatusBadRequest, "rp_id is required")
		return
	}
	if req.RPName == "" {
		req.RPName = req.RPID
	}

	// Step 1: Begin registration to create a session
	opts, err := h.webauthn.BeginPasskeyRegistration(
		r.Context(), sess.UserID, req.RPID, req.RPName, req.Username, req.DisplayName,
	)
	if err != nil {
		log.Error().Err(err).Msg("[extension] begin passkey registration failed")
		writeError(w, http.StatusInternalServerError, "failed to begin registration")
		return
	}

	algorithm := req.Algorithm
	if algorithm == 0 {
		algorithm = crypto.COSEAlgES256
	}

	// Step 2: Immediately finish using the extension session's master key
	finishReq := &auth.FinishPasskeyRegistrationRequest{
		SessionID:    opts.SessionID,
		Algorithm:    algorithm,
		MasterKeyHex: sess.MasterKeyHex,
		RPID:         req.RPID,
		RPName:       req.RPName,
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		UserIDB64:    req.UserIDB64,
	}

	passkey, err := h.webauthn.FinishPasskeyRegistration(r.Context(), sess.UserID, finishReq)
	if err != nil {
		log.Error().Err(err).Msg("[extension] finish passkey registration failed")
		writeError(w, http.StatusInternalServerError, "failed to create passkey")
		return
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	// Build a WebAuthn attestation response that the website can verify
	rpIDHash := crypto.RPIDHash(req.RPID)
	flags := crypto.FlagUserPresent | crypto.FlagUserVerified | crypto.FlagAttestedCred | crypto.FlagBackupElig | crypto.FlagBackupState
	attestedCred := crypto.BuildAttestedCredentialData(crypto.LGIPassAAGUID, passkey.CredentialID, passkey.PublicKeyCBOR)
	authData := crypto.MarshalAuthenticatorData(rpIDHash, flags, 0, attestedCred)

	// Use the website's challenge and origin for clientDataJSON so the
	// relying party can verify the attestation matches their ceremony.
	challenge := req.Challenge
	if challenge == "" {
		challenge = opts.Challenge
	}
	origin := req.Origin
	if origin == "" {
		origin = "https://" + req.RPID
	}

	clientData := map[string]interface{}{
		"type":        "webauthn.create",
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	}
	clientDataJSON, _ := json.Marshal(clientData)

	// Build attestation object with "packed" self-attestation for better RP compatibility,
	// falling back to "none" if signing fails (e.g. EdDSA key for signing authData).
	// Packed self-attestation: attStmt = {alg, sig} where sig = Sign(authData || SHA256(clientDataJSON))
	var attestObj []byte
	clientDataHash := sha256Hash(clientDataJSON)
	packSig, packErr := crypto.SignAssertion(
		decryptedPrivKey(passkey.EncryptedPrivKey, passkey.PrivateKeyNonce, sess.MasterKeyHex),
		passkey.Algorithm, authData, clientDataHash[:])
	if packErr == nil && packSig != nil {
		attestObj, _ = crypto.MarshalPackedAttestationObject(authData, packSig, passkey.Algorithm)
	}
	if attestObj == nil {
		attestObj, _ = crypto.MarshalAttestationObject("none", authData)
	}

	// Export public key in SPKI/DER format for getPublicKey()
	spkiKey, _ := crypto.COSEKeyToSPKI(passkey.PublicKeyCBOR)

	resp := map[string]interface{}{
		"credential_id":        b64.EncodeToString(passkey.CredentialID),
		"attestation_object":   b64.EncodeToString(attestObj),
		"client_data_json":     b64.EncodeToString(clientDataJSON),
		"auth_data":            b64.EncodeToString(authData),
		"public_key":           b64.EncodeToString(passkey.PublicKeyCBOR),
		"public_key_spki":      b64.EncodeToString(spkiKey),
		"public_key_algorithm": passkey.Algorithm,
		"transports":           passkey.Transports,
	}

	log.Info().
		Str("user_id", sess.UserID).
		Str("rp_id", req.RPID).
		Str("username", req.Username).
		Msg("[extension] passkey created")

	writeJSON(w, http.StatusCreated, resp)
}

// ExtSignPasskey handles POST /extension/passkeys/sign
func (h *ExtensionHandler) ExtSignPasskey(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sess := h.getSession()
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "vault is locked")
		return
	}

	var req struct {
		CredentialID string `json:"credential_id"`
		RPID         string `json:"rp_id"`
		Origin       string `json:"origin"`
		Challenge    string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CredentialID == "" || req.RPID == "" || req.Challenge == "" {
		writeError(w, http.StatusBadRequest, "credential_id, rp_id, and challenge are required")
		return
	}

	if req.Origin == "" {
		req.Origin = "https://" + req.RPID
	}

	// Begin authentication to get a session
	authOpts, err := h.webauthn.BeginPasskeyAuthentication(r.Context(), sess.UserID, req.RPID)
	if err != nil {
		log.Error().Err(err).Msg("[extension] begin passkey auth failed")
		writeError(w, http.StatusInternalServerError, "failed to begin authentication")
		return
	}

	// Sign using the extension session's master key
	signReq := &auth.PasskeySignRequest{
		SessionID:    authOpts.SessionID,
		CredentialID: req.CredentialID,
		MasterKeyHex: sess.MasterKeyHex,
		RPID:         req.RPID,
		Origin:       req.Origin,
		Challenge:    req.Challenge,
	}

	signResp, err := h.webauthn.SignPasskeyAssertion(r.Context(), sess.UserID, signReq)
	if err != nil {
		log.Error().Err(err).Msg("[extension] passkey sign failed")
		writeError(w, http.StatusInternalServerError, "failed to sign assertion")
		return
	}

	writeJSON(w, http.StatusOK, signResp)
}

// ExtDeletePasskey handles DELETE /extension/passkeys/{id}
func (h *ExtensionHandler) ExtDeletePasskey(w http.ResponseWriter, r *http.Request) {
	if !h.verifySecret(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sess := h.getSession()
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "vault is locked")
		return
	}

	passkeyID := chi.URLParam(r, "id")
	if passkeyID == "" {
		writeError(w, http.StatusBadRequest, "missing passkey ID")
		return
	}

	if err := h.webauthn.DeletePasskey(r.Context(), sess.UserID, passkeyID); err != nil {
		writeError(w, http.StatusNotFound, "passkey not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// getSession returns the current session, or nil if locked.
func (h *ExtensionHandler) getSession() *extensionSession {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.session
}

// sha256Hash returns the SHA-256 hash of data.
func sha256Hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// decryptedPrivKey decrypts a passkey private key with the session's master key hex.
// Returns nil on any error (caller should fall back to "none" attestation).
func decryptedPrivKey(encrypted, nonce []byte, masterKeyHex string) []byte {
	if len(masterKeyHex) != 64 {
		return nil
	}
	keyBytes, err := hex.DecodeString(masterKeyHex)
	if err != nil || len(keyBytes) != 32 {
		return nil
	}
	var key [32]byte
	copy(key[:], keyBytes)
	plain, err := crypto.DecryptPasskeyPrivateKey(encrypted, nonce, key)
	if err != nil {
		return nil
	}
	return plain
}


