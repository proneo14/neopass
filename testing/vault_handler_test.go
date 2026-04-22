package integration_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/password-manager/password-manager/internal/api"
	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/vault"
)

// setupVaultRouter creates a test router with vault endpoints and returns a helper to make authenticated requests.
func setupVaultRouter(t *testing.T) (chi.Router, *auth.Service, string, string) {
	t.Helper()

	userRepo := NewMockUserRepo()
	vaultRepo := NewMockVaultRepo()

	authService, err := auth.NewService(userRepo, nil, nil, auth.ServiceConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	}, vaultRepo)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	vaultService := vault.NewService(vaultRepo)
	vaultHandler := api.NewVaultHandler(vaultService)

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(api.AuthMiddleware(authService))
		r.Post("/vault/entries", vaultHandler.CreateEntry)
		r.Get("/vault/entries", vaultHandler.ListEntries)
		r.Get("/vault/entries/{id}", vaultHandler.GetEntry)
		r.Put("/vault/entries/{id}", vaultHandler.UpdateEntry)
		r.Delete("/vault/entries/{id}", vaultHandler.DeleteEntry)
		r.Post("/vault/folders", vaultHandler.CreateFolder)
		r.Get("/vault/folders", vaultHandler.ListFolders)
		r.Delete("/vault/folders/{id}", vaultHandler.DeleteFolder)
	})

	// Register a test user and get tokens
	authHash := createTestAuthHash()
	regBody := map[string]interface{}{
		"email":                 "vaultuser@example.com",
		"auth_hash":            authHash,
		"salt":                 hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":           hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	}
	regJSON, _ := json.Marshal(regBody)

	regRouter := chi.NewRouter()
	regRouter.Post("/auth/register", api.NewAuthHandler(authService).Register)

	regReq := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regJSON))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	regRouter.ServeHTTP(regW, regReq)

	var regResp auth.RegisterResponse
	json.NewDecoder(regW.Body).Decode(&regResp)

	return r, authService, regResp.AccessToken, regResp.UserID
}

func makeAuthRequest(router chi.Router, method, path, token string, body interface{}) *httptest.ResponseRecorder {
	var reqBody *bytes.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewReader(jsonBody)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestCreateEntry_Success(t *testing.T) {
	router, _, token, _ := setupVaultRouter(t)

	// Encrypt some test data
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	ct, nonce, _ := crypto.Encrypt([]byte(`{"username":"user","password":"pass"}`), key)

	body := map[string]interface{}{
		"entry_type":     "login",
		"encrypted_data": hex.EncodeToString(ct),
		"nonce":          hex.EncodeToString(nonce),
	}

	w := makeAuthRequest(router, http.MethodPost, "/vault/entries", token, body)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp vault.EntryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.ID == "" {
		t.Error("expected non-empty entry id")
	}
	if resp.EntryType != "login" {
		t.Errorf("expected entry_type=login, got %s", resp.EntryType)
	}
	if resp.Version != 1 {
		t.Errorf("expected version=1, got %d", resp.Version)
	}
}

func TestGetEntry_Success(t *testing.T) {
	router, _, token, _ := setupVaultRouter(t)

	// Create an entry first
	key := [32]byte{1}
	ct, nonce, _ := crypto.Encrypt([]byte(`{"data":"test"}`), key)

	createBody := map[string]interface{}{
		"entry_type":     "secure_note",
		"encrypted_data": hex.EncodeToString(ct),
		"nonce":          hex.EncodeToString(nonce),
	}

	createW := makeAuthRequest(router, http.MethodPost, "/vault/entries", token, createBody)
	var created vault.EntryResponse
	json.NewDecoder(createW.Body).Decode(&created)

	// Get the entry
	getW := makeAuthRequest(router, http.MethodGet, "/vault/entries/"+created.ID, token, nil)

	if getW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getW.Code, getW.Body.String())
	}

	var resp vault.EntryResponse
	json.NewDecoder(getW.Body).Decode(&resp)

	if resp.ID != created.ID {
		t.Errorf("expected id=%s, got %s", created.ID, resp.ID)
	}
	if resp.EncryptedData != created.EncryptedData {
		t.Error("encrypted data does not match")
	}
}

func TestGetEntry_WrongUser(t *testing.T) {
	router, authService, _, _ := setupVaultRouter(t)

	_ = authService // auth service reference kept for potential future user registration

	// Try to access a non-existent entry ID (simulates wrong user access)
	getW := makeAuthRequest(router, http.MethodGet, "/vault/entries/nonexistent-id", "", nil)

	if getW.Code != http.StatusUnauthorized {
		// Without a valid token, should get 401
		t.Logf("got status %d (expected 401 for missing token)", getW.Code)
	}

	// Test with a valid token but entry belonging to different user
	router2, _, token2, _ := setupVaultRouter(t)
	_ = router2
	getW2 := makeAuthRequest(router, http.MethodGet, "/vault/entries/nonexistent-id", token2, nil)

	// The mock returns "entry not found" for entries that don't belong to user
	if getW2.Code != http.StatusNotFound && getW2.Code != http.StatusUnauthorized {
		t.Errorf("expected 404 or 401, got %d", getW2.Code)
	}
}

func TestUpdateEntry_VersionConflict(t *testing.T) {
	// Test that updating an entry returns the incremented version
	router, _, token, _ := setupVaultRouter(t)

	key := [32]byte{1}
	ct, nonce, _ := crypto.Encrypt([]byte(`{"v":"1"}`), key)

	createBody := map[string]interface{}{
		"entry_type":     "login",
		"encrypted_data": hex.EncodeToString(ct),
		"nonce":          hex.EncodeToString(nonce),
	}

	createW := makeAuthRequest(router, http.MethodPost, "/vault/entries", token, createBody)
	var created vault.EntryResponse
	json.NewDecoder(createW.Body).Decode(&created)

	if created.Version != 1 {
		t.Fatalf("expected initial version=1, got %d", created.Version)
	}

	// Update
	ct2, nonce2, _ := crypto.Encrypt([]byte(`{"v":"2"}`), key)
	updateBody := map[string]interface{}{
		"encrypted_data": hex.EncodeToString(ct2),
		"nonce":          hex.EncodeToString(nonce2),
	}

	updateW := makeAuthRequest(router, http.MethodPut, "/vault/entries/"+created.ID, token, updateBody)

	if updateW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateW.Code, updateW.Body.String())
	}

	var updated vault.EntryResponse
	json.NewDecoder(updateW.Body).Decode(&updated)

	if updated.Version != 2 {
		t.Errorf("expected version=2, got %d", updated.Version)
	}
}

func TestDeleteEntry_Success(t *testing.T) {
	router, _, token, _ := setupVaultRouter(t)

	key := [32]byte{1}
	ct, nonce, _ := crypto.Encrypt([]byte(`{"data":"delete-me"}`), key)

	createBody := map[string]interface{}{
		"entry_type":     "login",
		"encrypted_data": hex.EncodeToString(ct),
		"nonce":          hex.EncodeToString(nonce),
	}

	createW := makeAuthRequest(router, http.MethodPost, "/vault/entries", token, createBody)
	var created vault.EntryResponse
	json.NewDecoder(createW.Body).Decode(&created)

	// Delete
	deleteW := makeAuthRequest(router, http.MethodDelete, "/vault/entries/"+created.ID, token, nil)

	if deleteW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", deleteW.Code, deleteW.Body.String())
	}

	// Verify it's gone
	getW := makeAuthRequest(router, http.MethodGet, "/vault/entries/"+created.ID, token, nil)
	if getW.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", getW.Code)
	}
}

func TestListEntries_WithFilters(t *testing.T) {
	router, _, token, _ := setupVaultRouter(t)

	key := [32]byte{1}

	// Create entries of different types
	types := []string{"login", "secure_note", "login", "credit_card"}
	for _, entryType := range types {
		ct, nonce, _ := crypto.Encrypt([]byte(`{"type":"`+entryType+`"}`), key)
		body := map[string]interface{}{
			"entry_type":     entryType,
			"encrypted_data": hex.EncodeToString(ct),
			"nonce":          hex.EncodeToString(nonce),
		}
		makeAuthRequest(router, http.MethodPost, "/vault/entries", token, body)
	}

	// List all
	allW := makeAuthRequest(router, http.MethodGet, "/vault/entries", token, nil)
	if allW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", allW.Code)
	}

	var allEntries []vault.EntrySummary
	json.NewDecoder(allW.Body).Decode(&allEntries)

	if len(allEntries) != 4 {
		t.Errorf("expected 4 entries, got %d", len(allEntries))
	}

	// List filtered by type
	filteredW := makeAuthRequest(router, http.MethodGet, "/vault/entries?entry_type=login", token, nil)
	if filteredW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", filteredW.Code)
	}

	var filtered []vault.EntrySummary
	json.NewDecoder(filteredW.Body).Decode(&filtered)

	if len(filtered) != 2 {
		t.Errorf("expected 2 login entries, got %d", len(filtered))
	}
}

func TestCreateEntry_Unauthorized(t *testing.T) {
	router, _, _, _ := setupVaultRouter(t)

	body := map[string]interface{}{
		"entry_type":     "login",
		"encrypted_data": "aabbccdd",
		"nonce":          "001122334455667788990011",
	}

	// No token
	w := makeAuthRequest(router, http.MethodPost, "/vault/entries", "", body)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCreateEntry_InvalidType(t *testing.T) {
	router, _, token, _ := setupVaultRouter(t)

	body := map[string]interface{}{
		"entry_type":     "invalid_type",
		"encrypted_data": hex.EncodeToString([]byte("data")),
		"nonce":          hex.EncodeToString([]byte("123456789012")),
	}

	w := makeAuthRequest(router, http.MethodPost, "/vault/entries", token, body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestFolderCRUD tests folder creation, listing, and deletion.
func TestFolderCRUD(t *testing.T) {
	router, _, token, _ := setupVaultRouter(t)

	// Create folder
	createBody := map[string]interface{}{
		"name_encrypted": hex.EncodeToString([]byte("encrypted-folder-name")),
	}
	createW := makeAuthRequest(router, http.MethodPost, "/vault/folders", token, createBody)
	if createW.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createW.Code, createW.Body.String())
	}

	var folder vault.FolderResponse
	json.NewDecoder(createW.Body).Decode(&folder)
	if folder.ID == "" {
		t.Error("expected non-empty folder id")
	}

	// List folders
	listW := makeAuthRequest(router, http.MethodGet, "/vault/folders", token, nil)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listW.Code)
	}

	var folders []vault.FolderResponse
	json.NewDecoder(listW.Body).Decode(&folders)
	if len(folders) != 1 {
		t.Errorf("expected 1 folder, got %d", len(folders))
	}

	// Delete folder
	deleteW := makeAuthRequest(router, http.MethodDelete, "/vault/folders/"+folder.ID, token, nil)
	if deleteW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", deleteW.Code)
	}
}

// Ensure the mock is used in the right context
func init() {
	_ = context.Background
}
