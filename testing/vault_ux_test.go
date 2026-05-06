package integration_test

import (
	"bytes"
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

// setupVaultUXRouter creates a test router with vault endpoints including UX routes.
func setupVaultUXRouter(t *testing.T) (chi.Router, string, string, *MockVaultRepo) {
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
		r.Use(api.AuthMiddleware(authService, userRepo))
		r.Post("/vault/entries", vaultHandler.CreateEntry)
		r.Get("/vault/entries", vaultHandler.ListEntries)
		r.Get("/vault/entries/{id}", vaultHandler.GetEntry)
		r.Put("/vault/entries/{id}", vaultHandler.UpdateEntry)
		r.Delete("/vault/entries/{id}", vaultHandler.DeleteEntry)
		r.Put("/vault/entries/{id}/favorite", vaultHandler.SetFavorite)
		r.Put("/vault/entries/{id}/archive", vaultHandler.SetArchived)
		r.Post("/vault/entries/{id}/restore", vaultHandler.RestoreEntry)
		r.Delete("/vault/entries/{id}/permanent", vaultHandler.PermanentDeleteEntry)
		r.Post("/vault/entries/{id}/clone", vaultHandler.CloneEntry)
		r.Post("/vault/trash/purge", vaultHandler.PurgeTrash)
	})

	// Register a test user
	authHash := createTestAuthHash()
	regBody := map[string]interface{}{
		"email":                  "uxuser@example.com",
		"auth_hash":             authHash,
		"salt":                  hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":            hex.EncodeToString([]byte("fake-public-key")),
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
	if err := json.NewDecoder(regW.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	return r, regResp.AccessToken, regResp.UserID, vaultRepo
}

func createTestEntry(t *testing.T, router chi.Router, token, entryType string) vault.EntryResponse {
	t.Helper()

	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	ct, nonce, _ := crypto.Encrypt([]byte(`{"name":"test entry"}`), key)

	body := map[string]interface{}{
		"entry_type":     entryType,
		"encrypted_data": hex.EncodeToString(ct),
		"nonce":          hex.EncodeToString(nonce),
	}

	w := makeAuthRequest(router, http.MethodPost, "/vault/entries", token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create entry expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp vault.EntryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Favorite Tests
// ---------------------------------------------------------------------------

func TestFavorite_SetAndUnset(t *testing.T) {
	router, token, _, _ := setupVaultUXRouter(t)

	entry := createTestEntry(t, router, token, "login")

	// Set favorite
	w := makeAuthRequest(router, http.MethodPut, "/vault/entries/"+entry.ID+"/favorite", token,
		map[string]interface{}{"is_favorite": true})
	if w.Code != http.StatusOK {
		t.Fatalf("set favorite expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// List with favorite filter
	req := httptest.NewRequest(http.MethodGet, "/vault/entries?favorite=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw := httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	if lw.Code != http.StatusOK {
		t.Fatalf("list favorites expected 200, got %d", lw.Code)
	}
	var entries []vault.EntrySummary
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 favorite entry, got %d", len(entries))
	}
	if len(entries) > 0 && entries[0].ID != entry.ID {
		t.Errorf("expected favorite entry id=%s, got %s", entry.ID, entries[0].ID)
	}

	// Unset favorite
	w = makeAuthRequest(router, http.MethodPut, "/vault/entries/"+entry.ID+"/favorite", token,
		map[string]interface{}{"is_favorite": false})
	if w.Code != http.StatusOK {
		t.Fatalf("unset favorite expected 200, got %d", w.Code)
	}

	// List again — no favorites
	req = httptest.NewRequest(http.MethodGet, "/vault/entries?favorite=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw = httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected 0 favorite entries after unset, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Archive Tests
// ---------------------------------------------------------------------------

func TestArchive_SetAndUnset(t *testing.T) {
	router, token, _, _ := setupVaultUXRouter(t)

	entry := createTestEntry(t, router, token, "login")

	// Archive
	w := makeAuthRequest(router, http.MethodPut, "/vault/entries/"+entry.ID+"/archive", token,
		map[string]interface{}{"is_archived": true})
	if w.Code != http.StatusOK {
		t.Fatalf("archive expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Default list should exclude archived
	req := httptest.NewRequest(http.MethodGet, "/vault/entries", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw := httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	var entries []vault.EntrySummary
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries in default list (archived excluded), got %d", len(entries))
	}

	// List archived
	req = httptest.NewRequest(http.MethodGet, "/vault/entries?filter=archived", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw = httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 archived entry, got %d", len(entries))
	}

	// Unarchive
	w = makeAuthRequest(router, http.MethodPut, "/vault/entries/"+entry.ID+"/archive", token,
		map[string]interface{}{"is_archived": false})
	if w.Code != http.StatusOK {
		t.Fatalf("unarchive expected 200, got %d", w.Code)
	}

	// Default list should include it again
	req = httptest.NewRequest(http.MethodGet, "/vault/entries", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw = httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry after unarchive, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Trash Tests
// ---------------------------------------------------------------------------

func TestTrash_DeleteAndRestore(t *testing.T) {
	router, token, _, _ := setupVaultUXRouter(t)

	entry := createTestEntry(t, router, token, "login")

	// Soft delete (move to trash)
	w := makeAuthRequest(router, http.MethodDelete, "/vault/entries/"+entry.ID, token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Default list excludes trashed entries
	req := httptest.NewRequest(http.MethodGet, "/vault/entries", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw := httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	var entries []vault.EntrySummary
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries in default list (trashed excluded), got %d", len(entries))
	}

	// List trash
	req = httptest.NewRequest(http.MethodGet, "/vault/entries?filter=trash", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw = httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 trashed entry, got %d", len(entries))
	}

	// Restore
	w = makeAuthRequest(router, http.MethodPost, "/vault/entries/"+entry.ID+"/restore", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("restore expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Default list should include it again
	req = httptest.NewRequest(http.MethodGet, "/vault/entries", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw = httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry after restore, got %d", len(entries))
	}
}

func TestTrash_PermanentDelete(t *testing.T) {
	router, token, _, _ := setupVaultUXRouter(t)

	entry := createTestEntry(t, router, token, "login")

	// Move to trash first
	makeAuthRequest(router, http.MethodDelete, "/vault/entries/"+entry.ID, token, nil)

	// Permanently delete
	w := makeAuthRequest(router, http.MethodDelete, "/vault/entries/"+entry.ID+"/permanent", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("permanent delete expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify gone from trash
	req := httptest.NewRequest(http.MethodGet, "/vault/entries?filter=trash", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw := httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	var entries []vault.EntrySummary
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after permanent delete, got %d", len(entries))
	}
}

func TestTrash_AutoPurge(t *testing.T) {
	router, token, _, vaultRepo := setupVaultUXRouter(t)

	entry := createTestEntry(t, router, token, "login")

	// Move to trash
	makeAuthRequest(router, http.MethodDelete, "/vault/entries/"+entry.ID, token, nil)

	// Manually set deleted_at to 31 days ago to simulate old trash
	vaultRepo.mu.Lock()
	e := vaultRepo.entries[entry.ID]
	oldTime := time.Now().Add(-31 * 24 * time.Hour)
	e.DeletedAt = &oldTime
	vaultRepo.entries[entry.ID] = e
	vaultRepo.mu.Unlock()

	// Purge trash
	w := makeAuthRequest(router, http.MethodPost, "/vault/trash/purge", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("purge expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if count, ok := resp["count"].(float64); !ok || count < 1 {
		t.Errorf("expected purge count >= 1, got %v", resp["count"])
	}

	// Verify entry is gone
	req := httptest.NewRequest(http.MethodGet, "/vault/entries?filter=trash", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lw := httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	var entries []vault.EntrySummary
	json.NewDecoder(lw.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after purge, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Clone Tests
// ---------------------------------------------------------------------------

func TestClone_Entry(t *testing.T) {
	router, token, _, _ := setupVaultUXRouter(t)

	original := createTestEntry(t, router, token, "login")

	// Clone the entry
	w := makeAuthRequest(router, http.MethodPost, "/vault/entries/"+original.ID+"/clone", token, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("clone expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var clone vault.EntryResponse
	if err := json.NewDecoder(w.Body).Decode(&clone); err != nil {
		t.Fatalf("decode clone response: %v", err)
	}

	if clone.ID == "" {
		t.Error("clone should have a non-empty ID")
	}
	if clone.ID == original.ID {
		t.Error("clone should have a different ID than original")
	}
	if clone.EntryType != original.EntryType {
		t.Errorf("clone entry_type=%s, original=%s", clone.EntryType, original.EntryType)
	}
	if clone.EncryptedData != original.EncryptedData {
		t.Error("clone should have the same encrypted data as original")
	}
	if clone.Nonce != original.Nonce {
		t.Error("clone should have the same nonce as original")
	}
	if clone.Version != 1 {
		t.Errorf("clone should have version=1, got %d", clone.Version)
	}
}

// ---------------------------------------------------------------------------
// Combined Filters
// ---------------------------------------------------------------------------

func TestListEntries_Filters(t *testing.T) {
	router, token, _, _ := setupVaultUXRouter(t)

	// Create entries of different types
	login := createTestEntry(t, router, token, "login")
	_ = createTestEntry(t, router, token, "secure_note")

	// Favorite the login entry
	makeAuthRequest(router, http.MethodPut, "/vault/entries/"+login.ID+"/favorite", token,
		map[string]interface{}{"is_favorite": true})

	// List only favorites
	req := httptest.NewRequest(http.MethodGet, "/vault/entries?favorite=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var entries []vault.EntrySummary
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("favorite filter: expected 1 entry, got %d", len(entries))
	}

	// List by entry_type
	req = httptest.NewRequest(http.MethodGet, "/vault/entries?entry_type=secure_note", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Errorf("entry_type filter: expected 1 entry, got %d", len(entries))
	}
	if len(entries) > 0 && entries[0].EntryType != "secure_note" {
		t.Errorf("expected secure_note, got %s", entries[0].EntryType)
	}

	// List all (should be 2)
	req = httptest.NewRequest(http.MethodGet, "/vault/entries", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 2 {
		t.Errorf("all filter: expected 2 entries, got %d", len(entries))
	}
}
