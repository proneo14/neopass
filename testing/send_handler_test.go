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
	"github.com/password-manager/password-manager/internal/db"
)

// setupSendRouter creates a test router with send endpoints and returns helpers.
func setupSendRouter(t *testing.T) (chi.Router, string, string, *MockSendRepo) {
	t.Helper()

	userRepo := NewMockUserRepo()
	vaultRepo := NewMockVaultRepo()
	sendRepo := NewMockSendRepo()

	authService, err := auth.NewService(userRepo, nil, nil, auth.ServiceConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	}, vaultRepo)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	sendHandler := api.NewSendHandler(sendRepo, userRepo)

	r := chi.NewRouter()

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(api.AuthMiddleware(authService, userRepo))
		r.Post("/sends", sendHandler.CreateSend)
		r.Get("/sends", sendHandler.ListSends)
		r.Delete("/sends/{id}", sendHandler.DeleteSend)
		r.Put("/sends/{id}/disable", sendHandler.DisableSend)
	})

	// Public routes
	r.Get("/send/{slug}", sendHandler.AccessSend)
	r.Post("/send/{slug}/access", sendHandler.AccessSendWithPassword)

	// Register a test user
	authHash := createTestAuthHash()
	regBody := map[string]interface{}{
		"email":                  "senduser@example.com",
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

	return r, regResp.AccessToken, regResp.UserID, sendRepo
}

func createTestSend(t *testing.T, router chi.Router, token string, opts map[string]interface{}) map[string]interface{} {
	t.Helper()

	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	ct, nonce, _ := crypto.Encrypt([]byte("hello send"), key)

	body := map[string]interface{}{
		"type":             "text",
		"encrypted_data":   hex.EncodeToString(ct),
		"nonce":            hex.EncodeToString(nonce),
		"expires_in_hours": 24,
	}
	for k, v := range opts {
		body[k] = v
	}

	w := makeAuthRequest(router, http.MethodPost, "/sends", token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create send expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	return resp
}

// ---------------------------------------------------------------------------
// Create & Access
// ---------------------------------------------------------------------------

func TestCreateSend_Text(t *testing.T) {
	router, token, _, _ := setupSendRouter(t)

	resp := createTestSend(t, router, token, nil)

	if resp["id"] == "" {
		t.Error("expected non-empty send id")
	}
	if resp["slug"] == "" {
		t.Error("expected non-empty slug")
	}
	if resp["url"] == nil {
		t.Error("expected url in response")
	}
}

func TestAccessSend_Success(t *testing.T) {
	router, token, _, sendRepo := setupSendRouter(t)

	resp := createTestSend(t, router, token, nil)
	slug := resp["slug"].(string)

	// Access the send
	req := httptest.NewRequest(http.MethodGet, "/send/"+slug, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("access send expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var accessResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&accessResp)

	if accessResp["type"] != "text" {
		t.Errorf("expected type=text, got %v", accessResp["type"])
	}
	if accessResp["encrypted_data"] == nil {
		t.Error("expected encrypted_data in response")
	}

	// Verify access count incremented
	sendRepo.mu.Lock()
	for _, s := range sendRepo.sends {
		if s.Slug == slug {
			if s.AccessCount != 1 {
				t.Errorf("expected access_count=1, got %d", s.AccessCount)
			}
			break
		}
	}
	sendRepo.mu.Unlock()
}

func TestAccessSend_Expired(t *testing.T) {
	router, token, _, sendRepo := setupSendRouter(t)

	resp := createTestSend(t, router, token, map[string]interface{}{
		"expires_in_hours": 1,
	})
	slug := resp["slug"].(string)
	sendID := resp["id"].(string)

	// Set expiry to the past
	sendRepo.mu.Lock()
	s := sendRepo.sends[sendID]
	s.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	sendRepo.sends[sendID] = s
	sendRepo.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/send/"+slug, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusGone {
		t.Errorf("expired send expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAccessSend_MaxAccess(t *testing.T) {
	router, token, _, _ := setupSendRouter(t)

	maxAccess := 1
	resp := createTestSend(t, router, token, map[string]interface{}{
		"max_access_count": maxAccess,
	})
	slug := resp["slug"].(string)

	// First access succeeds
	req := httptest.NewRequest(http.MethodGet, "/send/"+slug, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first access expected 200, got %d", w.Code)
	}

	// Second access should fail
	req = httptest.NewRequest(http.MethodGet, "/send/"+slug, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusGone {
		t.Errorf("second access expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAccessSend_Password(t *testing.T) {
	router, token, _, _ := setupSendRouter(t)

	resp := createTestSend(t, router, token, map[string]interface{}{
		"password": "secret123",
	})
	slug := resp["slug"].(string)

	// Access without password should return 401
	req := httptest.NewRequest(http.MethodGet, "/send/"+slug, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("access without password expected 401, got %d", w.Code)
	}

	var authResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&authResp)
	if authResp["requires_password"] != true {
		t.Error("expected requires_password=true")
	}
}

func TestAccessSend_WithPassword(t *testing.T) {
	router, token, _, _ := setupSendRouter(t)

	resp := createTestSend(t, router, token, map[string]interface{}{
		"password": "secret123",
	})
	slug := resp["slug"].(string)

	// Access with correct password
	body := map[string]interface{}{
		"password": "secret123",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/send/"+slug+"/access", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("access with password expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var accessResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&accessResp)
	if accessResp["encrypted_data"] == nil {
		t.Error("expected encrypted_data in response")
	}
}

func TestAccessSend_WrongPassword(t *testing.T) {
	router, token, _, _ := setupSendRouter(t)

	resp := createTestSend(t, router, token, map[string]interface{}{
		"password": "secret123",
	})
	slug := resp["slug"].(string)

	body := map[string]interface{}{
		"password": "wrongpassword",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/send/"+slug+"/access", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password expected 401, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// List & Delete
// ---------------------------------------------------------------------------

func TestListSends(t *testing.T) {
	router, token, _, _ := setupSendRouter(t)

	createTestSend(t, router, token, nil)
	createTestSend(t, router, token, nil)

	w := makeAuthRequest(router, http.MethodGet, "/sends", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list sends expected 200, got %d", w.Code)
	}

	var sends []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&sends)
	if len(sends) != 2 {
		t.Errorf("expected 2 sends, got %d", len(sends))
	}
}

func TestDeleteSend(t *testing.T) {
	router, token, _, _ := setupSendRouter(t)

	resp := createTestSend(t, router, token, nil)
	sendID := resp["id"].(string)

	w := makeAuthRequest(router, http.MethodDelete, "/sends/"+sendID, token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete send expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify gone
	lw := makeAuthRequest(router, http.MethodGet, "/sends", token, nil)
	var sends []map[string]interface{}
	json.NewDecoder(lw.Body).Decode(&sends)
	if len(sends) != 0 {
		t.Errorf("expected 0 sends after delete, got %d", len(sends))
	}
}

func TestDisableSend(t *testing.T) {
	router, token, _, _ := setupSendRouter(t)

	resp := createTestSend(t, router, token, nil)
	sendID := resp["id"].(string)
	slug := resp["slug"].(string)

	// Disable
	w := makeAuthRequest(router, http.MethodPut, "/sends/"+sendID+"/disable", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("disable send expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Access should return 410
	req := httptest.NewRequest(http.MethodGet, "/send/"+slug, nil)
	aw := httptest.NewRecorder()
	router.ServeHTTP(aw, req)
	if aw.Code != http.StatusGone {
		t.Errorf("disabled send access expected 410, got %d", aw.Code)
	}
}

// ---------------------------------------------------------------------------
// Purge
// ---------------------------------------------------------------------------

func TestPurgeSends(t *testing.T) {
	_, _, _, sendRepo := setupSendRouter(t)

	// Directly create expired sends in the repo
	past := time.Now().UTC().Add(-2 * time.Hour)
	sendRepo.mu.Lock()
	sendRepo.nextID++
	sendRepo.sends["expired-1"] = db.Send{
		ID:        "expired-1",
		UserID:    "user-1",
		Slug:      "exp-slug-1",
		SendType:  "text",
		ExpiresAt: past,
	}
	sendRepo.bySlug["exp-slug-1"] = "expired-1"
	sendRepo.nextID++
	sendRepo.sends["expired-2"] = db.Send{
		ID:        "expired-2",
		UserID:    "user-1",
		Slug:      "exp-slug-2",
		SendType:  "text",
		ExpiresAt: past,
	}
	sendRepo.bySlug["exp-slug-2"] = "expired-2"
	sendRepo.mu.Unlock()

	purged, err := sendRepo.PurgeExpiredSends(nil)
	if err != nil {
		t.Fatalf("purge failed: %v", err)
	}
	if purged != 2 {
		t.Errorf("expected 2 purged, got %d", purged)
	}

	sendRepo.mu.Lock()
	remaining := len(sendRepo.sends)
	sendRepo.mu.Unlock()
	if remaining != 0 {
		t.Errorf("expected 0 sends after purge, got %d", remaining)
	}
}
