package integration_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/password-manager/password-manager/internal/api"
	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/crypto"
)

// setupAuthRouter creates a test router with auth endpoints using mock repos.
func setupAuthRouter(t *testing.T) (chi.Router, *MockUserRepo, *auth.Service) {
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

	authLimiter := api.NewRateLimiter(5, 1*time.Minute)
	r := chi.NewRouter()
	r.Route("/auth", func(r chi.Router) {
		r.Use(authLimiter.RateLimit)
		r.Post("/register", api.NewAuthHandler(authService).Register)
		r.Post("/login", api.NewAuthHandler(authService).Login)
		r.Post("/refresh", api.NewAuthHandler(authService).Refresh)
	})

	return r, userRepo, authService
}

// createTestAuthHash generates a deterministic auth hash for testing.
func createTestAuthHash() string {
	_, ah, _, _ := crypto.DeriveKeys("testpassword", []byte("0123456789abcdef"))
	return hex.EncodeToString(ah[:])
}

func TestRegister_Success(t *testing.T) {
	router, _, _ := setupAuthRouter(t)

	body := map[string]interface{}{
		"email":                 "test@example.com",
		"auth_hash":            createTestAuthHash(),
		"salt":                 hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":           hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp auth.RegisterResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.UserID == "" {
		t.Error("expected non-empty user_id")
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access_token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh_token")
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	router, _, _ := setupAuthRouter(t)

	body := map[string]interface{}{
		"email":                 "dup@example.com",
		"auth_hash":            createTestAuthHash(),
		"salt":                 hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":           hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	}
	jsonBody, _ := json.Marshal(body)

	// First registration
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("first register expected 201, got %d", w.Code)
	}

	// Second registration with same email
	jsonBody, _ = json.Marshal(body)
	req = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_Success(t *testing.T) {
	router, _, _ := setupAuthRouter(t)

	authHash := createTestAuthHash()

	// Register first
	regBody := map[string]interface{}{
		"email":                 "login@example.com",
		"auth_hash":            authHash,
		"salt":                 hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":           hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	}
	regJSON, _ := json.Marshal(regBody)
	regReq := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regJSON))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	router.ServeHTTP(regW, regReq)

	if regW.Code != http.StatusCreated {
		t.Fatalf("register failed: %d %s", regW.Code, regW.Body.String())
	}

	// Login
	loginBody := map[string]interface{}{
		"email":     "login@example.com",
		"auth_hash": authHash,
	}
	loginJSON, _ := json.Marshal(loginBody)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginJSON))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	router.ServeHTTP(loginW, loginReq)

	if loginW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", loginW.Code, loginW.Body.String())
	}

	var resp auth.LoginResponse
	if err := json.NewDecoder(loginW.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected access_token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh_token")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	router, _, _ := setupAuthRouter(t)

	authHash := createTestAuthHash()

	// Register
	regBody := map[string]interface{}{
		"email":                 "wrong@example.com",
		"auth_hash":            authHash,
		"salt":                 hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":           hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	}
	regJSON, _ := json.Marshal(regBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Login with wrong auth hash
	wrongHash := hex.EncodeToString([]byte("0000000000000000000000000000000000000000000000000000000000000000"))
	loginBody := map[string]interface{}{
		"email":     "wrong@example.com",
		"auth_hash": wrongHash,
	}
	loginJSON, _ := json.Marshal(loginBody)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginJSON))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	router.ServeHTTP(loginW, loginReq)

	if loginW.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", loginW.Code)
	}
}

func TestLogin_With2FA(t *testing.T) {
	router, userRepo, _ := setupAuthRouter(t)

	authHash := createTestAuthHash()

	// Register
	regBody := map[string]interface{}{
		"email":                 "2fa@example.com",
		"auth_hash":            authHash,
		"salt":                 hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":           hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	}
	regJSON, _ := json.Marshal(regBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var regResp auth.RegisterResponse
	if err := json.NewDecoder(w.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	// Enable 2FA
	userRepo.SetHas2FA(regResp.UserID, true)

	// Login — should require 2FA
	loginBody := map[string]interface{}{
		"email":     "2fa@example.com",
		"auth_hash": authHash,
	}
	loginJSON, _ := json.Marshal(loginBody)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginJSON))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	router.ServeHTTP(loginW, loginReq)

	if loginW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", loginW.Code, loginW.Body.String())
	}

	var resp auth.LoginResponse
	if err := json.NewDecoder(loginW.Body).Decode(&resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}

	if !resp.Requires2FA {
		t.Error("expected requires_2fa to be true")
	}
	if resp.TempToken == "" {
		t.Error("expected temp_token for 2FA flow")
	}
	if resp.AccessToken != "" {
		t.Error("should not have access_token before 2FA completion")
	}
}

func TestLogin_RateLimit(t *testing.T) {
	router, _, _ := setupAuthRouter(t)

	loginBody := map[string]interface{}{
		"email":     "nonexistent@example.com",
		"auth_hash": "aabbccdd",
	}
	loginJSON, _ := json.Marshal(loginBody)

	// Send 5 requests (within limit)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginJSON))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		// These may return 401 (wrong creds), but not 429 yet
	}

	// 6th request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func TestRefreshToken_Valid(t *testing.T) {
	router, _, _ := setupAuthRouter(t)

	authHash := createTestAuthHash()

	// Register
	regBody := map[string]interface{}{
		"email":                 "refresh@example.com",
		"auth_hash":            authHash,
		"salt":                 hex.EncodeToString([]byte("0123456789abcdef")),
		"public_key":           hex.EncodeToString([]byte("fake-public-key")),
		"encrypted_private_key": hex.EncodeToString([]byte("fake-enc-priv-key")),
	}
	regJSON, _ := json.Marshal(regBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var regResp auth.RegisterResponse
	if err := json.NewDecoder(w.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	// Refresh
	refreshBody := map[string]interface{}{
		"refresh_token": regResp.RefreshToken,
	}
	refreshJSON, _ := json.Marshal(refreshBody)
	refreshReq := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshJSON))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshW := httptest.NewRecorder()
	router.ServeHTTP(refreshW, refreshReq)

	if refreshW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", refreshW.Code, refreshW.Body.String())
	}

	var resp auth.TokenResponse
	if err := json.NewDecoder(refreshW.Body).Decode(&resp); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected new access_token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected new refresh_token")
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	router, _, _ := setupAuthRouter(t)

	// Use an obviously invalid/expired token
	refreshBody := map[string]interface{}{
		"refresh_token": "invalid.token.string",
	}
	refreshJSON, _ := json.Marshal(refreshBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid") && !strings.Contains(body, "expired") {
		t.Errorf("expected error about invalid/expired token, got: %s", body)
	}
}
