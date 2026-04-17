package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/auth"
)

// AuthHandler handles authentication HTTP endpoints.
type AuthHandler struct {
	authService *auth.Service
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authService *auth.Service) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Register handles POST /api/v1/auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req auth.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.AuthHash == "" || req.Salt == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	resp, err := h.authService.Register(r.Context(), req)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		log.Error().Err(err).Msg("registration failed")
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// Login handles POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.AuthHash == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	resp, err := h.authService.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		log.Error().Err(err).Msg("login failed")
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Refresh handles POST /api/v1/auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "missing refresh_token")
		return
	}

	resp, err := h.authService.RefreshToken(r.Context(), body.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		log.Error().Err(err).Msg("token refresh failed")
		writeError(w, http.StatusInternalServerError, "token refresh failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Logout handles POST /api/v1/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Client-side logout: just acknowledge.
	// Server-side token invalidation would require a revocation list (future enhancement).
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// ChangePassword handles POST /api/v1/auth/change-password
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		OldMasterKey string `json:"old_master_key"`
		NewMasterKey string `json:"new_master_key"`
		NewAuthHash  string `json:"new_auth_hash"`
		NewSalt      string `json:"new_salt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.OldMasterKey == "" || body.NewMasterKey == "" || body.NewAuthHash == "" || body.NewSalt == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	oldKeyBytes, err := hex.DecodeString(body.OldMasterKey)
	if err != nil || len(oldKeyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid old_master_key")
		return
	}
	newKeyBytes, err := hex.DecodeString(body.NewMasterKey)
	if err != nil || len(newKeyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid new_master_key")
		return
	}

	var oldMasterKey, newMasterKey [32]byte
	copy(oldMasterKey[:], oldKeyBytes)
	copy(newMasterKey[:], newKeyBytes)

	if err := h.authService.ChangeOwnPassword(r.Context(), claims.UserID, oldMasterKey, newMasterKey, body.NewAuthHash, body.NewSalt); err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("password change failed")
		writeError(w, http.StatusInternalServerError, "failed to change password")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}
