package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/auth"
)

// TwoFactorHandler handles 2FA HTTP endpoints.
type TwoFactorHandler struct {
	totpService *auth.TOTPService
	smsService  *auth.SMSService
	authService *auth.Service
}

// NewTwoFactorHandler creates a new TwoFactorHandler.
func NewTwoFactorHandler(totpService *auth.TOTPService, smsService *auth.SMSService, authService *auth.Service) *TwoFactorHandler {
	return &TwoFactorHandler{
		totpService: totpService,
		smsService:  smsService,
		authService: authService,
	}
}

// Setup handles POST /api/v1/auth/2fa/setup
// Requires authentication. Client sends their encryption key (hex) to encrypt the TOTP secret.
func (h *TwoFactorHandler) Setup(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		EncryptionKey string `json:"encryption_key"` // hex-encoded 32-byte master key
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	keyBytes, err := hex.DecodeString(body.EncryptionKey)
	if err != nil || len(keyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid encryption key")
		return
	}

	var encKey [32]byte
	copy(encKey[:], keyBytes)

	resp, err := h.totpService.SetupTOTP(r.Context(), claims.UserID, encKey)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("2FA setup failed")
		writeError(w, http.StatusInternalServerError, "2fa setup failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// VerifySetup handles POST /api/v1/auth/2fa/verify-setup
// Confirms the first TOTP code to activate 2FA.
func (h *TwoFactorHandler) VerifySetup(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		Code          string `json:"code"`
		EncryptionKey string `json:"encryption_key"` // hex-encoded
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Code == "" || body.EncryptionKey == "" {
		writeError(w, http.StatusBadRequest, "missing code or encryption_key")
		return
	}

	keyBytes, err := hex.DecodeString(body.EncryptionKey)
	if err != nil || len(keyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid encryption key")
		return
	}

	var encKey [32]byte
	copy(encKey[:], keyBytes)

	if err := h.totpService.VerifyTOTPSetup(r.Context(), claims.UserID, body.Code, encKey); err != nil {
		if errors.Is(err, auth.ErrInvalidTOTPCode) {
			writeError(w, http.StatusUnauthorized, "invalid code")
			return
		}
		log.Error().Err(err).Msg("2FA verify setup failed")
		writeError(w, http.StatusInternalServerError, "verification failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "2fa_enabled"})
}

// Validate handles POST /api/v1/auth/2fa/validate
// Used during login to complete 2FA. Accepts temp_token + code.
func (h *TwoFactorHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TempToken     string `json:"temp_token"`
		Code          string `json:"code"`
		EncryptionKey string `json:"encryption_key"` // hex-encoded, needed to decrypt TOTP secret
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.TempToken == "" || body.Code == "" {
		writeError(w, http.StatusBadRequest, "missing temp_token or code")
		return
	}

	// Validate the temp token to get user ID
	claims, err := h.authService.ValidateToken(body.TempToken)
	if err != nil || !claims.Is2FA {
		writeError(w, http.StatusUnauthorized, "invalid or expired temp token")
		return
	}

	// Try recovery code first (no encryption key needed)
	if err := h.totpService.ValidateTOTPServerSide(r.Context(), claims.UserID, body.Code); err == nil {
		// Recovery code matched
		resp, err := h.authService.Complete2FALogin(r.Context(), body.TempToken, claims.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "login completion failed")
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// For TOTP code validation, need encryption key
	if body.EncryptionKey != "" {
		keyBytes, err := hex.DecodeString(body.EncryptionKey)
		if err == nil && len(keyBytes) == 32 {
			var encKey [32]byte
			copy(encKey[:], keyBytes)

			if err := h.totpService.ValidateTOTP(r.Context(), claims.UserID, body.Code, encKey); err == nil {
				resp, err := h.authService.Complete2FALogin(r.Context(), body.TempToken, claims.UserID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "login completion failed")
					return
				}
				writeJSON(w, http.StatusOK, resp)
				return
			}
		}
	}

	writeError(w, http.StatusUnauthorized, "invalid 2fa code")
}

// Share handles POST /api/v1/auth/2fa/share
// Admin shares a TOTP secret with another user (encrypted with recipient's public key).
func (h *TwoFactorHandler) Share(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		ToUserID    string `json:"to_user_id"`
		TOTPSecret  string `json:"totp_secret"`
		ExpiresInMin int   `json:"expires_in_minutes"` // default 60
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.ToUserID == "" || body.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "missing to_user_id or totp_secret")
		return
	}

	expiresIn := time.Duration(body.ExpiresInMin) * time.Minute
	if expiresIn <= 0 {
		expiresIn = 60 * time.Minute
	}

	shareID, err := h.totpService.ShareTOTP(r.Context(), claims.UserID, body.ToUserID, body.TOTPSecret, expiresIn)
	if err != nil {
		log.Error().Err(err).Msg("2FA share failed")
		writeError(w, http.StatusInternalServerError, "share failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"share_id": shareID,
		"status":   "shared",
	})
}

// Claim handles POST /api/v1/auth/2fa/claim/{id}
// User decrypts and claims a shared TOTP secret.
func (h *TwoFactorHandler) Claim(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	shareID := chi.URLParam(r, "id")
	if shareID == "" {
		writeError(w, http.StatusBadRequest, "missing share id")
		return
	}

	var body struct {
		PrivateKey string `json:"private_key"` // hex-encoded X-Wing private key
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.PrivateKey == "" {
		writeError(w, http.StatusBadRequest, "missing private_key")
		return
	}

	privKeyBytes, err := hex.DecodeString(body.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid private_key hex")
		return
	}

	secret, err := h.totpService.ClaimSharedTOTP(r.Context(), claims.UserID, shareID, privKeyBytes)
	if err != nil {
		if errors.Is(err, auth.ErrShareExpired) {
			writeError(w, http.StatusGone, "share expired")
			return
		}
		if errors.Is(err, auth.ErrShareClaimed) {
			writeError(w, http.StatusConflict, "already claimed")
			return
		}
		log.Error().Err(err).Msg("2FA claim failed")
		writeError(w, http.StatusInternalServerError, "claim failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"totp_secret": secret,
		"status":      "claimed",
	})
}

// SendSMS handles POST /api/v1/auth/2fa/sms/send
func (h *TwoFactorHandler) SendSMS(w http.ResponseWriter, r *http.Request) {
	if h.smsService == nil {
		writeError(w, http.StatusNotFound, "sms 2fa not enabled")
		return
	}

	var body struct {
		TempToken   string `json:"temp_token"`
		PhoneNumber string `json:"phone_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.PhoneNumber == "" || body.TempToken == "" {
		writeError(w, http.StatusBadRequest, "missing temp_token or phone_number")
		return
	}

	claims, err := h.authService.ValidateToken(body.TempToken)
	if err != nil || !claims.Is2FA {
		writeError(w, http.StatusUnauthorized, "invalid temp token")
		return
	}

	if err := h.smsService.SendSMS2FA(r.Context(), claims.UserID, body.PhoneNumber); err != nil {
		log.Error().Err(err).Msg("SMS send failed")
		writeError(w, http.StatusInternalServerError, "failed to send sms")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "sms_sent"})
}

// ValidateSMS handles POST /api/v1/auth/2fa/sms/validate
func (h *TwoFactorHandler) ValidateSMS(w http.ResponseWriter, r *http.Request) {
	if h.smsService == nil {
		writeError(w, http.StatusNotFound, "sms 2fa not enabled")
		return
	}

	var body struct {
		TempToken string `json:"temp_token"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.TempToken == "" || body.Code == "" {
		writeError(w, http.StatusBadRequest, "missing temp_token or code")
		return
	}

	claims, err := h.authService.ValidateToken(body.TempToken)
	if err != nil || !claims.Is2FA {
		writeError(w, http.StatusUnauthorized, "invalid temp token")
		return
	}

	if err := h.smsService.ValidateSMS2FA(r.Context(), claims.UserID, body.Code); err != nil {
		if errors.Is(err, auth.ErrSMSCodeInvalid) || errors.Is(err, auth.ErrSMSCodeExpired) {
			writeError(w, http.StatusUnauthorized, "invalid or expired code")
			return
		}
		writeError(w, http.StatusInternalServerError, "validation failed")
		return
	}

	// Issue full tokens
	resp, err := h.authService.Complete2FALogin(r.Context(), body.TempToken, claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login completion failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Disable handles POST /api/v1/auth/2fa/disable
func (h *TwoFactorHandler) Disable(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.totpService.DisableTOTP(r.Context(), claims.UserID); err != nil {
		log.Error().Err(err).Msg("2FA disable failed")
		writeError(w, http.StatusInternalServerError, "disable failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "2fa_disabled"})
}
