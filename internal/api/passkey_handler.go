package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// PasskeyHandler handles passkey and hardware key HTTP endpoints.
type PasskeyHandler struct {
	webauthnService *auth.WebAuthnService
}

// NewPasskeyHandler creates a new PasskeyHandler.
func NewPasskeyHandler(webauthnService *auth.WebAuthnService) *PasskeyHandler {
	return &PasskeyHandler{webauthnService: webauthnService}
}

// ListPasskeys handles GET /api/v1/vault/passkeys
func (h *PasskeyHandler) ListPasskeys(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rpID := r.URL.Query().Get("rp_id")
	passkeys, err := h.webauthnService.ListPasskeys(r.Context(), claims.UserID, rpID)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("list passkeys failed")
		writeError(w, http.StatusInternalServerError, "failed to list passkeys")
		return
	}

	if passkeys == nil {
		passkeys = []db.PasskeyCredential{}
	}

	writeJSON(w, http.StatusOK, passkeys)
}

// DeletePasskey handles DELETE /api/v1/vault/passkeys/:id
func (h *PasskeyHandler) DeletePasskey(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	passkeyID := chi.URLParam(r, "id")
	if passkeyID == "" {
		writeError(w, http.StatusBadRequest, "missing passkey ID")
		return
	}

	if err := h.webauthnService.DeletePasskey(r.Context(), claims.UserID, passkeyID); err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("delete passkey failed")
		writeError(w, http.StatusNotFound, "passkey not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// BeginRegistration handles POST /api/v1/vault/passkeys/register/begin
func (h *PasskeyHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		RPID        string `json:"rp_id"`
		RPName      string `json:"rp_name"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RPID == "" || req.RPName == "" {
		writeError(w, http.StatusBadRequest, "rp_id and rp_name are required")
		return
	}

	opts, err := h.webauthnService.BeginPasskeyRegistration(
		r.Context(), claims.UserID, req.RPID, req.RPName, req.Username, req.DisplayName,
	)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("begin passkey registration failed")
		writeError(w, http.StatusInternalServerError, "failed to begin registration")
		return
	}

	writeJSON(w, http.StatusOK, opts)
}

// FinishRegistration handles POST /api/v1/vault/passkeys/register/finish
func (h *PasskeyHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req auth.FinishPasskeyRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SessionID == "" || req.MasterKeyHex == "" || req.RPID == "" {
		writeError(w, http.StatusBadRequest, "session_id, master_key_hex, and rp_id are required")
		return
	}

	passkey, err := h.webauthnService.FinishPasskeyRegistration(r.Context(), claims.UserID, &req)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("finish passkey registration failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, passkey)
}

// BeginAuthentication handles POST /api/v1/vault/passkeys/authenticate/begin
func (h *PasskeyHandler) BeginAuthentication(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		RPID string `json:"rp_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RPID == "" {
		writeError(w, http.StatusBadRequest, "rp_id is required")
		return
	}

	opts, err := h.webauthnService.BeginPasskeyAuthentication(r.Context(), claims.UserID, req.RPID)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("begin passkey authentication failed")
		writeError(w, http.StatusInternalServerError, "failed to begin authentication")
		return
	}

	writeJSON(w, http.StatusOK, opts)
}

// FinishAuthentication handles POST /api/v1/vault/passkeys/authenticate/finish
func (h *PasskeyHandler) FinishAuthentication(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req auth.PasskeySignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SessionID == "" || req.CredentialID == "" || req.MasterKeyHex == "" {
		writeError(w, http.StatusBadRequest, "session_id, credential_id, and master_key_hex are required")
		return
	}

	resp, err := h.webauthnService.SignPasskeyAssertion(r.Context(), claims.UserID, &req)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("finish passkey authentication failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ListHardwareKeys handles GET /api/v1/auth/hardware-keys
func (h *PasskeyHandler) ListHardwareKeys(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	keys, err := h.webauthnService.ListHardwareKeys(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("list hardware keys failed")
		writeError(w, http.StatusInternalServerError, "failed to list hardware keys")
		return
	}

	if keys == nil {
		keys = []db.HardwareAuthKey{}
	}

	writeJSON(w, http.StatusOK, keys)
}

// DeleteHardwareKey handles DELETE /api/v1/auth/hardware-keys/:id
func (h *PasskeyHandler) DeleteHardwareKey(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "missing key ID")
		return
	}

	if err := h.webauthnService.DeleteHardwareKey(r.Context(), claims.UserID, keyID); err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("delete hardware key failed")
		writeError(w, http.StatusNotFound, "hardware key not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// BeginHardwareKeyRegistration handles POST /api/v1/auth/hardware-keys/register/begin
func (h *PasskeyHandler) BeginHardwareKeyRegistration(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		UserName    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	opts, err := h.webauthnService.BeginHardwareKeyRegistration(r.Context(), claims.UserID, req.UserName, req.DisplayName)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("begin hardware key registration failed")
		writeError(w, http.StatusInternalServerError, "failed to begin registration")
		return
	}

	writeJSON(w, http.StatusOK, opts)
}

// FinishHardwareKeyRegistration handles POST /api/v1/auth/hardware-keys/register/finish
func (h *PasskeyHandler) FinishHardwareKeyRegistration(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req auth.FinishHardwareKeyRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SessionID == "" || req.CredentialID == "" || req.PublicKeyCBOR == "" {
		writeError(w, http.StatusBadRequest, "session_id, credential_id, and public_key_cbor are required")
		return
	}

	key, err := h.webauthnService.FinishHardwareKeyRegistration(r.Context(), claims.UserID, &req)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("finish hardware key registration failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, key)
}

// BeginHardwareKeyAuth handles POST /api/v1/auth/hardware-keys/authenticate/begin
func (h *PasskeyHandler) BeginHardwareKeyAuth(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	opts, err := h.webauthnService.BeginHardwareKeyAuthentication(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("begin hardware key auth failed")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, opts)
}

// FinishHardwareKeyAuth handles POST /api/v1/auth/hardware-keys/authenticate/finish
func (h *PasskeyHandler) FinishHardwareKeyAuth(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req auth.FinishHardwareKeyAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SessionID == "" || req.CredentialID == "" || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "session_id, credential_id, and signature are required")
		return
	}

	if err := h.webauthnService.FinishHardwareKeyAuthentication(r.Context(), claims.UserID, &req); err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("finish hardware key auth failed")
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

// FIDOMetadata handles GET /api/v1/fido/metadata — serves the FIDO MDS metadata statement.
// This is a public endpoint that relying parties can query to verify our AAGUID.
func (h *PasskeyHandler) FIDOMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, crypto.FIDOMetadataStatement())
}
