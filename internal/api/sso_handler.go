package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/auth"
	"github.com/password-manager/password-manager/internal/db"
)

// SSOHandler handles SSO HTTP endpoints.
type SSOHandler struct {
	ssoService  *auth.SSOService
	authService *auth.Service
	orgRepo     db.OrgRepository
	auditRepo   db.AuditRepository
}

// NewSSOHandler creates a new SSOHandler.
func NewSSOHandler(ssoService *auth.SSOService, authService *auth.Service, orgRepo db.OrgRepository, auditRepo db.AuditRepository) *SSOHandler {
	return &SSOHandler{
		ssoService:  ssoService,
		authService: authService,
		orgRepo:     orgRepo,
		auditRepo:   auditRepo,
	}
}

// Login initiates the SSO login flow by redirecting to the IdP.
// GET /api/v1/sso/{orgId}/login
func (h *SSOHandler) Login(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgId")
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "missing org ID")
		return
	}

	redirectURL, err := h.ssoService.InitiateLogin(r.Context(), orgID)
	if err != nil {
		log.Warn().Err(err).Str("org_id", orgID).Msg("SSO login initiation failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_url": redirectURL,
	})
}

// Callback handles the IdP callback after authentication.
// POST /api/v1/sso/{orgId}/callback
func (h *SSOHandler) Callback(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgId")
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "missing org ID")
		return
	}

	// Collect callback parameters from request body or query
	params := make(map[string]string)

	// Support both form POST (SAML) and JSON body (OIDC)
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/x-www-form-urlencoded" || contentType == "" {
		if err := r.ParseForm(); err == nil {
			for key, values := range r.Form {
				if len(values) > 0 {
					params[key] = values[0]
				}
			}
		}
	} else {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			params = body
		}
	}

	// Also collect from URL query params (OIDC redirects include code+state in query)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			if _, exists := params[key]; !exists {
				params[key] = values[0]
			}
		}
	}

	result, err := h.ssoService.HandleCallback(r.Context(), orgID, params)
	if err != nil {
		log.Warn().Err(err).Str("org_id", orgID).Msg("SSO callback failed")
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// Unlock exchanges an SSO partial token + master password for full tokens.
// POST /api/v1/sso/{orgId}/unlock
func (h *SSOHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgId")
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "missing org ID")
		return
	}

	var req struct {
		SSOToken string `json:"sso_token"`
		AuthHash string `json:"auth_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SSOToken == "" {
		writeError(w, http.StatusBadRequest, "missing sso_token")
		return
	}

	// Validate the SSO token to get the user ID
	claims, err := h.authService.ValidateToken(req.SSOToken)
	if err != nil || !claims.Is2FA {
		writeError(w, http.StatusUnauthorized, "invalid or expired SSO token")
		return
	}

	result, err := h.ssoService.UnlockVault(r.Context(), req.SSOToken, claims.UserID)
	if err != nil {
		log.Warn().Err(err).Str("user_id", claims.UserID).Msg("SSO vault unlock failed")
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetSSOConfig returns the SSO configuration for an org (admin only).
// GET /api/v1/admin/orgs/{id}/sso
func (h *SSOHandler) GetSSOConfig(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "missing org ID")
		return
	}

	// Verify admin role
	member, err := h.orgRepo.GetMember(r.Context(), orgID, claims.UserID)
	if err != nil || member.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	org, err := h.orgRepo.GetOrg(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}

	// Return SSO config (mask sensitive fields)
	var cfg auth.SSOConfig
	if org.SSOConfig != nil {
		if err := json.Unmarshal(org.SSOConfig, &cfg); err == nil {
			// Mask OIDC client secret
			if cfg.OIDC != nil && cfg.OIDC.ClientSecretEncrypted != "" {
				cfg.OIDC.ClientSecretEncrypted = "••••••••"
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sso_enabled": org.SSOEnabled,
		"sso_config":  cfg,
	})
}

// SetSSOConfig updates the SSO configuration for an org (admin only).
// PUT /api/v1/admin/orgs/{id}/sso
func (h *SSOHandler) SetSSOConfig(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "missing org ID")
		return
	}

	// Verify admin role
	member, err := h.orgRepo.GetMember(r.Context(), orgID, claims.UserID)
	if err != nil || member.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	var req struct {
		Enabled bool            `json:"enabled"`
		Config  json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate the SSO config structure
	if req.Config != nil {
		var cfg auth.SSOConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid SSO configuration: "+err.Error())
			return
		}
		if cfg.Provider != "saml" && cfg.Provider != "oidc" {
			writeError(w, http.StatusBadRequest, "provider must be 'saml' or 'oidc'")
			return
		}
		if cfg.Provider == "saml" && cfg.SAML == nil {
			writeError(w, http.StatusBadRequest, "SAML configuration is required when provider is 'saml'")
			return
		}
		if cfg.Provider == "oidc" && cfg.OIDC == nil {
			writeError(w, http.StatusBadRequest, "OIDC configuration is required when provider is 'oidc'")
			return
		}
	}

	if err := h.orgRepo.SetSSOConfig(r.Context(), orgID, req.Enabled, req.Config); err != nil {
		log.Error().Err(err).Str("org_id", orgID).Msg("failed to update SSO config")
		writeError(w, http.StatusInternalServerError, "failed to update SSO configuration")
		return
	}

	// Audit log
	details, _ := json.Marshal(map[string]interface{}{"enabled": req.Enabled})
	_ = h.auditRepo.LogAction(r.Context(), &claims.UserID, &orgID, "sso_config_updated", details)

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
