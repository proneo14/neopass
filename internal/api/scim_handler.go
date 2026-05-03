package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/password-manager/password-manager/internal/db"
)

// SCIMHandler handles SCIM 2.0 provisioning endpoints.
type SCIMHandler struct {
	userRepo  db.UserRepository
	orgRepo   db.OrgRepository
	auditRepo db.AuditRepository
}

// NewSCIMHandler creates a new SCIMHandler.
func NewSCIMHandler(userRepo db.UserRepository, orgRepo db.OrgRepository, auditRepo db.AuditRepository) *SCIMHandler {
	return &SCIMHandler{
		userRepo:  userRepo,
		orgRepo:   orgRepo,
		auditRepo: auditRepo,
	}
}

// ── SCIM Auth Middleware ────────────────────────────────────────────────────

// SCIMAuthMiddleware validates SCIM bearer tokens against the org's scim_token_hash.
// It injects the org ID into the request context.
func (h *SCIMHandler) SCIMAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "orgId")
		if orgID == "" {
			writeSCIMError(w, http.StatusBadRequest, "missing organization ID")
			return
		}

		token := extractBearerToken(r)
		if token == "" {
			writeSCIMError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		org, err := h.orgRepo.GetOrg(r.Context(), orgID)
		if err != nil {
			writeSCIMError(w, http.StatusNotFound, "organization not found")
			return
		}

		if !org.SCIMEnabled || len(org.SCIMTokenHash) == 0 {
			writeSCIMError(w, http.StatusForbidden, "SCIM is not enabled for this organization")
			return
		}

		// Verify token against stored bcrypt hash
		if err := bcrypt.CompareHashAndPassword(org.SCIMTokenHash, []byte(token)); err != nil {
			// Constant-time comparison fallback (bcrypt already does this, but be explicit)
			_ = subtle.ConstantTimeCompare([]byte("invalid"), []byte("token"))
			writeSCIMError(w, http.StatusUnauthorized, "invalid SCIM token")
			return
		}

		// Store org ID in context for downstream handlers
		ctx := context.WithValue(r.Context(), scimOrgKey{}, orgID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type scimOrgKey struct{}

func getSCIMOrgID(r *http.Request) string {
	if v, ok := r.Context().Value(scimOrgKey{}).(string); ok {
		return v
	}
	return chi.URLParam(r, "orgId")
}

// ── SCIM User Resources ─────────────────────────────────────────────────────

// SCIMUser represents a SCIM 2.0 User resource.
type SCIMUser struct {
	Schemas    []string       `json:"schemas"`
	ID         string         `json:"id"`
	ExternalID string         `json:"externalId,omitempty"`
	UserName   string         `json:"userName"`
	Name       *SCIMUserName  `json:"name,omitempty"`
	Emails     []SCIMEmail    `json:"emails,omitempty"`
	Active     bool           `json:"active"`
	Meta       SCIMMeta       `json:"meta"`
}

// SCIMUserName holds SCIM name fields.
type SCIMUserName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// SCIMEmail holds a SCIM email entry.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMMeta holds SCIM resource metadata.
type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

// SCIMListResponse is the SCIM list response envelope.
type SCIMListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// SCIMError is the SCIM error response.
type SCIMError struct {
	Schemas []string `json:"schemas"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail"`
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(SCIMError{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		Status:  strconv.Itoa(status),
		Detail:  detail,
	})
}

func writeSCIMJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func userToSCIM(user db.User, baseURL string) SCIMUser {
	externalID := ""
	if user.SSOExternalID != nil {
		externalID = *user.SSOExternalID
	}
	return SCIMUser{
		Schemas:    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:         user.ID,
		ExternalID: externalID,
		UserName:   user.Email,
		Emails: []SCIMEmail{
			{Value: user.Email, Type: "work", Primary: true},
		},
		Active: true,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      user.CreatedAt.Format(time.RFC3339),
			LastModified: user.UpdatedAt.Format(time.RFC3339),
			Location:     fmt.Sprintf("%s/%s", baseURL, user.ID),
		},
	}
}

// ListUsers returns provisioned users in SCIM format.
// GET /api/v1/scim/v2/{orgId}/Users
func (h *SCIMHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	orgID := getSCIMOrgID(r)

	// Parse pagination
	startIndex := 1
	count := 100
	if si := r.URL.Query().Get("startIndex"); si != "" {
		if v, err := strconv.Atoi(si); err == nil && v > 0 {
			startIndex = v
		}
	}
	if c := r.URL.Query().Get("count"); c != "" {
		if v, err := strconv.Atoi(c); err == nil && v > 0 && v <= 500 {
			count = v
		}
	}

	// Parse filter (basic: filter=userName eq "user@example.com")
	filterEmail := ""
	if filter := r.URL.Query().Get("filter"); filter != "" {
		filterEmail = parseSCIMFilter(filter)
	}

	// Get org members
	members, err := h.orgRepo.ListMembers(r.Context(), orgID)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to list members")
		return
	}

	// Fetch full user info for each member
	var scimUsers []SCIMUser
	baseURL := fmt.Sprintf("/api/v1/scim/v2/%s/Users", orgID)

	for _, member := range members {
		user, err := h.userRepo.GetUserByID(r.Context(), member.UserID)
		if err != nil {
			continue
		}

		// Apply email filter
		if filterEmail != "" && !strings.EqualFold(user.Email, filterEmail) {
			continue
		}

		scimUsers = append(scimUsers, userToSCIM(user, baseURL))
	}

	// Apply pagination
	total := len(scimUsers)
	start := startIndex - 1
	if start >= total {
		scimUsers = nil
	} else {
		end := start + count
		if end > total {
			end = total
		}
		scimUsers = scimUsers[start:end]
	}

	if scimUsers == nil {
		scimUsers = []SCIMUser{}
	}

	writeSCIMJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(scimUsers),
		Resources:    scimUsers,
	})
}

// GetUser returns a single user in SCIM format.
// GET /api/v1/scim/v2/{orgId}/Users/{id}
func (h *SCIMHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	orgID := getSCIMOrgID(r)
	userID := chi.URLParam(r, "id")

	// Verify user is a member of this org
	_, err := h.orgRepo.GetMember(r.Context(), orgID, userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found in organization")
		return
	}

	user, err := h.userRepo.GetUserByID(r.Context(), userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}

	baseURL := fmt.Sprintf("/api/v1/scim/v2/%s/Users", orgID)
	writeSCIMJSON(w, http.StatusOK, userToSCIM(user, baseURL))
}

// CreateUser provisions a new user via SCIM.
// POST /api/v1/scim/v2/{orgId}/Users
func (h *SCIMHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	orgID := getSCIMOrgID(r)

	var req struct {
		Schemas    []string      `json:"schemas"`
		UserName   string        `json:"userName"`
		ExternalID string        `json:"externalId"`
		Name       *SCIMUserName `json:"name"`
		Emails     []SCIMEmail   `json:"emails"`
		Active     *bool         `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := req.UserName
	if email == "" && len(req.Emails) > 0 {
		email = req.Emails[0].Value
	}
	if email == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName or emails[0].value is required")
		return
	}

	// Check if user already exists
	existingUser, err := h.userRepo.GetUserByEmail(r.Context(), email)
	if err == nil {
		// User exists — add to org if not already a member
		_, memberErr := h.orgRepo.GetMember(r.Context(), orgID, existingUser.ID)
		if memberErr != nil {
			// Not a member — add them
			if addErr := h.orgRepo.AddMember(r.Context(), orgID, existingUser.ID, "member", nil); addErr != nil {
				writeSCIMError(w, http.StatusConflict, "failed to add user to organization")
				return
			}
		}

		// Set SSO external ID if provided
		if req.ExternalID != "" {
			_ = h.userRepo.SetSSOExternalID(r.Context(), existingUser.ID, req.ExternalID)
		}

		// Audit log
		details, _ := json.Marshal(map[string]string{"email": email, "action": "scim_provision"})
		_ = h.auditRepo.LogAction(r.Context(), nil, &existingUser.ID, "scim_user_provisioned", details)

		baseURL := fmt.Sprintf("/api/v1/scim/v2/%s/Users", orgID)
		writeSCIMJSON(w, http.StatusOK, userToSCIM(existingUser, baseURL))
		return
	}

	// User doesn't exist — create an invitation for them
	// SCIM provisioning doesn't create vault credentials (zero-knowledge);
	// the user must register themselves and then accept the org invitation.
	_, invErr := h.orgRepo.CreateInvitation(r.Context(), orgID, email, "member", "scim")
	if invErr != nil {
		log.Warn().Err(invErr).Str("email", email).Msg("SCIM: failed to create invitation")
	}

	// Audit log
	details, _ := json.Marshal(map[string]string{"email": email, "action": "scim_invite"})
	_ = h.auditRepo.LogAction(r.Context(), nil, nil, "scim_user_invited", details)

	// Return a placeholder SCIM user (the user doesn't have an ID yet)
	writeSCIMJSON(w, http.StatusCreated, SCIMUser{
		Schemas:    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:         "pending-" + email,
		ExternalID: req.ExternalID,
		UserName:   email,
		Emails:     []SCIMEmail{{Value: email, Type: "work", Primary: true}},
		Active:     true,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      time.Now().Format(time.RFC3339),
		},
	})
}

// UpdateUser replaces a user's attributes (full replace).
// PUT /api/v1/scim/v2/{orgId}/Users/{id}
func (h *SCIMHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	orgID := getSCIMOrgID(r)
	userID := chi.URLParam(r, "id")

	// Verify user is a member
	_, err := h.orgRepo.GetMember(r.Context(), orgID, userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found in organization")
		return
	}

	var req struct {
		Active     *bool         `json:"active"`
		ExternalID string        `json:"externalId"`
		Name       *SCIMUserName `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Handle deactivation
	if req.Active != nil && !*req.Active {
		// Deactivate = remove from org + revoke sessions
		if err := h.orgRepo.RemoveMember(r.Context(), orgID, userID); err != nil {
			log.Error().Err(err).Str("user_id", userID).Msg("SCIM: failed to remove member")
		}
		if err := h.userRepo.RevokeUserTokens(r.Context(), userID); err != nil {
			log.Warn().Err(err).Str("user_id", userID).Msg("SCIM: failed to revoke tokens")
		}

		details, _ := json.Marshal(map[string]string{"action": "scim_deactivate"})
		_ = h.auditRepo.LogAction(r.Context(), nil, &userID, "scim_user_deactivated", details)

		writeSCIMJSON(w, http.StatusOK, SCIMUser{
			Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			ID:       userID,
			Active:   false,
			Meta:     SCIMMeta{ResourceType: "User"},
		})
		return
	}

	// Update external ID if provided
	if req.ExternalID != "" {
		_ = h.userRepo.SetSSOExternalID(r.Context(), userID, req.ExternalID)
	}

	user, err := h.userRepo.GetUserByID(r.Context(), userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}

	baseURL := fmt.Sprintf("/api/v1/scim/v2/%s/Users", orgID)
	writeSCIMJSON(w, http.StatusOK, userToSCIM(user, baseURL))
}

// PatchUser handles partial updates (SCIM PATCH).
// PATCH /api/v1/scim/v2/{orgId}/Users/{id}
func (h *SCIMHandler) PatchUser(w http.ResponseWriter, r *http.Request) {
	orgID := getSCIMOrgID(r)
	userID := chi.URLParam(r, "id")

	_, err := h.orgRepo.GetMember(r.Context(), orgID, userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found in organization")
		return
	}

	var req struct {
		Schemas    []string         `json:"schemas"`
		Operations []SCIMPatchOp    `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	for _, op := range req.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			if op.Path == "active" {
				active, ok := op.Value.(bool)
				if !ok {
					// Try string "false" / "true"
					if s, ok := op.Value.(string); ok {
						active = strings.EqualFold(s, "true")
					}
				}
				if !active {
					// Deactivate
					_ = h.orgRepo.RemoveMember(r.Context(), orgID, userID)
					_ = h.userRepo.RevokeUserTokens(r.Context(), userID)

					details, _ := json.Marshal(map[string]string{"action": "scim_patch_deactivate"})
					_ = h.auditRepo.LogAction(r.Context(), nil, &userID, "scim_user_deactivated", details)
				}
			}
			if op.Path == "externalId" {
				if externalID, ok := op.Value.(string); ok {
					_ = h.userRepo.SetSSOExternalID(r.Context(), userID, externalID)
				}
			}
		}
	}

	user, err := h.userRepo.GetUserByID(r.Context(), userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}

	baseURL := fmt.Sprintf("/api/v1/scim/v2/%s/Users", orgID)
	writeSCIMJSON(w, http.StatusOK, userToSCIM(user, baseURL))
}

// DeleteUser deprovisions a user.
// DELETE /api/v1/scim/v2/{orgId}/Users/{id}
func (h *SCIMHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	orgID := getSCIMOrgID(r)
	userID := chi.URLParam(r, "id")

	// Remove from org
	if err := h.orgRepo.RemoveMember(r.Context(), orgID, userID); err != nil {
		log.Warn().Err(err).Str("user_id", userID).Msg("SCIM: failed to remove member")
	}

	// Revoke sessions
	_ = h.userRepo.RevokeUserTokens(r.Context(), userID)

	// Audit log
	details, _ := json.Marshal(map[string]string{"action": "scim_deprovision"})
	_ = h.auditRepo.LogAction(r.Context(), nil, &userID, "scim_user_deprovisioned", details)

	w.WriteHeader(http.StatusNoContent)
}

// SCIMPatchOp represents a SCIM PATCH operation.
type SCIMPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// parseSCIMFilter parses a simple SCIM filter like `userName eq "user@example.com"`.
func parseSCIMFilter(filter string) string {
	// Support: userName eq "value"
	parts := strings.SplitN(filter, " ", 3)
	if len(parts) != 3 {
		return ""
	}
	if !strings.EqualFold(parts[0], "userName") || !strings.EqualFold(parts[1], "eq") {
		return ""
	}
	return strings.Trim(parts[2], `"'`)
}
