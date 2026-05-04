package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/password-manager/password-manager/internal/admin"
	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// AdminHandler handles admin HTTP endpoints.
type AdminHandler struct {
	adminService   *admin.Service
	userRepo       db.UserRepository
	orgRepo        db.OrgRepository
	auditRepo      db.AuditRepository
	collectionRepo db.CollectionRepository
	sqliteDB       *sql.DB // nil when not using SQLite backend
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(adminService *admin.Service, userRepo db.UserRepository) *AdminHandler {
	return &AdminHandler{adminService: adminService, userRepo: userRepo}
}

// SetOrgAndAuditRepo sets org and audit repos for SSO/SCIM admin endpoints.
func (h *AdminHandler) SetOrgAndAuditRepo(orgRepo db.OrgRepository, auditRepo db.AuditRepository) {
	h.orgRepo = orgRepo
	h.auditRepo = auditRepo
}

// SetSQLiteDB sets the SQLite database reference for migration support.
func (h *AdminHandler) SetSQLiteDB(sqliteDB *sql.DB) {
	h.sqliteDB = sqliteDB
}

// SetCollectionRepo sets the collection repository for group-collection key distribution.
func (h *AdminHandler) SetCollectionRepo(repo db.CollectionRepository) {
	h.collectionRepo = repo
}

// CreateOrg handles POST /api/v1/admin/orgs
func (h *AdminHandler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		Name      string `json:"name"`
		MasterKey string `json:"master_key"` // hex-encoded 32-byte key
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Name == "" || body.MasterKey == "" {
		writeError(w, http.StatusBadRequest, "missing name or master_key")
		return
	}

	masterKeyBytes, err := hex.DecodeString(body.MasterKey)
	if err != nil || len(masterKeyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid master_key")
		return
	}

	var masterKey [32]byte
	copy(masterKey[:], masterKeyBytes)

	org, err := h.adminService.CreateOrg(r.Context(), claims.UserID, body.Name, masterKey)
	if err != nil {
		log.Error().Err(err).Msg("create org failed")
		writeError(w, http.StatusInternalServerError, "failed to create organization")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         org.ID,
		"name":       org.Name,
		"created_at": org.CreatedAt,
	})
}

// InviteUser handles POST /api/v1/admin/orgs/{id}/invite
func (h *AdminHandler) InviteUser(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Email == "" {
		writeError(w, http.StatusBadRequest, "missing email")
		return
	}

	inv, err := h.adminService.InviteUser(r.Context(), claims.UserID, orgID, body.Email, body.Role)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("invite user failed")
		writeError(w, http.StatusInternalServerError, "failed to invite user")
		return
	}

	writeJSON(w, http.StatusCreated, inv)
}

// AcceptInvite handles POST /api/v1/admin/orgs/{id}/accept
func (h *AdminHandler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	var body struct {
		MasterKey string `json:"master_key"` // hex-encoded
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.MasterKey == "" {
		writeError(w, http.StatusBadRequest, "missing master_key")
		return
	}

	keyBytes, err := hex.DecodeString(body.MasterKey)
	if err != nil || len(keyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid master_key")
		return
	}

	var masterKey [32]byte
	copy(masterKey[:], keyBytes)

	if err := h.adminService.AcceptInvite(r.Context(), claims.UserID, orgID, masterKey); err != nil {
		if errors.Is(err, admin.ErrNoInvitation) {
			writeError(w, http.StatusNotFound, "no pending invitation")
			return
		}
		log.Error().Err(err).Msg("accept invite failed")
		writeError(w, http.StatusInternalServerError, "failed to accept invite")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "joined"})
}

// RemoveUser handles DELETE /api/v1/admin/orgs/{id}/members/{uid}
func (h *AdminHandler) RemoveUser(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	targetUID := chi.URLParam(r, "uid")

	// Export vault entries before removal so they can be preserved
	entries, err := h.adminService.ExportUserVault(r.Context(), targetUID)
	if err != nil {
		log.Warn().Err(err).Msg("failed to export vault before removing user")
		entries = nil
	}

	if err := h.adminService.RemoveUser(r.Context(), claims.UserID, orgID, targetUID); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("remove user failed")
		writeError(w, http.StatusInternalServerError, "failed to remove user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "removed",
		"entries": entries,
	})
}

// LeaveOrg handles POST /api/v1/admin/orgs/{id}/leave
func (h *AdminHandler) LeaveOrg(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	// Export vault entries before removing membership so client can save them locally
	entries, err := h.adminService.ExportUserVault(r.Context(), claims.UserID)
	if err != nil {
		log.Warn().Err(err).Msg("failed to export vault before leaving org — proceeding anyway")
		entries = nil
	}

	// Export passkeys too
	passkeys, err := h.adminService.ExportUserPasskeys(r.Context(), claims.UserID)
	if err != nil {
		log.Warn().Err(err).Msg("failed to export passkeys before leaving org")
		passkeys = nil
	}

	if err := h.adminService.LeaveOrg(r.Context(), claims.UserID, orgID); err != nil {
		log.Error().Err(err).Msg("leave org failed")
		writeError(w, http.StatusInternalServerError, "failed to leave organization")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "left",
		"entries":  entries,
		"passkeys": passkeys,
	})
}

// ListMembers handles GET /api/v1/admin/orgs/{id}/members
func (h *AdminHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	members, err := h.adminService.ListMembers(r.Context(), claims.UserID, orgID)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("list members failed")
		writeError(w, http.StatusInternalServerError, "failed to list members")
		return
	}

	if members == nil {
		members = []db.OrgMember{}
	}

	writeJSON(w, http.StatusOK, members)
}

// AccessUserVault handles GET /api/v1/admin/orgs/{id}/vault/{uid}
func (h *AdminHandler) AccessUserVault(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	targetUID := chi.URLParam(r, "uid")

	masterKeyHex := r.URL.Query().Get("master_key")
	if masterKeyHex == "" {
		writeError(w, http.StatusBadRequest, "missing master_key query parameter")
		return
	}

	keyBytes, err := hex.DecodeString(masterKeyHex)
	if err != nil || len(keyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid master_key")
		return
	}

	var masterKey [32]byte
	copy(masterKey[:], keyBytes)

	entries, err := h.adminService.AccessUserVault(r.Context(), claims.UserID, orgID, targetUID, masterKey)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("admin vault access failed")
		// Provide a helpful message for org key propagation issues
		errMsg := err.Error()
		if strings.Contains(errMsg, "not yet propagated") || strings.Contains(errMsg, "cannot decrypt org key") {
			writeError(w, http.StatusPreconditionFailed, "Org encryption key not available. The organization creator must log in first to propagate keys to other admins.")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to access vault")
		return
	}

	if entries == nil {
		entries = []admin.DecryptedEntry{}
	}

	writeJSON(w, http.StatusOK, entries)
}

// ResetPassword handles POST /api/v1/admin/orgs/{id}/vault/{uid}/reset-password
func (h *AdminHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	targetUID := chi.URLParam(r, "uid")

	var body struct {
		MasterKey    string `json:"master_key"`     // admin's hex-encoded master key
		NewMasterKey string `json:"new_master_key"` // new user master key hex
		NewAuthHash  string `json:"new_auth_hash"`  // hex-encoded
		NewSalt      string `json:"new_salt"`       // hex-encoded
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.MasterKey == "" || body.NewMasterKey == "" || body.NewAuthHash == "" || body.NewSalt == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	keyBytes, err := hex.DecodeString(body.MasterKey)
	if err != nil || len(keyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid master_key")
		return
	}

	newMasterKeyBytes, err := hex.DecodeString(body.NewMasterKey)
	if err != nil || len(newMasterKeyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid new_master_key")
		return
	}

	var masterKey [32]byte
	copy(masterKey[:], keyBytes)

	var newMasterKey [32]byte
	copy(newMasterKey[:], newMasterKeyBytes)

	if err := h.adminService.ChangeUserPassword(r.Context(), claims.UserID, orgID, targetUID, masterKey, newMasterKey, body.NewAuthHash, body.NewSalt); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("admin password reset failed")
		writeError(w, http.StatusInternalServerError, "failed to reset password")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

// SetPolicy handles PUT /api/v1/admin/orgs/{id}/policy
func (h *AdminHandler) SetPolicy(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	var policy admin.OrgPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.adminService.SetOrgPolicy(r.Context(), claims.UserID, orgID, policy); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("set policy failed")
		writeError(w, http.StatusInternalServerError, "failed to set policy")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "policy_updated"})
}

// GetPolicy handles GET /api/v1/admin/orgs/{id}/policy
func (h *AdminHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	policy, err := h.adminService.GetOrgPolicy(r.Context(), orgID)
	if err != nil {
		log.Error().Err(err).Msg("get policy failed")
		writeError(w, http.StatusInternalServerError, "failed to get policy")
		return
	}

	writeJSON(w, http.StatusOK, policy)
}

// ListInvitations handles GET /api/v1/admin/orgs/{id}/invitations
func (h *AdminHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	invs, err := h.adminService.ListInvitations(r.Context(), claims.UserID, orgID)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("list invitations failed")
		writeError(w, http.StatusInternalServerError, "failed to list invitations")
		return
	}

	if invs == nil {
		invs = []db.Invitation{}
	}

	writeJSON(w, http.StatusOK, invs)
}

// GetAuditLog handles GET /api/v1/admin/orgs/{id}/audit
func (h *AdminHandler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	filters := db.AuditFilters{
		ActorID:  r.URL.Query().Get("actor_id"),
		TargetID: r.URL.Query().Get("target_id"),
		Action:   r.URL.Query().Get("action"),
	}

	if from := r.URL.Query().Get("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid from: use RFC3339")
			return
		}
		filters.From = &t
	}
	if to := r.URL.Query().Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid to: use RFC3339")
			return
		}
		filters.To = &t
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil {
			filters.Limit = v
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil {
			filters.Offset = v
		}
	}

	entries, err := h.adminService.GetAuditLog(r.Context(), claims.UserID, orgID, filters)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("get audit log failed")
		writeError(w, http.StatusInternalServerError, "failed to get audit log")
		return
	}

	if entries == nil {
		entries = []db.AuditEntry{}
	}

	// Resolve user IDs to emails
	emailMap := map[string]string{}
	if h.userRepo != nil {
		seen := map[string]bool{}
		for _, e := range entries {
			if e.ActorID != nil && !seen[*e.ActorID] {
				seen[*e.ActorID] = true
			}
			if e.TargetID != nil && !seen[*e.TargetID] {
				seen[*e.TargetID] = true
			}
		}
		for uid := range seen {
			if u, err := h.userRepo.GetUserByID(r.Context(), uid); err == nil {
				emailMap[uid] = u.Email
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"users":   emailMap,
	})
}

// PropagateKeys handles POST /api/v1/admin/orgs/{id}/propagate-keys
func (h *AdminHandler) PropagateKeys(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")

	var body struct {
		MasterKey string `json:"master_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.MasterKey == "" {
		writeError(w, http.StatusBadRequest, "missing master_key")
		return
	}

	keyBytes, err := hex.DecodeString(body.MasterKey)
	if err != nil || len(keyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid master_key")
		return
	}

	var masterKey [32]byte
	copy(masterKey[:], keyBytes)

	if err := h.adminService.PropagateOrgKeys(r.Context(), claims.UserID, orgID, masterKey); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		// Non-fatal: this admin may not be the org creator
		log.Warn().Err(err).Msg("propagate keys skipped (not org creator?)")
		writeJSON(w, http.StatusOK, map[string]string{"status": "skipped", "reason": "org creator must log in first to propagate keys"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "keys_propagated"})
}

// GetMyOrg handles GET /api/v1/admin/my-org
func (h *AdminHandler) GetMyOrg(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	member, org, err := h.adminService.GetMyOrg(r.Context(), claims.UserID)
	if err != nil {
		// No org membership is not an error — return empty
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"member": false,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"member":   true,
		"org_id":   org.ID,
		"org_name": org.Name,
		"role":     member.Role,
	})
}

// GetMyInvitations handles GET /api/v1/admin/my-invitations
func (h *AdminHandler) GetMyInvitations(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	invs, err := h.adminService.GetMyInvitations(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Msg("get my invitations failed")
		writeError(w, http.StatusInternalServerError, "failed to get invitations")
		return
	}

	type invWithOrg struct {
		ID        string    `json:"id"`
		OrgID     string    `json:"org_id"`
		OrgName   string    `json:"org_name"`
		Email     string    `json:"email"`
		Role      string    `json:"role"`
		CreatedAt time.Time `json:"created_at"`
	}

	results := make([]invWithOrg, 0, len(invs))
	for _, inv := range invs {
		orgName := inv.OrgID // fallback
		if org, err := h.adminService.GetOrgByID(r.Context(), inv.OrgID); err == nil {
			orgName = org.Name
		}
		results = append(results, invWithOrg{
			ID:        inv.ID,
			OrgID:     inv.OrgID,
			OrgName:   orgName,
			Email:     inv.Email,
			Role:      inv.Role,
			CreatedAt: inv.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, results)
}

// TestPgConnection handles POST /api/v1/admin/test-pg-connection
func (h *AdminHandler) TestPgConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DatabaseURL string `json:"database_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DatabaseURL == "" {
		writeError(w, http.StatusBadRequest, "database_url required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, req.DatabaseURL)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"error": "Failed to connect: " + err.Error()})
		return
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"error": "Ping failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// MigrateToPostgres handles POST /api/v1/admin/migrate-to-postgres
func (h *AdminHandler) MigrateToPostgres(w http.ResponseWriter, r *http.Request) {
	if h.sqliteDB == nil {
		writeError(w, http.StatusBadRequest, "not running in SQLite mode")
		return
	}

	var req struct {
		DatabaseURL string `json:"database_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DatabaseURL == "" {
		writeError(w, http.StatusBadRequest, "database_url required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, req.DatabaseURL)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"error": "Failed to connect: " + err.Error()})
		return
	}
	defer pool.Close()

	// Connect to PG and run migrations
	pgDB, err := db.New(ctx, req.DatabaseURL)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"error": "PG connection failed: " + err.Error()})
		return
	}
	defer pgDB.Close()

	if err := pgDB.RunMigrations(ctx, "migrations"); err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"error": "PG migrations failed: " + err.Error()})
		return
	}

	// Migrate data
	result, err := db.MigrateSQLiteToPg(ctx, h.sqliteDB, pgDB.Pool)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"error": "Migration failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GenerateSCIMToken generates a new SCIM bearer token for the organization.
// POST /api/v1/admin/orgs/{id}/scim/generate-token
func (h *AdminHandler) GenerateSCIMToken(w http.ResponseWriter, r *http.Request) {
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
	if h.orgRepo == nil {
		writeError(w, http.StatusNotImplemented, "SCIM requires PostgreSQL")
		return
	}

	// Verify admin role
	member, err := h.orgRepo.GetMember(r.Context(), orgID, claims.UserID)
	if err != nil || member.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	// Generate a random SCIM token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash and store
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash token")
		return
	}

	org, err := h.orgRepo.GetOrg(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}

	if err := h.orgRepo.SetSCIMConfig(r.Context(), orgID, org.SCIMEnabled, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store SCIM token")
		return
	}

	// Audit log
	if h.auditRepo != nil {
		details, _ := json.Marshal(map[string]string{"action": "scim_token_generated"})
		_ = h.auditRepo.LogAction(r.Context(), &claims.UserID, &orgID, "scim_token_generated", details)
	}

	// Return the plaintext token (shown once, cannot be retrieved again)
	writeJSON(w, http.StatusOK, map[string]string{
		"token":    token,
		"warning":  "This token will not be shown again. Store it securely.",
	})
}

// GetSCIMConfig returns the SCIM configuration for an org.
// GET /api/v1/admin/orgs/{id}/scim
func (h *AdminHandler) GetSCIMConfig(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	orgID := chi.URLParam(r, "id")
	if h.orgRepo == nil {
		writeError(w, http.StatusNotImplemented, "SCIM requires PostgreSQL")
		return
	}

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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scim_enabled":   org.SCIMEnabled,
		"has_token":      len(org.SCIMTokenHash) > 0,
		"endpoint":       fmt.Sprintf("/api/v1/scim/v2/%s", orgID),
	})
}

// SetSCIMConfig enables or disables SCIM for an organization.
// PUT /api/v1/admin/orgs/{id}/scim
func (h *AdminHandler) SetSCIMConfig(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	orgID := chi.URLParam(r, "id")
	if h.orgRepo == nil {
		writeError(w, http.StatusNotImplemented, "SCIM requires PostgreSQL")
		return
	}

	member, err := h.orgRepo.GetMember(r.Context(), orgID, claims.UserID)
	if err != nil || member.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	org, err := h.orgRepo.GetOrg(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}

	if err := h.orgRepo.SetSCIMConfig(r.Context(), orgID, req.Enabled, org.SCIMTokenHash); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update SCIM configuration")
		return
	}

	if h.auditRepo != nil {
		details, _ := json.Marshal(map[string]interface{}{"enabled": req.Enabled})
		_ = h.auditRepo.LogAction(r.Context(), &claims.UserID, &orgID, "scim_config_updated", details)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Role Management Endpoints ---

// ListRoles handles GET /api/v1/admin/orgs/{id}/roles
func (h *AdminHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	roles, err := h.adminService.ListRoles(r.Context(), claims.UserID, orgID)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("list roles failed")
		writeError(w, http.StatusInternalServerError, "failed to list roles")
		return
	}
	if roles == nil {
		roles = []db.Role{}
	}
	writeJSON(w, http.StatusOK, roles)
}

// CreateRole handles POST /api/v1/admin/orgs/{id}/roles
func (h *AdminHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	role, err := h.adminService.CreateRole(r.Context(), claims.UserID, orgID, body.Name, body.Description, body.Permissions)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("create role failed")
		writeError(w, http.StatusInternalServerError, "failed to create role")
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

// UpdateRole handles PUT /api/v1/admin/orgs/{id}/roles/{roleId}
func (h *AdminHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	roleID := chi.URLParam(r, "roleId")

	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.adminService.UpdateRole(r.Context(), claims.UserID, orgID, roleID, body.Name, body.Description, body.Permissions); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("update role failed")
		writeError(w, http.StatusInternalServerError, "failed to update role")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// DeleteRole handles DELETE /api/v1/admin/orgs/{id}/roles/{roleId}
func (h *AdminHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	roleID := chi.URLParam(r, "roleId")

	if err := h.adminService.DeleteRole(r.Context(), claims.UserID, orgID, roleID); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("delete role failed")
		writeError(w, http.StatusInternalServerError, "failed to delete role")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// SetMemberRole handles PUT /api/v1/admin/orgs/{id}/members/{uid}/role
func (h *AdminHandler) SetMemberRole(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	targetUID := chi.URLParam(r, "uid")

	var body struct {
		RoleID string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.RoleID == "" {
		writeError(w, http.StatusBadRequest, "role_id is required")
		return
	}

	if err := h.adminService.SetMemberRole(r.Context(), claims.UserID, orgID, targetUID, body.RoleID); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("set member role failed")
		writeError(w, http.StatusInternalServerError, "failed to set member role")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "role_updated"})
}

// --- Group Management Endpoints ---

// ListGroups handles GET /api/v1/admin/orgs/{id}/groups
func (h *AdminHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	groups, err := h.adminService.ListGroups(r.Context(), claims.UserID, orgID)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("list groups failed")
		writeError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}
	if groups == nil {
		groups = []db.Group{}
	}
	writeJSON(w, http.StatusOK, groups)
}

// CreateGroup handles POST /api/v1/admin/orgs/{id}/groups
func (h *AdminHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	group, err := h.adminService.CreateGroup(r.Context(), claims.UserID, orgID, body.Name)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("create group failed")
		writeError(w, http.StatusInternalServerError, "failed to create group")
		return
	}
	writeJSON(w, http.StatusCreated, group)
}

// UpdateGroup handles PUT /api/v1/admin/orgs/{id}/groups/{gid}
func (h *AdminHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	groupID := chi.URLParam(r, "gid")

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.adminService.UpdateGroup(r.Context(), claims.UserID, orgID, groupID, body.Name); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("update group failed")
		writeError(w, http.StatusInternalServerError, "failed to update group")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// DeleteGroup handles DELETE /api/v1/admin/orgs/{id}/groups/{gid}
func (h *AdminHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	groupID := chi.URLParam(r, "gid")

	if err := h.adminService.DeleteGroup(r.Context(), claims.UserID, orgID, groupID); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("delete group failed")
		writeError(w, http.StatusInternalServerError, "failed to delete group")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListGroupMembers handles GET /api/v1/admin/orgs/{id}/groups/{gid}/members
func (h *AdminHandler) ListGroupMembers(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	groupID := chi.URLParam(r, "gid")

	members, err := h.adminService.ListGroupMembers(r.Context(), claims.UserID, orgID, groupID)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("list group members failed")
		writeError(w, http.StatusInternalServerError, "failed to list group members")
		return
	}
	if members == nil {
		members = []db.GroupMember{}
	}
	writeJSON(w, http.StatusOK, members)
}

// AddGroupMember handles POST /api/v1/admin/orgs/{id}/groups/{gid}/members
func (h *AdminHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	groupID := chi.URLParam(r, "gid")

	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	if err := h.adminService.AddGroupMember(r.Context(), claims.UserID, orgID, groupID, body.UserID); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("add group member failed")
		writeError(w, http.StatusInternalServerError, "failed to add member to group")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

// RemoveGroupMember handles DELETE /api/v1/admin/orgs/{id}/groups/{gid}/members/{uid}
func (h *AdminHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	groupID := chi.URLParam(r, "gid")
	userID := chi.URLParam(r, "uid")

	if err := h.adminService.RemoveGroupMember(r.Context(), claims.UserID, orgID, groupID, userID); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("remove group member failed")
		writeError(w, http.StatusInternalServerError, "failed to remove member from group")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// ListCollectionGroups handles GET /api/v1/admin/orgs/{id}/collections/{collId}/groups
func (h *AdminHandler) ListCollectionGroups(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "orgId")
	collID := chi.URLParam(r, "collId")

	groups, err := h.adminService.ListCollectionGroups(r.Context(), claims.UserID, orgID, collID)
	if err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("list collection groups failed")
		writeError(w, http.StatusInternalServerError, "failed to list collection groups")
		return
	}
	if groups == nil {
		groups = []db.CollectionGroup{}
	}
	writeJSON(w, http.StatusOK, groups)
}

// AddCollectionGroup handles POST /api/v1/admin/orgs/{orgId}/collections/{collId}/groups
// Assigns a group to a collection and distributes the collection key to all group members via escrow.
func (h *AdminHandler) AddCollectionGroup(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "orgId")
	collID := chi.URLParam(r, "collId")

	var body struct {
		GroupID    string `json:"group_id"`
		Permission string `json:"permission"`
		MasterKey  string `json:"master_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	if body.MasterKey == "" {
		writeError(w, http.StatusBadRequest, "master_key is required")
		return
	}
	if body.Permission == "" {
		body.Permission = "read"
	}

	// Save the group-collection mapping
	cg := db.CollectionGroup{
		CollectionID: collID,
		GroupID:      body.GroupID,
		Permission:   body.Permission,
		EncryptedKey: []byte{},
	}
	if err := h.adminService.AddCollectionGroup(r.Context(), claims.UserID, orgID, cg); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("add collection group failed")
		writeError(w, http.StatusInternalServerError, "failed to add group to collection")
		return
	}

	// Distribute collection key to group members via escrow
	adminMasterKeyBytes, err := hex.DecodeString(body.MasterKey)
	if err != nil || len(adminMasterKeyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid master_key")
		return
	}
	var adminMasterKey [32]byte
	copy(adminMasterKey[:], adminMasterKeyBytes)
	defer crypto.ZeroBytes(adminMasterKey[:])

	// Get org private key via admin's escrow
	orgPrivKey, err := h.decryptOrgPrivKey(r.Context(), orgID, claims.UserID, adminMasterKey)
	if err != nil {
		log.Error().Err(err).Msg("failed to decrypt org key for collection group")
		// Group mapping saved but key distribution failed — still return success
		writeJSON(w, http.StatusCreated, map[string]string{"status": "added", "warning": "group added but key distribution failed — members may need manual access"})
		return
	}
	defer crypto.ZeroBytes(orgPrivKey)

	// Get collection key
	collKeyPlain, err := h.getCollectionKey(r.Context(), collID, orgID, claims.UserID, adminMasterKey, orgPrivKey)
	if err != nil {
		log.Error().Err(err).Msg("failed to get collection key")
		writeJSON(w, http.StatusCreated, map[string]string{"status": "added", "warning": "group added but key distribution failed"})
		return
	}
	defer crypto.ZeroBytes(collKeyPlain)

	// Get group members and add each as collection member
	groupMembers, err := h.adminService.ListGroupMembers(r.Context(), claims.UserID, orgID, body.GroupID)
	if err != nil {
		log.Error().Err(err).Msg("failed to list group members")
		writeJSON(w, http.StatusCreated, map[string]string{"status": "added", "warning": "group added but could not list members"})
		return
	}

	var addedCount int
	for _, gm := range groupMembers {
		// Skip if already a collection member
		if _, err := h.collectionRepo.GetCollectionKey(r.Context(), collID, gm.UserID); err == nil {
			continue
		}

		// Decrypt target user's master key via escrow
		escrowBlob, err := h.orgRepo.GetMemberEscrow(r.Context(), orgID, gm.UserID)
		if err != nil {
			log.Warn().Err(err).Str("user_id", gm.UserID).Msg("skipping member — no escrow")
			continue
		}
		targetMasterKey, err := crypto.DecryptEscrow(escrowBlob, orgPrivKey)
		if err != nil {
			log.Warn().Err(err).Str("user_id", gm.UserID).Msg("skipping member — escrow decrypt failed")
			continue
		}

		// Encrypt collection key with target user's master key
		encKeyForTarget, err := aesGCMEncrypt(collKeyPlain, targetMasterKey)
		crypto.ZeroBytes(targetMasterKey[:])
		if err != nil {
			log.Warn().Err(err).Str("user_id", gm.UserID).Msg("skipping member — encrypt failed")
			continue
		}

		if err := h.collectionRepo.AddCollectionMember(r.Context(), collID, gm.UserID, encKeyForTarget, body.Permission); err != nil {
			log.Warn().Err(err).Str("user_id", gm.UserID).Msg("skipping member — add failed")
			continue
		}
		addedCount++
	}

	log.Info().Int("added", addedCount).Int("total", len(groupMembers)).Msg("collection group members distributed")
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

// decryptOrgPrivKey decrypts the org private key using the admin's escrow or org key.
func (h *AdminHandler) decryptOrgPrivKey(ctx context.Context, orgID, adminUserID string, adminMasterKey [32]byte) ([]byte, error) {
	org, err := h.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("get org: %w", err)
	}

	encAdminOrgKey, _ := h.orgRepo.GetMemberOrgKey(ctx, orgID, adminUserID)
	if len(encAdminOrgKey) > 0 {
		return crypto.DecryptOrgPrivateKey(encAdminOrgKey, adminMasterKey)
	}
	return crypto.DecryptOrgPrivateKey(org.EncryptedOrgPrivateKey, adminMasterKey)
}

// getCollectionKey retrieves and decrypts the collection key.
func (h *AdminHandler) getCollectionKey(ctx context.Context, collID, orgID, adminUserID string, adminMasterKey [32]byte, orgPrivKey []byte) ([]byte, error) {
	// Try admin's own collection key first
	adminEncKey, err := h.collectionRepo.GetCollectionKey(ctx, collID, adminUserID)
	if err == nil && len(adminEncKey) >= 12 {
		return aesGCMDecrypt(adminEncKey, adminMasterKey)
	}

	// Fall back to escrow via any existing member
	members, err := h.collectionRepo.GetCollectionMembers(ctx, collID)
	if err != nil || len(members) == 0 {
		return nil, fmt.Errorf("no existing members to derive collection key from")
	}

	existingEncKey, err := h.collectionRepo.GetCollectionKey(ctx, collID, members[0].UserID)
	if err != nil {
		return nil, fmt.Errorf("get existing member key: %w", err)
	}
	existingEscrow, err := h.orgRepo.GetMemberEscrow(ctx, orgID, members[0].UserID)
	if err != nil {
		return nil, fmt.Errorf("get member escrow: %w", err)
	}
	existingMasterKey, err := crypto.DecryptEscrow(existingEscrow, orgPrivKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt member escrow: %w", err)
	}
	plainKey, err := aesGCMDecrypt(existingEncKey, existingMasterKey)
	crypto.ZeroBytes(existingMasterKey[:])
	return plainKey, err
}

// RemoveCollectionGroup handles DELETE /api/v1/admin/orgs/{id}/collections/{collId}/groups/{gid}
func (h *AdminHandler) RemoveCollectionGroup(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "orgId")
	collID := chi.URLParam(r, "collId")
	groupID := chi.URLParam(r, "gid")

	if err := h.adminService.RemoveCollectionGroup(r.Context(), claims.UserID, orgID, collID, groupID); err != nil {
		if errors.Is(err, admin.ErrNotAdmin) {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		log.Error().Err(err).Msg("remove collection group failed")
		writeError(w, http.StatusInternalServerError, "failed to remove group from collection")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}
