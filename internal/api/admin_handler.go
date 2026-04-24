package api

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/admin"
	"github.com/password-manager/password-manager/internal/db"
)

// AdminHandler handles admin HTTP endpoints.
type AdminHandler struct {
	adminService *admin.Service
	sqliteDB     *sql.DB // nil when not using SQLite backend
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(adminService *admin.Service) *AdminHandler {
	return &AdminHandler{adminService: adminService}
}

// SetSQLiteDB sets the SQLite database reference for migration support.
func (h *AdminHandler) SetSQLiteDB(sqliteDB *sql.DB) {
	h.sqliteDB = sqliteDB
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

	writeJSON(w, http.StatusOK, entries)
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
		log.Error().Err(err).Msg("propagate keys failed")
		writeError(w, http.StatusInternalServerError, "failed to propagate keys")
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
