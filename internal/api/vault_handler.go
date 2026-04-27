package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/vault"
)

// VaultHandler handles vault HTTP endpoints.
type VaultHandler struct {
	vaultService *vault.Service
}

// NewVaultHandler creates a new VaultHandler.
func NewVaultHandler(vaultService *vault.Service) *VaultHandler {
	return &VaultHandler{vaultService: vaultService}
}

// CreateEntry handles POST /api/v1/vault/entries
func (h *VaultHandler) CreateEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req vault.CreateEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EncryptedData == "" || req.Nonce == "" || req.EntryType == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: entry_type, encrypted_data, nonce")
		return
	}

	entry, err := h.vaultService.CreateEntry(r.Context(), claims.UserID, req)
	if err != nil {
		log.Error().Err(err).Str("user_id", claims.UserID).Msg("create vault entry failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, entry)
}

// ListEntries handles GET /api/v1/vault/entries
func (h *VaultHandler) ListEntries(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	filters := vault.ListFilters{
		EntryType: r.URL.Query().Get("entry_type"),
		FolderID:  r.URL.Query().Get("folder_id"),
	}

	if since := r.URL.Query().Get("updated_since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid updated_since: use RFC3339 format")
			return
		}
		filters.UpdatedSince = &t
	}

	if fav := r.URL.Query().Get("favorite"); fav == "true" {
		t := true
		filters.IsFavorite = &t
	}

	switch r.URL.Query().Get("filter") {
	case "archived":
		t := true
		filters.IsArchived = &t
	case "trash":
		filters.InTrash = true
	case "":
		// default: exclude archived entries
		f := false
		filters.IsArchived = &f
	}

	entries, err := h.vaultService.ListEntries(r.Context(), claims.UserID, filters)
	if err != nil {
		log.Error().Err(err).Msg("list vault entries failed")
		writeError(w, http.StatusInternalServerError, "failed to list entries")
		return
	}

	if entries == nil {
		entries = []vault.EntrySummary{}
	}

	writeJSON(w, http.StatusOK, entries)
}

// GetEntry handles GET /api/v1/vault/entries/{id}
func (h *VaultHandler) GetEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	entry, err := h.vaultService.GetEntry(r.Context(), claims.UserID, entryID)
	if err != nil {
		writeError(w, http.StatusNotFound, "entry not found")
		return
	}

	writeJSON(w, http.StatusOK, entry)
}

// UpdateEntry handles PUT /api/v1/vault/entries/{id}
func (h *VaultHandler) UpdateEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	var req vault.UpdateEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EncryptedData == "" || req.Nonce == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: encrypted_data, nonce")
		return
	}

	entry, err := h.vaultService.UpdateEntry(r.Context(), claims.UserID, entryID, req)
	if err != nil {
		log.Error().Err(err).Msg("update vault entry failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, entry)
}

// DeleteEntry handles DELETE /api/v1/vault/entries/{id}
func (h *VaultHandler) DeleteEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	if err := h.vaultService.DeleteEntry(r.Context(), claims.UserID, entryID); err != nil {
		writeError(w, http.StatusNotFound, "entry not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// SetFavorite handles PUT /api/v1/vault/entries/{id}/favorite
func (h *VaultHandler) SetFavorite(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	var req struct {
		IsFavorite bool `json:"is_favorite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.vaultService.SetFavorite(r.Context(), claims.UserID, entryID, req.IsFavorite); err != nil {
		writeError(w, http.StatusNotFound, "entry not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "updated", "is_favorite": req.IsFavorite})
}

// SetArchived handles PUT /api/v1/vault/entries/{id}/archive
func (h *VaultHandler) SetArchived(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	var req struct {
		IsArchived bool `json:"is_archived"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.vaultService.SetArchived(r.Context(), claims.UserID, entryID, req.IsArchived); err != nil {
		writeError(w, http.StatusNotFound, "entry not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "updated", "is_archived": req.IsArchived})
}

// RestoreEntry handles POST /api/v1/vault/entries/{id}/restore
func (h *VaultHandler) RestoreEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	if err := h.vaultService.RestoreEntry(r.Context(), claims.UserID, entryID); err != nil {
		writeError(w, http.StatusNotFound, "entry not found in trash")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "restored"})
}

// PermanentDeleteEntry handles DELETE /api/v1/vault/entries/{id}/permanent
func (h *VaultHandler) PermanentDeleteEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	if err := h.vaultService.PermanentDeleteEntry(r.Context(), claims.UserID, entryID); err != nil {
		writeError(w, http.StatusNotFound, "entry not found in trash")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "permanently_deleted"})
}

// PurgeTrash handles POST /api/v1/vault/trash/purge
func (h *VaultHandler) PurgeTrash(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	purged, err := h.vaultService.PurgeExpiredTrash(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Msg("purge trash failed")
		writeError(w, http.StatusInternalServerError, "failed to purge trash")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "purged", "count": purged})
}

// CreateFolder handles POST /api/v1/vault/folders
func (h *VaultHandler) CreateFolder(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req vault.CreateFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.NameEncrypted == "" {
		writeError(w, http.StatusBadRequest, "missing name_encrypted")
		return
	}

	folder, err := h.vaultService.CreateFolder(r.Context(), claims.UserID, req)
	if err != nil {
		log.Error().Err(err).Msg("create folder failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, folder)
}

// ListFolders handles GET /api/v1/vault/folders
func (h *VaultHandler) ListFolders(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	folders, err := h.vaultService.ListFolders(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Msg("list folders failed")
		writeError(w, http.StatusInternalServerError, "failed to list folders")
		return
	}

	if folders == nil {
		folders = []vault.FolderResponse{}
	}

	writeJSON(w, http.StatusOK, folders)
}

// CloneEntry handles POST /api/v1/vault/entries/{id}/clone
func (h *VaultHandler) CloneEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	if entryID == "" {
		writeError(w, http.StatusBadRequest, "missing entry id")
		return
	}

	clone, err := h.vaultService.CloneEntry(r.Context(), claims.UserID, entryID)
	if err != nil {
		log.Error().Err(err).Msg("clone vault entry failed")
		writeError(w, http.StatusNotFound, "entry not found")
		return
	}

	writeJSON(w, http.StatusCreated, clone)
}

// DeleteFolder handles DELETE /api/v1/vault/folders/{id}
func (h *VaultHandler) DeleteFolder(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	folderID := chi.URLParam(r, "id")
	if folderID == "" {
		writeError(w, http.StatusBadRequest, "missing folder id")
		return
	}

	if err := h.vaultService.DeleteFolder(r.Context(), claims.UserID, folderID); err != nil {
		writeError(w, http.StatusNotFound, "folder not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
