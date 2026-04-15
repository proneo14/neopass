package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	syncsvc "github.com/password-manager/password-manager/internal/sync"
)

// SyncHandler handles sync HTTP endpoints.
type SyncHandler struct {
	syncService *syncsvc.Service
}

// NewSyncHandler creates a new SyncHandler.
func NewSyncHandler(syncService *syncsvc.Service) *SyncHandler {
	return &SyncHandler{syncService: syncService}
}

// Pull handles POST /api/v1/sync/pull
func (h *SyncHandler) Pull(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		DeviceID   string `json:"device_id"`
		LastSyncAt string `json:"last_sync_at"` // RFC3339 or empty for full sync
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "missing device_id")
		return
	}

	var lastSyncAt time.Time
	if body.LastSyncAt != "" {
		var err error
		lastSyncAt, err = time.Parse(time.RFC3339, body.LastSyncAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid last_sync_at: use RFC3339 format")
			return
		}
	}

	resp, err := h.syncService.Pull(r.Context(), claims.UserID, body.DeviceID, lastSyncAt)
	if err != nil {
		log.Error().Err(err).Msg("sync pull failed")
		writeError(w, http.StatusInternalServerError, "sync pull failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Push handles POST /api/v1/sync/push
func (h *SyncHandler) Push(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		DeviceID string                     `json:"device_id"`
		Changes  []syncsvc.VaultEntryChange `json:"changes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "missing device_id")
		return
	}

	resp, err := h.syncService.Push(r.Context(), claims.UserID, body.DeviceID, body.Changes)
	if err != nil {
		log.Error().Err(err).Msg("sync push failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if resp.Conflicts == nil {
		resp.Conflicts = []syncsvc.ConflictEntry{}
	}

	writeJSON(w, http.StatusOK, resp)
}

// Resolve handles POST /api/v1/sync/resolve
func (h *SyncHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req syncsvc.ResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EntryID == "" || req.Resolution == "" {
		writeError(w, http.StatusBadRequest, "missing entry_id or resolution")
		return
	}

	if err := h.syncService.ResolveConflict(r.Context(), claims.UserID, req); err != nil {
		log.Error().Err(err).Msg("sync resolve failed")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "resolved"})
}
