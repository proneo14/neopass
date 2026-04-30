package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// EmergencyAccessHandler handles emergency access HTTP endpoints.
type EmergencyAccessHandler struct {
	eaRepo         db.EmergencyAccessRepository
	userRepo       db.UserRepository
	vaultRepo      db.VaultRepository
	auditRepo      db.AuditRepository
	orgRepo        db.OrgRepository
	collectionRepo db.CollectionRepository
}

// NewEmergencyAccessHandler creates a new EmergencyAccessHandler.
func NewEmergencyAccessHandler(eaRepo db.EmergencyAccessRepository, userRepo db.UserRepository, vaultRepo db.VaultRepository, auditRepo db.AuditRepository, orgRepo db.OrgRepository, collectionRepo db.CollectionRepository) *EmergencyAccessHandler {
	return &EmergencyAccessHandler{
		eaRepo:         eaRepo,
		userRepo:       userRepo,
		vaultRepo:      vaultRepo,
		auditRepo:      auditRepo,
		orgRepo:        orgRepo,
		collectionRepo: collectionRepo,
	}
}

func (h *EmergencyAccessHandler) audit(r *http.Request, actorID, targetID *string, action string, details map[string]interface{}) {
	detailsJSON, _ := json.Marshal(details)
	if err := h.auditRepo.LogAction(r.Context(), actorID, targetID, action, detailsJSON); err != nil {
		log.Error().Err(err).Str("action", action).Msg("audit log failed")
	}
}

// Invite handles POST /api/v1/emergency-access/invite
func (h *EmergencyAccessHandler) Invite(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Email        string `json:"email"`
		AccessType   string `json:"access_type"`
		WaitTimeDays int    `json:"wait_time_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.AccessType != "view" && req.AccessType != "takeover" {
		writeError(w, http.StatusBadRequest, "access_type must be 'view' or 'takeover'")
		return
	}
	if req.WaitTimeDays < 1 || req.WaitTimeDays > 30 {
		writeError(w, http.StatusBadRequest, "wait_time_days must be between 1 and 30")
		return
	}

	// Look up the grantee user by email (they may not have an account yet)
	var granteeID *string
	grantee, err := h.userRepo.GetUserByEmail(r.Context(), req.Email)
	if err == nil {
		granteeID = &grantee.ID
	}

	ea := db.EmergencyAccess{
		GrantorID:    claims.UserID,
		GranteeID:    granteeID,
		GranteeEmail: req.Email,
		Status:       "invited",
		AccessType:   req.AccessType,
		WaitTimeDays: req.WaitTimeDays,
	}

	created, err := h.eaRepo.CreateEmergencyAccess(r.Context(), ea)
	if err != nil {
		log.Error().Err(err).Msg("create emergency access failed")
		writeError(w, http.StatusInternalServerError, "failed to create emergency access")
		return
	}

	h.audit(r, &claims.UserID, granteeID, "emergency_access_invited", map[string]interface{}{
		"grantee_email": req.Email,
		"access_type":   req.AccessType,
		"wait_time_days": req.WaitTimeDays,
	})

	writeJSON(w, http.StatusCreated, created)
}

// GetGranteePublicKey handles GET /api/v1/emergency-access/{id}/public-key
// Returns the grantee's X25519 public key so the grantor can encrypt their vault key.
func (h *EmergencyAccessHandler) GetGranteePublicKey(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	if ea.GrantorID != claims.UserID {
		writeError(w, http.StatusForbidden, "only the grantor can view the grantee public key")
		return
	}
	if ea.GranteeID == nil {
		writeError(w, http.StatusConflict, "grantee has not accepted yet")
		return
	}

	grantee, err := h.userRepo.GetUserByID(r.Context(), *ea.GranteeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to look up grantee")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"public_key": hex.EncodeToString(grantee.PublicKey),
	})
}

// ListGranted handles GET /api/v1/emergency-access/granted
func (h *EmergencyAccessHandler) ListGranted(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	list, err := h.eaRepo.ListGrantedAccess(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Msg("list granted access failed")
		writeError(w, http.StatusInternalServerError, "failed to list emergency access")
		return
	}
	if list == nil {
		list = []db.EmergencyAccess{}
	}

	writeJSON(w, http.StatusOK, list)
}

// ListTrusted handles GET /api/v1/emergency-access/trusted
func (h *EmergencyAccessHandler) ListTrusted(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	list, err := h.eaRepo.ListTrustedBy(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Msg("list trusted by failed")
		writeError(w, http.StatusInternalServerError, "failed to list emergency access")
		return
	}
	if list == nil {
		list = []db.EmergencyAccess{}
	}

	// Populate grantor email for each record so the UI can display it
	for i := range list {
		grantor, err := h.userRepo.GetUserByID(r.Context(), list[i].GrantorID)
		if err == nil {
			list[i].GrantorEmail = grantor.Email
		}
	}

	writeJSON(w, http.StatusOK, list)
}

// Accept handles POST /api/v1/emergency-access/{id}/accept
func (h *EmergencyAccessHandler) Accept(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	// Look up the user's email to verify they are the invited grantee
	user, err := h.userRepo.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to look up user")
		return
	}
	if ea.GranteeEmail != user.Email {
		writeError(w, http.StatusForbidden, "you are not the invited grantee")
		return
	}
	if ea.Status != "invited" {
		writeError(w, http.StatusConflict, "invitation is not in invited status")
		return
	}

	// Link grantee user ID if not already set
	if ea.GranteeID == nil {
		_ = h.eaRepo.SetGranteeID(r.Context(), eaID, claims.UserID)
	}

	if err := h.eaRepo.UpdateStatus(r.Context(), eaID, "accepted"); err != nil {
		log.Error().Err(err).Msg("accept emergency access failed")
		writeError(w, http.StatusInternalServerError, "failed to accept")
		return
	}

	h.audit(r, &claims.UserID, &ea.GrantorID, "emergency_access_accepted", map[string]interface{}{
		"emergency_access_id": eaID,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// Confirm handles POST /api/v1/emergency-access/{id}/confirm
func (h *EmergencyAccessHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	var req struct {
		EncryptedKey string `json:"encrypted_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EncryptedKey == "" {
		writeError(w, http.StatusBadRequest, "encrypted_key is required")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	// Only the grantor can confirm key exchange
	if ea.GrantorID != claims.UserID {
		writeError(w, http.StatusForbidden, "only the grantor can confirm")
		return
	}
	// Allow confirm in any active state (accepted, recovery_initiated, recovery_approved)
	// This makes the key exchange idempotent and fixes the race condition
	// where grantee initiates recovery before grantor's client polls
	if ea.Status != "accepted" && ea.Status != "recovery_initiated" && ea.Status != "recovery_approved" {
		writeError(w, http.StatusConflict, "emergency access is not in a confirmable status")
		return
	}

	encKey, err := hex.DecodeString(req.EncryptedKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid encrypted_key hex")
		return
	}

	// Store the blob as encrypted_key; key_nonce is unused for X25519 blobs
	if err := h.eaRepo.SetEncryptedKey(r.Context(), eaID, encKey, []byte{}); err != nil {
		log.Error().Err(err).Msg("set encrypted key failed")
		writeError(w, http.StatusInternalServerError, "failed to set encrypted key")
		return
	}

	h.audit(r, &claims.UserID, ea.GranteeID, "emergency_access_confirmed", map[string]interface{}{
		"emergency_access_id": eaID,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

// Initiate handles POST /api/v1/emergency-access/{id}/initiate
func (h *EmergencyAccessHandler) Initiate(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	// Only the grantee can initiate recovery
	if ea.GranteeID == nil || *ea.GranteeID != claims.UserID {
		writeError(w, http.StatusForbidden, "only the grantee can initiate recovery")
		return
	}

	// Allow re-requesting after a previous rejection
	if ea.Status != "accepted" && ea.Status != "recovery_rejected" {
		writeError(w, http.StatusConflict, "emergency access is not in an eligible status")
		return
	}

	if err := h.eaRepo.InitiateRecovery(r.Context(), eaID); err != nil {
		log.Error().Err(err).Msg("initiate recovery failed")
		writeError(w, http.StatusInternalServerError, "failed to initiate recovery")
		return
	}

	h.audit(r, &claims.UserID, &ea.GrantorID, "emergency_access_recovery_initiated", map[string]interface{}{
		"emergency_access_id": eaID,
		"wait_time_days":      ea.WaitTimeDays,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "recovery_initiated"})
}

// Approve handles POST /api/v1/emergency-access/{id}/approve
func (h *EmergencyAccessHandler) Approve(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	// Only the grantor can approve
	if ea.GrantorID != claims.UserID {
		writeError(w, http.StatusForbidden, "only the grantor can approve")
		return
	}
	if ea.Status != "recovery_initiated" {
		writeError(w, http.StatusConflict, "recovery has not been initiated")
		return
	}

	if err := h.eaRepo.UpdateStatus(r.Context(), eaID, "recovery_approved"); err != nil {
		log.Error().Err(err).Msg("approve recovery failed")
		writeError(w, http.StatusInternalServerError, "failed to approve recovery")
		return
	}

	h.audit(r, &claims.UserID, ea.GranteeID, "emergency_access_approved", map[string]interface{}{
		"emergency_access_id": eaID,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "recovery_approved"})
}

// Reject handles POST /api/v1/emergency-access/{id}/reject
func (h *EmergencyAccessHandler) Reject(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	// Only the grantor can reject
	if ea.GrantorID != claims.UserID {
		writeError(w, http.StatusForbidden, "only the grantor can reject")
		return
	}
	if ea.Status != "recovery_initiated" {
		writeError(w, http.StatusConflict, "recovery has not been initiated")
		return
	}

	if err := h.eaRepo.UpdateStatus(r.Context(), eaID, "recovery_rejected"); err != nil {
		log.Error().Err(err).Msg("reject recovery failed")
		writeError(w, http.StatusInternalServerError, "failed to reject recovery")
		return
	}

	h.audit(r, &claims.UserID, ea.GranteeID, "emergency_access_rejected", map[string]interface{}{
		"emergency_access_id": eaID,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "recovery_rejected"})
}

// GetVault handles GET /api/v1/emergency-access/{id}/vault
func (h *EmergencyAccessHandler) GetVault(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	// Only the grantee can access the vault
	if ea.GranteeID == nil || *ea.GranteeID != claims.UserID {
		writeError(w, http.StatusForbidden, "only the grantee can access the vault")
		return
	}

	// Check access is approved (either explicitly or auto-approved after wait period)
	accessAllowed := false
	if ea.Status == "recovery_approved" {
		accessAllowed = true
	} else if ea.Status == "recovery_initiated" && ea.RecoveryInitiatedAt != nil {
		deadline := ea.RecoveryInitiatedAt.Add(time.Duration(ea.WaitTimeDays) * 24 * time.Hour)
		if time.Now().UTC().After(deadline) {
			accessAllowed = true
			// Auto-approve since wait period has passed
			_ = h.eaRepo.UpdateStatus(r.Context(), eaID, "recovery_approved")
		}
	}

	if !accessAllowed {
		writeError(w, http.StatusForbidden, "recovery access has not been approved")
		return
	}

	// Fetch the grantor's vault entries
	entries, err := h.vaultRepo.ListEntries(r.Context(), ea.GrantorID, db.VaultFilters{})
	if err != nil {
		log.Error().Err(err).Msg("list vault entries for emergency access failed")
		writeError(w, http.StatusInternalServerError, "failed to retrieve vault")
		return
	}
	if entries == nil {
		entries = []db.VaultEntry{}
	}

	h.audit(r, &claims.UserID, &ea.GrantorID, "emergency_access_vault_viewed", map[string]interface{}{
		"emergency_access_id": eaID,
		"entry_count":         len(entries),
	})

	// Return hex-encoded entries matching the sync/vault API format
	type entrySummary struct {
		ID            string     `json:"id"`
		EntryType     string     `json:"entry_type"`
		EncryptedData string     `json:"encrypted_data"`
		Nonce         string     `json:"nonce"`
		Version       int        `json:"version"`
		FolderID      *string    `json:"folder_id,omitempty"`
		IsFavorite    bool       `json:"is_favorite"`
		IsArchived    bool       `json:"is_archived"`
		CreatedAt     time.Time  `json:"created_at"`
		UpdatedAt     time.Time  `json:"updated_at"`
	}
	summaries := make([]entrySummary, 0, len(entries))
	for _, e := range entries {
		summaries = append(summaries, entrySummary{
			ID:            e.ID,
			EntryType:     e.EntryType,
			EncryptedData: hex.EncodeToString(e.EncryptedData),
			Nonce:         hex.EncodeToString(e.Nonce),
			Version:       e.Version,
			FolderID:      e.FolderID,
			IsFavorite:    e.IsFavorite,
			IsArchived:    e.IsArchived,
			CreatedAt:     e.CreatedAt,
			UpdatedAt:     e.UpdatedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries":       summaries,
		"encrypted_key": hex.EncodeToString(ea.EncryptedKey),
		"key_nonce":     hex.EncodeToString(ea.KeyNonce),
	})
}

// Takeover handles POST /api/v1/emergency-access/{id}/takeover
func (h *EmergencyAccessHandler) Takeover(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	var req struct {
		NewAuthHash        string `json:"new_auth_hash"`
		NewSalt            string `json:"new_salt"`
		NewPublicKey       string `json:"new_public_key"`
		NewEncPrivateKey   string `json:"new_encrypted_private_key"`
		NewMasterKey       string `json:"new_master_key"` // hex — needed to update org escrow
		OldMasterKey       string `json:"old_master_key"` // hex — grantor's old master key, for re-encrypting collection keys
		ReEncryptedEntries []struct {
			ID            string `json:"id"`
			EncryptedData string `json:"encrypted_data"`
			Nonce         string `json:"nonce"`
		} `json:"re_encrypted_entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	// Only the grantee can takeover
	if ea.GranteeID == nil || *ea.GranteeID != claims.UserID {
		writeError(w, http.StatusForbidden, "only the grantee can takeover")
		return
	}
	if ea.AccessType != "takeover" {
		writeError(w, http.StatusForbidden, "this emergency access does not allow takeover")
		return
	}

	// Check access is approved
	accessAllowed := false
	if ea.Status == "recovery_approved" {
		accessAllowed = true
	} else if ea.Status == "recovery_initiated" && ea.RecoveryInitiatedAt != nil {
		deadline := ea.RecoveryInitiatedAt.Add(time.Duration(ea.WaitTimeDays) * 24 * time.Hour)
		if time.Now().UTC().After(deadline) {
			accessAllowed = true
		}
	}
	if !accessAllowed {
		writeError(w, http.StatusForbidden, "recovery access has not been approved")
		return
	}

	// Decode new credentials
	newAuthHash, err := hex.DecodeString(req.NewAuthHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid new_auth_hash hex")
		return
	}
	newSalt, err := hex.DecodeString(req.NewSalt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid new_salt hex")
		return
	}
	newPubKey, err := hex.DecodeString(req.NewPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid new_public_key hex")
		return
	}
	newEncPrivKey, err := hex.DecodeString(req.NewEncPrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid new_encrypted_private_key hex")
		return
	}

	// Bcrypt the auth hash (same as registration — server stores bcrypt of client's auth hash)
	bcryptHash, err := bcrypt.GenerateFromPassword(newAuthHash, bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("bcrypt auth hash for takeover failed")
		writeError(w, http.StatusInternalServerError, "failed to process credentials")
		return
	}

	// Update user credentials
	if err := h.userRepo.UpdateUserKeys(r.Context(), ea.GrantorID, bcryptHash, newSalt, newPubKey, newEncPrivKey); err != nil {
		log.Error().Err(err).Msg("update user keys for takeover failed")
		writeError(w, http.StatusInternalServerError, "failed to update user credentials")
		return
	}

	// Update re-encrypted vault entries
	for _, entry := range req.ReEncryptedEntries {
		encData, err := hex.DecodeString(entry.EncryptedData)
		if err != nil {
			continue
		}
		nonce, err := hex.DecodeString(entry.Nonce)
		if err != nil {
			continue
		}
		existing, err := h.vaultRepo.GetEntry(r.Context(), entry.ID, ea.GrantorID)
		if err != nil {
			continue
		}
		existing.EncryptedData = encData
		existing.Nonce = nonce
		if _, err := h.vaultRepo.UpdateEntry(r.Context(), existing); err != nil {
			log.Error().Err(err).Str("entry_id", entry.ID).Msg("re-encrypt entry failed during takeover")
		}
	}

	// Mark emergency access as expired after takeover
	_ = h.eaRepo.UpdateStatus(r.Context(), eaID, "expired")

	// Revoke all existing tokens for the taken-over user (force logout)
	if err := h.userRepo.RevokeUserTokens(r.Context(), ea.GrantorID); err != nil {
		log.Warn().Err(err).Msg("takeover: failed to revoke user tokens")
	} else {
		log.Info().Str("user_id", ea.GrantorID).Msg("takeover: revoked all tokens for taken-over user")
	}

	// Update org escrow if user is in an org and new_master_key was provided
	if req.NewMasterKey != "" {
		newMasterKeyBytes, err := hex.DecodeString(req.NewMasterKey)
		if err == nil && len(newMasterKeyBytes) == 32 {
			var newMK [32]byte
			copy(newMK[:], newMasterKeyBytes)
			// Try to find grantor's org membership
			if _, org, err := h.orgRepo.GetUserOrg(r.Context(), ea.GrantorID); err == nil {
				// Create new escrow blob with new master key
				escrowBlob, err := crypto.EncryptEscrow(newMK, org.OrgPublicKey)
				if err == nil {
					if err := h.orgRepo.UpdateEscrowBlob(r.Context(), org.ID, ea.GrantorID, escrowBlob); err != nil {
						log.Warn().Err(err).Msg("takeover: failed to update escrow blob")
					} else {
						log.Info().Str("user_id", ea.GrantorID).Msg("takeover: updated org escrow blob")
					}
				} else {
					log.Warn().Err(err).Msg("takeover: failed to encrypt escrow")
				}
				// Clear stale encrypted_org_key — will be re-propagated when an admin calls propagate-keys
				if err := h.orgRepo.SetMemberOrgKey(r.Context(), org.ID, ea.GrantorID, nil); err != nil {
					log.Warn().Err(err).Msg("takeover: failed to clear encrypted_org_key")
				}
			}
			crypto.ZeroBytes(newMK[:])
			crypto.ZeroBytes(newMasterKeyBytes)
		}
	}

	// Re-encrypt collection keys: old master key → new master key (preserve memberships)
	if req.OldMasterKey != "" && req.NewMasterKey != "" {
		oldMKBytes, err := hex.DecodeString(req.OldMasterKey)
		newMKBytes2, err2 := hex.DecodeString(req.NewMasterKey)
		if err == nil && err2 == nil && len(oldMKBytes) == 32 && len(newMKBytes2) == 32 {
			var oldMK, newMK2 [32]byte
			copy(oldMK[:], oldMKBytes)
			copy(newMK2[:], newMKBytes2)
			if collections, err := h.collectionRepo.ListUserCollections(r.Context(), ea.GrantorID); err == nil {
				reEncrypted := 0
				for _, c := range collections {
					encKey, err := h.collectionRepo.GetCollectionKey(r.Context(), c.ID, ea.GrantorID)
					if err != nil || len(encKey) < 12 {
						log.Warn().Err(err).Str("collection_id", c.ID).Msg("takeover: failed to get collection key")
						continue
					}
					// Decrypt with old master key
					plainKey, err := aesGCMDecrypt(encKey, oldMK)
					if err != nil {
						log.Warn().Err(err).Str("collection_id", c.ID).Msg("takeover: failed to decrypt collection key with old master key")
						continue
					}
					// Re-encrypt with new master key
					newEncKey, err := aesGCMEncrypt(plainKey, newMK2)
					crypto.ZeroBytes(plainKey)
					if err != nil {
						log.Warn().Err(err).Str("collection_id", c.ID).Msg("takeover: failed to re-encrypt collection key")
						continue
					}
					// Update the member's encrypted key (AddCollectionMember does upsert)
					if err := h.collectionRepo.AddCollectionMember(r.Context(), c.ID, ea.GrantorID, newEncKey, c.Permission); err != nil {
						log.Warn().Err(err).Str("collection_id", c.ID).Msg("takeover: failed to update collection member key")
					} else {
						reEncrypted++
					}
				}
				log.Info().Int("count", reEncrypted).Str("user_id", ea.GrantorID).Msg("takeover: re-encrypted collection keys")
			}
			crypto.ZeroBytes(oldMK[:])
			crypto.ZeroBytes(newMK2[:])
			crypto.ZeroBytes(oldMKBytes)
			crypto.ZeroBytes(newMKBytes2)
		}
	}

	h.audit(r, &claims.UserID, &ea.GrantorID, "emergency_access_takeover", map[string]interface{}{
		"emergency_access_id": eaID,
		"entries_updated":     len(req.ReEncryptedEntries),
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "takeover_complete"})
}

// Delete handles DELETE /api/v1/emergency-access/{id}
func (h *EmergencyAccessHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	eaID := chi.URLParam(r, "id")
	if eaID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	ea, err := h.eaRepo.GetEmergencyAccess(r.Context(), eaID)
	if err != nil {
		writeError(w, http.StatusNotFound, "emergency access not found")
		return
	}

	// Either the grantor or the grantee can delete/revoke
	isGrantor := ea.GrantorID == claims.UserID
	isGrantee := ea.GranteeID != nil && *ea.GranteeID == claims.UserID
	if !isGrantor && !isGrantee {
		writeError(w, http.StatusForbidden, "you are not authorized to delete this emergency access")
		return
	}

	if err := h.eaRepo.DeleteEmergencyAccess(r.Context(), eaID); err != nil {
		log.Error().Err(err).Msg("delete emergency access failed")
		writeError(w, http.StatusInternalServerError, "failed to delete emergency access")
		return
	}

	action := "emergency_access_revoked"
	if isGrantee {
		action = "emergency_access_declined"
	}
	h.audit(r, &claims.UserID, &ea.GrantorID, action, map[string]interface{}{
		"emergency_access_id": eaID,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
