package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// CollectionHandler handles collection HTTP endpoints.
type CollectionHandler struct {
	collectionRepo db.CollectionRepository
	orgRepo        db.OrgRepository
	userRepo       db.UserRepository
	auditRepo      db.AuditRepository
}

// NewCollectionHandler creates a new CollectionHandler.
func NewCollectionHandler(collectionRepo db.CollectionRepository, orgRepo db.OrgRepository, userRepo db.UserRepository, auditRepo db.AuditRepository) *CollectionHandler {
	return &CollectionHandler{
		collectionRepo: collectionRepo,
		orgRepo:        orgRepo,
		userRepo:       userRepo,
		auditRepo:      auditRepo,
	}
}

// requireOrgMember verifies the user is a member of the org and returns the member record.
func (h *CollectionHandler) requireOrgMember(w http.ResponseWriter, r *http.Request, orgID, userID string) (*db.OrgMember, bool) {
	member, err := h.orgRepo.GetMember(r.Context(), orgID, userID)
	if err != nil {
		writeError(w, http.StatusForbidden, "not a member of this organization")
		return nil, false
	}
	return &member, true
}

// requireCollectionPermission checks that the user has at least the required permission level on a collection.
// Permission hierarchy: manage > write > read.
func (h *CollectionHandler) requireCollectionPermission(w http.ResponseWriter, r *http.Request, collectionID, userID, requiredPerm string) bool {
	_, err := h.collectionRepo.GetCollectionKey(r.Context(), collectionID, userID)
	if err != nil {
		writeError(w, http.StatusForbidden, "not a member of this collection")
		return false
	}
	members, err := h.collectionRepo.GetCollectionMembers(r.Context(), collectionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check permissions")
		return false
	}
	var userPerm string
	for _, m := range members {
		if m.UserID == userID {
			userPerm = m.Permission
			break
		}
	}
	if !hasPermission(userPerm, requiredPerm) {
		writeError(w, http.StatusForbidden, "insufficient collection permission")
		return false
	}
	return true
}

// hasPermission checks if actual >= required in the hierarchy: manage > write > read.
func hasPermission(actual, required string) bool {
	levels := map[string]int{"read": 1, "write": 2, "manage": 3}
	return levels[actual] >= levels[required]
}

// CreateCollection handles POST /api/v1/orgs/{orgId}/collections
func (h *CollectionHandler) CreateCollection(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "orgId")

	member, ok := h.requireOrgMember(w, r, orgID, claims.UserID)
	if !ok {
		return
	}
	if member.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin role required to create collections")
		return
	}

	var body struct {
		NameEncrypted string `json:"name_encrypted"` // hex
		NameNonce     string `json:"name_nonce"`      // hex
		ExternalID    string `json:"external_id,omitempty"`
		EncryptedKey  string `json:"encrypted_key"` // hex — collection key encrypted with creator's master key
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.NameEncrypted == "" || body.NameNonce == "" || body.EncryptedKey == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	nameEnc, err := hex.DecodeString(body.NameEncrypted)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid name_encrypted hex")
		return
	}
	nameNonce, err := hex.DecodeString(body.NameNonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid name_nonce hex")
		return
	}

	encCollKey, err := hex.DecodeString(body.EncryptedKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid encrypted_key hex")
		return
	}

	var extID *string
	if body.ExternalID != "" {
		extID = &body.ExternalID
	}

	coll := db.Collection{
		OrgID:         orgID,
		NameEncrypted: nameEnc,
		NameNonce:     nameNonce,
		ExternalID:    extID,
	}

	created, err := h.collectionRepo.CreateCollection(r.Context(), coll)
	if err != nil {
		log.Error().Err(err).Msg("create collection failed")
		writeError(w, http.StatusInternalServerError, "failed to create collection")
		return
	}

	// Add creator as a manage-level member with their client-encrypted collection key
	if err := h.collectionRepo.AddCollectionMember(r.Context(), created.ID, claims.UserID, encCollKey, "manage"); err != nil {
		log.Error().Err(err).Msg("add creator to collection failed")
		writeError(w, http.StatusInternalServerError, "failed to add creator to collection")
		return
	}

	h.audit(r, &claims.UserID, nil, "collection_created", map[string]string{
		"collection_id": created.ID,
		"org_id":        orgID,
	})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":               created.ID,
		"org_id":           created.OrgID,
		"name_encrypted":   hex.EncodeToString(created.NameEncrypted),
		"name_nonce":       hex.EncodeToString(created.NameNonce),
		"encrypted_key":    hex.EncodeToString(encCollKey),
		"created_at":       created.CreatedAt,
	})
}

// ListOrgCollections handles GET /api/v1/orgs/{orgId}/collections
func (h *CollectionHandler) ListOrgCollections(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "orgId")
	if _, ok := h.requireOrgMember(w, r, orgID, claims.UserID); !ok {
		return
	}

	collections, err := h.collectionRepo.ListCollections(r.Context(), orgID, claims.UserID)
	if err != nil {
		log.Error().Err(err).Msg("list collections failed")
		writeError(w, http.StatusInternalServerError, "failed to list collections")
		return
	}

	if collections == nil {
		collections = []db.CollectionWithPermission{}
	}

	// Encode binary fields to hex for JSON transport
	type collResp struct {
		ID            string  `json:"id"`
		OrgID         string  `json:"org_id"`
		NameEncrypted string  `json:"name_encrypted"`
		NameNonce     string  `json:"name_nonce"`
		EncryptedKey  string  `json:"encrypted_key,omitempty"`
		ExternalID    *string `json:"external_id,omitempty"`
		MemberCount   int     `json:"member_count"`
		EntryCount    int     `json:"entry_count"`
		CreatedAt     string  `json:"created_at"`
		UpdatedAt     string  `json:"updated_at"`
	}
	resp := make([]collResp, len(collections))
	for i, c := range collections {
		resp[i] = collResp{
			ID:            c.ID,
			OrgID:         c.OrgID,
			NameEncrypted: hex.EncodeToString(c.NameEncrypted),
			NameNonce:     hex.EncodeToString(c.NameNonce),
			EncryptedKey:  hex.EncodeToString(c.EncryptedKey),
			ExternalID:    c.ExternalID,
			MemberCount:   c.MemberCount,
			EntryCount:    c.EntryCount,
			CreatedAt:     c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:     c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetCollection handles GET /api/v1/collections/{id}
func (h *CollectionHandler) GetCollection(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	coll, err := h.collectionRepo.GetCollection(r.Context(), collID)
	if err != nil {
		writeError(w, http.StatusNotFound, "collection not found")
		return
	}

	// Verify membership
	if _, ok := h.requireOrgMember(w, r, coll.OrgID, claims.UserID); !ok {
		return
	}

	members, _ := h.collectionRepo.GetCollectionMembers(r.Context(), collID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":             coll.ID,
		"org_id":         coll.OrgID,
		"name_encrypted": hex.EncodeToString(coll.NameEncrypted),
		"name_nonce":     hex.EncodeToString(coll.NameNonce),
		"external_id":    coll.ExternalID,
		"members":        members,
		"created_at":     coll.CreatedAt,
		"updated_at":     coll.UpdatedAt,
	})
}

// UpdateCollection handles PUT /api/v1/collections/{id}
func (h *CollectionHandler) UpdateCollection(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	coll, err := h.collectionRepo.GetCollection(r.Context(), collID)
	if err != nil {
		writeError(w, http.StatusNotFound, "collection not found")
		return
	}

	if !h.requireCollectionPermission(w, r, collID, claims.UserID, "manage") {
		return
	}

	var body struct {
		NameEncrypted string `json:"name_encrypted"` // hex
		NameNonce     string `json:"name_nonce"`      // hex
		ExternalID    string `json:"external_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.NameEncrypted != "" {
		nameEnc, err := hex.DecodeString(body.NameEncrypted)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid name_encrypted hex")
			return
		}
		coll.NameEncrypted = nameEnc
	}
	if body.NameNonce != "" {
		nameNonce, err := hex.DecodeString(body.NameNonce)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid name_nonce hex")
			return
		}
		coll.NameNonce = nameNonce
	}
	if body.ExternalID != "" {
		coll.ExternalID = &body.ExternalID
	}

	if err := h.collectionRepo.UpdateCollection(r.Context(), coll); err != nil {
		log.Error().Err(err).Msg("update collection failed")
		writeError(w, http.StatusInternalServerError, "failed to update collection")
		return
	}

	h.audit(r, &claims.UserID, nil, "collection_updated", map[string]string{"collection_id": collID})

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// DeleteCollection handles DELETE /api/v1/collections/{id}
func (h *CollectionHandler) DeleteCollection(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	if !h.requireCollectionPermission(w, r, collID, claims.UserID, "manage") {
		return
	}

	if err := h.collectionRepo.DeleteCollection(r.Context(), collID); err != nil {
		log.Error().Err(err).Msg("delete collection failed")
		writeError(w, http.StatusInternalServerError, "failed to delete collection")
		return
	}

	h.audit(r, &claims.UserID, nil, "collection_deleted", map[string]string{"collection_id": collID})

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// AddMember handles POST /api/v1/collections/{id}/members
// The admin provides their master_key so the server can use escrow to recover
// the target user's master key and re-encrypt the collection key for them.
func (h *CollectionHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")

	// Check if user is a collection member with manage permission, OR an org admin
	coll, err := h.collectionRepo.GetCollection(r.Context(), collID)
	if err != nil {
		writeError(w, http.StatusNotFound, "collection not found")
		return
	}

	isCollectionManager := false
	if _, err := h.collectionRepo.GetCollectionKey(r.Context(), collID, claims.UserID); err == nil {
		members, _ := h.collectionRepo.GetCollectionMembers(r.Context(), collID)
		for _, m := range members {
			if m.UserID == claims.UserID && hasPermission(m.Permission, "manage") {
				isCollectionManager = true
				break
			}
		}
	}

	// Allow org admins even if not a collection member
	isOrgAdmin := false
	if !isCollectionManager {
		member, err := h.orgRepo.GetMember(r.Context(), coll.OrgID, claims.UserID)
		if err != nil || member.Role != "admin" {
			writeError(w, http.StatusForbidden, "insufficient permission")
			return
		}
		isOrgAdmin = true
	}

	var body struct {
		UserID    string `json:"user_id"`
		Permission string `json:"permission"`
		MasterKey  string `json:"master_key"` // hex — admin's master key for escrow
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.UserID == "" || body.Permission == "" || body.MasterKey == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: user_id, permission, master_key")
		return
	}

	if body.Permission != "read" && body.Permission != "write" && body.Permission != "manage" {
		writeError(w, http.StatusBadRequest, "permission must be read, write, or manage")
		return
	}

	adminMasterKeyBytes, err := hex.DecodeString(body.MasterKey)
	if err != nil || len(adminMasterKeyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid master_key")
		return
	}
	var adminMasterKey [32]byte
	copy(adminMasterKey[:], adminMasterKeyBytes)
	defer crypto.ZeroBytes(adminMasterKey[:])

	// Verify the target user is in the same org
	if _, err := h.orgRepo.GetMember(r.Context(), coll.OrgID, body.UserID); err != nil {
		writeError(w, http.StatusBadRequest, "user is not a member of the organization")
		return
	}

	// Decrypt org private key first (needed for escrow operations)
	org, err := h.orgRepo.GetOrg(r.Context(), coll.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get org")
		return
	}

	var orgPrivKey []byte
	encAdminOrgKey, _ := h.orgRepo.GetMemberOrgKey(r.Context(), coll.OrgID, claims.UserID)
	if len(encAdminOrgKey) > 0 {
		orgPrivKey, err = crypto.DecryptOrgPrivateKey(encAdminOrgKey, adminMasterKey)
	} else {
		orgPrivKey, err = crypto.DecryptOrgPrivateKey(org.EncryptedOrgPrivateKey, adminMasterKey)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to decrypt org key")
		return
	}
	defer crypto.ZeroBytes(orgPrivKey)

	// 1. Get the collection key — either from admin's own membership or from any existing member
	var collKeyPlain []byte
	adminEncKey, adminKeyErr := h.collectionRepo.GetCollectionKey(r.Context(), collID, claims.UserID)
	if adminKeyErr == nil && len(adminEncKey) >= 12 {
		// Admin is a member — decrypt their own key
		collKeyPlain, err = aesGCMDecrypt(adminEncKey, adminMasterKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to decrypt collection key — invalid master key")
			return
		}
	} else if isOrgAdmin {
		// Admin is NOT a member — find any existing member and use escrow
		members, err := h.collectionRepo.GetCollectionMembers(r.Context(), collID)
		if err != nil || len(members) == 0 {
			writeError(w, http.StatusInternalServerError, "no existing members to derive collection key from")
			return
		}
		existingMember := members[0]
		existingEncKey, err := h.collectionRepo.GetCollectionKey(r.Context(), collID, existingMember.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get existing member's key")
			return
		}
		existingEscrow, err := h.orgRepo.GetMemberEscrow(r.Context(), coll.OrgID, existingMember.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get member escrow")
			return
		}
		existingMasterKey, err := crypto.DecryptEscrow(existingEscrow, orgPrivKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to decrypt member escrow")
			return
		}
		collKeyPlain, err = aesGCMDecrypt(existingEncKey, existingMasterKey)
		crypto.ZeroBytes(existingMasterKey[:])
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to decrypt collection key from existing member")
			return
		}
	} else {
		writeError(w, http.StatusInternalServerError, "failed to get collection key")
		return
	}
	defer crypto.ZeroBytes(collKeyPlain)

	// 2. Use escrow to get target user's master key
	escrowBlob, err := h.orgRepo.GetMemberEscrow(r.Context(), coll.OrgID, body.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to get target user's escrow")
		return
	}

	targetMasterKey, err := crypto.DecryptEscrow(escrowBlob, orgPrivKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to decrypt target user's escrow")
		return
	}
	defer crypto.ZeroBytes(targetMasterKey[:])

	// 4. Re-encrypt collection key with target user's master key
	encKeyForTarget, err := aesGCMEncrypt(collKeyPlain, targetMasterKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encrypt collection key for target user")
		return
	}

	if err := h.collectionRepo.AddCollectionMember(r.Context(), collID, body.UserID, encKeyForTarget, body.Permission); err != nil {
		log.Error().Err(err).Msg("add collection member failed")
		writeError(w, http.StatusInternalServerError, "failed to add member")
		return
	}

	h.audit(r, &claims.UserID, &body.UserID, "collection_member_added", map[string]string{
		"collection_id": collID,
		"permission":    body.Permission,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

// aesGCMEncrypt encrypts plaintext with AES-256-GCM. Returns nonce || ciphertext+tag.
func aesGCMEncrypt(plaintext []byte, key [32]byte) ([]byte, error) {
	ciphertext, nonce, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, len(nonce)+len(ciphertext))
	copy(blob, nonce)
	copy(blob[len(nonce):], ciphertext)
	return blob, nil
}

// aesGCMDecrypt decrypts a blob of nonce || ciphertext+tag with AES-256-GCM.
func aesGCMDecrypt(blob []byte, key [32]byte) ([]byte, error) {
	if len(blob) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := blob[:12]
	ciphertext := blob[12:]
	return crypto.Decrypt(ciphertext, nonce, key)
}

// RemoveMember handles DELETE /api/v1/collections/{id}/members/{uid}
func (h *CollectionHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	targetUID := chi.URLParam(r, "uid")

	if !h.requireCollectionPermission(w, r, collID, claims.UserID, "manage") {
		return
	}

	if err := h.collectionRepo.RemoveCollectionMember(r.Context(), collID, targetUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.audit(r, &claims.UserID, &targetUID, "collection_member_removed", map[string]string{
		"collection_id": collID,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// UpdateMemberPermission handles PUT /api/v1/collections/{id}/members/{uid}/permission
func (h *CollectionHandler) UpdateMemberPermission(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	targetUID := chi.URLParam(r, "uid")

	if !h.requireCollectionPermission(w, r, collID, claims.UserID, "manage") {
		return
	}

	var body struct {
		Permission string `json:"permission"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Permission != "read" && body.Permission != "write" && body.Permission != "manage" {
		writeError(w, http.StatusBadRequest, "permission must be read, write, or manage")
		return
	}

	if err := h.collectionRepo.UpdateCollectionMemberPermission(r.Context(), collID, targetUID, body.Permission); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.audit(r, &claims.UserID, &targetUID, "collection_permission_changed", map[string]string{
		"collection_id": collID,
		"permission":    body.Permission,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// AddEntry handles POST /api/v1/collections/{id}/entries
func (h *CollectionHandler) AddEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	if !h.requireCollectionPermission(w, r, collID, claims.UserID, "write") {
		return
	}

	var body struct {
		EntryID       string `json:"entry_id"`
		EntryType     string `json:"entry_type"`
		EncryptedData string `json:"encrypted_data"` // hex — entry data encrypted with collection key
		Nonce         string `json:"nonce"`           // hex
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.EntryID == "" || body.EncryptedData == "" || body.Nonce == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: entry_id, encrypted_data, nonce")
		return
	}

	encData, err := hex.DecodeString(body.EncryptedData)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid encrypted_data hex")
		return
	}
	nonce, err := hex.DecodeString(body.Nonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid nonce hex")
		return
	}

	entryType := body.EntryType
	if entryType == "" {
		entryType = "login"
	}

	if err := h.collectionRepo.AddEntryToCollection(r.Context(), collID, body.EntryID, entryType, encData, nonce); err != nil {
		log.Error().Err(err).Msg("add entry to collection failed")
		writeError(w, http.StatusInternalServerError, "failed to add entry")
		return
	}

	h.audit(r, &claims.UserID, nil, "collection_entry_added", map[string]string{
		"collection_id": collID,
		"entry_id":      body.EntryID,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

// RemoveEntry handles DELETE /api/v1/collections/{id}/entries/{entryId}
func (h *CollectionHandler) RemoveEntry(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	entryID := chi.URLParam(r, "entryId")

	if !h.requireCollectionPermission(w, r, collID, claims.UserID, "write") {
		return
	}

	if err := h.collectionRepo.RemoveEntryFromCollection(r.Context(), collID, entryID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.audit(r, &claims.UserID, nil, "collection_entry_removed", map[string]string{
		"collection_id": collID,
		"entry_id":      entryID,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// ListEntries handles GET /api/v1/collections/{id}/entries
func (h *CollectionHandler) ListEntries(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	if !h.requireCollectionPermission(w, r, collID, claims.UserID, "read") {
		return
	}

	entries, err := h.collectionRepo.GetCollectionEntries(r.Context(), collID)
	if err != nil {
		log.Error().Err(err).Msg("get collection entries failed")
		writeError(w, http.StatusInternalServerError, "failed to get entries")
		return
	}

	type entryResp struct {
		EntryID       string `json:"entry_id"`
		EntryType     string `json:"entry_type"`
		EncryptedData string `json:"encrypted_data"`
		Nonce         string `json:"nonce"`
	}

	resp := make([]entryResp, 0, len(entries))
	for _, e := range entries {
		resp = append(resp, entryResp{
			EntryID:       e.EntryID,
			EntryType:     e.EntryType,
			EncryptedData: hex.EncodeToString(e.EncryptedData),
			Nonce:         hex.EncodeToString(e.Nonce),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetCollectionMembers handles GET /api/v1/collections/{id}/members
func (h *CollectionHandler) GetCollectionMembers(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collID := chi.URLParam(r, "id")
	if !h.requireCollectionPermission(w, r, collID, claims.UserID, "read") {
		return
	}

	members, err := h.collectionRepo.GetCollectionMembers(r.Context(), collID)
	if err != nil {
		log.Error().Err(err).Msg("get collection members failed")
		writeError(w, http.StatusInternalServerError, "failed to get members")
		return
	}

	if members == nil {
		members = []db.CollectionMember{}
	}

	// Encode encrypted_key to hex for JSON
	type memberResp struct {
		CollectionID string `json:"collection_id"`
		UserID       string `json:"user_id"`
		Email        string `json:"email"`
		EncryptedKey string `json:"encrypted_key"`
		Permission   string `json:"permission"`
	}
	resp := make([]memberResp, len(members))
	for i, m := range members {
		resp[i] = memberResp{
			CollectionID: m.CollectionID,
			UserID:       m.UserID,
			Email:        m.Email,
			EncryptedKey: hex.EncodeToString(m.EncryptedKey),
			Permission:   m.Permission,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// ListUserCollections handles GET /api/v1/collections (user's collections across orgs)
func (h *CollectionHandler) ListUserCollections(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	collections, err := h.collectionRepo.ListUserCollections(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Msg("list user collections failed")
		writeError(w, http.StatusInternalServerError, "failed to list collections")
		return
	}

	if collections == nil {
		collections = []db.CollectionWithPermission{}
	}

	type collResp struct {
		ID            string  `json:"id"`
		OrgID         string  `json:"org_id"`
		NameEncrypted string  `json:"name_encrypted"`
		NameNonce     string  `json:"name_nonce"`
		EncryptedKey  string  `json:"encrypted_key,omitempty"`
		Permission    string  `json:"permission"`
		MemberCount   int     `json:"member_count"`
		EntryCount    int     `json:"entry_count"`
		ExternalID    *string `json:"external_id,omitempty"`
		CreatedAt     string  `json:"created_at"`
		UpdatedAt     string  `json:"updated_at"`
	}
	resp := make([]collResp, len(collections))
	for i, c := range collections {
		resp[i] = collResp{
			ID:            c.ID,
			OrgID:         c.OrgID,
			NameEncrypted: hex.EncodeToString(c.NameEncrypted),
			NameNonce:     hex.EncodeToString(c.NameNonce),
			EncryptedKey:  hex.EncodeToString(c.EncryptedKey),
			Permission:    c.Permission,
			MemberCount:   c.MemberCount,
			EntryCount:    c.EntryCount,
			ExternalID:    c.ExternalID,
			CreatedAt:     c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:     c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetEntryCollections handles GET /api/v1/vault/entries/{id}/collections
func (h *CollectionHandler) GetEntryCollections(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entryID := chi.URLParam(r, "id")
	collections, err := h.collectionRepo.GetEntryCollections(r.Context(), entryID, claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get entry collections")
		return
	}

	if collections == nil {
		collections = []db.CollectionWithPermission{}
	}

	type collResp struct {
		ID            string `json:"id"`
		NameEncrypted string `json:"name_encrypted"`
		NameNonce     string `json:"name_nonce"`
		EncryptedKey  string `json:"encrypted_key,omitempty"`
	}
	resp := make([]collResp, len(collections))
	for i, c := range collections {
		resp[i] = collResp{
			ID:            c.ID,
			NameEncrypted: hex.EncodeToString(c.NameEncrypted),
			NameNonce:     hex.EncodeToString(c.NameNonce),
			EncryptedKey:  hex.EncodeToString(c.EncryptedKey),
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// audit logs an action.
func (h *CollectionHandler) audit(r *http.Request, actorID, targetID *string, action string, details map[string]string) {
	detailsJSON, _ := json.Marshal(details)
	if err := h.auditRepo.LogAction(r.Context(), actorID, targetID, action, detailsJSON); err != nil {
		log.Error().Err(err).Str("action", action).Msg("failed to write audit log")
	}
}
