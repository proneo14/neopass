package db

import (
	"context"
	"encoding/json"
	"time"
)

// UserRepository defines the interface for user database operations.
type UserRepository interface {
	CreateUser(ctx context.Context, email string, authHash, salt []byte, kdfParams json.RawMessage, publicKey, encryptedPrivateKey []byte) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id string) (User, error)
	UpdateUserKeys(ctx context.Context, id string, authHash, salt, publicKey, encryptedPrivateKey []byte) error
	SetRequireHWKey(ctx context.Context, userID string, require bool) error
	RevokeUserTokens(ctx context.Context, userID string) error
}

// VaultRepository defines the interface for vault entry database operations.
type VaultRepository interface {
	CreateEntry(ctx context.Context, entry VaultEntry) (VaultEntry, error)
	GetEntry(ctx context.Context, entryID, userID string) (VaultEntry, error)
	ListEntries(ctx context.Context, userID string, filters VaultFilters) ([]VaultEntry, error)
	UpdateEntry(ctx context.Context, entry VaultEntry) (VaultEntry, error)
	UpdateEntryVersioned(ctx context.Context, entry VaultEntry, expectedVersion int) (VaultEntry, error)
	DeleteEntry(ctx context.Context, entryID, userID string) error
	ListEntriesForSync(ctx context.Context, userID string, since time.Time) ([]VaultEntry, error)
	GetEntryByID(ctx context.Context, entryID string) (VaultEntry, error)
	CreateFolder(ctx context.Context, folder Folder) (Folder, error)
	ListFolders(ctx context.Context, userID string) ([]Folder, error)
	DeleteFolder(ctx context.Context, folderID, userID string) error
	SetFavorite(ctx context.Context, entryID, userID string, favorite bool) error
	SetArchived(ctx context.Context, entryID, userID string, archived bool) error
	RestoreEntry(ctx context.Context, entryID, userID string) error
	PermanentDeleteEntry(ctx context.Context, entryID, userID string) error
	PurgeExpiredTrash(ctx context.Context, userID string, olderThan time.Time) (int, error)
}

// OrgRepository defines the interface for organization database operations.
type OrgRepository interface {
	CreateOrg(ctx context.Context, name string, orgPubKey, encOrgPrivKey []byte) (Organization, error)
	GetOrg(ctx context.Context, orgID string) (Organization, error)
	AddMember(ctx context.Context, orgID, userID, role string, escrowBlob []byte) error
	GetMember(ctx context.Context, orgID, userID string) (OrgMember, error)
	GetMemberEscrow(ctx context.Context, orgID, userID string) ([]byte, error)
	GetMemberOrgKey(ctx context.Context, orgID, userID string) ([]byte, error)
	SetMemberOrgKey(ctx context.Context, orgID, userID string, encOrgKey []byte) error
	ListMembers(ctx context.Context, orgID string) ([]OrgMember, error)
	RemoveMember(ctx context.Context, orgID, userID string) error
	UpdateEscrowBlob(ctx context.Context, orgID, userID string, escrowBlob []byte) error
	CreateInvitation(ctx context.Context, orgID, email, role, invitedBy string) (Invitation, error)
	GetPendingInvitation(ctx context.Context, orgID, email string) (Invitation, error)
	MarkInvitationAccepted(ctx context.Context, invID string) error
	ListInvitations(ctx context.Context, orgID string) ([]Invitation, error)
	SetOrgPolicy(ctx context.Context, orgID string, policy json.RawMessage) error
	GetUserOrg(ctx context.Context, userID string) (OrgMember, Organization, error)
	GetInvitationsByEmail(ctx context.Context, email string) ([]Invitation, error)
}

// AuditRepository defines the interface for audit log database operations.
type AuditRepository interface {
	LogAction(ctx context.Context, actorID, targetID *string, action string, details json.RawMessage) error
	GetAuditLog(ctx context.Context, filters AuditFilters) ([]AuditEntry, error)
}

// SyncRepository defines the interface for sync cursor database operations.
type SyncRepository interface {
	GetSyncCursor(ctx context.Context, userID, deviceID string) (time.Time, error)
	UpsertSyncCursor(ctx context.Context, userID, deviceID string, syncAt time.Time) error
	ListDevices(ctx context.Context, userID string) ([]SyncCursor, error)
	DeleteDevice(ctx context.Context, userID, deviceID string) error
}

// TOTPRepository defines the interface for 2FA database operations.
type TOTPRepository interface {
	UpsertTOTPSecret(ctx context.Context, userID string, encryptedSecret []byte) (string, error)
	GetTOTPSecret(ctx context.Context, userID string) (TOTPSecret, error)
	MarkTOTPVerified(ctx context.Context, userID string) error
	DeleteTOTPSecret(ctx context.Context, userID string) error
	InsertRecoveryCodes(ctx context.Context, userID string, codeHashes [][]byte) error
	GetUnusedRecoveryCodes(ctx context.Context, userID string) ([]RecoveryCode, error)
	MarkRecoveryCodeUsed(ctx context.Context, codeID string) error
	InsertSharedTOTP(ctx context.Context, fromUserID, toUserID string, encryptedSecret []byte, label string, expiresAt time.Time) (string, error)
	GetSharedTOTP(ctx context.Context, shareID, toUserID string) (SharedTOTP, error)
	MarkSharedTOTPClaimed(ctx context.Context, shareID string) error
	ListPendingSharedTOTP(ctx context.Context, toUserID string) ([]SharedTOTP, error)
}

// PasskeyRepository defines the interface for passkey credential database operations.
type PasskeyRepository interface {
	CreatePasskey(ctx context.Context, passkey PasskeyCredential) (PasskeyCredential, error)
	GetPasskeysByRPID(ctx context.Context, userID, rpID string) ([]PasskeyCredential, error)
	GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (PasskeyCredential, error)
	GetAllPasskeys(ctx context.Context, userID string) ([]PasskeyCredential, error)
	UpdateSignCount(ctx context.Context, credentialID []byte, newCount int) error
	DeletePasskey(ctx context.Context, userID, passkeyID string) error
}

// HardwareKeyRepository defines the interface for hardware auth key database operations.
type HardwareKeyRepository interface {
	RegisterHardwareKey(ctx context.Context, key HardwareAuthKey) (HardwareAuthKey, error)
	GetHardwareKeys(ctx context.Context, userID string) ([]HardwareAuthKey, error)
	GetHardwareKeyByCredentialID(ctx context.Context, credentialID []byte) (HardwareAuthKey, error)
	UpdateHardwareKeySignCount(ctx context.Context, credentialID []byte, count int) error
	DeleteHardwareKey(ctx context.Context, userID, keyID string) error
}

// Send represents a Secure Send record.
type Send struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	Slug           string     `json:"slug"`
	SendType       string     `json:"send_type"`
	EncryptedData  []byte     `json:"encrypted_data"`
	Nonce          []byte     `json:"nonce"`
	EncryptedName  []byte     `json:"encrypted_name,omitempty"`
	NameNonce      []byte     `json:"name_nonce,omitempty"`
	PasswordHash   []byte     `json:"-"`
	HasPassword    bool       `json:"has_password"`
	MaxAccessCount *int       `json:"max_access_count,omitempty"`
	AccessCount    int        `json:"access_count"`
	FileName       *string    `json:"file_name,omitempty"`
	FileSize       *int       `json:"file_size,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Disabled       bool       `json:"disabled"`
	HideEmail      bool       `json:"hide_email"`
	CreatedAt      time.Time  `json:"created_at"`
}

// SendRepository defines the interface for Secure Send database operations.
type SendRepository interface {
	CreateSend(ctx context.Context, send Send) (Send, error)
	GetSendBySlug(ctx context.Context, slug string) (Send, error)
	ListSends(ctx context.Context, userID string) ([]Send, error)
	IncrementAccessCount(ctx context.Context, sendID string) error
	DeleteSend(ctx context.Context, sendID, userID string) error
	DisableSend(ctx context.Context, sendID, userID string) error
	PurgeExpiredSends(ctx context.Context) (int, error)
}

// Collection represents a shared vault collection.
type Collection struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	NameEncrypted []byte    `json:"name_encrypted"`
	NameNonce     []byte    `json:"name_nonce"`
	ExternalID    *string   `json:"external_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CollectionMember represents a user's membership in a collection.
type CollectionMember struct {
	CollectionID string `json:"collection_id"`
	UserID       string `json:"user_id"`
	Email        string `json:"email,omitempty"`
	EncryptedKey []byte `json:"encrypted_key"`
	Permission   string `json:"permission"`
}

// CollectionWithPermission is a collection with the requesting user's permission.
type CollectionWithPermission struct {
	Collection
	Permission   string `json:"permission"`
	EncryptedKey []byte `json:"encrypted_key,omitempty"` // requesting user's encrypted copy of the collection key
	MemberCount  int    `json:"member_count"`
	EntryCount   int    `json:"entry_count"`
}

// CollectionEntryData represents a vault entry's data stored in a collection,
// encrypted with the collection key so all members can decrypt.
type CollectionEntryData struct {
	CollectionID  string `json:"collection_id"`
	EntryID       string `json:"entry_id"`
	EntryType     string `json:"entry_type"`
	EncryptedData []byte `json:"encrypted_data"`
	Nonce         []byte `json:"nonce"`
}

// CollectionRepository defines the interface for collection database operations.
type CollectionRepository interface {
	CreateCollection(ctx context.Context, collection Collection) (Collection, error)
	GetCollection(ctx context.Context, collectionID string) (Collection, error)
	ListCollections(ctx context.Context, orgID string, requestingUserID string) ([]CollectionWithPermission, error)
	ListUserCollections(ctx context.Context, userID string) ([]CollectionWithPermission, error)
	UpdateCollection(ctx context.Context, collection Collection) error
	DeleteCollection(ctx context.Context, collectionID string) error
	AddCollectionMember(ctx context.Context, collectionID, userID string, encryptedKey []byte, permission string) error
	RemoveCollectionMember(ctx context.Context, collectionID, userID string) error
	UpdateCollectionMemberPermission(ctx context.Context, collectionID, userID, permission string) error
	GetCollectionMembers(ctx context.Context, collectionID string) ([]CollectionMember, error)
	GetCollectionKey(ctx context.Context, collectionID, userID string) ([]byte, error)
	AddEntryToCollection(ctx context.Context, collectionID, entryID, entryType string, encryptedData, nonce []byte) error
	RemoveEntryFromCollection(ctx context.Context, collectionID, entryID string) error
	GetCollectionEntries(ctx context.Context, collectionID string) ([]CollectionEntryData, error)
	GetEntryCollections(ctx context.Context, entryID string, userID string) ([]CollectionWithPermission, error)
}

// EmergencyAccess represents an emergency access grant between two users.
type EmergencyAccess struct {
	ID                  string     `json:"id"`
	GrantorID           string     `json:"grantor_id"`
	GranteeID           *string    `json:"grantee_id,omitempty"`
	GranteeEmail        string     `json:"grantee_email"`
	GrantorEmail        string     `json:"grantor_email,omitempty"`
	Status              string     `json:"status"`
	AccessType          string     `json:"access_type"`
	WaitTimeDays        int        `json:"wait_time_days"`
	EncryptedKey        []byte     `json:"encrypted_key,omitempty"`
	KeyNonce            []byte     `json:"key_nonce,omitempty"`
	RecoveryInitiatedAt *time.Time `json:"recovery_initiated_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// EmergencyAccessRepository defines the interface for emergency access database operations.
type EmergencyAccessRepository interface {
	CreateEmergencyAccess(ctx context.Context, ea EmergencyAccess) (EmergencyAccess, error)
	GetEmergencyAccess(ctx context.Context, id string) (EmergencyAccess, error)
	ListGrantedAccess(ctx context.Context, grantorID string) ([]EmergencyAccess, error)
	ListTrustedBy(ctx context.Context, granteeID string) ([]EmergencyAccess, error)
	UpdateStatus(ctx context.Context, id, status string) error
	SetEncryptedKey(ctx context.Context, id string, encryptedKey, nonce []byte) error
	InitiateRecovery(ctx context.Context, id string) error
	DeleteEmergencyAccess(ctx context.Context, id string) error
	GetAutoApproveEligible(ctx context.Context) ([]EmergencyAccess, error)
	SetGranteeID(ctx context.Context, id, granteeID string) error
	ListByGranteeEmail(ctx context.Context, email string) ([]EmergencyAccess, error)
	AutoApproveExpired(ctx context.Context) (int, error)
}
