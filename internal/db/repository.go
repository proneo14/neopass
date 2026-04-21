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
}

// OrgRepository defines the interface for organization database operations.
type OrgRepository interface {
	CreateOrg(ctx context.Context, name string, orgPubKey, encOrgPrivKey []byte) (Organization, error)
	GetOrg(ctx context.Context, orgID string) (Organization, error)
	AddMember(ctx context.Context, orgID, userID, role string, escrowBlob []byte) error
	GetMember(ctx context.Context, orgID, userID string) (OrgMember, error)
	GetMemberEscrow(ctx context.Context, orgID, userID string) ([]byte, error)
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
	InsertSharedTOTP(ctx context.Context, fromUserID, toUserID string, encryptedSecret []byte, expiresAt time.Time) (string, error)
	GetSharedTOTP(ctx context.Context, shareID, toUserID string) (SharedTOTP, error)
	MarkSharedTOTPClaimed(ctx context.Context, shareID string) error
	ListPendingSharedTOTP(ctx context.Context, toUserID string) ([]SharedTOTP, error)
}
