package admin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/password-manager/password-manager/internal/crypto"
	"github.com/password-manager/password-manager/internal/db"
)

// Errors
var (
	ErrNotAdmin     = fmt.Errorf("admin role required")
	ErrNotMember    = fmt.Errorf("not a member of organization")
	ErrNoInvitation = fmt.Errorf("no pending invitation")
)

// OrgPolicy defines organization-level security policies.
type OrgPolicy struct {
	Require2FA       bool `json:"require_2fa"`
	MinPasswordLen   int  `json:"min_password_length"`
	RotationDays     int  `json:"rotation_days"`
}

// DecryptedEntry is a decrypted vault entry (for admin escrow access).
type DecryptedEntry struct {
	ID        string          `json:"id"`
	EntryType string          `json:"entry_type"`
	Data      json.RawMessage `json:"data"`
	Version   int             `json:"version"`
}

// Service provides admin operations.
type Service struct {
	orgRepo   db.OrgRepository
	userRepo  db.UserRepository
	vaultRepo db.VaultRepository
	auditRepo db.AuditRepository
}

// NewService creates a new admin Service.
func NewService(orgRepo db.OrgRepository, userRepo db.UserRepository, vaultRepo db.VaultRepository, auditRepo db.AuditRepository) *Service {
	return &Service{
		orgRepo:   orgRepo,
		userRepo:  userRepo,
		vaultRepo: vaultRepo,
		auditRepo: auditRepo,
	}
}

// CreateOrg creates a new organization. The caller becomes the admin.
// adminMasterKey is the admin's 32-byte master key (hex-encoded by handler).
func (s *Service) CreateOrg(ctx context.Context, adminUserID, orgName string, adminMasterKey [32]byte) (db.Organization, error) {
	// Check if user already belongs to an org
	if _, _, err := s.orgRepo.GetUserOrg(ctx, adminUserID); err == nil {
		return db.Organization{}, fmt.Errorf("user already belongs to an organization")
	}

	// Generate org X-Wing keypair, encrypted with admin's master key
	orgPubKey, encOrgPrivKey, err := crypto.GenerateOrgKeyPair(adminMasterKey)
	if err != nil {
		return db.Organization{}, fmt.Errorf("generate org keypair: %w", err)
	}

	// Create org record
	org, err := s.orgRepo.CreateOrg(ctx, orgName, orgPubKey, encOrgPrivKey)
	if err != nil {
		return db.Organization{}, err
	}

	// Create escrow blob for admin (encrypt admin's master key with org public key)
	escrowBlob, err := crypto.EncryptEscrow(adminMasterKey, orgPubKey)
	if err != nil {
		return db.Organization{}, fmt.Errorf("encrypt escrow for admin: %w", err)
	}

	// Add admin as org admin
	if err := s.orgRepo.AddMember(ctx, org.ID, adminUserID, "admin", escrowBlob); err != nil {
		return db.Organization{}, err
	}

	// Audit log
	s.audit(ctx, &adminUserID, nil, "org_created", map[string]string{"org_id": org.ID, "org_name": orgName})

	log.Info().Str("org_id", org.ID).Str("admin_id", adminUserID).Msg("organization created")
	return org, nil
}

// InviteUser invites a user to an organization.
func (s *Service) InviteUser(ctx context.Context, adminUserID, orgID, email, role string) (db.Invitation, error) {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return db.Invitation{}, err
	}

	if role != "admin" && role != "member" {
		role = "member"
	}

	inv, err := s.orgRepo.CreateInvitation(ctx, orgID, email, role, adminUserID)
	if err != nil {
		return db.Invitation{}, err
	}

	s.audit(ctx, &adminUserID, nil, "user_invited", map[string]string{
		"org_id": orgID, "email": email, "role": role,
	})

	return inv, nil
}

// AcceptInvite accepts a pending org invitation. userMasterKey is needed to create escrow.
func (s *Service) AcceptInvite(ctx context.Context, userID, orgID string, userMasterKey [32]byte) error {
	// Get user to find their email
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Find pending invitation
	inv, err := s.orgRepo.GetPendingInvitation(ctx, orgID, user.Email)
	if err != nil {
		return ErrNoInvitation
	}

	// Get org public key for escrow
	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return err
	}

	// Create escrow blob
	escrowBlob, err := crypto.EncryptEscrow(userMasterKey, org.OrgPublicKey)
	if err != nil {
		return fmt.Errorf("encrypt escrow: %w", err)
	}

	// Add member
	if err := s.orgRepo.AddMember(ctx, orgID, userID, inv.Role, escrowBlob); err != nil {
		return err
	}

	// Mark invitation accepted
	if err := s.orgRepo.MarkInvitationAccepted(ctx, inv.ID); err != nil {
		return err
	}

	s.audit(ctx, &userID, nil, "user_joined", map[string]string{
		"org_id": orgID, "role": inv.Role,
	})

	return nil
}

// RemoveUser removes a user from an organization.
func (s *Service) RemoveUser(ctx context.Context, adminUserID, orgID, targetUserID string) error {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return err
	}

	if err := s.orgRepo.RemoveMember(ctx, orgID, targetUserID); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, &targetUserID, "user_removed", map[string]string{
		"org_id": orgID,
	})

	return nil
}

// LeaveOrg lets a user leave an organization voluntarily.
func (s *Service) LeaveOrg(ctx context.Context, userID, orgID string) error {
	if err := s.orgRepo.RemoveMember(ctx, orgID, userID); err != nil {
		return err
	}

	s.audit(ctx, &userID, nil, "user_left_org", map[string]string{
		"org_id": orgID,
	})

	return nil
}

// ListMembers returns all members of an organization.
func (s *Service) ListMembers(ctx context.Context, adminUserID, orgID string) ([]db.OrgMember, error) {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return nil, err
	}
	return s.orgRepo.ListMembers(ctx, orgID)
}

// AccessUserVault decrypts a target user's vault entries via escrow.
// This is a sensitive operation — always audit-logged.
func (s *Service) AccessUserVault(ctx context.Context, adminUserID, orgID, targetUserID string, adminMasterKey [32]byte) ([]DecryptedEntry, error) {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return nil, err
	}

	// Always audit-log vault access, even if it fails
	defer func() {
		s.audit(ctx, &adminUserID, &targetUserID, "vault_accessed", map[string]string{
			"org_id": orgID,
		})
	}()

	// Decrypt org private key with admin's master key
	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}

	orgPrivKey, err := crypto.DecryptOrgPrivateKey(org.EncryptedOrgPrivateKey, adminMasterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt org private key: %w", err)
	}
	defer crypto.ZeroBytes(orgPrivKey)

	// Get target user's escrow blob
	escrowBlob, err := s.orgRepo.GetMemberEscrow(ctx, orgID, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("get user escrow: %w", err)
	}

	// Decrypt escrow to get user's master key
	userMasterKey, err := crypto.DecryptEscrow(escrowBlob, orgPrivKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt user escrow: %w", err)
	}
	defer crypto.ZeroBytes(userMasterKey[:])

	// Get all user vault entries
	entries, err := s.vaultRepo.ListEntries(ctx, targetUserID, db.VaultFilters{})
	if err != nil {
		return nil, fmt.Errorf("list user vault: %w", err)
	}

	// Decrypt each entry
	var decrypted []DecryptedEntry
	for _, e := range entries {
		plaintext, err := crypto.Decrypt(e.EncryptedData, e.Nonce, userMasterKey)
		if err != nil {
			log.Warn().Err(err).Str("entry_id", e.ID).Msg("failed to decrypt vault entry during admin access")
			continue
		}
		// Copy plaintext so we can zero the original decrypted buffer
		dataCopy := make([]byte, len(plaintext))
		copy(dataCopy, plaintext)
		crypto.ZeroBytes(plaintext)
		decrypted = append(decrypted, DecryptedEntry{
			ID:        e.ID,
			EntryType: e.EntryType,
			Data:      json.RawMessage(dataCopy),
			Version:   e.Version,
		})
	}

	log.Warn().Str("admin_id", adminUserID).Str("target_user_id", targetUserID).
		Str("org_id", orgID).Int("entries_accessed", len(decrypted)).
		Msg("ADMIN VAULT ACCESS — sensitive operation")

	return decrypted, nil
}

// ChangeUserPassword changes a user's password via admin escrow access.
// This re-encrypts all vault entries with the provided new master key.
func (s *Service) ChangeUserPassword(ctx context.Context, adminUserID, orgID, targetUserID string, adminMasterKey, newMasterKey [32]byte, newAuthHash, newSalt string) error {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return err
	}

	// Decrypt org private key
	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return err
	}

	orgPrivKey, err := crypto.DecryptOrgPrivateKey(org.EncryptedOrgPrivateKey, adminMasterKey)
	if err != nil {
		return fmt.Errorf("decrypt org private key: %w", err)
	}
	defer crypto.ZeroBytes(orgPrivKey)

	// Decrypt escrow to get user's old master key
	escrowBlob, err := s.orgRepo.GetMemberEscrow(ctx, orgID, targetUserID)
	if err != nil {
		return fmt.Errorf("get user escrow: %w", err)
	}

	oldMasterKey, err := crypto.DecryptEscrow(escrowBlob, orgPrivKey)
	if err != nil {
		return fmt.Errorf("decrypt user escrow: %w", err)
	}
	defer crypto.ZeroBytes(oldMasterKey[:])

	// Decode new credentials
	newSaltBytes, err := hex.DecodeString(newSalt)
	if err != nil {
		return fmt.Errorf("decode new salt: %w", err)
	}
	newAuthHashBytes, err := hex.DecodeString(newAuthHash)
	if err != nil {
		return fmt.Errorf("decode new auth hash: %w", err)
	}

	// newMasterKey is provided directly by the caller (derived client-side via KDF)
	defer crypto.ZeroBytes(newMasterKey[:])

	// Re-encrypt all vault entries
	entries, err := s.vaultRepo.ListEntries(ctx, targetUserID, db.VaultFilters{})
	if err != nil {
		return fmt.Errorf("list vault entries: %w", err)
	}

	for _, e := range entries {
		// Decrypt with old key
		plaintext, err := crypto.Decrypt(e.EncryptedData, e.Nonce, oldMasterKey)
		if err != nil {
			log.Warn().Str("entry_id", e.ID).Err(err).Msg("deleting unrecoverable vault entry during admin password reset")
			_ = s.vaultRepo.DeleteEntry(ctx, e.ID, targetUserID)
			continue
		}

		// Re-encrypt with new key
		newCt, newNonce, err := crypto.Encrypt(plaintext, newMasterKey)
		crypto.ZeroBytes(plaintext)
		if err != nil {
			return fmt.Errorf("re-encrypt entry %s: %w", e.ID, err)
		}

		e.EncryptedData = newCt
		e.Nonce = newNonce
		if _, err := s.vaultRepo.UpdateEntry(ctx, e); err != nil {
			return fmt.Errorf("update entry %s: %w", e.ID, err)
		}
	}

	// Update user's auth hash (bcrypt of the new auth hash)
	bcryptHash, err := bcrypt.GenerateFromPassword(newAuthHashBytes, bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}

	// Get the user's current keys to re-encrypt private key
	user, err := s.userRepo.GetUserByID(ctx, targetUserID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Decrypt user's private key with old master key, re-encrypt with new
	var oldKey [32]byte
	copy(oldKey[:], oldMasterKey[:])
	newEncPrivKey := user.EncryptedPrivateKey
	if len(user.EncryptedPrivateKey) > crypto.NonceSize {
		oldNonce := user.EncryptedPrivateKey[:crypto.NonceSize]
		oldCt := user.EncryptedPrivateKey[crypto.NonceSize:]
		privKeyPlain, err := crypto.Decrypt(oldCt, oldNonce, oldKey)
		if err != nil {
			log.Warn().Str("user_id", targetUserID).Err(err).Msg("could not decrypt private key during admin password reset, keeping existing")
		} else {
			newCt, newNonce, err := crypto.Encrypt(privKeyPlain, newMasterKey)
			crypto.ZeroBytes(privKeyPlain)
			if err != nil {
				return fmt.Errorf("re-encrypt user private key: %w", err)
			}

			newEncPrivKey = make([]byte, len(newNonce)+len(newCt))
			copy(newEncPrivKey, newNonce)
			copy(newEncPrivKey[len(newNonce):], newCt)
		}
	}
	if err := s.userRepo.UpdateUserKeys(ctx, targetUserID, bcryptHash, newSaltBytes, user.PublicKey, newEncPrivKey); err != nil {
		return fmt.Errorf("update user keys: %w", err)
	}

	// Update escrow blob with new master key
	newEscrow, err := crypto.EncryptEscrow(newMasterKey, org.OrgPublicKey)
	if err != nil {
		return fmt.Errorf("re-encrypt escrow: %w", err)
	}
	if err := s.orgRepo.UpdateEscrowBlob(ctx, orgID, targetUserID, newEscrow); err != nil {
		return fmt.Errorf("update escrow: %w", err)
	}

	s.audit(ctx, &adminUserID, &targetUserID, "password_changed_by_admin", map[string]string{
		"org_id": orgID,
	})

	log.Warn().Str("admin_id", adminUserID).Str("target_user_id", targetUserID).
		Str("org_id", orgID).Msg("ADMIN PASSWORD CHANGE — sensitive operation")

	return nil
}

// SetOrgPolicy sets the organization's security policy.
func (s *Service) SetOrgPolicy(ctx context.Context, adminUserID, orgID string, policy OrgPolicy) error {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return err
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	if err := s.orgRepo.SetOrgPolicy(ctx, orgID, policyJSON); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, nil, "policy_updated", map[string]string{
		"org_id": orgID,
	})

	return nil
}

// GetOrgPolicy retrieves the organization's security policy.
func (s *Service) GetOrgPolicy(ctx context.Context, orgID string) (OrgPolicy, error) {
	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return OrgPolicy{}, err
	}

	var policy OrgPolicy
	if org.Policy != nil {
		if err := json.Unmarshal(org.Policy, &policy); err != nil {
			return OrgPolicy{}, fmt.Errorf("unmarshal policy: %w", err)
		}
	}
	return policy, nil
}

// ListInvitations returns all invitations for an organization.
func (s *Service) ListInvitations(ctx context.Context, adminUserID, orgID string) ([]db.Invitation, error) {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return nil, err
	}
	return s.orgRepo.ListInvitations(ctx, orgID)
}

// GetMyOrg returns the current user's organization membership and org info.
func (s *Service) GetMyOrg(ctx context.Context, userID string) (db.OrgMember, db.Organization, error) {
	return s.orgRepo.GetUserOrg(ctx, userID)
}

// GetMyInvitations returns pending invitations for the current user's email.
func (s *Service) GetMyInvitations(ctx context.Context, userID string) ([]db.Invitation, error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	invs, err := s.orgRepo.GetInvitationsByEmail(ctx, user.Email)
	if err != nil {
		return nil, err
	}
	return invs, nil
}

// GetOrgByID returns an organization by its ID.
func (s *Service) GetOrgByID(ctx context.Context, orgID string) (db.Organization, error) {
	return s.orgRepo.GetOrg(ctx, orgID)
}

// GetAuditLog retrieves the audit log for an organization's context.
func (s *Service) GetAuditLog(ctx context.Context, adminUserID, orgID string, filters db.AuditFilters) ([]db.AuditEntry, error) {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return nil, err
	}
	return s.auditRepo.GetAuditLog(ctx, filters)
}

// verifyAdmin checks that the user is an admin of the organization.
func (s *Service) verifyAdmin(ctx context.Context, orgID, userID string) error {
	member, err := s.orgRepo.GetMember(ctx, orgID, userID)
	if err != nil {
		return ErrNotMember
	}
	if member.Role != "admin" {
		return ErrNotAdmin
	}
	return nil
}

// audit logs an action to the audit_log table, swallowing errors.
func (s *Service) audit(ctx context.Context, actorID, targetID *string, action string, details map[string]string) {
	detailsJSON, _ := json.Marshal(details)
	if err := s.auditRepo.LogAction(ctx, actorID, targetID, action, detailsJSON); err != nil {
		log.Error().Err(err).Str("action", action).Msg("failed to write audit log")
	}
}
