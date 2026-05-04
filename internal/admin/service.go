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
	ErrNotAdmin          = fmt.Errorf("admin role required")
	ErrNotMember         = fmt.Errorf("not a member of organization")
	ErrNoInvitation      = fmt.Errorf("no pending invitation")
	ErrInsufficientPerms = fmt.Errorf("insufficient permissions")
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
	orgRepo     db.OrgRepository
	userRepo    db.UserRepository
	vaultRepo   db.VaultRepository
	auditRepo   db.AuditRepository
	passkeyRepo db.PasskeyRepository
	roleRepo    db.RoleRepository
	groupRepo   db.GroupRepository
	webhookRepo db.WebhookRepository
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

// SetPasskeyRepo sets the passkey repository (optional, for vault transfer).
func (s *Service) SetPasskeyRepo(repo db.PasskeyRepository) {
	s.passkeyRepo = repo
}

// SetRoleRepo sets the role repository for permission-based access control.
func (s *Service) SetRoleRepo(repo db.RoleRepository) {
	s.roleRepo = repo
}

// SetGroupRepo sets the group repository.
func (s *Service) SetGroupRepo(repo db.GroupRepository) {
	s.groupRepo = repo
}

// SetWebhookRepo sets the webhook repository for SIEM integration.
func (s *Service) SetWebhookRepo(repo db.WebhookRepository) {
	s.webhookRepo = repo
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

	// Store the encrypted org private key for this admin (per-admin key for vault access)
	if err := s.orgRepo.SetMemberOrgKey(ctx, org.ID, adminUserID, encOrgPrivKey); err != nil {
		log.Warn().Err(err).Msg("failed to set creator's org key — vault access may require manual propagation")
	}

	// Seed built-in roles (Admin, Member) for the new org
	if s.roleRepo != nil {
		if err := s.roleRepo.SeedBuiltinRoles(ctx, org.ID); err != nil {
			log.Warn().Err(err).Msg("failed to seed built-in roles")
		} else {
			// Assign the Admin role to the creator
			adminRole, err := s.roleRepo.GetRoleByName(ctx, org.ID, "Admin")
			if err == nil {
				_ = s.roleRepo.SetMemberRole(ctx, org.ID, adminUserID, adminRole.ID)
			}
		}
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

	// Assign role_id if role repo is available
	if s.roleRepo != nil {
		roleName := "Member"
		if inv.Role == "admin" {
			roleName = "Admin"
		}
		role, err := s.roleRepo.GetRoleByName(ctx, orgID, roleName)
		if err == nil {
			_ = s.roleRepo.SetMemberRole(ctx, orgID, userID, role.ID)
		}
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

// ExportUserVault returns all non-deleted vault entries for a user (encrypted blobs).
// Used to export data before leaving an org so the client can store them locally.
func (s *Service) ExportUserVault(ctx context.Context, userID string) ([]db.VaultEntry, error) {
	return s.vaultRepo.ListEntries(ctx, userID, db.VaultFilters{})
}

// ExportUserPasskeys returns all passkeys for a user.
func (s *Service) ExportUserPasskeys(ctx context.Context, userID string) ([]db.PasskeyCredential, error) {
	if s.passkeyRepo == nil {
		return nil, nil
	}
	return s.passkeyRepo.GetAllPasskeys(ctx, userID)
}

// PropagateOrgKeys propagates the org private key to all admins who don't have a per-admin copy.
// Must be called by an admin who can decrypt the org private key (creator or admin with per-admin key).
func (s *Service) PropagateOrgKeys(ctx context.Context, adminUserID, orgID string, adminMasterKey [32]byte) error {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return err
	}

	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return err
	}

	// Try to decrypt org private key
	var orgPrivKey []byte
	encAdminKey, _ := s.orgRepo.GetMemberOrgKey(ctx, orgID, adminUserID)
	if len(encAdminKey) > 0 {
		orgPrivKey, err = crypto.DecryptOrgPrivateKey(encAdminKey, adminMasterKey)
	} else {
		orgPrivKey, err = crypto.DecryptOrgPrivateKey(org.EncryptedOrgPrivateKey, adminMasterKey)
	}
	if err != nil {
		return fmt.Errorf("cannot decrypt org key — only the org creator can trigger initial propagation: %w", err)
	}
	defer crypto.ZeroBytes(orgPrivKey)

	// Save own per-admin key if not present
	if len(encAdminKey) == 0 {
		_ = s.orgRepo.SetMemberOrgKey(ctx, orgID, adminUserID, org.EncryptedOrgPrivateKey)
	}

	s.propagateOrgKey(ctx, orgID, orgPrivKey)
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

	// Decrypt org private key — try per-admin key first, then fallback to org-level key
	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}

	var orgPrivKey []byte
	encAdminKey, _ := s.orgRepo.GetMemberOrgKey(ctx, orgID, adminUserID)
	if len(encAdminKey) > 0 {
		orgPrivKey, err = crypto.DecryptOrgPrivateKey(encAdminKey, adminMasterKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt org private key: %w", err)
		}
	} else {
		// Fallback: try org-level key (works only for the org creator)
		orgPrivKey, err = crypto.DecryptOrgPrivateKey(org.EncryptedOrgPrivateKey, adminMasterKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt org private key: org key not yet propagated to this admin")
		}
		// Creator succeeded — save per-admin key and propagate to other admins
		_ = s.orgRepo.SetMemberOrgKey(ctx, orgID, adminUserID, org.EncryptedOrgPrivateKey)
		go s.propagateOrgKey(context.Background(), orgID, orgPrivKey) // #nosec G118 -- intentionally detached goroutine for async propagation
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

	// Decrypt org private key — try per-admin key first
	org, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return err
	}

	var orgPrivKey []byte
	encAdminKey, _ := s.orgRepo.GetMemberOrgKey(ctx, orgID, adminUserID)
	if len(encAdminKey) > 0 {
		orgPrivKey, err = crypto.DecryptOrgPrivateKey(encAdminKey, adminMasterKey)
	} else {
		orgPrivKey, err = crypto.DecryptOrgPrivateKey(org.EncryptedOrgPrivateKey, adminMasterKey)
	}
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

// propagateOrgKey distributes the org private key to all admins who don't have a per-admin copy.
// It decrypts each admin's escrow to obtain their master key, then re-encrypts the org private key
// with that admin's master key.
func (s *Service) propagateOrgKey(ctx context.Context, orgID string, orgPrivKey []byte) {
	members, err := s.orgRepo.ListMembers(ctx, orgID)
	if err != nil {
		log.Warn().Err(err).Msg("propagateOrgKey: failed to list members")
		return
	}

	for _, m := range members {
		if m.Role != "admin" {
			continue
		}

		// Always re-propagate: re-derive the admin's master key from escrow
		// and re-encrypt the org private key. This handles cases where the
		// admin re-registered with a new password (invalidating old per-admin key).

		// Get their escrow → decrypt to get their master key
		escrow, err := s.orgRepo.GetMemberEscrow(ctx, orgID, m.UserID)
		if err != nil {
			log.Warn().Err(err).Str("user_id", m.UserID).Msg("propagateOrgKey: failed to get escrow")
			continue
		}

		userMasterKey, err := crypto.DecryptEscrow(escrow, orgPrivKey)
		if err != nil {
			log.Warn().Err(err).Str("user_id", m.UserID).Msg("propagateOrgKey: failed to decrypt escrow")
			continue
		}

		// Re-encrypt org private key with this admin's master key
		encPrivKey, nonce, err := crypto.Encrypt(orgPrivKey, userMasterKey)
		crypto.ZeroBytes(userMasterKey[:])
		if err != nil {
			log.Warn().Err(err).Str("user_id", m.UserID).Msg("propagateOrgKey: failed to encrypt org key")
			continue
		}

		// Store as nonce || encrypted key (same format as GenerateOrgKeyPair)
		blob := make([]byte, len(nonce)+len(encPrivKey))
		copy(blob[:len(nonce)], nonce)
		copy(blob[len(nonce):], encPrivKey)

		if err := s.orgRepo.SetMemberOrgKey(ctx, orgID, m.UserID, blob); err != nil {
			log.Warn().Err(err).Str("user_id", m.UserID).Msg("propagateOrgKey: failed to save key")
		} else {
			log.Info().Str("user_id", m.UserID).Str("org_id", orgID).Msg("propagated org key to admin")
		}
	}
}

// verifyAdmin checks that the user is an admin of the organization.
// Uses role-based permissions when roleRepo is available, falls back to legacy role check.
func (s *Service) verifyAdmin(ctx context.Context, orgID, userID string) error {
	if s.roleRepo != nil {
		role, err := s.roleRepo.GetMemberRole(ctx, orgID, userID)
		if err != nil {
			return ErrNotMember
		}
		if !hasPermissionFromRole(role, "*") && role.Name != "Admin" {
			return ErrNotAdmin
		}
		return nil
	}
	// Legacy fallback
	member, err := s.orgRepo.GetMember(ctx, orgID, userID)
	if err != nil {
		return ErrNotMember
	}
	if member.Role != "admin" {
		return ErrNotAdmin
	}
	return nil
}

// verifyPermission checks that the user has a specific permission in the organization.
func (s *Service) verifyPermission(ctx context.Context, orgID, userID, permission string) error {
	if s.roleRepo != nil {
		role, err := s.roleRepo.GetMemberRole(ctx, orgID, userID)
		if err != nil {
			return ErrNotMember
		}
		if !hasPermissionFromRole(role, permission) {
			return ErrInsufficientPerms
		}
		return nil
	}
	// Legacy fallback: admin has all perms, member has basic perms
	member, err := s.orgRepo.GetMember(ctx, orgID, userID)
	if err != nil {
		return ErrNotMember
	}
	if member.Role == "admin" {
		return nil
	}
	// Members get basic permissions
	basicPerms := map[string]bool{
		"vault.read": true, "vault.write": true, "collection.read": true,
	}
	if basicPerms[permission] {
		return nil
	}
	return ErrInsufficientPerms
}

// hasPermissionFromRole checks if a Role has a given permission.
func hasPermissionFromRole(role db.Role, permission string) bool {
	var perms []string
	if err := json.Unmarshal(role.Permissions, &perms); err != nil {
		return false
	}
	for _, p := range perms {
		if p == "*" || p == permission {
			return true
		}
	}
	return false
}

// audit logs an action to the audit_log table, swallowing errors.
func (s *Service) audit(ctx context.Context, actorID, targetID *string, action string, details map[string]string) {
	detailsJSON, _ := json.Marshal(details)
	if err := s.auditRepo.LogAction(ctx, actorID, targetID, action, detailsJSON); err != nil {
		log.Error().Err(err).Str("action", action).Msg("failed to write audit log")
	}
}

// --- Role management ---

// ListRoles returns all roles for an organization.
func (s *Service) ListRoles(ctx context.Context, adminUserID, orgID string) ([]db.Role, error) {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return nil, ErrNotAdmin
		}
		return nil, err
	}
	if s.roleRepo == nil {
		return nil, fmt.Errorf("roles not supported")
	}
	return s.roleRepo.ListRoles(ctx, orgID)
}

// CreateRole creates a custom role.
func (s *Service) CreateRole(ctx context.Context, adminUserID, orgID string, name, description string, permissions []string) (db.Role, error) {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return db.Role{}, ErrNotAdmin
		}
		return db.Role{}, err
	}
	if s.roleRepo == nil {
		return db.Role{}, fmt.Errorf("roles not supported")
	}

	permsJSON, _ := json.Marshal(permissions)
	role, err := s.roleRepo.CreateRole(ctx, db.Role{
		OrgID:       orgID,
		Name:        name,
		Description: description,
		Permissions: permsJSON,
		IsBuiltin:   false,
	})
	if err != nil {
		return db.Role{}, err
	}

	s.audit(ctx, &adminUserID, nil, "role_created", map[string]string{
		"org_id": orgID, "role_name": name,
	})
	return role, nil
}

// UpdateRole updates a custom role's name, description, and permissions.
func (s *Service) UpdateRole(ctx context.Context, adminUserID, orgID, roleID string, name, description string, permissions []string) error {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return ErrNotAdmin
		}
		return err
	}
	if s.roleRepo == nil {
		return fmt.Errorf("roles not supported")
	}

	// Prevent saving a role with no permissions
	if len(permissions) == 0 {
		return fmt.Errorf("at least one permission is required")
	}

	// Protect built-in Admin role: must always have "*" permission
	existing, err := s.roleRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found")
	}
	if existing.IsBuiltin && existing.Name == "Admin" {
		hasWildcard := false
		for _, p := range permissions {
			if p == "*" {
				hasWildcard = true
				break
			}
		}
		if !hasWildcard {
			return fmt.Errorf("built-in Admin role must retain the * (superadmin) permission")
		}
	}

	permsJSON, _ := json.Marshal(permissions)
	if err := s.roleRepo.UpdateRole(ctx, db.Role{
		ID:          roleID,
		Name:        name,
		Description: description,
		Permissions: permsJSON,
	}); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, nil, "role_updated", map[string]string{
		"org_id": orgID, "role_id": roleID, "role_name": name,
	})
	return nil
}

// DeleteRole deletes a custom role.
func (s *Service) DeleteRole(ctx context.Context, adminUserID, orgID, roleID string) error {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return ErrNotAdmin
		}
		return err
	}
	if s.roleRepo == nil {
		return fmt.Errorf("roles not supported")
	}

	if err := s.roleRepo.DeleteRole(ctx, roleID); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, nil, "role_deleted", map[string]string{
		"org_id": orgID, "role_id": roleID,
	})
	return nil
}

// SetMemberRole assigns a role to a member.
func (s *Service) SetMemberRole(ctx context.Context, adminUserID, orgID, targetUserID, roleID string) error {
	if err := s.verifyAdmin(ctx, orgID, adminUserID); err != nil {
		return err
	}
	if s.roleRepo == nil {
		return fmt.Errorf("roles not supported")
	}

	if err := s.roleRepo.SetMemberRole(ctx, orgID, targetUserID, roleID); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, &targetUserID, "member_role_changed", map[string]string{
		"org_id": orgID, "role_id": roleID,
	})
	return nil
}

// --- Group management ---

// ListGroups returns all groups for an organization.
func (s *Service) ListGroups(ctx context.Context, adminUserID, orgID string) ([]db.Group, error) {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return nil, ErrNotAdmin
		}
		return nil, err
	}
	if s.groupRepo == nil {
		return nil, fmt.Errorf("groups not supported")
	}
	return s.groupRepo.ListGroups(ctx, orgID)
}

// CreateGroup creates a new group.
func (s *Service) CreateGroup(ctx context.Context, adminUserID, orgID, name string) (db.Group, error) {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return db.Group{}, ErrNotAdmin
		}
		return db.Group{}, err
	}
	if s.groupRepo == nil {
		return db.Group{}, fmt.Errorf("groups not supported")
	}

	group, err := s.groupRepo.CreateGroup(ctx, db.Group{
		OrgID: orgID,
		Name:  name,
	})
	if err != nil {
		return db.Group{}, err
	}

	s.audit(ctx, &adminUserID, nil, "group_created", map[string]string{
		"org_id": orgID, "group_name": name,
	})
	return group, nil
}

// UpdateGroup updates a group's name.
func (s *Service) UpdateGroup(ctx context.Context, adminUserID, orgID, groupID, name string) error {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return ErrNotAdmin
		}
		return err
	}
	if s.groupRepo == nil {
		return fmt.Errorf("groups not supported")
	}

	if err := s.groupRepo.UpdateGroup(ctx, db.Group{ID: groupID, Name: name}); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, nil, "group_updated", map[string]string{
		"org_id": orgID, "group_id": groupID, "group_name": name,
	})
	return nil
}

// DeleteGroup deletes a group.
func (s *Service) DeleteGroup(ctx context.Context, adminUserID, orgID, groupID string) error {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return ErrNotAdmin
		}
		return err
	}
	if s.groupRepo == nil {
		return fmt.Errorf("groups not supported")
	}

	if err := s.groupRepo.DeleteGroup(ctx, groupID); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, nil, "group_deleted", map[string]string{
		"org_id": orgID, "group_id": groupID,
	})
	return nil
}

// AddGroupMember adds a user to a group.
func (s *Service) AddGroupMember(ctx context.Context, adminUserID, orgID, groupID, userID string) error {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return ErrNotAdmin
		}
		return err
	}
	if s.groupRepo == nil {
		return fmt.Errorf("groups not supported")
	}

	if err := s.groupRepo.AddGroupMember(ctx, groupID, userID); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, &userID, "group_member_added", map[string]string{
		"org_id": orgID, "group_id": groupID,
	})
	return nil
}

// RemoveGroupMember removes a user from a group.
func (s *Service) RemoveGroupMember(ctx context.Context, adminUserID, orgID, groupID, userID string) error {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return ErrNotAdmin
		}
		return err
	}
	if s.groupRepo == nil {
		return fmt.Errorf("groups not supported")
	}

	if err := s.groupRepo.RemoveGroupMember(ctx, groupID, userID); err != nil {
		return err
	}

	s.audit(ctx, &adminUserID, &userID, "group_member_removed", map[string]string{
		"org_id": orgID, "group_id": groupID,
	})
	return nil
}

// ListGroupMembers returns members of a group.
func (s *Service) ListGroupMembers(ctx context.Context, adminUserID, orgID, groupID string) ([]db.GroupMember, error) {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "org.policy"); err != nil {
		if err == ErrInsufficientPerms {
			return nil, ErrNotAdmin
		}
		return nil, err
	}
	if s.groupRepo == nil {
		return nil, fmt.Errorf("groups not supported")
	}
	return s.groupRepo.ListGroupMembers(ctx, groupID)
}

// ListCollectionGroups returns the groups assigned to a collection.
func (s *Service) ListCollectionGroups(ctx context.Context, adminUserID, orgID, collectionID string) ([]db.CollectionGroup, error) {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "collection.manage"); err != nil {
		if err == ErrInsufficientPerms {
			return nil, ErrNotAdmin
		}
		return nil, err
	}
	if s.groupRepo == nil {
		return nil, fmt.Errorf("groups not supported")
	}
	return s.groupRepo.ListCollectionGroups(ctx, collectionID)
}

// AddCollectionGroup assigns a group to a collection with a permission level.
func (s *Service) AddCollectionGroup(ctx context.Context, adminUserID, orgID string, cg db.CollectionGroup) error {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "collection.manage"); err != nil {
		if err == ErrInsufficientPerms {
			return ErrNotAdmin
		}
		return err
	}
	if s.groupRepo == nil {
		return fmt.Errorf("groups not supported")
	}
	if err := s.groupRepo.AddCollectionGroup(ctx, cg); err != nil {
		return err
	}
	s.audit(ctx, &adminUserID, nil, "collection_group_added", map[string]string{
		"org_id": orgID, "collection_id": cg.CollectionID, "group_id": cg.GroupID,
	})
	return nil
}

// RemoveCollectionGroup removes a group from a collection.
func (s *Service) RemoveCollectionGroup(ctx context.Context, adminUserID, orgID, collectionID, groupID string) error {
	if err := s.verifyPermission(ctx, orgID, adminUserID, "collection.manage"); err != nil {
		if err == ErrInsufficientPerms {
			return ErrNotAdmin
		}
		return err
	}
	if s.groupRepo == nil {
		return fmt.Errorf("groups not supported")
	}
	if err := s.groupRepo.RemoveCollectionGroup(ctx, collectionID, groupID); err != nil {
		return err
	}
	s.audit(ctx, &adminUserID, nil, "collection_group_removed", map[string]string{
		"org_id": orgID, "collection_id": collectionID, "group_id": groupID,
	})
	return nil
}
