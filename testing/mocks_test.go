package integration_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/password-manager/password-manager/internal/db"
)

// ---------------------------------------------------------------------------
// Mock Repositories for testing without a real database
// ---------------------------------------------------------------------------

// MockUserRepo implements db.UserRepository in memory.
type MockUserRepo struct {
	mu    sync.Mutex
	users map[string]db.User
	byEmail map[string]string // email -> id
	nextID int
}

func NewMockUserRepo() *MockUserRepo {
	return &MockUserRepo{
		users:  make(map[string]db.User),
		byEmail: make(map[string]string),
	}
}

func (m *MockUserRepo) CreateUser(ctx context.Context, email string, authHash, salt []byte, kdfParams json.RawMessage, publicKey, encryptedPrivateKey []byte) (db.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.byEmail[email]; exists {
		return db.User{}, fmt.Errorf("duplicate email: unique constraint violation")
	}

	m.nextID++
	id := fmt.Sprintf("user-%d", m.nextID)

	user := db.User{
		ID:                  id,
		Email:               email,
		AuthHash:            authHash,
		Salt:                salt,
		KDFParams:           kdfParams,
		PublicKey:            publicKey,
		EncryptedPrivateKey: encryptedPrivateKey,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	m.users[id] = user
	m.byEmail[email] = id
	return user, nil
}

func (m *MockUserRepo) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id, exists := m.byEmail[email]
	if !exists {
		return db.User{}, fmt.Errorf("user not found")
	}
	return m.users[id], nil
}

func (m *MockUserRepo) GetUserByID(ctx context.Context, id string) (db.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[id]
	if !exists {
		return db.User{}, fmt.Errorf("user not found")
	}
	return user, nil
}

func (m *MockUserRepo) UpdateUserKeys(ctx context.Context, id string, authHash, salt, publicKey, encryptedPrivateKey []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[id]
	if !exists {
		return fmt.Errorf("user not found")
	}

	user.AuthHash = authHash
	user.Salt = salt
	user.PublicKey = publicKey
	user.EncryptedPrivateKey = encryptedPrivateKey
	user.UpdatedAt = time.Now()
	m.users[id] = user
	return nil
}

func (m *MockUserRepo) RevokeUserTokens(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}
	user.UpdatedAt = time.Now()
	m.users[userID] = user
	return nil
}

func (m *MockUserRepo) SetRequireHWKey(ctx context.Context, userID string, require bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[userID]; !exists {
		return fmt.Errorf("user not found")
	}
	return nil
}

// SetHas2FA helper for testing — sets the Has2FA flag on a user.
func (m *MockUserRepo) SetHas2FA(id string, has2fa bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if user, exists := m.users[id]; exists {
		user.Has2FA = has2fa
		m.users[id] = user
	}
}

func (m *MockUserRepo) GetUserBySSOExternalID(ctx context.Context, externalID string) (db.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, u := range m.users {
		if u.SSOExternalID != nil && *u.SSOExternalID == externalID {
			return u, nil
		}
	}
	return db.User{}, fmt.Errorf("user not found")
}

func (m *MockUserRepo) SetSSOExternalID(ctx context.Context, userID, externalID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}
	user.SSOExternalID = &externalID
	m.users[userID] = user
	return nil
}

// MockVaultRepo implements db.VaultRepository in memory.
type MockVaultRepo struct {
	mu      sync.Mutex
	entries map[string]db.VaultEntry
	folders map[string]db.Folder
	nextID  int
}

func NewMockVaultRepo() *MockVaultRepo {
	return &MockVaultRepo{
		entries: make(map[string]db.VaultEntry),
		folders: make(map[string]db.Folder),
	}
}

func (m *MockVaultRepo) CreateEntry(ctx context.Context, entry db.VaultEntry) (db.VaultEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	entry.ID = fmt.Sprintf("entry-%d", m.nextID)
	entry.Version = 1
	entry.CreatedAt = time.Now()
	entry.UpdatedAt = time.Now()
	m.entries[entry.ID] = entry
	return entry, nil
}

func (m *MockVaultRepo) GetEntry(ctx context.Context, entryID, userID string) (db.VaultEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[entryID]
	if !exists || entry.UserID != userID {
		return db.VaultEntry{}, fmt.Errorf("entry not found")
	}
	return entry, nil
}

func (m *MockVaultRepo) ListEntries(ctx context.Context, userID string, filters db.VaultFilters) ([]db.VaultEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.VaultEntry
	for _, e := range m.entries {
		if e.UserID != userID || e.IsDeleted {
			continue
		}
		if filters.EntryType != "" && e.EntryType != filters.EntryType {
			continue
		}
		if filters.FolderID != "" && (e.FolderID == nil || *e.FolderID != filters.FolderID) {
			continue
		}
		if filters.UpdatedSince != nil && e.UpdatedAt.Before(*filters.UpdatedSince) {
			continue
		}
		result = append(result, e)
	}
	return result, nil
}

func (m *MockVaultRepo) UpdateEntry(ctx context.Context, entry db.VaultEntry) (db.VaultEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.entries[entry.ID]
	if !exists || existing.UserID != entry.UserID {
		return db.VaultEntry{}, fmt.Errorf("entry not found")
	}

	entry.Version = existing.Version + 1
	entry.CreatedAt = existing.CreatedAt
	entry.UpdatedAt = time.Now()
	m.entries[entry.ID] = entry
	return entry, nil
}

func (m *MockVaultRepo) UpdateEntryVersioned(ctx context.Context, entry db.VaultEntry, expectedVersion int) (db.VaultEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.entries[entry.ID]
	if !exists || existing.UserID != entry.UserID {
		return db.VaultEntry{}, fmt.Errorf("entry not found")
	}

	if existing.Version != expectedVersion {
		return db.VaultEntry{}, fmt.Errorf("version conflict: expected %d, got %d", expectedVersion, existing.Version)
	}

	entry.Version = existing.Version + 1
	entry.CreatedAt = existing.CreatedAt
	entry.UpdatedAt = time.Now()
	m.entries[entry.ID] = entry
	return entry, nil
}

func (m *MockVaultRepo) DeleteEntry(ctx context.Context, entryID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[entryID]
	if !exists || entry.UserID != userID {
		return fmt.Errorf("entry not found")
	}
	delete(m.entries, entryID)
	return nil
}

func (m *MockVaultRepo) ListEntriesForSync(ctx context.Context, userID string, since time.Time) ([]db.VaultEntry, error) {
	return m.ListEntries(ctx, userID, db.VaultFilters{UpdatedSince: &since})
}

func (m *MockVaultRepo) GetEntryByID(ctx context.Context, entryID string) (db.VaultEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[entryID]
	if !exists {
		return db.VaultEntry{}, fmt.Errorf("entry not found")
	}
	return entry, nil
}

func (m *MockVaultRepo) PermanentDeleteEntry(ctx context.Context, entryID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[entryID]
	if !exists || entry.UserID != userID {
		return fmt.Errorf("entry not found")
	}
	delete(m.entries, entryID)
	return nil
}

func (m *MockVaultRepo) SetFavorite(ctx context.Context, entryID, userID string, favorite bool) error {
	return nil
}

func (m *MockVaultRepo) SetArchived(ctx context.Context, entryID, userID string, archived bool) error {
	return nil
}

func (m *MockVaultRepo) RestoreEntry(ctx context.Context, entryID, userID string) error {
	return nil
}

func (m *MockVaultRepo) PurgeExpiredTrash(ctx context.Context, userID string, olderThan time.Time) (int, error) {
	return 0, nil
}

func (m *MockVaultRepo) CreateFolder(ctx context.Context, folder db.Folder) (db.Folder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	folder.ID = fmt.Sprintf("folder-%d", m.nextID)
	m.folders[folder.ID] = folder
	return folder, nil
}

func (m *MockVaultRepo) ListFolders(ctx context.Context, userID string) ([]db.Folder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.Folder
	for _, f := range m.folders {
		if f.UserID == userID {
			result = append(result, f)
		}
	}
	return result, nil
}

func (m *MockVaultRepo) DeleteFolder(ctx context.Context, folderID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	folder, exists := m.folders[folderID]
	if !exists || folder.UserID != userID {
		return fmt.Errorf("folder not found")
	}
	delete(m.folders, folderID)
	return nil
}

// ---------------------------------------------------------------------------
// Mock Org Repository
// ---------------------------------------------------------------------------

type MockOrgRepo struct {
	mu          sync.Mutex
	orgs        map[string]db.Organization
	members     map[string]map[string]db.OrgMember // orgID -> userID -> member
	invitations map[string]db.Invitation
	nextID      int
}

func NewMockOrgRepo() *MockOrgRepo {
	return &MockOrgRepo{
		orgs:        make(map[string]db.Organization),
		members:     make(map[string]map[string]db.OrgMember),
		invitations: make(map[string]db.Invitation),
	}
}

func (m *MockOrgRepo) CreateOrg(ctx context.Context, name string, orgPubKey, encOrgPrivKey []byte) (db.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	org := db.Organization{
		ID:                     fmt.Sprintf("org-%d", m.nextID),
		Name:                   name,
		OrgPublicKey:           orgPubKey,
		EncryptedOrgPrivateKey: encOrgPrivKey,
		CreatedAt:              time.Now(),
	}
	m.orgs[org.ID] = org
	m.members[org.ID] = make(map[string]db.OrgMember)
	return org, nil
}

func (m *MockOrgRepo) GetOrg(ctx context.Context, orgID string) (db.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	org, exists := m.orgs[orgID]
	if !exists {
		return db.Organization{}, fmt.Errorf("org not found")
	}
	return org, nil
}

func (m *MockOrgRepo) AddMember(ctx context.Context, orgID, userID, role string, escrowBlob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.members[orgID]; !exists {
		m.members[orgID] = make(map[string]db.OrgMember)
	}
	m.members[orgID][userID] = db.OrgMember{
		OrgID:    orgID,
		UserID:   userID,
		Role:     role,
		JoinedAt: time.Now(),
	}
	return nil
}

func (m *MockOrgRepo) GetMember(ctx context.Context, orgID, userID string) (db.OrgMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	members, exists := m.members[orgID]
	if !exists {
		return db.OrgMember{}, fmt.Errorf("not a member")
	}
	member, exists := members[userID]
	if !exists {
		return db.OrgMember{}, fmt.Errorf("not a member")
	}
	return member, nil
}

func (m *MockOrgRepo) GetMemberEscrow(ctx context.Context, orgID, userID string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockOrgRepo) GetMemberOrgKey(ctx context.Context, orgID, userID string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockOrgRepo) SetMemberOrgKey(ctx context.Context, orgID, userID string, encOrgKey []byte) error {
	return nil
}

func (m *MockOrgRepo) ListMembers(ctx context.Context, orgID string) ([]db.OrgMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	members, exists := m.members[orgID]
	if !exists {
		return nil, nil
	}
	var result []db.OrgMember
	for _, member := range members {
		result = append(result, member)
	}
	return result, nil
}

func (m *MockOrgRepo) RemoveMember(ctx context.Context, orgID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if members, exists := m.members[orgID]; exists {
		delete(members, userID)
	}
	return nil
}

func (m *MockOrgRepo) UpdateEscrowBlob(ctx context.Context, orgID, userID string, escrowBlob []byte) error {
	return nil
}

func (m *MockOrgRepo) CreateInvitation(ctx context.Context, orgID, email, role, invitedBy string) (db.Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	inv := db.Invitation{
		ID:        fmt.Sprintf("inv-%d", m.nextID),
		OrgID:     orgID,
		Email:     email,
		Role:      role,
		InvitedBy: invitedBy,
		CreatedAt: time.Now(),
	}
	m.invitations[inv.ID] = inv
	return inv, nil
}

func (m *MockOrgRepo) GetPendingInvitation(ctx context.Context, orgID, email string) (db.Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, inv := range m.invitations {
		if inv.OrgID == orgID && inv.Email == email && !inv.Accepted {
			return inv, nil
		}
	}
	return db.Invitation{}, fmt.Errorf("no pending invitation")
}

func (m *MockOrgRepo) MarkInvitationAccepted(ctx context.Context, invID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	inv, exists := m.invitations[invID]
	if !exists {
		return fmt.Errorf("invitation not found")
	}
	inv.Accepted = true
	m.invitations[invID] = inv
	return nil
}

func (m *MockOrgRepo) ListInvitations(ctx context.Context, orgID string) ([]db.Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.Invitation
	for _, inv := range m.invitations {
		if inv.OrgID == orgID {
			result = append(result, inv)
		}
	}
	return result, nil
}

func (m *MockOrgRepo) SetOrgPolicy(ctx context.Context, orgID string, policy json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	org, exists := m.orgs[orgID]
	if !exists {
		return fmt.Errorf("org not found")
	}
	org.Policy = policy
	m.orgs[orgID] = org
	return nil
}

func (m *MockOrgRepo) GetUserOrg(ctx context.Context, userID string) (db.OrgMember, db.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for orgID, members := range m.members {
		if member, exists := members[userID]; exists {
			return member, m.orgs[orgID], nil
		}
	}
	return db.OrgMember{}, db.Organization{}, fmt.Errorf("user not in any org")
}

func (m *MockOrgRepo) GetInvitationsByEmail(ctx context.Context, email string) ([]db.Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.Invitation
	for _, inv := range m.invitations {
		if inv.Email == email && !inv.Accepted {
			result = append(result, inv)
		}
	}
	return result, nil
}

func (m *MockOrgRepo) SetSSOConfig(ctx context.Context, orgID string, ssoEnabled bool, ssoConfig json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	org, exists := m.orgs[orgID]
	if !exists {
		return fmt.Errorf("org not found")
	}
	org.SSOEnabled = ssoEnabled
	org.SSOConfig = ssoConfig
	m.orgs[orgID] = org
	return nil
}

func (m *MockOrgRepo) SetSCIMConfig(ctx context.Context, orgID string, scimEnabled bool, scimTokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	org, exists := m.orgs[orgID]
	if !exists {
		return fmt.Errorf("org not found")
	}
	org.SCIMEnabled = scimEnabled
	org.SCIMTokenHash = scimTokenHash
	m.orgs[orgID] = org
	return nil
}

// ---------------------------------------------------------------------------
// Mock Audit Repository
// ---------------------------------------------------------------------------

type MockAuditRepo struct {
	mu      sync.Mutex
	entries []db.AuditEntry
}

func NewMockAuditRepo() *MockAuditRepo {
	return &MockAuditRepo{}
}

func (m *MockAuditRepo) LogAction(ctx context.Context, actorID, targetID *string, action string, details json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries = append(m.entries, db.AuditEntry{
		Action:  action,
		Details: details,
	})
	return nil
}

func (m *MockAuditRepo) GetAuditLog(ctx context.Context, filters db.AuditFilters) ([]db.AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.entries, nil
}

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

// registerTestUser is a helper that creates a user in the mock repo with
// a pre-hashed auth hash (bcrypt of a known value) for login testing.
func registerTestUser(repo *MockUserRepo, email, authHashHex string) (db.User, error) {
	authHashBytes, _ := hex.DecodeString(authHashHex)
	bcryptHash, err := bcrypt.GenerateFromPassword(authHashBytes, bcrypt.MinCost) // MinCost for speed in tests
	if err != nil {
		return db.User{}, err
	}

	return repo.CreateUser(
		context.Background(),
		email,
		bcryptHash,
		[]byte("0123456789abcdef"),
		json.RawMessage(`{"memory":65536,"iterations":3,"parallelism":4}`),
		[]byte("pubkey"),
		[]byte("encprivkey"),
	)
}
