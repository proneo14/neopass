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
	if !exists || entry.UserID != userID || entry.IsDeleted {
		return db.VaultEntry{}, fmt.Errorf("entry not found")
	}
	return entry, nil
}

func (m *MockVaultRepo) ListEntries(ctx context.Context, userID string, filters db.VaultFilters) ([]db.VaultEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.VaultEntry
	for _, e := range m.entries {
		if e.UserID != userID {
			continue
		}
		// Default: exclude deleted unless InTrash is set
		if filters.InTrash {
			if !e.IsDeleted {
				continue
			}
		} else if e.IsDeleted {
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
		if filters.IsFavorite != nil && e.IsFavorite != *filters.IsFavorite {
			continue
		}
		if filters.IsArchived != nil && e.IsArchived != *filters.IsArchived {
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
	now := time.Now()
	entry.IsDeleted = true
	entry.DeletedAt = &now
	entry.UpdatedAt = now
	m.entries[entryID] = entry
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
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[entryID]
	if !exists || entry.UserID != userID {
		return fmt.Errorf("entry not found")
	}
	entry.IsFavorite = favorite
	entry.UpdatedAt = time.Now()
	m.entries[entryID] = entry
	return nil
}

func (m *MockVaultRepo) SetArchived(ctx context.Context, entryID, userID string, archived bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[entryID]
	if !exists || entry.UserID != userID {
		return fmt.Errorf("entry not found")
	}
	entry.IsArchived = archived
	entry.UpdatedAt = time.Now()
	m.entries[entryID] = entry
	return nil
}

func (m *MockVaultRepo) RestoreEntry(ctx context.Context, entryID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[entryID]
	if !exists || entry.UserID != userID {
		return fmt.Errorf("entry not found")
	}
	if !entry.IsDeleted {
		return fmt.Errorf("entry is not in trash")
	}
	entry.IsDeleted = false
	entry.DeletedAt = nil
	entry.UpdatedAt = time.Now()
	m.entries[entryID] = entry
	return nil
}

func (m *MockVaultRepo) PurgeExpiredTrash(ctx context.Context, userID string, olderThan time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	purged := 0
	for id, entry := range m.entries {
		if entry.UserID == userID && entry.IsDeleted && entry.DeletedAt != nil && entry.DeletedAt.Before(olderThan) {
			delete(m.entries, id)
			purged++
		}
	}
	return purged, nil
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
// Mock Send Repository
// ---------------------------------------------------------------------------

type MockSendRepo struct {
	mu    sync.Mutex
	sends map[string]db.Send
	bySlug map[string]string // slug -> id
	nextID int
}

func NewMockSendRepo() *MockSendRepo {
	return &MockSendRepo{
		sends:  make(map[string]db.Send),
		bySlug: make(map[string]string),
	}
}

func (m *MockSendRepo) CreateSend(ctx context.Context, send db.Send) (db.Send, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	send.ID = fmt.Sprintf("send-%d", m.nextID)
	send.HasPassword = len(send.PasswordHash) > 0
	send.AccessCount = 0
	send.CreatedAt = time.Now().UTC()
	m.sends[send.ID] = send
	m.bySlug[send.Slug] = send.ID
	return send, nil
}

func (m *MockSendRepo) GetSendBySlug(ctx context.Context, slug string) (db.Send, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id, exists := m.bySlug[slug]
	if !exists {
		return db.Send{}, fmt.Errorf("send not found")
	}
	return m.sends[id], nil
}

func (m *MockSendRepo) ListSends(ctx context.Context, userID string) ([]db.Send, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.Send
	for _, s := range m.sends {
		if s.UserID == userID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *MockSendRepo) IncrementAccessCount(ctx context.Context, sendID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	send, exists := m.sends[sendID]
	if !exists {
		return fmt.Errorf("send not found")
	}
	send.AccessCount++
	m.sends[sendID] = send
	return nil
}

func (m *MockSendRepo) DeleteSend(ctx context.Context, sendID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	send, exists := m.sends[sendID]
	if !exists || send.UserID != userID {
		return fmt.Errorf("send not found")
	}
	delete(m.bySlug, send.Slug)
	delete(m.sends, sendID)
	return nil
}

func (m *MockSendRepo) DisableSend(ctx context.Context, sendID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	send, exists := m.sends[sendID]
	if !exists || send.UserID != userID {
		return fmt.Errorf("send not found")
	}
	send.Disabled = true
	m.sends[sendID] = send
	return nil
}

func (m *MockSendRepo) PurgeExpiredSends(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	purged := 0
	for id, s := range m.sends {
		if time.Now().UTC().After(s.ExpiresAt) {
			delete(m.bySlug, s.Slug)
			delete(m.sends, id)
			purged++
		}
	}
	return purged, nil
}

// ---------------------------------------------------------------------------
// Mock Collection Repository
// ---------------------------------------------------------------------------

type MockCollectionRepo struct {
	mu          sync.Mutex
	collections map[string]db.Collection
	members     map[string][]db.CollectionMember // collectionID -> members
	entries     map[string][]db.CollectionEntryData // collectionID -> entries
	nextID      int
}

func NewMockCollectionRepo() *MockCollectionRepo {
	return &MockCollectionRepo{
		collections: make(map[string]db.Collection),
		members:     make(map[string][]db.CollectionMember),
		entries:     make(map[string][]db.CollectionEntryData),
	}
}

func (m *MockCollectionRepo) CreateCollection(ctx context.Context, collection db.Collection) (db.Collection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	collection.ID = fmt.Sprintf("coll-%d", m.nextID)
	collection.CreatedAt = time.Now()
	collection.UpdatedAt = time.Now()
	m.collections[collection.ID] = collection
	return collection, nil
}

func (m *MockCollectionRepo) GetCollection(ctx context.Context, collectionID string) (db.Collection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	coll, exists := m.collections[collectionID]
	if !exists {
		return db.Collection{}, fmt.Errorf("collection not found")
	}
	return coll, nil
}

func (m *MockCollectionRepo) ListCollections(ctx context.Context, orgID string, requestingUserID string) ([]db.CollectionWithPermission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.CollectionWithPermission
	for _, c := range m.collections {
		if c.OrgID == orgID {
			perm := ""
			for _, mem := range m.members[c.ID] {
				if mem.UserID == requestingUserID {
					perm = mem.Permission
					break
				}
			}
			result = append(result, db.CollectionWithPermission{
				Collection:  c,
				Permission:  perm,
				MemberCount: len(m.members[c.ID]),
				EntryCount:  len(m.entries[c.ID]),
			})
		}
	}
	return result, nil
}

func (m *MockCollectionRepo) ListUserCollections(ctx context.Context, userID string) ([]db.CollectionWithPermission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.CollectionWithPermission
	for collID, members := range m.members {
		for _, mem := range members {
			if mem.UserID == userID {
				if coll, exists := m.collections[collID]; exists {
					result = append(result, db.CollectionWithPermission{
						Collection:   coll,
						Permission:   mem.Permission,
						EncryptedKey: mem.EncryptedKey,
						MemberCount:  len(m.members[collID]),
						EntryCount:   len(m.entries[collID]),
					})
				}
				break
			}
		}
	}
	return result, nil
}

func (m *MockCollectionRepo) UpdateCollection(ctx context.Context, collection db.Collection) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.collections[collection.ID]; !exists {
		return fmt.Errorf("collection not found")
	}
	collection.UpdatedAt = time.Now()
	m.collections[collection.ID] = collection
	return nil
}

func (m *MockCollectionRepo) DeleteCollection(ctx context.Context, collectionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.collections[collectionID]; !exists {
		return fmt.Errorf("collection not found")
	}
	delete(m.collections, collectionID)
	delete(m.members, collectionID)
	delete(m.entries, collectionID)
	return nil
}

func (m *MockCollectionRepo) AddCollectionMember(ctx context.Context, collectionID, userID string, encryptedKey []byte, permission string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.collections[collectionID]; !exists {
		return fmt.Errorf("collection not found")
	}
	m.members[collectionID] = append(m.members[collectionID], db.CollectionMember{
		CollectionID: collectionID,
		UserID:       userID,
		EncryptedKey: encryptedKey,
		Permission:   permission,
	})
	return nil
}

func (m *MockCollectionRepo) RemoveCollectionMember(ctx context.Context, collectionID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	members := m.members[collectionID]
	for i, mem := range members {
		if mem.UserID == userID {
			m.members[collectionID] = append(members[:i], members[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("member not found")
}

func (m *MockCollectionRepo) UpdateCollectionMemberPermission(ctx context.Context, collectionID, userID, permission string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	members := m.members[collectionID]
	for i, mem := range members {
		if mem.UserID == userID {
			members[i].Permission = permission
			m.members[collectionID] = members
			return nil
		}
	}
	return fmt.Errorf("member not found")
}

func (m *MockCollectionRepo) GetCollectionMembers(ctx context.Context, collectionID string) ([]db.CollectionMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.members[collectionID], nil
}

func (m *MockCollectionRepo) GetCollectionKey(ctx context.Context, collectionID, userID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, mem := range m.members[collectionID] {
		if mem.UserID == userID {
			return mem.EncryptedKey, nil
		}
	}
	return nil, fmt.Errorf("not a member")
}

func (m *MockCollectionRepo) AddEntryToCollection(ctx context.Context, collectionID, entryID, entryType string, encryptedData, nonce []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.collections[collectionID]; !exists {
		return fmt.Errorf("collection not found")
	}
	m.entries[collectionID] = append(m.entries[collectionID], db.CollectionEntryData{
		CollectionID:  collectionID,
		EntryID:       entryID,
		EntryType:     entryType,
		EncryptedData: encryptedData,
		Nonce:         nonce,
	})
	return nil
}

func (m *MockCollectionRepo) RemoveEntryFromCollection(ctx context.Context, collectionID, entryID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries := m.entries[collectionID]
	for i, e := range entries {
		if e.EntryID == entryID {
			m.entries[collectionID] = append(entries[:i], entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("entry not found in collection")
}

func (m *MockCollectionRepo) GetCollectionEntries(ctx context.Context, collectionID string) ([]db.CollectionEntryData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.entries[collectionID], nil
}

func (m *MockCollectionRepo) GetEntryCollections(ctx context.Context, entryID string, userID string) ([]db.CollectionWithPermission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.CollectionWithPermission
	for collID, entries := range m.entries {
		for _, e := range entries {
			if e.EntryID == entryID {
				if coll, exists := m.collections[collID]; exists {
					perm := ""
					for _, mem := range m.members[collID] {
						if mem.UserID == userID {
							perm = mem.Permission
							break
						}
					}
					result = append(result, db.CollectionWithPermission{
						Collection: coll,
						Permission: perm,
					})
				}
				break
			}
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Mock Emergency Access Repository
// ---------------------------------------------------------------------------

type MockEmergencyAccessRepo struct {
	mu      sync.Mutex
	records map[string]db.EmergencyAccess
	nextID  int
}

func NewMockEmergencyAccessRepo() *MockEmergencyAccessRepo {
	return &MockEmergencyAccessRepo{
		records: make(map[string]db.EmergencyAccess),
	}
}

func (m *MockEmergencyAccessRepo) CreateEmergencyAccess(ctx context.Context, ea db.EmergencyAccess) (db.EmergencyAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	ea.ID = fmt.Sprintf("ea-%d", m.nextID)
	ea.CreatedAt = time.Now()
	ea.UpdatedAt = time.Now()
	m.records[ea.ID] = ea
	return ea, nil
}

func (m *MockEmergencyAccessRepo) GetEmergencyAccess(ctx context.Context, id string) (db.EmergencyAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ea, exists := m.records[id]
	if !exists {
		return db.EmergencyAccess{}, fmt.Errorf("emergency access not found")
	}
	return ea, nil
}

func (m *MockEmergencyAccessRepo) ListGrantedAccess(ctx context.Context, grantorID string) ([]db.EmergencyAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.EmergencyAccess
	for _, ea := range m.records {
		if ea.GrantorID == grantorID {
			result = append(result, ea)
		}
	}
	return result, nil
}

func (m *MockEmergencyAccessRepo) ListTrustedBy(ctx context.Context, granteeID string) ([]db.EmergencyAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.EmergencyAccess
	for _, ea := range m.records {
		if ea.GranteeID != nil && *ea.GranteeID == granteeID {
			result = append(result, ea)
		}
	}
	return result, nil
}

func (m *MockEmergencyAccessRepo) UpdateStatus(ctx context.Context, id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ea, exists := m.records[id]
	if !exists {
		return fmt.Errorf("emergency access not found")
	}
	ea.Status = status
	ea.UpdatedAt = time.Now()
	m.records[id] = ea
	return nil
}

func (m *MockEmergencyAccessRepo) SetEncryptedKey(ctx context.Context, id string, encryptedKey, nonce []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ea, exists := m.records[id]
	if !exists {
		return fmt.Errorf("emergency access not found")
	}
	ea.EncryptedKey = encryptedKey
	ea.KeyNonce = nonce
	ea.UpdatedAt = time.Now()
	m.records[id] = ea
	return nil
}

func (m *MockEmergencyAccessRepo) InitiateRecovery(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ea, exists := m.records[id]
	if !exists {
		return fmt.Errorf("emergency access not found")
	}
	now := time.Now()
	ea.RecoveryInitiatedAt = &now
	ea.Status = "recovery_initiated"
	ea.UpdatedAt = now
	m.records[id] = ea
	return nil
}

func (m *MockEmergencyAccessRepo) DeleteEmergencyAccess(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.records[id]; !exists {
		return fmt.Errorf("emergency access not found")
	}
	delete(m.records, id)
	return nil
}

func (m *MockEmergencyAccessRepo) GetAutoApproveEligible(ctx context.Context) ([]db.EmergencyAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.EmergencyAccess
	now := time.Now()
	for _, ea := range m.records {
		if ea.Status == "recovery_initiated" && ea.RecoveryInitiatedAt != nil {
			waitDuration := time.Duration(ea.WaitTimeDays) * 24 * time.Hour
			if now.After(ea.RecoveryInitiatedAt.Add(waitDuration)) {
				result = append(result, ea)
			}
		}
	}
	return result, nil
}

func (m *MockEmergencyAccessRepo) SetGranteeID(ctx context.Context, id, granteeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ea, exists := m.records[id]
	if !exists {
		return fmt.Errorf("emergency access not found")
	}
	ea.GranteeID = &granteeID
	ea.UpdatedAt = time.Now()
	m.records[id] = ea
	return nil
}

func (m *MockEmergencyAccessRepo) ListByGranteeEmail(ctx context.Context, email string) ([]db.EmergencyAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []db.EmergencyAccess
	for _, ea := range m.records {
		if ea.GranteeEmail == email {
			result = append(result, ea)
		}
	}
	return result, nil
}

func (m *MockEmergencyAccessRepo) AutoApproveExpired(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	approved := 0
	now := time.Now()
	for id, ea := range m.records {
		if ea.Status == "recovery_initiated" && ea.RecoveryInitiatedAt != nil {
			waitDuration := time.Duration(ea.WaitTimeDays) * 24 * time.Hour
			if now.After(ea.RecoveryInitiatedAt.Add(waitDuration)) {
				ea.Status = "recovery_approved"
				ea.UpdatedAt = now
				m.records[id] = ea
				approved++
			}
		}
	}
	return approved, nil
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
