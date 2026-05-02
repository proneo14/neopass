package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

const timeFormat = "2006-01-02T15:04:05.000Z"

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func parseTime(s string) time.Time {
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339Nano, s)
	}
	return t
}

func nowUTC() string {
	return time.Now().UTC().Format(timeFormat)
}

// ── SQLite User Repo ─────────────────────────────────────────────────────────

// SQLiteUserRepo implements UserRepository for SQLite.
type SQLiteUserRepo struct {
	db *sql.DB
}

// NewSQLiteUserRepo creates a new SQLiteUserRepo.
func NewSQLiteUserRepo(db *sql.DB) *SQLiteUserRepo {
	return &SQLiteUserRepo{db: db}
}

func (r *SQLiteUserRepo) CreateUser(ctx context.Context, email string, authHash, salt []byte, kdfParams json.RawMessage, publicKey, encryptedPrivateKey []byte) (User, error) {
	id := newUUID()
	now := nowUTC()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, auth_hash, salt, kdf_params, public_key, encrypted_private_key, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, email, authHash, salt, string(kdfParams), publicKey, encryptedPrivateKey, now, now,
	)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return User{
		ID:        id,
		Email:     email,
		KDFParams: kdfParams,
		PublicKey: publicKey,
		CreatedAt: parseTime(now),
		UpdatedAt: parseTime(now),
	}, nil
}

func (r *SQLiteUserRepo) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	var kdfStr string
	var createdStr, updatedStr string
	var has2fa int
	err := r.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.auth_hash, u.salt, u.kdf_params,
		       u.public_key, u.encrypted_private_key, u.created_at, u.updated_at,
		       (SELECT COUNT(*) FROM totp_secrets t WHERE t.user_id = u.id AND t.verified = 1)
		FROM users u WHERE u.email = ?
	`, email).Scan(&u.ID, &u.Email, &u.AuthHash, &u.Salt, &kdfStr,
		&u.PublicKey, &u.EncryptedPrivateKey, &createdStr, &updatedStr, &has2fa)
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, fmt.Errorf("user not found")
		}
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	u.KDFParams = json.RawMessage(kdfStr)
	u.CreatedAt = parseTime(createdStr)
	u.UpdatedAt = parseTime(updatedStr)
	u.Has2FA = has2fa > 0
	return u, nil
}

func (r *SQLiteUserRepo) GetUserByID(ctx context.Context, id string) (User, error) {
	var u User
	var kdfStr string
	var createdStr, updatedStr string
	var has2fa int
	err := r.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.auth_hash, u.salt, u.kdf_params,
		       u.public_key, u.encrypted_private_key, u.created_at, u.updated_at,
		       (SELECT COUNT(*) FROM totp_secrets t WHERE t.user_id = u.id AND t.verified = 1)
		FROM users u WHERE u.id = ?
	`, id).Scan(&u.ID, &u.Email, &u.AuthHash, &u.Salt, &kdfStr,
		&u.PublicKey, &u.EncryptedPrivateKey, &createdStr, &updatedStr, &has2fa)
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, fmt.Errorf("user not found")
		}
		return User{}, fmt.Errorf("get user by id: %w", err)
	}
	u.KDFParams = json.RawMessage(kdfStr)
	u.CreatedAt = parseTime(createdStr)
	u.UpdatedAt = parseTime(updatedStr)
	u.Has2FA = has2fa > 0
	return u, nil
}

func (r *SQLiteUserRepo) UpdateUserKeys(ctx context.Context, id string, authHash, salt, publicKey, encryptedPrivateKey []byte) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE users SET auth_hash = ?, salt = ?, public_key = ?, encrypted_private_key = ?
		WHERE id = ?
	`, authHash, salt, publicKey, encryptedPrivateKey, id)
	if err != nil {
		return fmt.Errorf("update user keys: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// SetRequireHWKey updates a user's hardware key requirement.
func (r *SQLiteUserRepo) SetRequireHWKey(ctx context.Context, userID string, require bool) error {
	// SQLite doesn't have the column by default; add it if missing
	r.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN require_hw_key INTEGER NOT NULL DEFAULT 0`) //nolint:errcheck
	val := 0
	if require {
		val = 1
	}
	res, err := r.db.ExecContext(ctx, `UPDATE users SET require_hw_key = ? WHERE id = ?`, val, userID)
	if err != nil {
		return fmt.Errorf("set require_hw_key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// RevokeUserTokens sets tokens_revoked_at to now, invalidating all existing JWTs for this user.
func (r *SQLiteUserRepo) RevokeUserTokens(ctx context.Context, userID string) error {
	r.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN tokens_revoked_at TEXT`) //nolint:errcheck
	res, err := r.db.ExecContext(ctx, `UPDATE users SET tokens_revoked_at = datetime('now') WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("revoke user tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// ── SQLite Vault Repo ────────────────────────────────────────────────────────

const sqliteVaultColumns = `id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, is_favorite, is_archived, deleted_at, created_at, updated_at`

func scanSQLiteVaultEntry(row interface{ Scan(dest ...interface{}) error }) (VaultEntry, error) {
	var e VaultEntry
	var createdStr, updatedStr string
	var isDeleted, isFavorite, isArchived int
	var deletedAtStr sql.NullString
	err := row.Scan(&e.ID, &e.UserID, &e.OrgID, &e.EntryType, &e.EncryptedData, &e.Nonce,
		&e.Version, &e.FolderID, &isDeleted, &isFavorite, &isArchived, &deletedAtStr, &createdStr, &updatedStr)
	if err != nil {
		return VaultEntry{}, err
	}
	e.IsDeleted = isDeleted != 0
	e.IsFavorite = isFavorite != 0
	e.IsArchived = isArchived != 0
	if deletedAtStr.Valid {
		t := parseTime(deletedAtStr.String)
		e.DeletedAt = &t
	}
	e.CreatedAt = parseTime(createdStr)
	e.UpdatedAt = parseTime(updatedStr)
	return e, nil
}

// SQLiteVaultRepo implements VaultRepository for SQLite.
type SQLiteVaultRepo struct {
	db *sql.DB
}

// NewSQLiteVaultRepo creates a new SQLiteVaultRepo.
func NewSQLiteVaultRepo(db *sql.DB) *SQLiteVaultRepo {
	return &SQLiteVaultRepo{db: db}
}

func (r *SQLiteVaultRepo) CreateEntry(ctx context.Context, entry VaultEntry) (VaultEntry, error) {
	if entry.ID == "" {
		entry.ID = newUUID()
	}
	now := nowUTC()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO vault_entries (id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, is_favorite, is_archived, deleted_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 1, ?, 0, 0, 0, NULL, ?, ?)`,
		entry.ID, entry.UserID, entry.OrgID, entry.EntryType, entry.EncryptedData, entry.Nonce, entry.FolderID, now, now,
	)
	if err != nil {
		return VaultEntry{}, fmt.Errorf("insert vault entry: %w", err)
	}
	entry.Version = 1
	entry.CreatedAt = parseTime(now)
	entry.UpdatedAt = parseTime(now)
	return entry, nil
}

func (r *SQLiteVaultRepo) GetEntry(ctx context.Context, entryID, userID string) (VaultEntry, error) {
	e, err := scanSQLiteVaultEntry(r.db.QueryRowContext(ctx,
		`SELECT `+sqliteVaultColumns+`
		 FROM vault_entries WHERE id = ? AND user_id = ?`,
		entryID, userID,
	))
	if err != nil {
		if err == sql.ErrNoRows {
			return VaultEntry{}, fmt.Errorf("vault entry not found")
		}
		return VaultEntry{}, fmt.Errorf("get vault entry: %w", err)
	}
	return e, nil
}

func (r *SQLiteVaultRepo) ListEntries(ctx context.Context, userID string, filters VaultFilters) ([]VaultEntry, error) {
	var baseFilter string
	if filters.InTrash {
		baseFilter = " AND is_deleted = 1"
	} else {
		baseFilter = " AND is_deleted = 0"
	}
	query := `SELECT ` + sqliteVaultColumns + `
	          FROM vault_entries WHERE user_id = ?` + baseFilter // #nosec G202 -- baseFilter is a static string, not user input
	args := []interface{}{userID}

	if filters.EntryType != "" {
		query += " AND entry_type = ?"
		args = append(args, filters.EntryType)
	}
	if filters.FolderID != "" {
		query += " AND folder_id = ?"
		args = append(args, filters.FolderID)
	}
	if filters.UpdatedSince != nil {
		query += " AND updated_at > ?"
		args = append(args, filters.UpdatedSince.UTC().Format(timeFormat))
	}
	if filters.IsFavorite != nil && *filters.IsFavorite {
		query += " AND is_favorite = 1"
	}
	if filters.IsArchived != nil {
		if *filters.IsArchived {
			query += " AND is_archived = 1"
		} else {
			query += " AND is_archived = 0"
		}
	}
	query += " ORDER BY updated_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vault entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []VaultEntry
	for rows.Next() {
		e, err := scanSQLiteVaultEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("scan vault entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (r *SQLiteVaultRepo) UpdateEntry(ctx context.Context, entry VaultEntry) (VaultEntry, error) {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE vault_entries SET encrypted_data = ?, nonce = ?, entry_type = ?, folder_id = ?, version = version + 1, updated_at = ?
		 WHERE id = ? AND user_id = ?`,
		entry.EncryptedData, entry.Nonce, entry.EntryType, entry.FolderID, now, entry.ID, entry.UserID,
	)
	if err != nil {
		return VaultEntry{}, fmt.Errorf("update vault entry: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return VaultEntry{}, fmt.Errorf("vault entry not found")
	}
	// Read back
	return r.GetEntry(ctx, entry.ID, entry.UserID)
}

func (r *SQLiteVaultRepo) UpdateEntryVersioned(ctx context.Context, entry VaultEntry, expectedVersion int) (VaultEntry, error) {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE vault_entries SET encrypted_data = ?, nonce = ?, entry_type = ?, folder_id = ?,
		 is_deleted = ?, version = version + 1, updated_at = ?
		 WHERE id = ? AND user_id = ? AND version = ?`,
		entry.EncryptedData, entry.Nonce, entry.EntryType, entry.FolderID,
		boolToInt(entry.IsDeleted), now, entry.ID, entry.UserID, expectedVersion,
	)
	if err != nil {
		return VaultEntry{}, fmt.Errorf("update entry versioned: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return VaultEntry{}, fmt.Errorf("version conflict")
	}
	return r.GetEntry(ctx, entry.ID, entry.UserID)
}

func (r *SQLiteVaultRepo) DeleteEntry(ctx context.Context, entryID, userID string) error {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE vault_entries SET is_deleted = 1, deleted_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND user_id = ? AND is_deleted = 0`,
		now, now, entryID, userID,
	)
	if err != nil {
		return fmt.Errorf("delete vault entry: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("vault entry not found")
	}
	return nil
}

func (r *SQLiteVaultRepo) ListEntriesForSync(ctx context.Context, userID string, since time.Time) ([]VaultEntry, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+sqliteVaultColumns+`
		 FROM vault_entries WHERE user_id = ? AND updated_at > ? ORDER BY updated_at ASC`,
		userID, since.UTC().Format(timeFormat),
	)
	if err != nil {
		return nil, fmt.Errorf("list entries for sync: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []VaultEntry
	for rows.Next() {
		e, err := scanSQLiteVaultEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("scan sync entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (r *SQLiteVaultRepo) GetEntryByID(ctx context.Context, entryID string) (VaultEntry, error) {
	e, err := scanSQLiteVaultEntry(r.db.QueryRowContext(ctx,
		`SELECT `+sqliteVaultColumns+` FROM vault_entries WHERE id = ?`, entryID,
	))
	if err != nil {
		if err == sql.ErrNoRows {
			return VaultEntry{}, fmt.Errorf("vault entry not found")
		}
		return VaultEntry{}, fmt.Errorf("get entry by id: %w", err)
	}
	return e, nil
}

func (r *SQLiteVaultRepo) CreateFolder(ctx context.Context, folder Folder) (Folder, error) {
	id := newUUID()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO folders (id, user_id, name_encrypted, parent_id) VALUES (?, ?, ?, ?)`,
		id, folder.UserID, folder.NameEncrypted, folder.ParentID,
	)
	if err != nil {
		return Folder{}, fmt.Errorf("insert folder: %w", err)
	}
	folder.ID = id
	return folder, nil
}

func (r *SQLiteVaultRepo) ListFolders(ctx context.Context, userID string) ([]Folder, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, name_encrypted, parent_id FROM folders WHERE user_id = ? ORDER BY id`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var folders []Folder
	for rows.Next() {
		var f Folder
		if err := rows.Scan(&f.ID, &f.UserID, &f.NameEncrypted, &f.ParentID); err != nil {
			return nil, fmt.Errorf("scan folder: %w", err)
		}
		folders = append(folders, f)
	}
	return folders, rows.Err()
}

func (r *SQLiteVaultRepo) DeleteFolder(ctx context.Context, folderID, userID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM folders WHERE id = ? AND user_id = ?`, folderID, userID)
	if err != nil {
		return fmt.Errorf("delete folder: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("folder not found")
	}
	return nil
}

func (r *SQLiteVaultRepo) SetFavorite(ctx context.Context, entryID, userID string, favorite bool) error {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE vault_entries SET is_favorite = ?, updated_at = ? WHERE id = ? AND user_id = ? AND is_deleted = 0`,
		boolToInt(favorite), now, entryID, userID,
	)
	if err != nil {
		return fmt.Errorf("set favorite: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("vault entry not found")
	}
	return nil
}

func (r *SQLiteVaultRepo) SetArchived(ctx context.Context, entryID, userID string, archived bool) error {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE vault_entries SET is_archived = ?, updated_at = ? WHERE id = ? AND user_id = ? AND is_deleted = 0`,
		boolToInt(archived), now, entryID, userID,
	)
	if err != nil {
		return fmt.Errorf("set archived: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("vault entry not found")
	}
	return nil
}

func (r *SQLiteVaultRepo) RestoreEntry(ctx context.Context, entryID, userID string) error {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE vault_entries SET is_deleted = 0, deleted_at = NULL, version = version + 1, updated_at = ? WHERE id = ? AND user_id = ? AND is_deleted = 1`,
		now, entryID, userID,
	)
	if err != nil {
		return fmt.Errorf("restore entry: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("vault entry not found in trash")
	}
	return nil
}

func (r *SQLiteVaultRepo) PermanentDeleteEntry(ctx context.Context, entryID, userID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM vault_entries WHERE id = ? AND user_id = ? AND is_deleted = 1`,
		entryID, userID,
	)
	if err != nil {
		return fmt.Errorf("permanent delete entry: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("vault entry not found in trash")
	}
	return nil
}

func (r *SQLiteVaultRepo) PurgeExpiredTrash(ctx context.Context, userID string, olderThan time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM vault_entries WHERE user_id = ? AND is_deleted = 1 AND deleted_at < ?`,
		userID, olderThan.UTC().Format(timeFormat),
	)
	if err != nil {
		return 0, fmt.Errorf("purge expired trash: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ── SQLite Audit Repo ────────────────────────────────────────────────────────

// SQLiteAuditRepo implements AuditRepository for SQLite.
type SQLiteAuditRepo struct {
	db *sql.DB
}

// NewSQLiteAuditRepo creates a new SQLiteAuditRepo.
func NewSQLiteAuditRepo(db *sql.DB) *SQLiteAuditRepo {
	return &SQLiteAuditRepo{db: db}
}

func (r *SQLiteAuditRepo) LogAction(ctx context.Context, actorID, targetID *string, action string, details json.RawMessage) error {
	id := newUUID()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_log (id, actor_id, target_id, action, details) VALUES (?, ?, ?, ?, ?)`,
		id, actorID, targetID, action, nullableString(details),
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

func (r *SQLiteAuditRepo) GetAuditLog(ctx context.Context, filters AuditFilters) ([]AuditEntry, error) {
	query := `SELECT id, actor_id, target_id, action, details, created_at FROM audit_log WHERE 1=1`
	args := []interface{}{}

	if filters.ActorID != "" {
		query += " AND actor_id = ?"
		args = append(args, filters.ActorID)
	}
	if filters.TargetID != "" {
		query += " AND target_id = ?"
		args = append(args, filters.TargetID)
	}
	if filters.Action != "" {
		query += " AND action = ?"
		args = append(args, filters.Action)
	}
	if filters.From != nil {
		query += " AND created_at >= ?"
		args = append(args, filters.From.UTC().Format(timeFormat))
	}
	if filters.To != nil {
		query += " AND created_at <= ?"
		args = append(args, filters.To.UTC().Format(timeFormat))
	}

	query += " ORDER BY created_at DESC"

	limit := filters.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query += " LIMIT ?"
	args = append(args, limit)

	if filters.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filters.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var detailsStr *string
		var createdStr string
		if err := rows.Scan(&e.ID, &e.ActorID, &e.TargetID, &e.Action, &detailsStr, &createdStr); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		if detailsStr != nil {
			e.Details = json.RawMessage(*detailsStr)
		}
		e.CreatedAt = parseTime(createdStr)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ── SQLite Org Repo ──────────────────────────────────────────────────────────

// SQLiteOrgRepo implements OrgRepository for SQLite.
type SQLiteOrgRepo struct {
	db *sql.DB
}

// NewSQLiteOrgRepo creates a new SQLiteOrgRepo.
func NewSQLiteOrgRepo(db *sql.DB) *SQLiteOrgRepo {
	return &SQLiteOrgRepo{db: db}
}

func (r *SQLiteOrgRepo) CreateOrg(ctx context.Context, name string, orgPubKey, encOrgPrivKey []byte) (Organization, error) {
	id := newUUID()
	now := nowUTC()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO organizations (id, name, org_public_key, encrypted_org_private_key, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, name, orgPubKey, encOrgPrivKey, now,
	)
	if err != nil {
		return Organization{}, fmt.Errorf("insert org: %w", err)
	}
	return Organization{
		ID:                     id,
		Name:                   name,
		OrgPublicKey:           orgPubKey,
		EncryptedOrgPrivateKey: encOrgPrivKey,
		CreatedAt:              parseTime(now),
	}, nil
}

func (r *SQLiteOrgRepo) GetOrg(ctx context.Context, orgID string) (Organization, error) {
	var org Organization
	var policyStr *string
	var createdStr string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, org_public_key, encrypted_org_private_key, policy, created_at FROM organizations WHERE id = ?`, orgID,
	).Scan(&org.ID, &org.Name, &org.OrgPublicKey, &org.EncryptedOrgPrivateKey, &policyStr, &createdStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return Organization{}, fmt.Errorf("organization not found")
		}
		return Organization{}, fmt.Errorf("get org: %w", err)
	}
	if policyStr != nil {
		org.Policy = json.RawMessage(*policyStr)
	}
	org.CreatedAt = parseTime(createdStr)
	return org, nil
}

func (r *SQLiteOrgRepo) AddMember(ctx context.Context, orgID, userID, role string, escrowBlob []byte) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO org_members (org_id, user_id, role, escrow_blob) VALUES (?, ?, ?, ?)`,
		orgID, userID, role, escrowBlob,
	)
	if err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	return nil
}

func (r *SQLiteOrgRepo) GetMember(ctx context.Context, orgID, userID string) (OrgMember, error) {
	var m OrgMember
	var joinedStr string
	err := r.db.QueryRowContext(ctx,
		`SELECT org_id, user_id, role, joined_at FROM org_members WHERE org_id = ? AND user_id = ?`,
		orgID, userID,
	).Scan(&m.OrgID, &m.UserID, &m.Role, &joinedStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return OrgMember{}, fmt.Errorf("member not found")
		}
		return OrgMember{}, fmt.Errorf("get member: %w", err)
	}
	m.JoinedAt = parseTime(joinedStr)
	return m, nil
}

func (r *SQLiteOrgRepo) GetMemberEscrow(ctx context.Context, orgID, userID string) ([]byte, error) {
	var blob []byte
	err := r.db.QueryRowContext(ctx,
		`SELECT escrow_blob FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID,
	).Scan(&blob)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("member not found")
		}
		return nil, fmt.Errorf("get escrow: %w", err)
	}
	return blob, nil
}

func (r *SQLiteOrgRepo) GetMemberOrgKey(ctx context.Context, orgID, userID string) ([]byte, error) {
	var blob []byte
	err := r.db.QueryRowContext(ctx,
		`SELECT encrypted_org_key FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID,
	).Scan(&blob)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("member not found")
		}
		return nil, fmt.Errorf("get member org key: %w", err)
	}
	return blob, nil
}

func (r *SQLiteOrgRepo) SetMemberOrgKey(ctx context.Context, orgID, userID string, encOrgKey []byte) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE org_members SET encrypted_org_key = ? WHERE org_id = ? AND user_id = ?`, encOrgKey, orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("set member org key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}

func (r *SQLiteOrgRepo) ListMembers(ctx context.Context, orgID string) ([]OrgMember, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT om.org_id, om.user_id, u.email, om.role, om.joined_at
		 FROM org_members om JOIN users u ON u.id = om.user_id
		 WHERE om.org_id = ? ORDER BY om.joined_at`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var members []OrgMember
	for rows.Next() {
		var m OrgMember
		var joinedStr string
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Email, &m.Role, &joinedStr); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		m.JoinedAt = parseTime(joinedStr)
		members = append(members, m)
	}
	return members, rows.Err()
}

func (r *SQLiteOrgRepo) RemoveMember(ctx context.Context, orgID, userID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID)
	if err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}

func (r *SQLiteOrgRepo) UpdateEscrowBlob(ctx context.Context, orgID, userID string, escrowBlob []byte) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE org_members SET escrow_blob = ? WHERE org_id = ? AND user_id = ?`,
		escrowBlob, orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("update escrow: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}

func (r *SQLiteOrgRepo) CreateInvitation(ctx context.Context, orgID, email, role, invitedBy string) (Invitation, error) {
	// Delete existing pending
	_, _ = r.db.ExecContext(ctx, `DELETE FROM invitations WHERE org_id = ? AND email = ? AND accepted = 0`, orgID, email)

	id := newUUID()
	now := nowUTC()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO invitations (id, org_id, email, role, invited_by, accepted, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)`,
		id, orgID, email, role, invitedBy, now,
	)
	if err != nil {
		return Invitation{}, fmt.Errorf("create invitation: %w", err)
	}
	return Invitation{
		ID:        id,
		OrgID:     orgID,
		Email:     email,
		Role:      role,
		InvitedBy: invitedBy,
		Accepted:  false,
		CreatedAt: parseTime(now),
	}, nil
}

func (r *SQLiteOrgRepo) GetPendingInvitation(ctx context.Context, orgID, email string) (Invitation, error) {
	var inv Invitation
	var accepted int
	var createdStr string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, org_id, email, role, invited_by, accepted, created_at
		 FROM invitations WHERE org_id = ? AND email = ? AND accepted = 0
		 ORDER BY created_at DESC LIMIT 1`,
		orgID, email,
	).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.InvitedBy, &accepted, &createdStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return Invitation{}, fmt.Errorf("invitation not found")
		}
		return Invitation{}, fmt.Errorf("get invitation: %w", err)
	}
	inv.Accepted = accepted != 0
	inv.CreatedAt = parseTime(createdStr)
	return inv, nil
}

func (r *SQLiteOrgRepo) MarkInvitationAccepted(ctx context.Context, invID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE invitations SET accepted = 1 WHERE id = ?`, invID)
	return err
}

func (r *SQLiteOrgRepo) ListInvitations(ctx context.Context, orgID string) ([]Invitation, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, org_id, email, role, invited_by, accepted, created_at
		 FROM invitations WHERE org_id = ? ORDER BY created_at DESC`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var invs []Invitation
	for rows.Next() {
		var inv Invitation
		var accepted int
		var createdStr string
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.InvitedBy, &accepted, &createdStr); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		inv.Accepted = accepted != 0
		inv.CreatedAt = parseTime(createdStr)
		invs = append(invs, inv)
	}
	return invs, rows.Err()
}

func (r *SQLiteOrgRepo) SetOrgPolicy(ctx context.Context, orgID string, policy json.RawMessage) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET policy = ? WHERE id = ?`, string(policy), orgID,
	)
	if err != nil {
		return fmt.Errorf("set org policy: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("organization not found")
	}
	return nil
}

func (r *SQLiteOrgRepo) GetUserOrg(ctx context.Context, userID string) (OrgMember, Organization, error) {
	var m OrgMember
	var org Organization
	var joinedStr, orgCreatedStr string
	err := r.db.QueryRowContext(ctx,
		`SELECT om.org_id, om.user_id, u.email, om.role, om.joined_at,
		        o.id, o.name, o.org_public_key, o.created_at
		 FROM org_members om
		 JOIN users u ON u.id = om.user_id
		 JOIN organizations o ON o.id = om.org_id
		 WHERE om.user_id = ? LIMIT 1`, userID,
	).Scan(&m.OrgID, &m.UserID, &m.Email, &m.Role, &joinedStr,
		&org.ID, &org.Name, &org.OrgPublicKey, &orgCreatedStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return OrgMember{}, Organization{}, fmt.Errorf("no org membership")
		}
		return OrgMember{}, Organization{}, fmt.Errorf("get user org: %w", err)
	}
	m.JoinedAt = parseTime(joinedStr)
	org.CreatedAt = parseTime(orgCreatedStr)
	return m, org, nil
}

func (r *SQLiteOrgRepo) GetInvitationsByEmail(ctx context.Context, email string) ([]Invitation, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, org_id, email, role, invited_by, accepted, created_at
		 FROM invitations WHERE email = ? AND accepted = 0 ORDER BY created_at DESC`, email,
	)
	if err != nil {
		return nil, fmt.Errorf("get invitations by email: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var invs []Invitation
	for rows.Next() {
		var inv Invitation
		var accepted int
		var createdStr string
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.InvitedBy, &accepted, &createdStr); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		inv.Accepted = accepted != 0
		inv.CreatedAt = parseTime(createdStr)
		invs = append(invs, inv)
	}
	return invs, rows.Err()
}

// ── SQLite Sync Repo ─────────────────────────────────────────────────────────

// SQLiteSyncRepo implements SyncRepository for SQLite.
type SQLiteSyncRepo struct {
	db *sql.DB
}

// NewSQLiteSyncRepo creates a new SQLiteSyncRepo.
func NewSQLiteSyncRepo(db *sql.DB) *SQLiteSyncRepo {
	return &SQLiteSyncRepo{db: db}
}

func (r *SQLiteSyncRepo) GetSyncCursor(ctx context.Context, userID, deviceID string) (time.Time, error) {
	var lastSyncStr string
	err := r.db.QueryRowContext(ctx,
		`SELECT last_sync_at FROM sync_cursors WHERE user_id = ? AND device_id = ?`, userID, deviceID,
	).Scan(&lastSyncStr)
	if err != nil {
		return time.Time{}, nil
	}
	return parseTime(lastSyncStr), nil
}

func (r *SQLiteSyncRepo) UpsertSyncCursor(ctx context.Context, userID, deviceID string, syncAt time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sync_cursors (user_id, device_id, last_sync_at) VALUES (?, ?, ?)
		 ON CONFLICT (user_id, device_id) DO UPDATE SET last_sync_at = ?`,
		userID, deviceID, syncAt.UTC().Format(timeFormat), syncAt.UTC().Format(timeFormat),
	)
	if err != nil {
		return fmt.Errorf("upsert sync cursor: %w", err)
	}
	return nil
}

func (r *SQLiteSyncRepo) ListDevices(ctx context.Context, userID string) ([]SyncCursor, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT user_id, device_id, last_sync_at FROM sync_cursors WHERE user_id = ? ORDER BY last_sync_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
	var devices []SyncCursor
	for rows.Next() {
		var d SyncCursor
		var lastSyncStr string
		if err := rows.Scan(&d.UserID, &d.DeviceID, &lastSyncStr); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		d.LastSyncAt = parseTime(lastSyncStr)
		devices = append(devices, d)
	}
	return devices, nil
}

func (r *SQLiteSyncRepo) DeleteDevice(ctx context.Context, userID, deviceID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM sync_cursors WHERE user_id = ? AND device_id = ?`,
		userID, deviceID,
	)
	if err != nil {
		return fmt.Errorf("delete device: %w", err)
	}
	return nil
}

// ── SQLite TOTP Repo ─────────────────────────────────────────────────────────

// SQLiteTOTPRepo implements TOTPRepository for SQLite.
type SQLiteTOTPRepo struct {
	db *sql.DB
}

// NewSQLiteTOTPRepo creates a new SQLiteTOTPRepo.
func NewSQLiteTOTPRepo(db *sql.DB) *SQLiteTOTPRepo {
	return &SQLiteTOTPRepo{db: db}
}

func (r *SQLiteTOTPRepo) UpsertTOTPSecret(ctx context.Context, userID string, encryptedSecret []byte) (string, error) {
	id := newUUID()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO totp_secrets (id, user_id, encrypted_secret, verified)
		VALUES (?, ?, ?, 0)
		ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = ?, verified = 0
	`, id, userID, encryptedSecret, encryptedSecret)
	if err != nil {
		return "", fmt.Errorf("upsert totp secret: %w", err)
	}
	// Read back actual ID (may be existing row)
	var actualID string
	err = r.db.QueryRowContext(ctx, `SELECT id FROM totp_secrets WHERE user_id = ?`, userID).Scan(&actualID)
	if err != nil {
		return id, nil
	}
	return actualID, nil
}

func (r *SQLiteTOTPRepo) GetTOTPSecret(ctx context.Context, userID string) (TOTPSecret, error) {
	var s TOTPSecret
	var verified int
	var createdStr string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, encrypted_secret, verified, created_at FROM totp_secrets WHERE user_id = ?
	`, userID).Scan(&s.ID, &s.UserID, &s.EncryptedSecret, &verified, &createdStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return TOTPSecret{}, fmt.Errorf("totp not configured")
		}
		return TOTPSecret{}, fmt.Errorf("get totp secret: %w", err)
	}
	s.Verified = verified != 0
	s.CreatedAt = parseTime(createdStr)
	return s, nil
}

func (r *SQLiteTOTPRepo) MarkTOTPVerified(ctx context.Context, userID string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE totp_secrets SET verified = 1 WHERE user_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("mark totp verified: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("totp not found")
	}
	return nil
}

func (r *SQLiteTOTPRepo) DeleteTOTPSecret(ctx context.Context, userID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_secrets WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete totp secret: %w", err)
	}
	return tx.Commit()
}

func (r *SQLiteTOTPRepo) InsertRecoveryCodes(ctx context.Context, userID string, codeHashes [][]byte) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete old recovery codes: %w", err)
	}
	for _, hash := range codeHashes {
		id := newUUID()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO recovery_codes (id, user_id, code_hash, used) VALUES (?, ?, ?, 0)`,
			id, userID, hash,
		); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return tx.Commit()
}

func (r *SQLiteTOTPRepo) GetUnusedRecoveryCodes(ctx context.Context, userID string) ([]RecoveryCode, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, code_hash, used FROM recovery_codes WHERE user_id = ? AND used = 0
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("get recovery codes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var codes []RecoveryCode
	for rows.Next() {
		var c RecoveryCode
		var used int
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &used); err != nil {
			return nil, fmt.Errorf("scan recovery code: %w", err)
		}
		c.Used = used != 0
		codes = append(codes, c)
	}
	return codes, rows.Err()
}

func (r *SQLiteTOTPRepo) MarkRecoveryCodeUsed(ctx context.Context, codeID string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE recovery_codes SET used = 1 WHERE id = ? AND used = 0`, codeID)
	if err != nil {
		return fmt.Errorf("mark recovery code used: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("recovery code not found or already used")
	}
	return nil
}

func (r *SQLiteTOTPRepo) InsertSharedTOTP(ctx context.Context, fromUserID, toUserID string, encryptedSecret []byte, label string, expiresAt time.Time) (string, error) {
	id := newUUID()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO shared_2fa (id, from_user_id, to_user_id, encrypted_totp_secret, label, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, fromUserID, toUserID, encryptedSecret, label, expiresAt.UTC().Format(timeFormat))
	if err != nil {
		return "", fmt.Errorf("insert shared totp: %w", err)
	}
	return id, nil
}

func (r *SQLiteTOTPRepo) GetSharedTOTP(ctx context.Context, shareID, toUserID string) (SharedTOTP, error) {
	var s SharedTOTP
	var claimed int
	var expiresStr, createdStr string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, from_user_id, to_user_id, encrypted_totp_secret, label, expires_at, claimed, created_at
		FROM shared_2fa WHERE id = ? AND to_user_id = ?
	`, shareID, toUserID).Scan(&s.ID, &s.FromUserID, &s.ToUserID, &s.EncryptedTOTPSecret, &s.Label,
		&expiresStr, &claimed, &createdStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return SharedTOTP{}, fmt.Errorf("shared totp not found")
		}
		return SharedTOTP{}, fmt.Errorf("get shared totp: %w", err)
	}
	s.ExpiresAt = parseTime(expiresStr)
	s.Claimed = claimed != 0
	s.CreatedAt = parseTime(createdStr)
	return s, nil
}

func (r *SQLiteTOTPRepo) MarkSharedTOTPClaimed(ctx context.Context, shareID string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE shared_2fa SET claimed = 1 WHERE id = ?`, shareID)
	if err != nil {
		return fmt.Errorf("mark shared totp claimed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("shared totp not found")
	}
	return nil
}

func (r *SQLiteTOTPRepo) ListPendingSharedTOTP(ctx context.Context, toUserID string) ([]SharedTOTP, error) {
	now := nowUTC()
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, from_user_id, to_user_id, encrypted_totp_secret, label, expires_at, claimed, created_at
		FROM shared_2fa
		WHERE to_user_id = ? AND claimed = 0 AND expires_at > ?
		ORDER BY created_at DESC
	`, toUserID, now)
	if err != nil {
		return nil, fmt.Errorf("list shared totp: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var list []SharedTOTP
	for rows.Next() {
		var s SharedTOTP
		var claimed int
		var expiresStr, createdStr string
		if err := rows.Scan(&s.ID, &s.FromUserID, &s.ToUserID, &s.EncryptedTOTPSecret, &s.Label,
			&expiresStr, &claimed, &createdStr); err != nil {
			return nil, fmt.Errorf("scan shared totp: %w", err)
		}
		s.ExpiresAt = parseTime(expiresStr)
		s.Claimed = claimed != 0
		s.CreatedAt = parseTime(createdStr)
		list = append(list, s)
	}
	return list, rows.Err()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableString(data json.RawMessage) *string {
	if data == nil {
		return nil
	}
	s := string(data)
	return &s
}

// ── SQLite Send Repo ─────────────────────────────────────────────────────────

// SQLiteSendRepo implements SendRepository for SQLite.
type SQLiteSendRepo struct {
	db *sql.DB
}

// NewSQLiteSendRepo creates a new SQLiteSendRepo.
func NewSQLiteSendRepo(db *sql.DB) *SQLiteSendRepo {
	return &SQLiteSendRepo{db: db}
}

func (r *SQLiteSendRepo) CreateSend(ctx context.Context, send Send) (Send, error) {
	id := newUUID()
	now := nowUTC()
	expiresStr := send.ExpiresAt.UTC().Format(timeFormat)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sends (id, user_id, slug, send_type, encrypted_data, nonce, encrypted_name, name_nonce, password_hash, max_access_count, file_name, file_size, expires_at, disabled, hide_email, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		id, send.UserID, send.Slug, send.SendType, send.EncryptedData, send.Nonce,
		send.EncryptedName, send.NameNonce, send.PasswordHash, send.MaxAccessCount,
		send.FileName, send.FileSize, expiresStr, boolToInt(send.HideEmail), now,
	)
	if err != nil {
		return Send{}, fmt.Errorf("create send: %w", err)
	}
	send.ID = id
	send.AccessCount = 0
	send.Disabled = false
	send.CreatedAt = parseTime(now)
	send.HasPassword = len(send.PasswordHash) > 0
	return send, nil
}

func (r *SQLiteSendRepo) GetSendBySlug(ctx context.Context, slug string) (Send, error) {
	var s Send
	var expiresStr, createdStr string
	var disabled, hideEmail int
	err := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, slug, send_type, encrypted_data, nonce, encrypted_name, name_nonce, password_hash, max_access_count, access_count, file_name, file_size, expires_at, disabled, hide_email, created_at
		 FROM sends WHERE slug = ?`, slug,
	).Scan(&s.ID, &s.UserID, &s.Slug, &s.SendType, &s.EncryptedData, &s.Nonce,
		&s.EncryptedName, &s.NameNonce, &s.PasswordHash, &s.MaxAccessCount, &s.AccessCount,
		&s.FileName, &s.FileSize, &expiresStr, &disabled, &hideEmail, &createdStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return Send{}, fmt.Errorf("send not found")
		}
		return Send{}, fmt.Errorf("get send by slug: %w", err)
	}
	s.ExpiresAt = parseTime(expiresStr)
	s.Disabled = disabled != 0
	s.HideEmail = hideEmail != 0
	s.CreatedAt = parseTime(createdStr)
	s.HasPassword = len(s.PasswordHash) > 0
	return s, nil
}

func (r *SQLiteSendRepo) ListSends(ctx context.Context, userID string) ([]Send, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, slug, send_type, encrypted_data, nonce, encrypted_name, name_nonce, password_hash, max_access_count, access_count, file_name, file_size, expires_at, disabled, hide_email, created_at
		 FROM sends WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list sends: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sends []Send
	for rows.Next() {
		var s Send
		var expiresStr, createdStr string
		var disabled, hideEmail int
		if err := rows.Scan(&s.ID, &s.UserID, &s.Slug, &s.SendType, &s.EncryptedData, &s.Nonce,
			&s.EncryptedName, &s.NameNonce, &s.PasswordHash, &s.MaxAccessCount, &s.AccessCount,
			&s.FileName, &s.FileSize, &expiresStr, &disabled, &hideEmail, &createdStr); err != nil {
			return nil, fmt.Errorf("scan send: %w", err)
		}
		s.ExpiresAt = parseTime(expiresStr)
		s.Disabled = disabled != 0
		s.HideEmail = hideEmail != 0
		s.CreatedAt = parseTime(createdStr)
		s.HasPassword = len(s.PasswordHash) > 0
		sends = append(sends, s)
	}
	return sends, rows.Err()
}

func (r *SQLiteSendRepo) IncrementAccessCount(ctx context.Context, sendID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE sends SET access_count = access_count + 1 WHERE id = ?`, sendID)
	if err != nil {
		return fmt.Errorf("increment access count: %w", err)
	}
	return nil
}

func (r *SQLiteSendRepo) DeleteSend(ctx context.Context, sendID, userID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM sends WHERE id = ? AND user_id = ?`, sendID, userID)
	if err != nil {
		return fmt.Errorf("delete send: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("send not found")
	}
	return nil
}

func (r *SQLiteSendRepo) DisableSend(ctx context.Context, sendID, userID string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE sends SET disabled = 1 WHERE id = ? AND user_id = ?`, sendID, userID)
	if err != nil {
		return fmt.Errorf("disable send: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("send not found")
	}
	return nil
}

func (r *SQLiteSendRepo) PurgeExpiredSends(ctx context.Context) (int, error) {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM sends WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("purge expired sends: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ── SQLite Collection Repo (stub — org feature, returns errors) ──────────────

var errCollectionsNotSupported = fmt.Errorf("collections require PostgreSQL (organization feature)")

// SQLiteCollectionRepo stubs out CollectionRepository for SQLite.
type SQLiteCollectionRepo struct{}

// NewSQLiteCollectionRepo creates a new SQLiteCollectionRepo.
func NewSQLiteCollectionRepo() *SQLiteCollectionRepo { return &SQLiteCollectionRepo{} }

func (r *SQLiteCollectionRepo) CreateCollection(ctx context.Context, c Collection) (Collection, error) {
	return Collection{}, errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) GetCollection(ctx context.Context, id string) (Collection, error) {
	return Collection{}, errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) ListCollections(ctx context.Context, orgID string, requestingUserID string) ([]CollectionWithPermission, error) {
	return nil, errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) ListUserCollections(ctx context.Context, userID string) ([]CollectionWithPermission, error) {
	return nil, errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) UpdateCollection(ctx context.Context, c Collection) error {
	return errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) DeleteCollection(ctx context.Context, id string) error {
	return errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) AddCollectionMember(ctx context.Context, collID, userID string, key []byte, perm string) error {
	return errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) RemoveCollectionMember(ctx context.Context, collID, userID string) error {
	return errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) UpdateCollectionMemberPermission(ctx context.Context, collID, userID, perm string) error {
	return errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) GetCollectionMembers(ctx context.Context, collID string) ([]CollectionMember, error) {
	return nil, errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) GetCollectionKey(ctx context.Context, collID, userID string) ([]byte, error) {
	return nil, errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) AddEntryToCollection(ctx context.Context, collID, entryID, entryType string, encryptedData, nonce []byte) error {
	return errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) RemoveEntryFromCollection(ctx context.Context, collID, entryID string) error {
	return errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) GetCollectionEntries(ctx context.Context, collID string) ([]CollectionEntryData, error) {
	return nil, errCollectionsNotSupported
}
func (r *SQLiteCollectionRepo) GetEntryCollections(ctx context.Context, entryID string, userID string) ([]CollectionWithPermission, error) {
	return nil, errCollectionsNotSupported
}

// ── SQLite Emergency Access Repo ─────────────────────────────────────────────

// SQLiteEmergencyAccessRepo implements EmergencyAccessRepository for SQLite.
type SQLiteEmergencyAccessRepo struct {
	db *sql.DB
}

// NewSQLiteEmergencyAccessRepo creates a new SQLiteEmergencyAccessRepo.
func NewSQLiteEmergencyAccessRepo(db *sql.DB) *SQLiteEmergencyAccessRepo {
	return &SQLiteEmergencyAccessRepo{db: db}
}

func (r *SQLiteEmergencyAccessRepo) CreateEmergencyAccess(ctx context.Context, ea EmergencyAccess) (EmergencyAccess, error) {
	id := newUUID()
	now := nowUTC()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO emergency_access (id, grantor_id, grantee_id, grantee_email, status, access_type, wait_time_days, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ea.GrantorID, ea.GranteeID, ea.GranteeEmail, ea.Status, ea.AccessType, ea.WaitTimeDays, now, now,
	)
	if err != nil {
		return EmergencyAccess{}, fmt.Errorf("create emergency access: %w", err)
	}
	ea.ID = id
	ea.CreatedAt = parseTime(now)
	ea.UpdatedAt = parseTime(now)
	return ea, nil
}

func (r *SQLiteEmergencyAccessRepo) GetEmergencyAccess(ctx context.Context, id string) (EmergencyAccess, error) {
	var ea EmergencyAccess
	var createdStr, updatedStr string
	var recoveryStr sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT id, grantor_id, grantee_id, grantee_email, status, access_type, wait_time_days,
		        encrypted_key, key_nonce, recovery_initiated_at, created_at, updated_at
		 FROM emergency_access WHERE id = ?`, id,
	).Scan(&ea.ID, &ea.GrantorID, &ea.GranteeID, &ea.GranteeEmail, &ea.Status,
		&ea.AccessType, &ea.WaitTimeDays, &ea.EncryptedKey, &ea.KeyNonce,
		&recoveryStr, &createdStr, &updatedStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return EmergencyAccess{}, fmt.Errorf("emergency access not found")
		}
		return EmergencyAccess{}, fmt.Errorf("get emergency access: %w", err)
	}
	ea.CreatedAt = parseTime(createdStr)
	ea.UpdatedAt = parseTime(updatedStr)
	if recoveryStr.Valid {
		t := parseTime(recoveryStr.String)
		ea.RecoveryInitiatedAt = &t
	}
	return ea, nil
}

func (r *SQLiteEmergencyAccessRepo) scanEARows(rows *sql.Rows) ([]EmergencyAccess, error) {
	var results []EmergencyAccess
	for rows.Next() {
		var ea EmergencyAccess
		var createdStr, updatedStr string
		var recoveryStr sql.NullString
		if err := rows.Scan(&ea.ID, &ea.GrantorID, &ea.GranteeID, &ea.GranteeEmail, &ea.Status,
			&ea.AccessType, &ea.WaitTimeDays, &ea.EncryptedKey, &ea.KeyNonce,
			&recoveryStr, &createdStr, &updatedStr); err != nil {
			return nil, fmt.Errorf("scan emergency access: %w", err)
		}
		ea.CreatedAt = parseTime(createdStr)
		ea.UpdatedAt = parseTime(updatedStr)
		if recoveryStr.Valid {
			t := parseTime(recoveryStr.String)
			ea.RecoveryInitiatedAt = &t
		}
		results = append(results, ea)
	}
	return results, rows.Err()
}

func (r *SQLiteEmergencyAccessRepo) ListGrantedAccess(ctx context.Context, grantorID string) ([]EmergencyAccess, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, grantor_id, grantee_id, grantee_email, status, access_type, wait_time_days,
		        encrypted_key, key_nonce, recovery_initiated_at, created_at, updated_at
		 FROM emergency_access WHERE grantor_id = ? ORDER BY created_at DESC`, grantorID)
	if err != nil {
		return nil, fmt.Errorf("list granted access: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return r.scanEARows(rows)
}

func (r *SQLiteEmergencyAccessRepo) ListTrustedBy(ctx context.Context, granteeID string) ([]EmergencyAccess, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, grantor_id, grantee_id, grantee_email, status, access_type, wait_time_days,
		        encrypted_key, key_nonce, recovery_initiated_at, created_at, updated_at
		 FROM emergency_access WHERE grantee_id = ? ORDER BY created_at DESC`, granteeID)
	if err != nil {
		return nil, fmt.Errorf("list trusted by: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return r.scanEARows(rows)
}

func (r *SQLiteEmergencyAccessRepo) UpdateStatus(ctx context.Context, id, status string) error {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE emergency_access SET status = ?, updated_at = ? WHERE id = ?`, status, now, id)
	if err != nil {
		return fmt.Errorf("update emergency access status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("emergency access not found")
	}
	return nil
}

func (r *SQLiteEmergencyAccessRepo) SetEncryptedKey(ctx context.Context, id string, encryptedKey, nonce []byte) error {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE emergency_access SET encrypted_key = ?, key_nonce = ?, updated_at = ? WHERE id = ?`,
		encryptedKey, nonce, now, id)
	if err != nil {
		return fmt.Errorf("set encrypted key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("emergency access not found")
	}
	return nil
}

func (r *SQLiteEmergencyAccessRepo) InitiateRecovery(ctx context.Context, id string) error {
	now := nowUTC()
	res, err := r.db.ExecContext(ctx,
		`UPDATE emergency_access SET status = 'recovery_initiated', recovery_initiated_at = ?, updated_at = ?
		 WHERE id = ? AND status IN ('accepted', 'recovery_rejected')`, now, now, id)
	if err != nil {
		return fmt.Errorf("initiate recovery: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("emergency access not found or not in eligible status")
	}
	return nil
}

func (r *SQLiteEmergencyAccessRepo) DeleteEmergencyAccess(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM emergency_access WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete emergency access: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("emergency access not found")
	}
	return nil
}

func (r *SQLiteEmergencyAccessRepo) GetAutoApproveEligible(ctx context.Context) ([]EmergencyAccess, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, grantor_id, grantee_id, grantee_email, status, access_type, wait_time_days,
		        encrypted_key, key_nonce, recovery_initiated_at, created_at, updated_at
		 FROM emergency_access
		 WHERE status = 'recovery_initiated'
		   AND datetime(recovery_initiated_at, '+' || wait_time_days || ' days') <= datetime('now')`)
	if err != nil {
		return nil, fmt.Errorf("get auto-approve eligible: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return r.scanEARows(rows)
}

func (r *SQLiteEmergencyAccessRepo) SetGranteeID(ctx context.Context, id, granteeID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE emergency_access SET grantee_id = ?, updated_at = datetime('now') WHERE id = ?`,
		granteeID, id)
	if err != nil {
		return fmt.Errorf("set grantee id: %w", err)
	}
	return nil
}

func (r *SQLiteEmergencyAccessRepo) ListByGranteeEmail(ctx context.Context, email string) ([]EmergencyAccess, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, grantor_id, grantee_id, grantee_email, status, access_type, wait_time_days,
		        encrypted_key, key_nonce, recovery_initiated_at, created_at, updated_at
		 FROM emergency_access WHERE grantee_email = ?`, email)
	if err != nil {
		return nil, fmt.Errorf("list by grantee email: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return r.scanEARows(rows)
}

func (r *SQLiteEmergencyAccessRepo) AutoApproveExpired(ctx context.Context) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE emergency_access SET status = 'recovery_approved', updated_at = datetime('now')
		 WHERE status = 'recovery_initiated'
		   AND datetime(recovery_initiated_at, '+' || wait_time_days || ' days') <= datetime('now')`)
	if err != nil {
		return 0, fmt.Errorf("auto approve expired: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
