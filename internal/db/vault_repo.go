package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VaultEntry represents a stored vault entry row.
type VaultEntry struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	OrgID         *string   `json:"org_id,omitempty"`
	EntryType     string    `json:"entry_type"`
	EncryptedData []byte    `json:"encrypted_data"`
	Nonce         []byte    `json:"nonce"`
	Version       int       `json:"version"`
	FolderID      *string   `json:"folder_id,omitempty"`
	IsDeleted     bool      `json:"is_deleted"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// VaultFilters defines optional filters for listing vault entries.
type VaultFilters struct {
	EntryType    string
	FolderID     string
	UpdatedSince *time.Time
}

// Folder represents a folder row.
type Folder struct {
	ID            string  `json:"id"`
	UserID        string  `json:"user_id"`
	NameEncrypted []byte  `json:"name_encrypted"`
	ParentID      *string `json:"parent_id,omitempty"`
}

// VaultRepo provides database operations for vault entries and folders.
type VaultRepo struct {
	pool *pgxpool.Pool
}

// NewVaultRepo creates a new VaultRepo.
func NewVaultRepo(pool *pgxpool.Pool) *VaultRepo {
	return &VaultRepo{pool: pool}
}

// CreateEntry inserts a new vault entry and returns it.
func (r *VaultRepo) CreateEntry(ctx context.Context, entry VaultEntry) (VaultEntry, error) {
	var out VaultEntry
	err := r.pool.QueryRow(ctx,
		`INSERT INTO vault_entries (user_id, org_id, entry_type, encrypted_data, nonce, folder_id)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, created_at, updated_at`,
		entry.UserID, entry.OrgID, entry.EntryType, entry.EncryptedData, entry.Nonce, entry.FolderID,
	).Scan(&out.ID, &out.UserID, &out.OrgID, &out.EntryType, &out.EncryptedData, &out.Nonce,
		&out.Version, &out.FolderID, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return VaultEntry{}, fmt.Errorf("insert vault entry: %w", err)
	}
	return out, nil
}

// GetEntry retrieves a single vault entry by ID, scoped to the user.
func (r *VaultRepo) GetEntry(ctx context.Context, entryID, userID string) (VaultEntry, error) {
	var out VaultEntry
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, created_at, updated_at
		 FROM vault_entries
		 WHERE id = $1 AND user_id = $2 AND is_deleted = false`,
		entryID, userID,
	).Scan(&out.ID, &out.UserID, &out.OrgID, &out.EntryType, &out.EncryptedData, &out.Nonce,
		&out.Version, &out.FolderID, &out.IsDeleted, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return VaultEntry{}, fmt.Errorf("vault entry not found")
		}
		return VaultEntry{}, fmt.Errorf("get vault entry: %w", err)
	}
	return out, nil
}

// ListEntries returns vault entries for a user with optional filters (excludes soft-deleted).
func (r *VaultRepo) ListEntries(ctx context.Context, userID string, filters VaultFilters) ([]VaultEntry, error) {
	query := `SELECT id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, created_at, updated_at
	          FROM vault_entries
	          WHERE user_id = $1 AND is_deleted = false` // #nosec G201 -- only integer placeholders interpolated via Sprintf
	args := []interface{}{userID}
	argIdx := 2

	if filters.EntryType != "" {
		query += fmt.Sprintf(" AND entry_type = $%d", argIdx)
		args = append(args, filters.EntryType)
		argIdx++
	}
	if filters.FolderID != "" {
		query += fmt.Sprintf(" AND folder_id = $%d", argIdx)
		args = append(args, filters.FolderID)
		argIdx++
	}
	if filters.UpdatedSince != nil {
		query += fmt.Sprintf(" AND updated_at > $%d", argIdx)
		args = append(args, *filters.UpdatedSince)
	}

	query += " ORDER BY updated_at DESC"

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vault entries: %w", err)
	}
	defer rows.Close()

	var entries []VaultEntry
	for rows.Next() {
		var e VaultEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.OrgID, &e.EntryType, &e.EncryptedData, &e.Nonce,
			&e.Version, &e.FolderID, &e.IsDeleted, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan vault entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// UpdateEntry updates a vault entry's encrypted data, nonce, type, and folder, incrementing version.
func (r *VaultRepo) UpdateEntry(ctx context.Context, entry VaultEntry) (VaultEntry, error) {
	var out VaultEntry
	err := r.pool.QueryRow(ctx,
		`UPDATE vault_entries
		 SET encrypted_data = $1, nonce = $2, entry_type = $3, folder_id = $4, version = version + 1
		 WHERE id = $5 AND user_id = $6
		 RETURNING id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, created_at, updated_at`,
		entry.EncryptedData, entry.Nonce, entry.EntryType, entry.FolderID, entry.ID, entry.UserID,
	).Scan(&out.ID, &out.UserID, &out.OrgID, &out.EntryType, &out.EncryptedData, &out.Nonce,
		&out.Version, &out.FolderID, &out.IsDeleted, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return VaultEntry{}, fmt.Errorf("vault entry not found")
		}
		return VaultEntry{}, fmt.Errorf("update vault entry: %w", err)
	}
	return out, nil
}

// DeleteEntry soft-deletes a vault entry by ID, scoped to the user.
func (r *VaultRepo) DeleteEntry(ctx context.Context, entryID, userID string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE vault_entries SET is_deleted = true, version = version + 1
		 WHERE id = $1 AND user_id = $2 AND is_deleted = false`,
		entryID, userID,
	)
	if err != nil {
		return fmt.Errorf("delete vault entry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("vault entry not found")
	}
	return nil
}

// ListEntriesForSync returns all vault entries (including soft-deleted) updated after the given time.
func (r *VaultRepo) ListEntriesForSync(ctx context.Context, userID string, since time.Time) ([]VaultEntry, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, created_at, updated_at
		 FROM vault_entries
		 WHERE user_id = $1 AND updated_at > $2
		 ORDER BY updated_at ASC`,
		userID, since,
	)
	if err != nil {
		return nil, fmt.Errorf("list entries for sync: %w", err)
	}
	defer rows.Close()

	var entries []VaultEntry
	for rows.Next() {
		var e VaultEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.OrgID, &e.EntryType, &e.EncryptedData, &e.Nonce,
			&e.Version, &e.FolderID, &e.IsDeleted, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan sync entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// GetEntryByID retrieves a vault entry by ID only (no user scope, no soft-delete filter). Used for sync conflict checks.
func (r *VaultRepo) GetEntryByID(ctx context.Context, entryID string) (VaultEntry, error) {
	var out VaultEntry
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, created_at, updated_at
		 FROM vault_entries WHERE id = $1`,
		entryID,
	).Scan(&out.ID, &out.UserID, &out.OrgID, &out.EntryType, &out.EncryptedData, &out.Nonce,
		&out.Version, &out.FolderID, &out.IsDeleted, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return VaultEntry{}, fmt.Errorf("vault entry not found")
		}
		return VaultEntry{}, fmt.Errorf("get entry by id: %w", err)
	}
	return out, nil
}

// UpdateEntryVersioned updates a vault entry only if the current version matches expectedVersion.
// Returns the updated entry or an error.
func (r *VaultRepo) UpdateEntryVersioned(ctx context.Context, entry VaultEntry, expectedVersion int) (VaultEntry, error) {
	var out VaultEntry
	err := r.pool.QueryRow(ctx,
		`UPDATE vault_entries
		 SET encrypted_data = $1, nonce = $2, entry_type = $3, folder_id = $4,
		     is_deleted = $5, version = version + 1
		 WHERE id = $6 AND user_id = $7 AND version = $8
		 RETURNING id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, created_at, updated_at`,
		entry.EncryptedData, entry.Nonce, entry.EntryType, entry.FolderID,
		entry.IsDeleted, entry.ID, entry.UserID, expectedVersion,
	).Scan(&out.ID, &out.UserID, &out.OrgID, &out.EntryType, &out.EncryptedData, &out.Nonce,
		&out.Version, &out.FolderID, &out.IsDeleted, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return VaultEntry{}, fmt.Errorf("version conflict")
		}
		return VaultEntry{}, fmt.Errorf("update entry versioned: %w", err)
	}
	return out, nil
}

// CreateFolder inserts a new folder and returns it.
func (r *VaultRepo) CreateFolder(ctx context.Context, folder Folder) (Folder, error) {
	var out Folder
	err := r.pool.QueryRow(ctx,
		`INSERT INTO folders (user_id, name_encrypted, parent_id)
		 VALUES ($1, $2, $3)
		 RETURNING id, user_id, name_encrypted, parent_id`,
		folder.UserID, folder.NameEncrypted, folder.ParentID,
	).Scan(&out.ID, &out.UserID, &out.NameEncrypted, &out.ParentID)
	if err != nil {
		return Folder{}, fmt.Errorf("insert folder: %w", err)
	}
	return out, nil
}

// ListFolders returns all folders for a user.
func (r *VaultRepo) ListFolders(ctx context.Context, userID string) ([]Folder, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, name_encrypted, parent_id FROM folders WHERE user_id = $1 ORDER BY id`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	defer rows.Close()

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

// DeleteFolder removes a folder by ID, scoped to the user.
func (r *VaultRepo) DeleteFolder(ctx context.Context, folderID, userID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM folders WHERE id = $1 AND user_id = $2`,
		folderID, userID,
	)
	if err != nil {
		return fmt.Errorf("delete folder: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("folder not found")
	}
	return nil
}
