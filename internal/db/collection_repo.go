package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgCollectionRepo provides database operations for collections (PostgreSQL).
type PgCollectionRepo struct {
	pool *pgxpool.Pool
}

// NewPgCollectionRepo creates a new PgCollectionRepo.
func NewPgCollectionRepo(pool *pgxpool.Pool) *PgCollectionRepo {
	return &PgCollectionRepo{pool: pool}
}

const collectionColumns = `id, org_id, name_encrypted, name_nonce, external_id, created_at, updated_at`

func scanCollection(row interface{ Scan(dest ...interface{}) error }) (Collection, error) {
	var c Collection
	err := row.Scan(&c.ID, &c.OrgID, &c.NameEncrypted, &c.NameNonce, &c.ExternalID, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// CreateCollection inserts a new collection.
func (r *PgCollectionRepo) CreateCollection(ctx context.Context, collection Collection) (Collection, error) {
	row := r.pool.QueryRow(ctx,
		`INSERT INTO collections (org_id, name_encrypted, name_nonce, external_id)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+collectionColumns,
		collection.OrgID, collection.NameEncrypted, collection.NameNonce, collection.ExternalID,
	)
	return scanCollection(row)
}

// GetCollection retrieves a single collection by ID.
func (r *PgCollectionRepo) GetCollection(ctx context.Context, collectionID string) (Collection, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+collectionColumns+` FROM collections WHERE id = $1`, collectionID,
	)
	c, err := scanCollection(row)
	if err == pgx.ErrNoRows {
		return c, fmt.Errorf("collection not found")
	}
	return c, err
}

// ListCollections returns all collections for an organization with member/entry counts.
func (r *PgCollectionRepo) ListCollections(ctx context.Context, orgID string, requestingUserID string) ([]CollectionWithPermission, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT c.id, c.org_id, c.name_encrypted, c.name_nonce, c.external_id, c.created_at, c.updated_at,
		        COALESCE(cm.encrypted_key, ''::bytea) AS encrypted_key,
		        COALESCE((SELECT COUNT(*) FROM collection_members cm2 WHERE cm2.collection_id = c.id), 0) AS member_count,
		        COALESCE((SELECT COUNT(*) FROM collection_entries ce WHERE ce.collection_id = c.id), 0) AS entry_count
		 FROM collections c
		 LEFT JOIN collection_members cm ON cm.collection_id = c.id AND cm.user_id = $2
		 WHERE c.org_id = $1
		 ORDER BY c.created_at`, orgID, requestingUserID,
	)
	if err != nil {
		return nil, fmt.Errorf("list collections: %w", err)
	}
	defer rows.Close()

	var out []CollectionWithPermission
	for rows.Next() {
		var cw CollectionWithPermission
		if err := rows.Scan(&cw.ID, &cw.OrgID, &cw.NameEncrypted, &cw.NameNonce, &cw.ExternalID,
			&cw.CreatedAt, &cw.UpdatedAt, &cw.EncryptedKey, &cw.MemberCount, &cw.EntryCount); err != nil {
			return nil, fmt.Errorf("scan collection: %w", err)
		}
		out = append(out, cw)
	}
	return out, rows.Err()
}

// ListUserCollections returns collections the user is a member of.
func (r *PgCollectionRepo) ListUserCollections(ctx context.Context, userID string) ([]CollectionWithPermission, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT c.id, c.org_id, c.name_encrypted, c.name_nonce, c.external_id, c.created_at, c.updated_at,
		        cm.permission, cm.encrypted_key,
		        COALESCE((SELECT COUNT(*) FROM collection_members cm2 WHERE cm2.collection_id = c.id), 0) AS member_count,
		        COALESCE((SELECT COUNT(*) FROM collection_entries ce WHERE ce.collection_id = c.id), 0) AS entry_count
		 FROM collections c
		 JOIN collection_members cm ON cm.collection_id = c.id
		 WHERE cm.user_id = $1
		 ORDER BY c.created_at`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list user collections: %w", err)
	}
	defer rows.Close()

	var out []CollectionWithPermission
	for rows.Next() {
		var cw CollectionWithPermission
		if err := rows.Scan(&cw.ID, &cw.OrgID, &cw.NameEncrypted, &cw.NameNonce, &cw.ExternalID,
			&cw.CreatedAt, &cw.UpdatedAt, &cw.Permission, &cw.EncryptedKey, &cw.MemberCount, &cw.EntryCount); err != nil {
			return nil, fmt.Errorf("scan collection: %w", err)
		}
		out = append(out, cw)
	}
	return out, rows.Err()
}

// UpdateCollection updates a collection's name and external_id.
func (r *PgCollectionRepo) UpdateCollection(ctx context.Context, collection Collection) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE collections SET name_encrypted = $1, name_nonce = $2, external_id = $3, updated_at = now()
		 WHERE id = $4`,
		collection.NameEncrypted, collection.NameNonce, collection.ExternalID, collection.ID,
	)
	if err != nil {
		return fmt.Errorf("update collection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("collection not found")
	}
	return nil
}

// DeleteCollection deletes a collection and cascades to members and entries.
func (r *PgCollectionRepo) DeleteCollection(ctx context.Context, collectionID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM collections WHERE id = $1`, collectionID)
	if err != nil {
		return fmt.Errorf("delete collection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("collection not found")
	}
	return nil
}

// AddCollectionMember adds a user to a collection with an encrypted key and permission.
func (r *PgCollectionRepo) AddCollectionMember(ctx context.Context, collectionID, userID string, encryptedKey []byte, permission string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO collection_members (collection_id, user_id, encrypted_key, permission)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (collection_id, user_id) DO UPDATE SET encrypted_key = $3, permission = $4`,
		collectionID, userID, encryptedKey, permission,
	)
	if err != nil {
		return fmt.Errorf("add collection member: %w", err)
	}
	return nil
}

// RemoveCollectionMember removes a user from a collection.
func (r *PgCollectionRepo) RemoveCollectionMember(ctx context.Context, collectionID, userID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM collection_members WHERE collection_id = $1 AND user_id = $2`,
		collectionID, userID,
	)
	if err != nil {
		return fmt.Errorf("remove collection member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member not found in collection")
	}
	return nil
}

// UpdateCollectionMemberPermission changes a member's permission level.
func (r *PgCollectionRepo) UpdateCollectionMemberPermission(ctx context.Context, collectionID, userID, permission string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE collection_members SET permission = $1 WHERE collection_id = $2 AND user_id = $3`,
		permission, collectionID, userID,
	)
	if err != nil {
		return fmt.Errorf("update member permission: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member not found in collection")
	}
	return nil
}

// GetCollectionMembers returns all members of a collection.
func (r *PgCollectionRepo) GetCollectionMembers(ctx context.Context, collectionID string) ([]CollectionMember, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT cm.collection_id, cm.user_id, u.email, cm.encrypted_key, cm.permission
		 FROM collection_members cm
		 JOIN users u ON u.id = cm.user_id
		 WHERE cm.collection_id = $1
		 ORDER BY u.email`, collectionID,
	)
	if err != nil {
		return nil, fmt.Errorf("get collection members: %w", err)
	}
	defer rows.Close()

	var out []CollectionMember
	for rows.Next() {
		var m CollectionMember
		if err := rows.Scan(&m.CollectionID, &m.UserID, &m.Email, &m.EncryptedKey, &m.Permission); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetCollectionKey returns the encrypted collection key for a specific user.
func (r *PgCollectionRepo) GetCollectionKey(ctx context.Context, collectionID, userID string) ([]byte, error) {
	var key []byte
	err := r.pool.QueryRow(ctx,
		`SELECT encrypted_key FROM collection_members WHERE collection_id = $1 AND user_id = $2`,
		collectionID, userID,
	).Scan(&key)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("not a member of collection")
	}
	if err != nil {
		return nil, fmt.Errorf("get collection key: %w", err)
	}
	return key, nil
}

// AddEntryToCollection assigns a vault entry to a collection.
func (r *PgCollectionRepo) AddEntryToCollection(ctx context.Context, collectionID, entryID, entryType string, encryptedData, nonce []byte) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO collection_entries (collection_id, entry_id, entry_type, encrypted_data, nonce) VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (collection_id, entry_id) DO UPDATE SET encrypted_data = $4, nonce = $5, entry_type = $3`,
		collectionID, entryID, entryType, encryptedData, nonce,
	)
	if err != nil {
		return fmt.Errorf("add entry to collection: %w", err)
	}
	return nil
}

// RemoveEntryFromCollection removes a vault entry from a collection.
func (r *PgCollectionRepo) RemoveEntryFromCollection(ctx context.Context, collectionID, entryID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM collection_entries WHERE collection_id = $1 AND entry_id = $2`,
		collectionID, entryID,
	)
	if err != nil {
		return fmt.Errorf("remove entry from collection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("entry not in collection")
	}
	return nil
}

// GetCollectionEntries returns all collection entry data (encrypted with collection key).
func (r *PgCollectionRepo) GetCollectionEntries(ctx context.Context, collectionID string) ([]CollectionEntryData, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT collection_id, entry_id, entry_type, encrypted_data, nonce
		 FROM collection_entries
		 WHERE collection_id = $1 AND encrypted_data IS NOT NULL
		 ORDER BY entry_id`, collectionID,
	)
	if err != nil {
		return nil, fmt.Errorf("get collection entries: %w", err)
	}
	defer rows.Close()

	var out []CollectionEntryData
	for rows.Next() {
		var ce CollectionEntryData
		if err := rows.Scan(&ce.CollectionID, &ce.EntryID, &ce.EntryType, &ce.EncryptedData, &ce.Nonce); err != nil {
			return nil, fmt.Errorf("scan collection entry: %w", err)
		}
		out = append(out, ce)
	}
	return out, rows.Err()
}

// GetEntryCollections returns all collections that contain a given entry.
func (r *PgCollectionRepo) GetEntryCollections(ctx context.Context, entryID string, userID string) ([]CollectionWithPermission, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT c.id, c.org_id, c.name_encrypted, c.name_nonce, c.external_id, c.created_at, c.updated_at,
		        COALESCE(cm.encrypted_key, ''::bytea) AS encrypted_key
		 FROM collections c
		 JOIN collection_entries ce ON ce.collection_id = c.id
		 LEFT JOIN collection_members cm ON cm.collection_id = c.id AND cm.user_id = $2
		 WHERE ce.entry_id = $1
		 ORDER BY c.created_at`, entryID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("get entry collections: %w", err)
	}
	defer rows.Close()

	var out []CollectionWithPermission
	for rows.Next() {
		var cw CollectionWithPermission
		if err := rows.Scan(&cw.ID, &cw.OrgID, &cw.NameEncrypted, &cw.NameNonce, &cw.ExternalID,
			&cw.CreatedAt, &cw.UpdatedAt, &cw.EncryptedKey); err != nil {
			return nil, fmt.Errorf("scan collection: %w", err)
		}
		out = append(out, cw)
	}
	return out, rows.Err()
}
