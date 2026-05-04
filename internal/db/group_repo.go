package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgGroupRepo implements GroupRepository for PostgreSQL.
type PgGroupRepo struct {
	pool *pgxpool.Pool
}

// NewPgGroupRepo creates a new PgGroupRepo.
func NewPgGroupRepo(pool *pgxpool.Pool) *PgGroupRepo {
	return &PgGroupRepo{pool: pool}
}

func (r *PgGroupRepo) CreateGroup(ctx context.Context, group Group) (Group, error) {
	var out Group
	err := r.pool.QueryRow(ctx,
		`INSERT INTO groups (org_id, name, external_id)
		 VALUES ($1, $2, $3)
		 RETURNING id, org_id, name, COALESCE(external_id, ''), created_at`,
		group.OrgID, group.Name, nilIfEmpty(group.ExternalID),
	).Scan(&out.ID, &out.OrgID, &out.Name, &out.ExternalID, &out.CreatedAt)
	if err != nil {
		return Group{}, fmt.Errorf("create group: %w", err)
	}
	return out, nil
}

func (r *PgGroupRepo) GetGroup(ctx context.Context, groupID string) (Group, error) {
	var g Group
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, name, COALESCE(external_id, ''), created_at
		 FROM groups WHERE id = $1`, groupID,
	).Scan(&g.ID, &g.OrgID, &g.Name, &g.ExternalID, &g.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Group{}, fmt.Errorf("group not found")
		}
		return Group{}, fmt.Errorf("get group: %w", err)
	}
	return g, nil
}

func (r *PgGroupRepo) ListGroups(ctx context.Context, orgID string) ([]Group, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, org_id, name, COALESCE(external_id, ''), created_at
		 FROM groups WHERE org_id = $1 ORDER BY name`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.OrgID, &g.Name, &g.ExternalID, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (r *PgGroupRepo) UpdateGroup(ctx context.Context, group Group) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE groups SET name = $2, external_id = $3 WHERE id = $1`,
		group.ID, group.Name, nilIfEmpty(group.ExternalID),
	)
	if err != nil {
		return fmt.Errorf("update group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}

func (r *PgGroupRepo) DeleteGroup(ctx context.Context, groupID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM groups WHERE id = $1`, groupID)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}

func (r *PgGroupRepo) AddGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`,
		groupID, userID,
	)
	if err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

func (r *PgGroupRepo) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`,
		groupID, userID,
	)
	if err != nil {
		return fmt.Errorf("remove group member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member not found in group")
	}
	return nil
}

func (r *PgGroupRepo) ListGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT gm.group_id, gm.user_id, u.email
		 FROM group_members gm
		 JOIN users u ON u.id = gm.user_id
		 WHERE gm.group_id = $1
		 ORDER BY u.email`, groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	defer rows.Close()

	var members []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.GroupID, &m.UserID, &m.Email); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (r *PgGroupRepo) ListUserGroups(ctx context.Context, userID string) ([]Group, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT g.id, g.org_id, g.name, COALESCE(g.external_id, ''), g.created_at
		 FROM groups g
		 JOIN group_members gm ON gm.group_id = g.id
		 WHERE gm.user_id = $1
		 ORDER BY g.name`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list user groups: %w", err)
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.OrgID, &g.Name, &g.ExternalID, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (r *PgGroupRepo) AddCollectionGroup(ctx context.Context, cg CollectionGroup) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO collection_groups (collection_id, group_id, permission, encrypted_key)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (collection_id, group_id) DO UPDATE SET permission = $3, encrypted_key = $4`,
		cg.CollectionID, cg.GroupID, cg.Permission, cg.EncryptedKey,
	)
	if err != nil {
		return fmt.Errorf("add collection group: %w", err)
	}
	return nil
}

func (r *PgGroupRepo) RemoveCollectionGroup(ctx context.Context, collectionID, groupID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM collection_groups WHERE collection_id = $1 AND group_id = $2`,
		collectionID, groupID,
	)
	if err != nil {
		return fmt.Errorf("remove collection group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("collection group not found")
	}
	return nil
}

func (r *PgGroupRepo) ListCollectionGroups(ctx context.Context, collectionID string) ([]CollectionGroup, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT cg.collection_id, cg.group_id, g.name, cg.permission, cg.encrypted_key
		 FROM collection_groups cg
		 JOIN groups g ON g.id = cg.group_id
		 WHERE cg.collection_id = $1
		 ORDER BY g.name`, collectionID,
	)
	if err != nil {
		return nil, fmt.Errorf("list collection groups: %w", err)
	}
	defer rows.Close()

	var cgs []CollectionGroup
	for rows.Next() {
		var cg CollectionGroup
		if err := rows.Scan(&cg.CollectionID, &cg.GroupID, &cg.GroupName, &cg.Permission, &cg.EncryptedKey); err != nil {
			return nil, fmt.Errorf("scan collection group: %w", err)
		}
		cgs = append(cgs, cg)
	}
	return cgs, rows.Err()
}

func (r *PgGroupRepo) UpdateCollectionGroupPermission(ctx context.Context, collectionID, groupID, permission string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE collection_groups SET permission = $3 WHERE collection_id = $1 AND group_id = $2`,
		collectionID, groupID, permission,
	)
	if err != nil {
		return fmt.Errorf("update collection group permission: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("collection group not found")
	}
	return nil
}

// nilIfEmpty returns nil if s is empty, otherwise returns &s.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
