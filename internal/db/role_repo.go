package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgRoleRepo implements RoleRepository for PostgreSQL.
type PgRoleRepo struct {
	pool *pgxpool.Pool
}

// NewPgRoleRepo creates a new PgRoleRepo.
func NewPgRoleRepo(pool *pgxpool.Pool) *PgRoleRepo {
	return &PgRoleRepo{pool: pool}
}

func (r *PgRoleRepo) CreateRole(ctx context.Context, role Role) (Role, error) {
	var out Role
	err := r.pool.QueryRow(ctx,
		`INSERT INTO roles (org_id, name, description, permissions, is_builtin)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, name, description, permissions, is_builtin, created_at`,
		role.OrgID, role.Name, role.Description, role.Permissions, role.IsBuiltin,
	).Scan(&out.ID, &out.OrgID, &out.Name, &out.Description, &out.Permissions, &out.IsBuiltin, &out.CreatedAt)
	if err != nil {
		return Role{}, fmt.Errorf("create role: %w", err)
	}
	return out, nil
}

func (r *PgRoleRepo) GetRole(ctx context.Context, roleID string) (Role, error) {
	var role Role
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, name, description, permissions, is_builtin, created_at
		 FROM roles WHERE id = $1`, roleID,
	).Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &role.Permissions, &role.IsBuiltin, &role.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Role{}, fmt.Errorf("role not found")
		}
		return Role{}, fmt.Errorf("get role: %w", err)
	}
	return role, nil
}

func (r *PgRoleRepo) GetRoleByName(ctx context.Context, orgID, name string) (Role, error) {
	var role Role
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, name, description, permissions, is_builtin, created_at
		 FROM roles WHERE org_id = $1 AND name = $2`, orgID, name,
	).Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &role.Permissions, &role.IsBuiltin, &role.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Role{}, fmt.Errorf("role not found")
		}
		return Role{}, fmt.Errorf("get role by name: %w", err)
	}
	return role, nil
}

func (r *PgRoleRepo) ListRoles(ctx context.Context, orgID string) ([]Role, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, org_id, name, description, permissions, is_builtin, created_at
		 FROM roles WHERE org_id = $1 ORDER BY is_builtin DESC, name`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &role.Permissions, &role.IsBuiltin, &role.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *PgRoleRepo) UpdateRole(ctx context.Context, role Role) error {
	// Update permissions and description for any role (including built-in)
	tag, err := r.pool.Exec(ctx,
		`UPDATE roles SET description = $2, permissions = $3
		 WHERE id = $1`,
		role.ID, role.Description, role.Permissions,
	)
	if err != nil {
		return fmt.Errorf("update role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("role not found")
	}
	// Also update name for non-builtin roles
	if role.Name != "" {
		_, _ = r.pool.Exec(ctx,
			`UPDATE roles SET name = $2 WHERE id = $1 AND is_builtin = false`,
			role.ID, role.Name,
		)
	}
	return nil
}

func (r *PgRoleRepo) DeleteRole(ctx context.Context, roleID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM roles WHERE id = $1 AND is_builtin = false`, roleID,
	)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("role not found or is built-in")
	}
	return nil
}

// SeedBuiltinRoles creates the default Admin and Member roles for an org if they don't exist.
func (r *PgRoleRepo) SeedBuiltinRoles(ctx context.Context, orgID string) error {
	adminPerms, _ := json.Marshal([]string{"*"})
	memberPerms, _ := json.Marshal([]string{"vault.read", "vault.write", "collection.read"})

	_, err := r.pool.Exec(ctx,
		`INSERT INTO roles (org_id, name, description, permissions, is_builtin)
		 VALUES ($1, 'Admin', 'Full organization access', $2, true)
		 ON CONFLICT (org_id, name) DO NOTHING`,
		orgID, adminPerms,
	)
	if err != nil {
		return fmt.Errorf("seed admin role: %w", err)
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO roles (org_id, name, description, permissions, is_builtin)
		 VALUES ($1, 'Member', 'Standard member access', $2, true)
		 ON CONFLICT (org_id, name) DO NOTHING`,
		orgID, memberPerms,
	)
	if err != nil {
		return fmt.Errorf("seed member role: %w", err)
	}

	return nil
}

// GetMemberRole returns the role for a member in an organization.
// Falls back to the legacy text role column if role_id is not set.
func (r *PgRoleRepo) GetMemberRole(ctx context.Context, orgID, userID string) (Role, error) {
	var role Role
	err := r.pool.QueryRow(ctx,
		`SELECT r.id, r.org_id, r.name, r.description, r.permissions, r.is_builtin, r.created_at
		 FROM roles r
		 JOIN org_members om ON om.role_id = r.id
		 WHERE om.org_id = $1 AND om.user_id = $2`, orgID, userID,
	).Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &role.Permissions, &role.IsBuiltin, &role.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Fallback: check legacy role column and map to builtin role
			var legacyRole string
			legacyErr := r.pool.QueryRow(ctx,
				`SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID,
			).Scan(&legacyRole)
			if legacyErr != nil {
				return Role{}, fmt.Errorf("member not found")
			}
			// Map legacy role name to built-in role
			roleName := "Member"
			if legacyRole == "admin" {
				roleName = "Admin"
			}
			builtinRole, roleErr := r.GetRoleByName(ctx, orgID, roleName)
			if roleErr != nil {
				// Built-in roles don't exist yet for this org — seed them now
				if seedErr := r.SeedBuiltinRoles(ctx, orgID); seedErr != nil {
					return Role{}, fmt.Errorf("auto-seed roles: %w", seedErr)
				}
				builtinRole, roleErr = r.GetRoleByName(ctx, orgID, roleName)
				if roleErr != nil {
					return Role{}, fmt.Errorf("get seeded role: %w", roleErr)
				}
			}
			return builtinRole, nil
		}
		return Role{}, fmt.Errorf("get member role: %w", err)
	}
	return role, nil
}

func (r *PgRoleRepo) SetMemberRole(ctx context.Context, orgID, userID, roleID string) error {
	// Get the role to check its name for backward compatibility
	role, err := r.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	legacyRole := "member"
	if role.Name == "Admin" {
		legacyRole = "admin"
	}

	tag, err := r.pool.Exec(ctx,
		`UPDATE org_members SET role_id = $3, role = $4 WHERE org_id = $1 AND user_id = $2`,
		orgID, userID, roleID, legacyRole,
	)
	if err != nil {
		return fmt.Errorf("set member role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}
