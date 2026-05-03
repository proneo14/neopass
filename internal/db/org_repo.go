package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Organization represents an organization row.
type Organization struct {
	ID                       string          `json:"id"`
	Name                     string          `json:"name"`
	OrgPublicKey             []byte          `json:"-"`
	EncryptedOrgPrivateKey   []byte          `json:"-"`
	Policy                   json.RawMessage `json:"policy,omitempty"`
	SSOEnabled               bool            `json:"sso_enabled"`
	SSOConfig                json.RawMessage `json:"sso_config,omitempty"`
	SCIMEnabled              bool            `json:"scim_enabled"`
	SCIMTokenHash            []byte          `json:"-"`
	CreatedAt                time.Time       `json:"created_at"`
}

// OrgMember represents a membership row.
type OrgMember struct {
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email,omitempty"`
	Role      string    `json:"role"`
	JoinedAt  time.Time `json:"joined_at"`
}

// Invitation represents an org invitation row.
type Invitation struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	InvitedBy string    `json:"invited_by"`
	Accepted  bool      `json:"accepted"`
	CreatedAt time.Time `json:"created_at"`
}

// PgOrgRepo provides database operations for organizations (PostgreSQL).
type PgOrgRepo struct {
	pool *pgxpool.Pool
}

// NewPgOrgRepo creates a new PgOrgRepo.
func NewPgOrgRepo(pool *pgxpool.Pool) *PgOrgRepo {
	return &PgOrgRepo{pool: pool}
}

// CreateOrg inserts a new organization.
func (r *PgOrgRepo) CreateOrg(ctx context.Context, name string, orgPubKey, encOrgPrivKey []byte) (Organization, error) {
	var org Organization
	err := r.pool.QueryRow(ctx,
		`INSERT INTO organizations (name, org_public_key, encrypted_org_private_key)
		 VALUES ($1, $2, $3)
		 RETURNING id, name, org_public_key, encrypted_org_private_key, created_at`,
		name, orgPubKey, encOrgPrivKey,
	).Scan(&org.ID, &org.Name, &org.OrgPublicKey, &org.EncryptedOrgPrivateKey, &org.CreatedAt)
	if err != nil {
		return Organization{}, fmt.Errorf("insert org: %w", err)
	}
	return org, nil
}

// GetOrg retrieves an organization by ID.
func (r *PgOrgRepo) GetOrg(ctx context.Context, orgID string) (Organization, error) {
	var org Organization
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, org_public_key, encrypted_org_private_key, policy,
		        COALESCE(sso_enabled, false), sso_config,
		        COALESCE(scim_enabled, false), scim_token_hash,
		        created_at
		 FROM organizations WHERE id = $1`, orgID,
	).Scan(&org.ID, &org.Name, &org.OrgPublicKey, &org.EncryptedOrgPrivateKey, &org.Policy,
		&org.SSOEnabled, &org.SSOConfig,
		&org.SCIMEnabled, &org.SCIMTokenHash,
		&org.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Organization{}, fmt.Errorf("organization not found")
		}
		return Organization{}, fmt.Errorf("get org: %w", err)
	}
	return org, nil
}

// AddMember adds a user to an organization.
func (r *PgOrgRepo) AddMember(ctx context.Context, orgID, userID, role string, escrowBlob []byte) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO org_members (org_id, user_id, role, escrow_blob)
		 VALUES ($1, $2, $3, $4)`,
		orgID, userID, role, escrowBlob,
	)
	if err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	return nil
}

// GetMember retrieves a single org membership.
func (r *PgOrgRepo) GetMember(ctx context.Context, orgID, userID string) (OrgMember, error) {
	var m OrgMember
	err := r.pool.QueryRow(ctx,
		`SELECT org_id, user_id, role, joined_at FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, userID,
	).Scan(&m.OrgID, &m.UserID, &m.Role, &m.JoinedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return OrgMember{}, fmt.Errorf("member not found")
		}
		return OrgMember{}, fmt.Errorf("get member: %w", err)
	}
	return m, nil
}

// GetMemberEscrow retrieves the escrow blob for a member.
func (r *PgOrgRepo) GetMemberEscrow(ctx context.Context, orgID, userID string) ([]byte, error) {
	var blob []byte
	err := r.pool.QueryRow(ctx,
		`SELECT escrow_blob FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, userID,
	).Scan(&blob)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("member not found")
		}
		return nil, fmt.Errorf("get escrow: %w", err)
	}
	return blob, nil
}

// GetMemberOrgKey retrieves the per-admin encrypted org key for a member. May return nil.
func (r *PgOrgRepo) GetMemberOrgKey(ctx context.Context, orgID, userID string) ([]byte, error) {
	var blob []byte
	err := r.pool.QueryRow(ctx,
		`SELECT encrypted_org_key FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, userID,
	).Scan(&blob)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("member not found")
		}
		return nil, fmt.Errorf("get member org key: %w", err)
	}
	return blob, nil
}

// SetMemberOrgKey stores the per-admin encrypted org key for a member.
func (r *PgOrgRepo) SetMemberOrgKey(ctx context.Context, orgID, userID string, encOrgKey []byte) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE org_members SET encrypted_org_key = $3 WHERE org_id = $1 AND user_id = $2`,
		orgID, userID, encOrgKey,
	)
	if err != nil {
		return fmt.Errorf("set member org key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}

// ListMembers returns all members of an organization.
func (r *PgOrgRepo) ListMembers(ctx context.Context, orgID string) ([]OrgMember, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT om.org_id, om.user_id, u.email, om.role, om.joined_at
		 FROM org_members om
		 JOIN users u ON u.id = om.user_id
		 WHERE om.org_id = $1
		 ORDER BY om.joined_at`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()

	var members []OrgMember
	for rows.Next() {
		var m OrgMember
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Email, &m.Role, &m.JoinedAt); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// RemoveMember removes a user from an organization.
func (r *PgOrgRepo) RemoveMember(ctx context.Context, orgID, userID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}

// UpdateEscrowBlob updates the escrow blob for a member.
func (r *PgOrgRepo) UpdateEscrowBlob(ctx context.Context, orgID, userID string, escrowBlob []byte) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE org_members SET escrow_blob = $3 WHERE org_id = $1 AND user_id = $2`,
		orgID, userID, escrowBlob,
	)
	if err != nil {
		return fmt.Errorf("update escrow: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}

// CreateInvitation creates an organization invitation.
// If a pending invitation already exists for this org+email, it is replaced.
func (r *PgOrgRepo) CreateInvitation(ctx context.Context, orgID, email, role, invitedBy string) (Invitation, error) {
	// Delete any existing pending invitations for the same org+email
	_, _ = r.pool.Exec(ctx,
		`DELETE FROM invitations WHERE org_id = $1 AND email = $2 AND accepted = false`,
		orgID, email,
	)

	var inv Invitation
	err := r.pool.QueryRow(ctx,
		`INSERT INTO invitations (org_id, email, role, invited_by)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, email, role, invited_by, accepted, created_at`,
		orgID, email, role, invitedBy,
	).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.InvitedBy, &inv.Accepted, &inv.CreatedAt)
	if err != nil {
		return Invitation{}, fmt.Errorf("create invitation: %w", err)
	}
	return inv, nil
}

// GetPendingInvitation retrieves a pending invitation for a user by org and email.
func (r *PgOrgRepo) GetPendingInvitation(ctx context.Context, orgID, email string) (Invitation, error) {
	var inv Invitation
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, email, role, invited_by, accepted, created_at
		 FROM invitations
		 WHERE org_id = $1 AND email = $2 AND accepted = false
		 ORDER BY created_at DESC LIMIT 1`,
		orgID, email,
	).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.InvitedBy, &inv.Accepted, &inv.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Invitation{}, fmt.Errorf("invitation not found")
		}
		return Invitation{}, fmt.Errorf("get invitation: %w", err)
	}
	return inv, nil
}

// MarkInvitationAccepted marks an invitation as accepted.
func (r *PgOrgRepo) MarkInvitationAccepted(ctx context.Context, invID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE invitations SET accepted = true WHERE id = $1`, invID,
	)
	return err
}

// ListInvitations returns all invitations for an organization.
func (r *PgOrgRepo) ListInvitations(ctx context.Context, orgID string) ([]Invitation, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, org_id, email, role, invited_by, accepted, created_at
		 FROM invitations WHERE org_id = $1 ORDER BY created_at DESC`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer rows.Close()

	var invs []Invitation
	for rows.Next() {
		var inv Invitation
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.InvitedBy, &inv.Accepted, &inv.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		invs = append(invs, inv)
	}
	return invs, rows.Err()
}

// SetOrgPolicy updates the policy JSONB column on an organization.
func (r *PgOrgRepo) SetOrgPolicy(ctx context.Context, orgID string, policy json.RawMessage) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE organizations SET policy = $2 WHERE id = $1`,
		orgID, policy,
	)
	if err != nil {
		return fmt.Errorf("set org policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("organization not found")
	}
	return nil
}

// GetUserOrg returns the organization membership for a user (first org found).
func (r *PgOrgRepo) GetUserOrg(ctx context.Context, userID string) (OrgMember, Organization, error) {
	var m OrgMember
	var org Organization
	err := r.pool.QueryRow(ctx,
		`SELECT om.org_id, om.user_id, u.email, om.role, om.joined_at,
		        o.id, o.name, o.org_public_key, o.created_at
		 FROM org_members om
		 JOIN users u ON u.id = om.user_id
		 JOIN organizations o ON o.id = om.org_id
		 WHERE om.user_id = $1
		 LIMIT 1`, userID,
	).Scan(&m.OrgID, &m.UserID, &m.Email, &m.Role, &m.JoinedAt,
		&org.ID, &org.Name, &org.OrgPublicKey, &org.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return OrgMember{}, Organization{}, fmt.Errorf("no org membership")
		}
		return OrgMember{}, Organization{}, fmt.Errorf("get user org: %w", err)
	}
	return m, org, nil
}

// GetInvitationsByEmail returns all pending invitations for an email address.
func (r *PgOrgRepo) GetInvitationsByEmail(ctx context.Context, email string) ([]Invitation, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT i.id, i.org_id, i.email, i.role, i.invited_by, i.accepted, i.created_at
		 FROM invitations i
		 WHERE i.email = $1 AND i.accepted = false
		 ORDER BY i.created_at DESC`, email,
	)
	if err != nil {
		return nil, fmt.Errorf("get invitations by email: %w", err)
	}
	defer rows.Close()

	var invs []Invitation
	for rows.Next() {
		var inv Invitation
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.InvitedBy, &inv.Accepted, &inv.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		invs = append(invs, inv)
	}
	return invs, rows.Err()
}

// SetSSOConfig updates the SSO configuration for an organization.
func (r *PgOrgRepo) SetSSOConfig(ctx context.Context, orgID string, ssoEnabled bool, ssoConfig json.RawMessage) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE organizations SET sso_enabled = $2, sso_config = $3 WHERE id = $1`,
		orgID, ssoEnabled, ssoConfig,
	)
	if err != nil {
		return fmt.Errorf("set sso config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("organization not found")
	}
	return nil
}

// SetSCIMConfig updates the SCIM configuration for an organization.
func (r *PgOrgRepo) SetSCIMConfig(ctx context.Context, orgID string, scimEnabled bool, scimTokenHash []byte) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE organizations SET scim_enabled = $2, scim_token_hash = $3 WHERE id = $1`,
		orgID, scimEnabled, scimTokenHash,
	)
	if err != nil {
		return fmt.Errorf("set scim config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("organization not found")
	}
	return nil
}
