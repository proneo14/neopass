package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgEmergencyAccessRepo provides database operations for emergency access (PostgreSQL).
type PgEmergencyAccessRepo struct {
	pool *pgxpool.Pool
}

// NewPgEmergencyAccessRepo creates a new PgEmergencyAccessRepo.
func NewPgEmergencyAccessRepo(pool *pgxpool.Pool) *PgEmergencyAccessRepo {
	return &PgEmergencyAccessRepo{pool: pool}
}

const eaColumns = `id, grantor_id, grantee_id, grantee_email, status, access_type, wait_time_days, encrypted_key, key_nonce, recovery_initiated_at, created_at, updated_at`

func scanEA(row interface{ Scan(dest ...interface{}) error }) (EmergencyAccess, error) {
	var ea EmergencyAccess
	err := row.Scan(&ea.ID, &ea.GrantorID, &ea.GranteeID, &ea.GranteeEmail, &ea.Status,
		&ea.AccessType, &ea.WaitTimeDays, &ea.EncryptedKey, &ea.KeyNonce,
		&ea.RecoveryInitiatedAt, &ea.CreatedAt, &ea.UpdatedAt)
	return ea, err
}

func (r *PgEmergencyAccessRepo) CreateEmergencyAccess(ctx context.Context, ea EmergencyAccess) (EmergencyAccess, error) {
	row := r.pool.QueryRow(ctx,
		`INSERT INTO emergency_access (grantor_id, grantee_id, grantee_email, status, access_type, wait_time_days)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING `+eaColumns,
		ea.GrantorID, ea.GranteeID, ea.GranteeEmail, ea.Status, ea.AccessType, ea.WaitTimeDays,
	)
	out, err := scanEA(row)
	if err != nil {
		return EmergencyAccess{}, fmt.Errorf("create emergency access: %w", err)
	}
	return out, nil
}

func (r *PgEmergencyAccessRepo) GetEmergencyAccess(ctx context.Context, id string) (EmergencyAccess, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+eaColumns+` FROM emergency_access WHERE id = $1`, id)
	out, err := scanEA(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return EmergencyAccess{}, fmt.Errorf("emergency access not found")
		}
		return EmergencyAccess{}, fmt.Errorf("get emergency access: %w", err)
	}
	return out, nil
}

func (r *PgEmergencyAccessRepo) ListGrantedAccess(ctx context.Context, grantorID string) ([]EmergencyAccess, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+eaColumns+` FROM emergency_access WHERE grantor_id = $1 ORDER BY created_at DESC`, grantorID)
	if err != nil {
		return nil, fmt.Errorf("list granted access: %w", err)
	}
	defer rows.Close()

	var results []EmergencyAccess
	for rows.Next() {
		ea, err := scanEA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan emergency access: %w", err)
		}
		results = append(results, ea)
	}
	return results, rows.Err()
}

func (r *PgEmergencyAccessRepo) ListTrustedBy(ctx context.Context, granteeID string) ([]EmergencyAccess, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+eaColumns+` FROM emergency_access WHERE grantee_id = $1 ORDER BY created_at DESC`, granteeID)
	if err != nil {
		return nil, fmt.Errorf("list trusted by: %w", err)
	}
	defer rows.Close()

	var results []EmergencyAccess
	for rows.Next() {
		ea, err := scanEA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan emergency access: %w", err)
		}
		results = append(results, ea)
	}
	return results, rows.Err()
}

func (r *PgEmergencyAccessRepo) UpdateStatus(ctx context.Context, id, status string) error {
	ct, err := r.pool.Exec(ctx,
		`UPDATE emergency_access SET status = $1, updated_at = now() WHERE id = $2`, status, id)
	if err != nil {
		return fmt.Errorf("update emergency access status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("emergency access not found")
	}
	return nil
}

func (r *PgEmergencyAccessRepo) SetEncryptedKey(ctx context.Context, id string, encryptedKey, nonce []byte) error {
	ct, err := r.pool.Exec(ctx,
		`UPDATE emergency_access SET encrypted_key = $1, key_nonce = $2, updated_at = now() WHERE id = $3`,
		encryptedKey, nonce, id)
	if err != nil {
		return fmt.Errorf("set encrypted key: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("emergency access not found")
	}
	return nil
}

func (r *PgEmergencyAccessRepo) InitiateRecovery(ctx context.Context, id string) error {
	ct, err := r.pool.Exec(ctx,
		`UPDATE emergency_access SET status = 'recovery_initiated', recovery_initiated_at = now(), updated_at = now()
		 WHERE id = $1 AND status IN ('accepted', 'recovery_rejected')`, id)
	if err != nil {
		return fmt.Errorf("initiate recovery: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("emergency access not found or not in eligible status")
	}
	return nil
}

func (r *PgEmergencyAccessRepo) DeleteEmergencyAccess(ctx context.Context, id string) error {
	ct, err := r.pool.Exec(ctx,
		`DELETE FROM emergency_access WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete emergency access: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("emergency access not found")
	}
	return nil
}

func (r *PgEmergencyAccessRepo) GetAutoApproveEligible(ctx context.Context) ([]EmergencyAccess, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+eaColumns+` FROM emergency_access
		 WHERE status = 'recovery_initiated'
		   AND recovery_initiated_at + (wait_time_days || ' days')::INTERVAL <= now()`)
	if err != nil {
		return nil, fmt.Errorf("get auto-approve eligible: %w", err)
	}
	defer rows.Close()

	var results []EmergencyAccess
	for rows.Next() {
		ea, err := scanEA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan emergency access: %w", err)
		}
		results = append(results, ea)
	}
	return results, rows.Err()
}

// AutoApproveExpired finds recovery_initiated records past their wait period and marks them approved.
func (r *PgEmergencyAccessRepo) AutoApproveExpired(ctx context.Context) (int, error) {
	ct, err := r.pool.Exec(ctx,
		`UPDATE emergency_access SET status = 'recovery_approved', updated_at = now()
		 WHERE status = 'recovery_initiated'
		   AND recovery_initiated_at + (wait_time_days || ' days')::INTERVAL <= now()`)
	if err != nil {
		return 0, fmt.Errorf("auto-approve expired: %w", err)
	}
	return int(ct.RowsAffected()), nil
}

// ListByGranteeEmail returns emergency access records for a given email (used during accept).
func (r *PgEmergencyAccessRepo) ListByGranteeEmail(ctx context.Context, email string) ([]EmergencyAccess, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+eaColumns+` FROM emergency_access WHERE grantee_email = $1 AND status = 'invited' ORDER BY created_at DESC`, email)
	if err != nil {
		return nil, fmt.Errorf("list by grantee email: %w", err)
	}
	defer rows.Close()

	var results []EmergencyAccess
	for rows.Next() {
		ea, err := scanEA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan emergency access: %w", err)
		}
		results = append(results, ea)
	}
	return results, rows.Err()
}

// SetGranteeID links a grantee user account to an emergency access record.
func (r *PgEmergencyAccessRepo) SetGranteeID(ctx context.Context, id, granteeID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE emergency_access SET grantee_id = $1, updated_at = now() WHERE id = $2`,
		granteeID, id)
	if err != nil {
		return fmt.Errorf("set grantee id: %w", err)
	}
	return nil
}

// GetVaultEntries returns the grantor's encrypted vault entries for emergency access viewing.
func (r *PgEmergencyAccessRepo) GetVaultEntries(ctx context.Context, grantorID string) ([]VaultEntry, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id,
		        is_deleted, is_favorite, is_archived, deleted_at, created_at, updated_at
		 FROM vault_entries WHERE user_id = $1 AND is_deleted = false
		 ORDER BY updated_at DESC`, grantorID)
	if err != nil {
		return nil, fmt.Errorf("get vault entries for emergency access: %w", err)
	}
	defer rows.Close()

	var entries []VaultEntry
	for rows.Next() {
		var e VaultEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.OrgID, &e.EntryType, &e.EncryptedData, &e.Nonce,
			&e.Version, &e.FolderID, &e.IsDeleted, &e.IsFavorite, &e.IsArchived, &e.DeletedAt,
			&e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan vault entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
