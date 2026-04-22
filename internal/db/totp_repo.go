package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TOTPSecret represents a row in the totp_secrets table.
type TOTPSecret struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	EncryptedSecret []byte    `json:"-"`
	Verified        bool      `json:"verified"`
	CreatedAt       time.Time `json:"created_at"`
}

// SharedTOTP represents a row in the shared_2fa table.
type SharedTOTP struct {
	ID                  string    `json:"id"`
	FromUserID          string    `json:"from_user_id"`
	ToUserID            string    `json:"to_user_id"`
	EncryptedTOTPSecret []byte    `json:"-"`
	ExpiresAt           time.Time `json:"expires_at"`
	Claimed             bool      `json:"claimed"`
	CreatedAt           time.Time `json:"created_at"`
}

// RecoveryCode represents a row in the recovery_codes table.
type RecoveryCode struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	CodeHash []byte `json:"-"`
	Used     bool   `json:"used"`
}

// PgTOTPRepo provides database operations for 2FA (PostgreSQL).
type PgTOTPRepo struct {
	pool *pgxpool.Pool
}

// NewPgTOTPRepo creates a new PgTOTPRepo.
func NewPgTOTPRepo(pool *pgxpool.Pool) *PgTOTPRepo {
	return &PgTOTPRepo{pool: pool}
}

// UpsertTOTPSecret inserts or updates a TOTP secret for a user.
func (r *PgTOTPRepo) UpsertTOTPSecret(ctx context.Context, userID string, encryptedSecret []byte) (string, error) {
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO totp_secrets (user_id, encrypted_secret, verified)
		VALUES ($1, $2, false)
		ON CONFLICT (user_id) DO UPDATE
			SET encrypted_secret = $2, verified = false
		RETURNING id
	`, userID, encryptedSecret).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert totp secret: %w", err)
	}
	return id, nil
}

// GetTOTPSecret retrieves the TOTP secret for a user.
func (r *PgTOTPRepo) GetTOTPSecret(ctx context.Context, userID string) (TOTPSecret, error) {
	var s TOTPSecret
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, encrypted_secret, verified, created_at
		FROM totp_secrets
		WHERE user_id = $1
	`, userID).Scan(&s.ID, &s.UserID, &s.EncryptedSecret, &s.Verified, &s.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TOTPSecret{}, fmt.Errorf("totp not configured")
		}
		return TOTPSecret{}, fmt.Errorf("get totp secret: %w", err)
	}
	return s, nil
}

// MarkTOTPVerified sets the TOTP secret as verified.
func (r *PgTOTPRepo) MarkTOTPVerified(ctx context.Context, userID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE totp_secrets SET verified = true WHERE user_id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("mark totp verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("totp not found")
	}
	return nil
}

// DeleteTOTPSecret removes TOTP and all recovery codes for a user.
func (r *PgTOTPRepo) DeleteTOTPSecret(ctx context.Context, userID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM totp_secrets WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete totp secret: %w", err)
	}

	return tx.Commit(ctx)
}

// InsertRecoveryCodes stores bcrypt-hashed recovery codes for a user.
func (r *PgTOTPRepo) InsertRecoveryCodes(ctx context.Context, userID string, codeHashes [][]byte) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Remove old codes first
	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete old recovery codes: %w", err)
	}

	for _, hash := range codeHashes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO recovery_codes (user_id, code_hash, used) VALUES ($1, $2, false)
		`, userID, hash); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// GetUnusedRecoveryCodes returns all unused recovery code hashes for a user.
func (r *PgTOTPRepo) GetUnusedRecoveryCodes(ctx context.Context, userID string) ([]RecoveryCode, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, code_hash, used
		FROM recovery_codes
		WHERE user_id = $1 AND used = false
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("get recovery codes: %w", err)
	}
	defer rows.Close()

	var codes []RecoveryCode
	for rows.Next() {
		var c RecoveryCode
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &c.Used); err != nil {
			return nil, fmt.Errorf("scan recovery code: %w", err)
		}
		codes = append(codes, c)
	}
	return codes, rows.Err()
}

// MarkRecoveryCodeUsed marks a specific recovery code as used.
func (r *PgTOTPRepo) MarkRecoveryCodeUsed(ctx context.Context, codeID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE recovery_codes SET used = true WHERE id = $1 AND used = false
	`, codeID)
	if err != nil {
		return fmt.Errorf("mark recovery code used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("recovery code not found or already used")
	}
	return nil
}

// InsertSharedTOTP stores an encrypted TOTP secret shared between users.
func (r *PgTOTPRepo) InsertSharedTOTP(ctx context.Context, fromUserID, toUserID string, encryptedSecret []byte, expiresAt time.Time) (string, error) {
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO shared_2fa (from_user_id, to_user_id, encrypted_totp_secret, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, fromUserID, toUserID, encryptedSecret, expiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert shared totp: %w", err)
	}
	return id, nil
}

// GetSharedTOTP retrieves a shared TOTP entry by ID.
func (r *PgTOTPRepo) GetSharedTOTP(ctx context.Context, shareID, toUserID string) (SharedTOTP, error) {
	var s SharedTOTP
	err := r.pool.QueryRow(ctx, `
		SELECT id, from_user_id, to_user_id, encrypted_totp_secret, expires_at, claimed, created_at
		FROM shared_2fa
		WHERE id = $1 AND to_user_id = $2
	`, shareID, toUserID).Scan(
		&s.ID, &s.FromUserID, &s.ToUserID, &s.EncryptedTOTPSecret,
		&s.ExpiresAt, &s.Claimed, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SharedTOTP{}, fmt.Errorf("shared totp not found")
		}
		return SharedTOTP{}, fmt.Errorf("get shared totp: %w", err)
	}
	return s, nil
}

// MarkSharedTOTPClaimed marks a shared TOTP entry as claimed.
func (r *PgTOTPRepo) MarkSharedTOTPClaimed(ctx context.Context, shareID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE shared_2fa SET claimed = true WHERE id = $1
	`, shareID)
	if err != nil {
		return fmt.Errorf("mark shared totp claimed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("shared totp not found")
	}
	return nil
}

// ListPendingSharedTOTP lists unclaimed, non-expired shared TOTPs for a user.
func (r *PgTOTPRepo) ListPendingSharedTOTP(ctx context.Context, toUserID string) ([]SharedTOTP, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, from_user_id, to_user_id, encrypted_totp_secret, expires_at, claimed, created_at
		FROM shared_2fa
		WHERE to_user_id = $1 AND claimed = false AND expires_at > now()
		ORDER BY created_at DESC
	`, toUserID)
	if err != nil {
		return nil, fmt.Errorf("list shared totp: %w", err)
	}
	defer rows.Close()

	var list []SharedTOTP
	for rows.Next() {
		var s SharedTOTP
		if err := rows.Scan(&s.ID, &s.FromUserID, &s.ToUserID, &s.EncryptedTOTPSecret,
			&s.ExpiresAt, &s.Claimed, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan shared totp: %w", err)
		}
		list = append(list, s)
	}
	return list, rows.Err()
}
