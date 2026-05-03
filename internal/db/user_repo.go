package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// User represents a user row in the database.
type User struct {
	ID                  string          `json:"id"`
	Email               string          `json:"email"`
	AuthHash            []byte          `json:"-"`
	Salt                []byte          `json:"-"`
	KDFParams           json.RawMessage `json:"kdf_params"`
	PublicKey           []byte          `json:"public_key,omitempty"`
	EncryptedPrivateKey []byte          `json:"-"`
	Has2FA              bool            `json:"has_2fa"`
	RequireHWKey        bool            `json:"require_hw_key"`
	SSOExternalID       *string         `json:"sso_external_id,omitempty"`
	TokensRevokedAt     *time.Time      `json:"tokens_revoked_at,omitempty"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

// KDFParams represents the Argon2id parameters stored per user.
type KDFParams struct {
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// PgUserRepo provides database operations for users (PostgreSQL).
type PgUserRepo struct {
	pool *pgxpool.Pool
}

// NewPgUserRepo creates a new PgUserRepo.
func NewPgUserRepo(pool *pgxpool.Pool) *PgUserRepo {
	return &PgUserRepo{pool: pool}
}

// CreateUser inserts a new user and returns the created user.
func (r *PgUserRepo) CreateUser(
	ctx context.Context,
	email string,
	authHash []byte,
	salt []byte,
	kdfParams json.RawMessage,
	publicKey []byte,
	encryptedPrivateKey []byte,
) (User, error) {
	var u User
	err := r.pool.QueryRow(ctx, `
		INSERT INTO users (email, auth_hash, salt, kdf_params, public_key, encrypted_private_key)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, email, kdf_params, public_key, created_at, updated_at
	`, email, authHash, salt, kdfParams, publicKey, encryptedPrivateKey,
	).Scan(&u.ID, &u.Email, &u.KDFParams, &u.PublicKey, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// GetUserByEmail retrieves a user by email address.
func (r *PgUserRepo) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.auth_hash, u.salt, u.kdf_params,
		       u.public_key, u.encrypted_private_key, u.created_at, u.updated_at,
		       EXISTS(SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id AND t.verified = true) AS has_2fa,
		       COALESCE(u.require_hw_key, false),
		       u.tokens_revoked_at,
		       u.sso_external_id
		FROM users u
		WHERE u.email = $1
	`, email).Scan(
		&u.ID, &u.Email, &u.AuthHash, &u.Salt, &u.KDFParams,
		&u.PublicKey, &u.EncryptedPrivateKey, &u.CreatedAt, &u.UpdatedAt,
		&u.Has2FA, &u.RequireHWKey, &u.TokensRevokedAt, &u.SSOExternalID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, fmt.Errorf("user not found")
		}
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// GetUserByID retrieves a user by ID.
func (r *PgUserRepo) GetUserByID(ctx context.Context, id string) (User, error) {
	var u User
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.auth_hash, u.salt, u.kdf_params,
		       u.public_key, u.encrypted_private_key, u.created_at, u.updated_at,
		       EXISTS(SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id AND t.verified = true) AS has_2fa,
		       COALESCE(u.require_hw_key, false),
		       u.tokens_revoked_at,
		       u.sso_external_id
		FROM users u
		WHERE u.id = $1
	`, id).Scan(
		&u.ID, &u.Email, &u.AuthHash, &u.Salt, &u.KDFParams,
		&u.PublicKey, &u.EncryptedPrivateKey, &u.CreatedAt, &u.UpdatedAt,
		&u.Has2FA, &u.RequireHWKey, &u.TokensRevokedAt, &u.SSOExternalID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, fmt.Errorf("user not found")
		}
		return User{}, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// UpdateUserKeys updates a user's authentication and encryption keys.
func (r *PgUserRepo) UpdateUserKeys(
	ctx context.Context,
	id string,
	authHash []byte,
	salt []byte,
	publicKey []byte,
	encryptedPrivateKey []byte,
) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users
		SET auth_hash = $2, salt = $3, public_key = $4, encrypted_private_key = $5
		WHERE id = $1
	`, id, authHash, salt, publicKey, encryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("update user keys: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// SetRequireHWKey updates a user's hardware key requirement.
func (r *PgUserRepo) SetRequireHWKey(ctx context.Context, userID string, require bool) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET require_hw_key = $2 WHERE id = $1
	`, userID, require)
	if err != nil {
		return fmt.Errorf("set require_hw_key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// RevokeUserTokens sets tokens_revoked_at to now, invalidating all existing JWTs for this user.
func (r *PgUserRepo) RevokeUserTokens(ctx context.Context, userID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET tokens_revoked_at = now() WHERE id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("revoke user tokens: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// GetUserBySSOExternalID retrieves a user by their SSO external ID.
func (r *PgUserRepo) GetUserBySSOExternalID(ctx context.Context, externalID string) (User, error) {
	var u User
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.auth_hash, u.salt, u.kdf_params,
		       u.public_key, u.encrypted_private_key, u.created_at, u.updated_at,
		       EXISTS(SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id AND t.verified = true) AS has_2fa,
		       COALESCE(u.require_hw_key, false),
		       u.tokens_revoked_at,
		       u.sso_external_id
		FROM users u
		WHERE u.sso_external_id = $1
	`, externalID).Scan(
		&u.ID, &u.Email, &u.AuthHash, &u.Salt, &u.KDFParams,
		&u.PublicKey, &u.EncryptedPrivateKey, &u.CreatedAt, &u.UpdatedAt,
		&u.Has2FA, &u.RequireHWKey, &u.TokensRevokedAt, &u.SSOExternalID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, fmt.Errorf("user not found")
		}
		return User{}, fmt.Errorf("get user by sso external id: %w", err)
	}
	return u, nil
}

// SetSSOExternalID sets the SSO external ID for a user.
func (r *PgUserRepo) SetSSOExternalID(ctx context.Context, userID, externalID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET sso_external_id = $2 WHERE id = $1
	`, userID, externalID)
	if err != nil {
		return fmt.Errorf("set sso external id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}
