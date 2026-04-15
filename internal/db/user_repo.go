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
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

// KDFParams represents the Argon2id parameters stored per user.
type KDFParams struct {
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// UserRepo provides database operations for users.
type UserRepo struct {
	pool *pgxpool.Pool
}

// NewUserRepo creates a new UserRepo.
func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

// CreateUser inserts a new user and returns the created user.
func (r *UserRepo) CreateUser(
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
func (r *UserRepo) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.auth_hash, u.salt, u.kdf_params,
		       u.public_key, u.encrypted_private_key, u.created_at, u.updated_at,
		       EXISTS(SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id AND t.verified = true) AS has_2fa
		FROM users u
		WHERE u.email = $1
	`, email).Scan(
		&u.ID, &u.Email, &u.AuthHash, &u.Salt, &u.KDFParams,
		&u.PublicKey, &u.EncryptedPrivateKey, &u.CreatedAt, &u.UpdatedAt,
		&u.Has2FA,
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
func (r *UserRepo) GetUserByID(ctx context.Context, id string) (User, error) {
	var u User
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.auth_hash, u.salt, u.kdf_params,
		       u.public_key, u.encrypted_private_key, u.created_at, u.updated_at,
		       EXISTS(SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id AND t.verified = true) AS has_2fa
		FROM users u
		WHERE u.id = $1
	`, id).Scan(
		&u.ID, &u.Email, &u.AuthHash, &u.Salt, &u.KDFParams,
		&u.PublicKey, &u.EncryptedPrivateKey, &u.CreatedAt, &u.UpdatedAt,
		&u.Has2FA,
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
func (r *UserRepo) UpdateUserKeys(
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
