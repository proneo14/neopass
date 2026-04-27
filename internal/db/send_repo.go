package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgSendRepo provides database operations for Secure Send (PostgreSQL).
type PgSendRepo struct {
	pool *pgxpool.Pool
}

// NewPgSendRepo creates a new PgSendRepo.
func NewPgSendRepo(pool *pgxpool.Pool) *PgSendRepo {
	return &PgSendRepo{pool: pool}
}

const sendColumns = `id, user_id, slug, send_type, encrypted_data, nonce, encrypted_name, name_nonce, password_hash, max_access_count, access_count, file_name, file_size, expires_at, disabled, hide_email, created_at`

func scanSend(row interface{ Scan(dest ...interface{}) error }) (Send, error) {
	var s Send
	err := row.Scan(&s.ID, &s.UserID, &s.Slug, &s.SendType, &s.EncryptedData, &s.Nonce,
		&s.EncryptedName, &s.NameNonce, &s.PasswordHash, &s.MaxAccessCount, &s.AccessCount,
		&s.FileName, &s.FileSize, &s.ExpiresAt, &s.Disabled, &s.HideEmail, &s.CreatedAt)
	if err == nil {
		s.HasPassword = len(s.PasswordHash) > 0
	}
	return s, err
}

func (r *PgSendRepo) CreateSend(ctx context.Context, send Send) (Send, error) {
	row := r.pool.QueryRow(ctx,
		`INSERT INTO sends (slug, user_id, send_type, encrypted_data, nonce, encrypted_name, name_nonce, password_hash, max_access_count, file_name, file_size, expires_at, hide_email)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 RETURNING `+sendColumns,
		send.Slug, send.UserID, send.SendType, send.EncryptedData, send.Nonce,
		send.EncryptedName, send.NameNonce, send.PasswordHash, send.MaxAccessCount,
		send.FileName, send.FileSize, send.ExpiresAt, send.HideEmail,
	)
	out, err := scanSend(row)
	if err != nil {
		return Send{}, fmt.Errorf("create send: %w", err)
	}
	return out, nil
}

func (r *PgSendRepo) GetSendBySlug(ctx context.Context, slug string) (Send, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+sendColumns+` FROM sends WHERE slug = $1`, slug)
	out, err := scanSend(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Send{}, fmt.Errorf("send not found")
		}
		return Send{}, fmt.Errorf("get send by slug: %w", err)
	}
	return out, nil
}

func (r *PgSendRepo) ListSends(ctx context.Context, userID string) ([]Send, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+sendColumns+` FROM sends WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list sends: %w", err)
	}
	defer rows.Close()

	var sends []Send
	for rows.Next() {
		s, err := scanSend(rows)
		if err != nil {
			return nil, fmt.Errorf("scan send: %w", err)
		}
		sends = append(sends, s)
	}
	return sends, rows.Err()
}

func (r *PgSendRepo) IncrementAccessCount(ctx context.Context, sendID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE sends SET access_count = access_count + 1 WHERE id = $1`, sendID)
	if err != nil {
		return fmt.Errorf("increment access count: %w", err)
	}
	return nil
}

func (r *PgSendRepo) DeleteSend(ctx context.Context, sendID, userID string) error {
	ct, err := r.pool.Exec(ctx,
		`DELETE FROM sends WHERE id = $1 AND user_id = $2`, sendID, userID)
	if err != nil {
		return fmt.Errorf("delete send: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("send not found")
	}
	return nil
}

func (r *PgSendRepo) DisableSend(ctx context.Context, sendID, userID string) error {
	ct, err := r.pool.Exec(ctx,
		`UPDATE sends SET disabled = true WHERE id = $1 AND user_id = $2`, sendID, userID)
	if err != nil {
		return fmt.Errorf("disable send: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("send not found")
	}
	return nil
}

func (r *PgSendRepo) PurgeExpiredSends(ctx context.Context) (int, error) {
	ct, err := r.pool.Exec(ctx,
		`DELETE FROM sends WHERE expires_at < $1`, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("purge expired sends: %w", err)
	}
	return int(ct.RowsAffected()), nil
}
