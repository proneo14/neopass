package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SyncCursor represents a sync cursor row.
type SyncCursor struct {
	UserID     string    `json:"user_id"`
	DeviceID   string    `json:"device_id"`
	LastSyncAt time.Time `json:"last_sync_at"`
}

// PgSyncRepo provides database operations for sync cursors (PostgreSQL).
type PgSyncRepo struct {
	pool *pgxpool.Pool
}

// NewPgSyncRepo creates a new PgSyncRepo.
func NewPgSyncRepo(pool *pgxpool.Pool) *PgSyncRepo {
	return &PgSyncRepo{pool: pool}
}

// GetSyncCursor retrieves the last sync timestamp for a user/device pair.
func (r *PgSyncRepo) GetSyncCursor(ctx context.Context, userID, deviceID string) (time.Time, error) {
	var lastSync time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT last_sync_at FROM sync_cursors WHERE user_id = $1 AND device_id = $2`,
		userID, deviceID,
	).Scan(&lastSync)
	if err != nil {
		// Return zero time if no cursor exists
		return time.Time{}, nil
	}
	return lastSync, nil
}

// UpsertSyncCursor creates or updates a sync cursor.
func (r *PgSyncRepo) UpsertSyncCursor(ctx context.Context, userID, deviceID string, syncAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO sync_cursors (user_id, device_id, last_sync_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, device_id)
		 DO UPDATE SET last_sync_at = $3`,
		userID, deviceID, syncAt,
	)
	if err != nil {
		return fmt.Errorf("upsert sync cursor: %w", err)
	}
	return nil
}
