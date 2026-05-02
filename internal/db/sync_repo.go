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

// ListDevices returns all sync cursors for a user.
func (r *PgSyncRepo) ListDevices(ctx context.Context, userID string) ([]SyncCursor, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT user_id, device_id, last_sync_at FROM sync_cursors WHERE user_id = $1 ORDER BY last_sync_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
	var devices []SyncCursor
	for rows.Next() {
		var d SyncCursor
		if err := rows.Scan(&d.UserID, &d.DeviceID, &d.LastSyncAt); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// DeleteDevice removes a sync cursor for a specific device.
func (r *PgSyncRepo) DeleteDevice(ctx context.Context, userID, deviceID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM sync_cursors WHERE user_id = $1 AND device_id = $2`,
		userID, deviceID,
	)
	if err != nil {
		return fmt.Errorf("delete device: %w", err)
	}
	return nil
}
