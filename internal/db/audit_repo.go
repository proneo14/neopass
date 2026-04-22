package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEntry represents an audit log row.
type AuditEntry struct {
	ID        string          `json:"id"`
	ActorID   *string         `json:"actor_id,omitempty"`
	TargetID  *string         `json:"target_id,omitempty"`
	Action    string          `json:"action"`
	Details   json.RawMessage `json:"details,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// AuditFilters defines optional filters for querying the audit log.
type AuditFilters struct {
	ActorID  string
	TargetID string
	Action   string
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}

// PgAuditRepo provides database operations for the audit log (PostgreSQL).
type PgAuditRepo struct {
	pool *pgxpool.Pool
}

// NewPgAuditRepo creates a new PgAuditRepo.
func NewPgAuditRepo(pool *pgxpool.Pool) *PgAuditRepo {
	return &PgAuditRepo{pool: pool}
}

// LogAction inserts an audit log entry.
func (r *PgAuditRepo) LogAction(ctx context.Context, actorID, targetID *string, action string, details json.RawMessage) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO audit_log (actor_id, target_id, action, details) VALUES ($1, $2, $3, $4)`,
		actorID, targetID, action, details,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

// GetAuditLog returns audit log entries matching the given filters.
func (r *PgAuditRepo) GetAuditLog(ctx context.Context, filters AuditFilters) ([]AuditEntry, error) {
	query := `SELECT id, actor_id, target_id, action, details, created_at FROM audit_log WHERE 1=1` // #nosec G201 -- only integer placeholders interpolated via Sprintf
	args := []interface{}{}
	argIdx := 1

	if filters.ActorID != "" {
		query += fmt.Sprintf(" AND actor_id = $%d", argIdx)
		args = append(args, filters.ActorID)
		argIdx++
	}
	if filters.TargetID != "" {
		query += fmt.Sprintf(" AND target_id = $%d", argIdx)
		args = append(args, filters.TargetID)
		argIdx++
	}
	if filters.Action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIdx)
		args = append(args, filters.Action)
		argIdx++
	}
	if filters.From != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", argIdx)
		args = append(args, *filters.From)
		argIdx++
	}
	if filters.To != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", argIdx)
		args = append(args, *filters.To)
		argIdx++
	}

	query += " ORDER BY created_at DESC"

	limit := filters.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, limit)
	argIdx++

	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filters.Offset)
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.ActorID, &e.TargetID, &e.Action, &e.Details, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
