package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgWebhookRepo implements WebhookRepository for PostgreSQL.
type PgWebhookRepo struct {
	pool *pgxpool.Pool
}

// NewPgWebhookRepo creates a new PgWebhookRepo.
func NewPgWebhookRepo(pool *pgxpool.Pool) *PgWebhookRepo {
	return &PgWebhookRepo{pool: pool}
}

func (r *PgWebhookRepo) CreateWebhook(ctx context.Context, webhook Webhook) (Webhook, error) {
	var out Webhook
	err := r.pool.QueryRow(ctx,
		`INSERT INTO webhooks (org_id, url, events, secret_hash, enabled)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, url, events, enabled, created_at`,
		webhook.OrgID, webhook.URL, webhook.Events, webhook.SecretHash, webhook.Enabled,
	).Scan(&out.ID, &out.OrgID, &out.URL, &out.Events, &out.Enabled, &out.CreatedAt)
	if err != nil {
		return Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	return out, nil
}

func (r *PgWebhookRepo) GetWebhook(ctx context.Context, webhookID string) (Webhook, error) {
	var w Webhook
	err := r.pool.QueryRow(ctx,
		`SELECT id, org_id, url, events, secret_hash, enabled, created_at
		 FROM webhooks WHERE id = $1`, webhookID,
	).Scan(&w.ID, &w.OrgID, &w.URL, &w.Events, &w.SecretHash, &w.Enabled, &w.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Webhook{}, fmt.Errorf("webhook not found")
		}
		return Webhook{}, fmt.Errorf("get webhook: %w", err)
	}
	return w, nil
}

func (r *PgWebhookRepo) ListWebhooks(ctx context.Context, orgID string) ([]Webhook, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, org_id, url, events, enabled, created_at
		 FROM webhooks WHERE org_id = $1 ORDER BY created_at DESC`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []Webhook
	for rows.Next() {
		var w Webhook
		if err := rows.Scan(&w.ID, &w.OrgID, &w.URL, &w.Events, &w.Enabled, &w.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, rows.Err()
}

func (r *PgWebhookRepo) DeleteWebhook(ctx context.Context, webhookID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM webhooks WHERE id = $1`, webhookID)
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("webhook not found")
	}
	return nil
}

func (r *PgWebhookRepo) SetWebhookEnabled(ctx context.Context, webhookID string, enabled bool) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE webhooks SET enabled = $2 WHERE id = $1`, webhookID, enabled,
	)
	if err != nil {
		return fmt.Errorf("set webhook enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("webhook not found")
	}
	return nil
}

// GetMatchingWebhooks returns all enabled webhooks for an org that match a given action.
// A webhook matches if its events array contains the action or '*'.
func (r *PgWebhookRepo) GetMatchingWebhooks(ctx context.Context, orgID, action string) ([]Webhook, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, org_id, url, events, secret_hash, enabled, created_at
		 FROM webhooks
		 WHERE org_id = $1 AND enabled = true
		   AND ($2 = ANY(events) OR '*' = ANY(events))`,
		orgID, action,
	)
	if err != nil {
		return nil, fmt.Errorf("get matching webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []Webhook
	for rows.Next() {
		var w Webhook
		if err := rows.Scan(&w.ID, &w.OrgID, &w.URL, &w.Events, &w.SecretHash, &w.Enabled, &w.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, rows.Err()
}

func (r *PgWebhookRepo) CreateDelivery(ctx context.Context, delivery WebhookDelivery) (WebhookDelivery, error) {
	var out WebhookDelivery
	err := r.pool.QueryRow(ctx,
		`INSERT INTO webhook_deliveries (webhook_id, event_id, status, response_code, attempts, last_attempt_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, webhook_id, event_id, status, response_code, attempts, last_attempt_at, created_at`,
		delivery.WebhookID, delivery.EventID, delivery.Status, delivery.ResponseCode, delivery.Attempts, delivery.LastAttemptAt,
	).Scan(&out.ID, &out.WebhookID, &out.EventID, &out.Status, &out.ResponseCode, &out.Attempts, &out.LastAttemptAt, &out.CreatedAt)
	if err != nil {
		return WebhookDelivery{}, fmt.Errorf("create delivery: %w", err)
	}
	return out, nil
}

func (r *PgWebhookRepo) UpdateDelivery(ctx context.Context, deliveryID, status string, responseCode *int) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE webhook_deliveries
		 SET status = $2, response_code = $3, attempts = attempts + 1, last_attempt_at = now()
		 WHERE id = $1`,
		deliveryID, status, responseCode,
	)
	if err != nil {
		return fmt.Errorf("update delivery: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("delivery not found")
	}
	return nil
}

func (r *PgWebhookRepo) ListRecentDeliveries(ctx context.Context, webhookID string, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, webhook_id, event_id, status, response_code, attempts, last_attempt_at, created_at
		 FROM webhook_deliveries
		 WHERE webhook_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`, webhookID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list recent deliveries: %w", err)
	}
	defer rows.Close()

	var deliveries []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventID, &d.Status, &d.ResponseCode, &d.Attempts, &d.LastAttemptAt, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}

func (r *PgWebhookRepo) GetPendingDeliveries(ctx context.Context, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, webhook_id, event_id, status, response_code, attempts, last_attempt_at, created_at
		 FROM webhook_deliveries
		 WHERE status = 'pending' AND attempts < 3
		 ORDER BY created_at ASC
		 LIMIT $1`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("get pending deliveries: %w", err)
	}
	defer rows.Close()

	var deliveries []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventID, &d.Status, &d.ResponseCode, &d.Attempts, &d.LastAttemptAt, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}
