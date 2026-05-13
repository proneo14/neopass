package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/password-manager/password-manager/internal/db"
)

// SIEMHandler handles SIEM/webhook HTTP endpoints.
type SIEMHandler struct {
	webhookRepo db.WebhookRepository
	auditRepo   db.AuditRepository
	orgRepo     db.OrgRepository
	userRepo    db.UserRepository
	roleRepo    db.RoleRepository
}

// NewSIEMHandler creates a new SIEMHandler.
func NewSIEMHandler(webhookRepo db.WebhookRepository, auditRepo db.AuditRepository, orgRepo db.OrgRepository, userRepo db.UserRepository, roleRepo db.RoleRepository) *SIEMHandler {
	return &SIEMHandler{
		webhookRepo: webhookRepo,
		auditRepo:   auditRepo,
		orgRepo:     orgRepo,
		userRepo:    userRepo,
		roleRepo:    roleRepo,
	}
}

// ExportEvents handles GET /api/v1/admin/orgs/{id}/events/export
// Exports audit logs in structured format (JSON/CEF/Syslog).
func (h *SIEMHandler) ExportEvents(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	if _, err := CheckPermission(r.Context(), h.roleRepo, h.orgRepo, orgID, claims.UserID, "org.audit"); err != nil {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	filters := db.AuditFilters{
		Limit: 1000,
	}
	if since := r.URL.Query().Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since: use RFC3339")
			return
		}
		filters.From = &t
	}
	if until := r.URL.Query().Get("until"); until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid until: use RFC3339")
			return
		}
		filters.To = &t
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 10000 {
			filters.Limit = v
		}
	}

	entries, err := h.auditRepo.GetAuditLog(r.Context(), filters)
	if err != nil {
		log.Error().Err(err).Msg("export events failed")
		writeError(w, http.StatusInternalServerError, "failed to export events")
		return
	}

	switch format {
	case "json":
		h.exportJSON(w, entries)
	case "cef":
		h.exportCEF(w, entries)
	case "syslog":
		h.exportSyslog(w, entries)
	default:
		writeError(w, http.StatusBadRequest, "unsupported format: use json, cef, or syslog")
	}
}

func (h *SIEMHandler) exportJSON(w http.ResponseWriter, entries []db.AuditEntry) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=events.ndjson")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	for _, e := range entries {
		_ = enc.Encode(e)
	}
}

func (h *SIEMHandler) exportCEF(w http.ResponseWriter, entries []db.AuditEntry) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=events.cef")
	w.WriteHeader(http.StatusOK)

	for _, e := range entries {
		severity := eventSeverity(e.Action)
		actorID := ""
		if e.ActorID != nil {
			actorID = *e.ActorID
		}
		targetID := ""
		if e.TargetID != nil {
			targetID = *e.TargetID
		}
		line := fmt.Sprintf("CEF:0|NeoPass||1.0|%s|%s|%d|src=%s dst=%s rt=%s\n",
			e.Action, e.Action, severity, actorID, targetID,
			e.CreatedAt.Format(time.RFC3339))
		_, _ = w.Write([]byte(line))
	}
}

func (h *SIEMHandler) exportSyslog(w http.ResponseWriter, entries []db.AuditEntry) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=events.log")
	w.WriteHeader(http.StatusOK)

	for _, e := range entries {
		severity := eventSeverity(e.Action)
		pri := 8*14 + severity // facility=14(log audit), severity
		actorID := ""
		if e.ActorID != nil {
			actorID = *e.ActorID
		}
		details := ""
		if e.Details != nil {
			details = string(e.Details)
		}
		line := fmt.Sprintf("<%d>1 %s neopass - %s - [action=\"%s\" actor=\"%s\"] %s\n",
			pri, e.CreatedAt.Format(time.RFC3339Nano), e.ID, e.Action, actorID, details)
		_, _ = w.Write([]byte(line))
	}
}

func eventSeverity(action string) int {
	switch {
	case strings.Contains(action, "vault_accessed"), strings.Contains(action, "password_changed"):
		return 2 // critical
	case strings.Contains(action, "removed"), strings.Contains(action, "policy"),
		strings.Contains(action, "deleted"), strings.Contains(action, "takeover"):
		return 4 // warning
	default:
		return 6 // informational
	}
}

// CreateWebhook handles POST /api/v1/admin/orgs/{id}/webhooks
func (h *SIEMHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	if _, err := CheckPermission(r.Context(), h.roleRepo, h.orgRepo, orgID, claims.UserID, "org.audit"); err != nil {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var body struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
		Secret string   `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.URL == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}
	if body.Secret == "" {
		// Auto-generate a secret
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate secret")
			return
		}
		body.Secret = hex.EncodeToString(secretBytes)
	}
	if len(body.Events) == 0 {
		body.Events = []string{"*"}
	}

	secretHash, err := bcrypt.GenerateFromPassword([]byte(body.Secret), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash secret")
		return
	}

	webhook, err := h.webhookRepo.CreateWebhook(r.Context(), db.Webhook{
		OrgID:      orgID,
		URL:        body.URL,
		Events:     body.Events,
		SecretHash: secretHash,
		Enabled:    true,
	})
	if err != nil {
		log.Error().Err(err).Msg("create webhook failed")
		writeError(w, http.StatusInternalServerError, "failed to create webhook")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":      webhook.ID,
		"url":     webhook.URL,
		"events":  webhook.Events,
		"secret":  body.Secret,
		"warning": "The secret will not be shown again. Store it securely.",
	})
}

// ListWebhooks handles GET /api/v1/admin/orgs/{id}/webhooks
func (h *SIEMHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	if _, err := CheckPermission(r.Context(), h.roleRepo, h.orgRepo, orgID, claims.UserID, "org.audit"); err != nil {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	webhooks, err := h.webhookRepo.ListWebhooks(r.Context(), orgID)
	if err != nil {
		log.Error().Err(err).Msg("list webhooks failed")
		writeError(w, http.StatusInternalServerError, "failed to list webhooks")
		return
	}
	if webhooks == nil {
		webhooks = []db.Webhook{}
	}

	// Also fetch recent deliveries for each webhook
	type webhookWithDeliveries struct {
		db.Webhook
		RecentDeliveries []db.WebhookDelivery `json:"recent_deliveries"`
	}

	result := make([]webhookWithDeliveries, 0, len(webhooks))
	for _, wh := range webhooks {
		deliveries, _ := h.webhookRepo.ListRecentDeliveries(r.Context(), wh.ID, 5)
		if deliveries == nil {
			deliveries = []db.WebhookDelivery{}
		}
		result = append(result, webhookWithDeliveries{
			Webhook:          wh,
			RecentDeliveries: deliveries,
		})
	}

	writeJSON(w, http.StatusOK, result)
}

// DeleteWebhook handles DELETE /api/v1/admin/orgs/{id}/webhooks/{webhookId}
func (h *SIEMHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	if _, err := CheckPermission(r.Context(), h.roleRepo, h.orgRepo, orgID, claims.UserID, "org.audit"); err != nil {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	webhookID := chi.URLParam(r, "webhookId")
	if err := h.webhookRepo.DeleteWebhook(r.Context(), webhookID); err != nil {
		log.Error().Err(err).Msg("delete webhook failed")
		writeError(w, http.StatusInternalServerError, "failed to delete webhook")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ToggleWebhook handles PUT /api/v1/admin/orgs/{id}/webhooks/{webhookId}/toggle
func (h *SIEMHandler) ToggleWebhook(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	if _, err := CheckPermission(r.Context(), h.roleRepo, h.orgRepo, orgID, claims.UserID, "org.audit"); err != nil {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	webhookID := chi.URLParam(r, "webhookId")

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.webhookRepo.SetWebhookEnabled(r.Context(), webhookID, body.Enabled); err != nil {
		log.Error().Err(err).Msg("toggle webhook failed")
		writeError(w, http.StatusInternalServerError, "failed to toggle webhook")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "updated", "enabled": body.Enabled})
}

// TestWebhook handles POST /api/v1/admin/orgs/{id}/webhooks/{webhookId}/test
func (h *SIEMHandler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	orgID := chi.URLParam(r, "id")
	if _, err := CheckPermission(r.Context(), h.roleRepo, h.orgRepo, orgID, claims.UserID, "org.audit"); err != nil {
		writeError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	webhookID := chi.URLParam(r, "webhookId")
	webhook, err := h.webhookRepo.GetWebhook(r.Context(), webhookID)
	if err != nil {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	testPayload := map[string]interface{}{
		"event":     "webhook_test",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"actor":     claims.UserID,
		"org_id":    orgID,
		"details":   map[string]string{"message": "This is a test event from NeoPass"},
	}

	payloadBytes, _ := json.Marshal(testPayload)
	statusCode, err := deliverWebhook(webhook.URL, webhook.SecretHash, payloadBytes)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":       statusCode >= 200 && statusCode < 300,
		"response_code": statusCode,
	})
}

// --- Webhook Delivery System ---

// WebhookDeliveryService handles async webhook delivery.
type WebhookDeliveryService struct {
	webhookRepo db.WebhookRepository
	auditRepo   db.AuditRepository
}

// NewWebhookDeliveryService creates a new webhook delivery service.
func NewWebhookDeliveryService(webhookRepo db.WebhookRepository, auditRepo db.AuditRepository) *WebhookDeliveryService {
	return &WebhookDeliveryService{
		webhookRepo: webhookRepo,
		auditRepo:   auditRepo,
	}
}

// TriggerWebhooks finds matching webhooks for an audit event and queues deliveries.
// Called asynchronously after an audit log entry is created.
func (s *WebhookDeliveryService) TriggerWebhooks(ctx context.Context, orgID, eventID, action string, payload json.RawMessage) {
	webhooks, err := s.webhookRepo.GetMatchingWebhooks(ctx, orgID, action)
	if err != nil || len(webhooks) == 0 {
		return
	}

	for _, wh := range webhooks {
		delivery, err := s.webhookRepo.CreateDelivery(ctx, db.WebhookDelivery{
			WebhookID: wh.ID,
			EventID:   eventID,
			Status:    "pending",
			Attempts:  0,
		})
		if err != nil {
			log.Error().Err(err).Str("webhook_id", wh.ID).Msg("failed to create webhook delivery")
			continue
		}

		// Attempt delivery in a goroutine (intentionally detached from request context)
		go s.attemptDelivery(context.Background(), wh, delivery.ID, payload) // #nosec G118 -- webhook delivery must outlive the HTTP request
	}
}

func (s *WebhookDeliveryService) attemptDelivery(ctx context.Context, webhook db.Webhook, deliveryID string, payload json.RawMessage) {
	delays := []time.Duration{0, 1 * time.Second, 5 * time.Second, 30 * time.Second}

	for attempt, delay := range delays {
		if attempt > 0 {
			time.Sleep(delay)
		}

		statusCode, err := deliverWebhook(webhook.URL, webhook.SecretHash, payload)
		if err != nil {
			log.Warn().Err(err).Str("webhook_id", webhook.ID).Int("attempt", attempt+1).Msg("webhook delivery failed")
			if attempt == len(delays)-1 {
				_ = s.webhookRepo.UpdateDelivery(ctx, deliveryID, "failed", nil)
			}
			continue
		}

		status := "delivered"
		if statusCode < 200 || statusCode >= 300 {
			status = "failed"
		}
		_ = s.webhookRepo.UpdateDelivery(ctx, deliveryID, status, &statusCode)
		return
	}
}

// deliverWebhook sends a payload to a webhook URL with HMAC-SHA256 signature.
func deliverWebhook(url string, secretHash, payload []byte) (int, error) {
	// Sign payload with HMAC-SHA256
	// Note: we use the bcrypt hash as the HMAC key material (deterministic per webhook)
	mac := hmac.New(sha256.New, secretHash)
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NeoPass-Signature", signature)
	req.Header.Set("User-Agent", "NeoPass-Webhook/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("deliver webhook: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp.StatusCode, nil
}
