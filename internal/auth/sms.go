package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SMS 2FA errors
var (
	ErrSMSNotEnabled  = fmt.Errorf("sms 2fa not enabled")
	ErrSMSCodeExpired = fmt.Errorf("sms code expired")
	ErrSMSCodeInvalid = fmt.Errorf("invalid sms code")
)

// SMSConfig holds Telnyx API configuration.
type SMSConfig struct {
	Enabled    bool
	APIKey     string
	FromNumber string // Telnyx phone number or messaging profile ID
	APIURL     string // defaults to https://api.telnyx.com/v2/messages
}

// smsCodeEntry stores a pending SMS verification code.
type smsCodeEntry struct {
	code      string
	expiresAt time.Time
}

// SMSService provides SMS-based 2FA via Telnyx.
type SMSService struct {
	config     SMSConfig
	httpClient *http.Client
	mu         sync.Mutex
	pending    map[string]*smsCodeEntry // keyed by userID
}

// NewSMSService creates a new SMSService.
func NewSMSService(cfg SMSConfig) *SMSService {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.telnyx.com/v2/messages"
	}

	svc := &SMSService{
		config:     cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		pending:    make(map[string]*smsCodeEntry),
	}

	// Background cleanup of expired codes
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			svc.cleanup()
		}
	}()

	return svc
}

// SendSMS2FA generates a 6-digit code and sends it via Telnyx SMS.
func (s *SMSService) SendSMS2FA(ctx context.Context, userID string, phoneNumber string) error {
	if !s.config.Enabled {
		return ErrSMSNotEnabled
	}

	code, err := generateNumericCode(6)
	if err != nil {
		return fmt.Errorf("generate sms code: %w", err)
	}

	// Store pending code (5 minute expiry)
	s.mu.Lock()
	s.pending[userID] = &smsCodeEntry{
		code:      code,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	s.mu.Unlock()

	// Send via Telnyx
	if err := s.sendTelnyxSMS(ctx, phoneNumber, fmt.Sprintf("Your verification code is: %s", code)); err != nil {
		// Remove pending code on send failure
		s.mu.Lock()
		delete(s.pending, userID)
		s.mu.Unlock()
		return fmt.Errorf("send sms: %w", err)
	}

	log.Info().Str("user_id", userID).Msg("SMS 2FA code sent")
	return nil
}

// ValidateSMS2FA checks the submitted code against the pending code for the user.
func (s *SMSService) ValidateSMS2FA(ctx context.Context, userID string, code string) error {
	if !s.config.Enabled {
		return ErrSMSNotEnabled
	}

	s.mu.Lock()
	entry, exists := s.pending[userID]
	if exists {
		delete(s.pending, userID) // single use
	}
	s.mu.Unlock()

	if !exists {
		return ErrSMSCodeInvalid
	}

	if time.Now().After(entry.expiresAt) {
		return ErrSMSCodeExpired
	}

	if entry.code != code {
		return ErrSMSCodeInvalid
	}

	log.Info().Str("user_id", userID).Msg("SMS 2FA code validated")
	return nil
}

// sendTelnyxSMS sends an SMS message via the Telnyx API.
func (s *SMSService) sendTelnyxSMS(ctx context.Context, to string, body string) error {
	payload := map[string]interface{}{
		"from": s.config.FromNumber,
		"to":   to,
		"text": body,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal sms payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.APIURL, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.APIKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telnyx api call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telnyx api error: status %d", resp.StatusCode)
	}

	return nil
}

// cleanup removes expired pending codes.
func (s *SMSService) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for uid, entry := range s.pending {
		if now.After(entry.expiresAt) {
			delete(s.pending, uid)
		}
	}
}

// generateNumericCode generates a random numeric code of the specified length.
func generateNumericCode(length int) (string, error) {
	code := make([]byte, length)
	for i := range code {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		code[i] = '0' + byte(n.Int64())
	}
	return string(code), nil
}
