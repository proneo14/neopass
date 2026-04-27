package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/password-manager/password-manager/internal/db"
)

// SendHandler handles Secure Send HTTP endpoints.
type SendHandler struct {
	sendRepo db.SendRepository
	userRepo db.UserRepository
}

// NewSendHandler creates a new SendHandler.
func NewSendHandler(sendRepo db.SendRepository, userRepo db.UserRepository) *SendHandler {
	return &SendHandler{sendRepo: sendRepo, userRepo: userRepo}
}

// base62Chars is the character set for generating URL-safe slugs.
const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// generateSlug creates a cryptographically random base62 slug of the given length.
func generateSlug(length int) (string, error) {
	result := make([]byte, length)
	max := big.NewInt(int64(len(base62Chars)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = base62Chars[n.Int64()]
	}
	return string(result), nil
}

// CreateSend handles POST /api/v1/sends
func (h *SendHandler) CreateSend(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Type           string  `json:"type"`
		EncryptedData  string  `json:"encrypted_data"`
		Nonce          string  `json:"nonce"`
		EncryptedName  string  `json:"encrypted_name"`
		NameNonce      string  `json:"name_nonce"`
		Password       string  `json:"password"`
		MaxAccessCount *int    `json:"max_access_count"`
		ExpiresInHours int     `json:"expires_in_hours"`
		HideEmail      bool    `json:"hide_email"`
		FileName       *string `json:"file_name"`
		FileSize       *int    `json:"file_size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Type != "text" && req.Type != "file" {
		writeError(w, http.StatusBadRequest, "type must be 'text' or 'file'")
		return
	}
	if req.EncryptedData == "" || req.Nonce == "" {
		writeError(w, http.StatusBadRequest, "encrypted_data and nonce are required")
		return
	}
	if req.ExpiresInHours <= 0 || req.ExpiresInHours > 720 {
		writeError(w, http.StatusBadRequest, "expires_in_hours must be between 1 and 720")
		return
	}
	if req.FileSize != nil && *req.FileSize > 100*1024*1024 {
		writeError(w, http.StatusBadRequest, "file_size exceeds 100MB limit")
		return
	}

	encData, err := hex.DecodeString(req.EncryptedData)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid encrypted_data hex")
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid nonce hex")
		return
	}

	var encName []byte
	var nameNonce []byte
	if req.EncryptedName != "" {
		encName, err = hex.DecodeString(req.EncryptedName)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid encrypted_name hex")
			return
		}
	}
	if req.NameNonce != "" {
		nameNonce, err = hex.DecodeString(req.NameNonce)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid name_nonce hex")
			return
		}
	}

	var passwordHash []byte
	if req.Password != "" {
		passwordHash, err = bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Error().Err(err).Msg("failed to hash send password")
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}

	slug, err := generateSlug(16)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate slug")
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	send := db.Send{
		UserID:         claims.UserID,
		Slug:           slug,
		SendType:       req.Type,
		EncryptedData:  encData,
		Nonce:          nonce,
		EncryptedName:  encName,
		NameNonce:      nameNonce,
		PasswordHash:   passwordHash,
		MaxAccessCount: req.MaxAccessCount,
		FileName:       req.FileName,
		FileSize:       req.FileSize,
		ExpiresAt:      time.Now().UTC().Add(time.Duration(req.ExpiresInHours) * time.Hour),
		HideEmail:      req.HideEmail,
	}

	created, err := h.sendRepo.CreateSend(r.Context(), send)
	if err != nil {
		log.Error().Err(err).Msg("create send failed")
		writeError(w, http.StatusInternalServerError, "failed to create send")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":   created.ID,
		"slug": created.Slug,
		"url":  "/send/" + created.Slug,
	})
}

// ListSends handles GET /api/v1/sends
func (h *SendHandler) ListSends(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	sends, err := h.sendRepo.ListSends(r.Context(), claims.UserID)
	if err != nil {
		log.Error().Err(err).Msg("list sends failed")
		writeError(w, http.StatusInternalServerError, "failed to list sends")
		return
	}

	if sends == nil {
		sends = []db.Send{}
	}

	// Strip encrypted data from the list response — client doesn't need blobs for listing
	type sendSummary struct {
		ID             string     `json:"id"`
		Slug           string     `json:"slug"`
		SendType       string     `json:"send_type"`
		HasPassword    bool       `json:"has_password"`
		MaxAccessCount *int       `json:"max_access_count,omitempty"`
		AccessCount    int        `json:"access_count"`
		FileName       *string    `json:"file_name,omitempty"`
		FileSize       *int       `json:"file_size,omitempty"`
		ExpiresAt      time.Time  `json:"expires_at"`
		Disabled       bool       `json:"disabled"`
		HideEmail      bool       `json:"hide_email"`
		CreatedAt      time.Time  `json:"created_at"`
		EncryptedName  string     `json:"encrypted_name,omitempty"`
		NameNonce      string     `json:"name_nonce,omitempty"`
	}

	summaries := make([]sendSummary, len(sends))
	for i, s := range sends {
		summaries[i] = sendSummary{
			ID:             s.ID,
			Slug:           s.Slug,
			SendType:       s.SendType,
			HasPassword:    s.HasPassword,
			MaxAccessCount: s.MaxAccessCount,
			AccessCount:    s.AccessCount,
			FileName:       s.FileName,
			FileSize:       s.FileSize,
			ExpiresAt:      s.ExpiresAt,
			Disabled:       s.Disabled,
			HideEmail:      s.HideEmail,
			CreatedAt:      s.CreatedAt,
		}
		if len(s.EncryptedName) > 0 {
			summaries[i].EncryptedName = hex.EncodeToString(s.EncryptedName)
		}
		if len(s.NameNonce) > 0 {
			summaries[i].NameNonce = hex.EncodeToString(s.NameNonce)
		}
	}

	writeJSON(w, http.StatusOK, summaries)
}

// DeleteSend handles DELETE /api/v1/sends/{id}
func (h *SendHandler) DeleteSend(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	sendID := chi.URLParam(r, "id")
	if sendID == "" {
		writeError(w, http.StatusBadRequest, "missing send id")
		return
	}

	if err := h.sendRepo.DeleteSend(r.Context(), sendID, claims.UserID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// DisableSend handles PUT /api/v1/sends/{id}/disable
func (h *SendHandler) DisableSend(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	sendID := chi.URLParam(r, "id")
	if sendID == "" {
		writeError(w, http.StatusBadRequest, "missing send id")
		return
	}

	if err := h.sendRepo.DisableSend(r.Context(), sendID, claims.UserID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// AccessSend handles GET /api/v1/send/{slug} — public endpoint (no auth)
func (h *SendHandler) AccessSend(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "missing slug")
		return
	}

	send, err := h.sendRepo.GetSendBySlug(r.Context(), slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "send not found")
		return
	}

	// Check disabled
	if send.Disabled {
		writeError(w, http.StatusGone, "this send has been disabled")
		return
	}

	// Check expired
	if time.Now().UTC().After(send.ExpiresAt) {
		writeError(w, http.StatusGone, "this send has expired")
		return
	}

	// Check max access
	if send.MaxAccessCount != nil && send.AccessCount >= *send.MaxAccessCount {
		writeError(w, http.StatusGone, "this send has reached its maximum access count")
		return
	}

	// Check password
	if len(send.PasswordHash) > 0 {
		// Require password via POST to /send/{slug}/access
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"requires_password": true,
			"send_type":         send.SendType,
		})
		return
	}

	// Increment and return
	if err := h.sendRepo.IncrementAccessCount(r.Context(), send.ID); err != nil {
		log.Error().Err(err).Msg("increment access count failed")
	}

	h.writeSendResponse(w, r, send)
}

// AccessSendWithPassword handles POST /api/v1/send/{slug}/access — public endpoint (no auth)
func (h *SendHandler) AccessSendWithPassword(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "missing slug")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	send, err := h.sendRepo.GetSendBySlug(r.Context(), slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "send not found")
		return
	}

	if send.Disabled {
		writeError(w, http.StatusGone, "this send has been disabled")
		return
	}
	if time.Now().UTC().After(send.ExpiresAt) {
		writeError(w, http.StatusGone, "this send has expired")
		return
	}
	if send.MaxAccessCount != nil && send.AccessCount >= *send.MaxAccessCount {
		writeError(w, http.StatusGone, "this send has reached its maximum access count")
		return
	}

	if len(send.PasswordHash) > 0 {
		if err := bcrypt.CompareHashAndPassword(send.PasswordHash, []byte(req.Password)); err != nil {
			writeError(w, http.StatusUnauthorized, "incorrect password")
			return
		}
	}

	if err := h.sendRepo.IncrementAccessCount(r.Context(), send.ID); err != nil {
		log.Error().Err(err).Msg("increment access count failed")
	}

	h.writeSendResponse(w, r, send)
}

func (h *SendHandler) writeSendResponse(w http.ResponseWriter, r *http.Request, send db.Send) {
	resp := map[string]interface{}{
		"type":           send.SendType,
		"encrypted_data": hex.EncodeToString(send.EncryptedData),
		"nonce":          hex.EncodeToString(send.Nonce),
		"expires_at":     send.ExpiresAt,
	}

	if len(send.EncryptedName) > 0 {
		resp["encrypted_name"] = hex.EncodeToString(send.EncryptedName)
	}
	if len(send.NameNonce) > 0 {
		resp["name_nonce"] = hex.EncodeToString(send.NameNonce)
	}
	if send.FileName != nil {
		resp["file_name"] = *send.FileName
	}
	if send.FileSize != nil {
		resp["file_size"] = *send.FileSize
	}

	if !send.HideEmail {
		user, err := h.userRepo.GetUserByID(r.Context(), send.UserID)
		if err == nil {
			resp["sender_email"] = user.Email
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// PurgeExpiredSends removes all expired sends — called by background goroutine.
func (h *SendHandler) PurgeExpiredSends() {
	count, err := h.sendRepo.PurgeExpiredSends(context.Background())
	if err != nil {
		log.Error().Err(err).Msg("purge expired sends failed")
		return
	}
	if count > 0 {
		log.Info().Int("purged", count).Msg("purged expired sends")
	}
}
