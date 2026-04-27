package vault

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/password-manager/password-manager/internal/db"
)

// EntrySummary is a metadata-only view of a vault entry (no encrypted blob).
type EntrySummary struct {
	ID         string    `json:"id"`
	EntryType  string    `json:"entry_type"`
	FolderID   *string   `json:"folder_id,omitempty"`
	Version    int       `json:"version"`
	IsFavorite bool      `json:"is_favorite"`
	IsArchived bool      `json:"is_archived"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// EntryResponse is the full vault entry returned to the client.
type EntryResponse struct {
	ID            string     `json:"id"`
	EntryType     string     `json:"entry_type"`
	EncryptedData string     `json:"encrypted_data"` // hex-encoded
	Nonce         string     `json:"nonce"`           // hex-encoded
	FolderID      *string    `json:"folder_id,omitempty"`
	Version       int        `json:"version"`
	IsFavorite    bool       `json:"is_favorite"`
	IsArchived    bool       `json:"is_archived"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// CreateEntryRequest is the client's payload for creating a vault entry.
type CreateEntryRequest struct {
	EntryType     string  `json:"entry_type"`
	EncryptedData string  `json:"encrypted_data"` // hex-encoded
	Nonce         string  `json:"nonce"`           // hex-encoded
	FolderID      *string `json:"folder_id,omitempty"`
}

// UpdateEntryRequest is the client's payload for updating a vault entry.
type UpdateEntryRequest struct {
	EntryType     string  `json:"entry_type,omitempty"`
	EncryptedData string  `json:"encrypted_data"` // hex-encoded
	Nonce         string  `json:"nonce"`           // hex-encoded
	FolderID      *string `json:"folder_id,omitempty"`
}

// CreateFolderRequest is the client's payload for creating a folder.
type CreateFolderRequest struct {
	NameEncrypted string  `json:"name_encrypted"` // hex-encoded
	ParentID      *string `json:"parent_id,omitempty"`
}

// FolderResponse is a folder returned to the client.
type FolderResponse struct {
	ID            string  `json:"id"`
	NameEncrypted string  `json:"name_encrypted"` // hex-encoded
	ParentID      *string `json:"parent_id,omitempty"`
}

// ListFilters are query parameters for listing vault entries.
type ListFilters struct {
	EntryType    string
	FolderID     string
	UpdatedSince *time.Time
	IsFavorite   *bool
	IsArchived   *bool
	InTrash      bool
}

// Service provides vault operations.
// The server never decrypts vault entries — it stores and serves encrypted blobs.
type Service struct {
	vaultRepo db.VaultRepository
}

// NewService creates a new vault Service.
func NewService(vaultRepo db.VaultRepository) *Service {
	return &Service{vaultRepo: vaultRepo}
}

var validEntryTypes = map[string]bool{
	"login":       true,
	"secure_note": true,
	"credit_card": true,
	"identity":    true,
}

// CreateEntry stores a new encrypted vault entry.
func (s *Service) CreateEntry(ctx context.Context, userID string, req CreateEntryRequest) (EntryResponse, error) {
	if !validEntryTypes[req.EntryType] {
		return EntryResponse{}, fmt.Errorf("invalid entry_type")
	}

	encData, err := hex.DecodeString(req.EncryptedData)
	if err != nil {
		return EntryResponse{}, fmt.Errorf("invalid encrypted_data hex")
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil {
		return EntryResponse{}, fmt.Errorf("invalid nonce hex")
	}

	entry := db.VaultEntry{
		UserID:        userID,
		EntryType:     req.EntryType,
		EncryptedData: encData,
		Nonce:         nonce,
		FolderID:      req.FolderID,
	}

	created, err := s.vaultRepo.CreateEntry(ctx, entry)
	if err != nil {
		return EntryResponse{}, fmt.Errorf("create entry: %w", err)
	}
	return toEntryResponse(created), nil
}

// GetEntry retrieves a single encrypted vault entry.
func (s *Service) GetEntry(ctx context.Context, userID, entryID string) (EntryResponse, error) {
	entry, err := s.vaultRepo.GetEntry(ctx, entryID, userID)
	if err != nil {
		return EntryResponse{}, err
	}
	return toEntryResponse(entry), nil
}

// ListEntries returns metadata summaries of the user's vault entries.
func (s *Service) ListEntries(ctx context.Context, userID string, filters ListFilters) ([]EntrySummary, error) {
	// Auto-purge trash entries older than 30 days on every list request.
	olderThan := time.Now().Add(-30 * 24 * time.Hour)
	if n, err := s.vaultRepo.PurgeExpiredTrash(ctx, userID, olderThan); err == nil && n > 0 {
		log.Info().Int("purged", n).Str("user_id", userID).Msg("auto-purged expired trash entries")
	}

	dbFilters := db.VaultFilters{
		EntryType:    filters.EntryType,
		FolderID:     filters.FolderID,
		UpdatedSince: filters.UpdatedSince,
		IsFavorite:   filters.IsFavorite,
		IsArchived:   filters.IsArchived,
		InTrash:      filters.InTrash,
	}

	entries, err := s.vaultRepo.ListEntries(ctx, userID, dbFilters)
	if err != nil {
		return nil, err
	}

	summaries := make([]EntrySummary, len(entries))
	for i, e := range entries {
		summaries[i] = EntrySummary{
			ID:         e.ID,
			EntryType:  e.EntryType,
			FolderID:   e.FolderID,
			Version:    e.Version,
			IsFavorite: e.IsFavorite,
			IsArchived: e.IsArchived,
			CreatedAt:  e.CreatedAt,
			UpdatedAt:  e.UpdatedAt,
		}
	}
	return summaries, nil
}

// UpdateEntry updates an encrypted vault entry.
func (s *Service) UpdateEntry(ctx context.Context, userID, entryID string, req UpdateEntryRequest) (EntryResponse, error) {
	encData, err := hex.DecodeString(req.EncryptedData)
	if err != nil {
		return EntryResponse{}, fmt.Errorf("invalid encrypted_data hex")
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil {
		return EntryResponse{}, fmt.Errorf("invalid nonce hex")
	}

	entryType := req.EntryType
	if entryType != "" && !validEntryTypes[entryType] {
		return EntryResponse{}, fmt.Errorf("invalid entry_type")
	}

	// If no type change, fetch current type
	if entryType == "" {
		existing, err := s.vaultRepo.GetEntry(ctx, entryID, userID)
		if err != nil {
			return EntryResponse{}, err
		}
		entryType = existing.EntryType
	}

	entry := db.VaultEntry{
		ID:            entryID,
		UserID:        userID,
		EntryType:     entryType,
		EncryptedData: encData,
		Nonce:         nonce,
		FolderID:      req.FolderID,
	}

	updated, err := s.vaultRepo.UpdateEntry(ctx, entry)
	if err != nil {
		return EntryResponse{}, err
	}
	return toEntryResponse(updated), nil
}

// DeleteEntry removes a vault entry (moves to trash).
func (s *Service) DeleteEntry(ctx context.Context, userID, entryID string) error {
	return s.vaultRepo.DeleteEntry(ctx, entryID, userID)
}

// SetFavorite toggles the favorite flag on a vault entry.
func (s *Service) SetFavorite(ctx context.Context, userID, entryID string, favorite bool) error {
	return s.vaultRepo.SetFavorite(ctx, entryID, userID, favorite)
}

// SetArchived toggles the archived flag on a vault entry.
func (s *Service) SetArchived(ctx context.Context, userID, entryID string, archived bool) error {
	return s.vaultRepo.SetArchived(ctx, entryID, userID, archived)
}

// RestoreEntry restores a trashed vault entry.
func (s *Service) RestoreEntry(ctx context.Context, userID, entryID string) error {
	return s.vaultRepo.RestoreEntry(ctx, entryID, userID)
}

// PermanentDeleteEntry permanently deletes a trashed vault entry.
func (s *Service) PermanentDeleteEntry(ctx context.Context, userID, entryID string) error {
	return s.vaultRepo.PermanentDeleteEntry(ctx, entryID, userID)
}

// PurgeExpiredTrash removes trash entries older than 30 days.
func (s *Service) PurgeExpiredTrash(ctx context.Context, userID string) (int, error) {
	olderThan := time.Now().UTC().AddDate(0, 0, -30)
	return s.vaultRepo.PurgeExpiredTrash(ctx, userID, olderThan)
}

// CreateFolder creates a new folder for the user.
func (s *Service) CreateFolder(ctx context.Context, userID string, req CreateFolderRequest) (FolderResponse, error) {
	nameEnc, err := hex.DecodeString(req.NameEncrypted)
	if err != nil {
		return FolderResponse{}, fmt.Errorf("invalid name_encrypted hex")
	}

	folder := db.Folder{
		UserID:        userID,
		NameEncrypted: nameEnc,
		ParentID:      req.ParentID,
	}

	created, err := s.vaultRepo.CreateFolder(ctx, folder)
	if err != nil {
		return FolderResponse{}, fmt.Errorf("create folder: %w", err)
	}
	return toFolderResponse(created), nil
}

// ListFolders returns all folders for a user.
func (s *Service) ListFolders(ctx context.Context, userID string) ([]FolderResponse, error) {
	folders, err := s.vaultRepo.ListFolders(ctx, userID)
	if err != nil {
		return nil, err
	}

	out := make([]FolderResponse, len(folders))
	for i, f := range folders {
		out[i] = toFolderResponse(f)
	}
	return out, nil
}

// CloneEntry duplicates a vault entry with version=1 and a new ID.
// The encrypted data is copied as-is — the client is responsible for
// decrypting, modifying the name (e.g. "Copy of …"), re-encrypting,
// and updating the clone via UpdateEntry.
func (s *Service) CloneEntry(ctx context.Context, userID, entryID string) (EntryResponse, error) {
	existing, err := s.vaultRepo.GetEntry(ctx, entryID, userID)
	if err != nil {
		return EntryResponse{}, err
	}

	clone := db.VaultEntry{
		UserID:        userID,
		EntryType:     existing.EntryType,
		EncryptedData: existing.EncryptedData,
		Nonce:         existing.Nonce,
		FolderID:      existing.FolderID,
	}

	created, err := s.vaultRepo.CreateEntry(ctx, clone)
	if err != nil {
		return EntryResponse{}, fmt.Errorf("clone entry: %w", err)
	}
	return toEntryResponse(created), nil
}

// DeleteFolder removes a folder.
func (s *Service) DeleteFolder(ctx context.Context, userID, folderID string) error {
	return s.vaultRepo.DeleteFolder(ctx, folderID, userID)
}

func toEntryResponse(e db.VaultEntry) EntryResponse {
	return EntryResponse{
		ID:            e.ID,
		EntryType:     e.EntryType,
		EncryptedData: hex.EncodeToString(e.EncryptedData),
		Nonce:         hex.EncodeToString(e.Nonce),
		FolderID:      e.FolderID,
		Version:       e.Version,
		IsFavorite:    e.IsFavorite,
		IsArchived:    e.IsArchived,
		DeletedAt:     e.DeletedAt,
		CreatedAt:     e.CreatedAt,
		UpdatedAt:     e.UpdatedAt,
	}
}

func toFolderResponse(f db.Folder) FolderResponse {
	return FolderResponse{
		ID:            f.ID,
		NameEncrypted: hex.EncodeToString(f.NameEncrypted),
		ParentID:      f.ParentID,
	}
}
