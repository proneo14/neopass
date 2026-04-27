package sync

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/password-manager/password-manager/internal/db"
)

// SyncEntry is a vault entry in sync wire format.
type SyncEntry struct {
	ID            string     `json:"id"`
	EntryType     string     `json:"entry_type"`
	EncryptedData string     `json:"encrypted_data"` // hex-encoded
	Nonce         string     `json:"nonce"`           // hex-encoded
	Version       int        `json:"version"`
	FolderID      *string    `json:"folder_id,omitempty"`
	IsDeleted     bool       `json:"is_deleted"`
	IsFavorite    bool       `json:"is_favorite"`
	IsArchived    bool       `json:"is_archived"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// SyncResponse is returned from a pull operation.
type SyncResponse struct {
	Entries []SyncEntry `json:"entries"`
	SyncAt  time.Time   `json:"sync_at"`
}

// VaultEntryChange represents a client-side change to push.
type VaultEntryChange struct {
	ID            string  `json:"id"`
	EntryType     string  `json:"entry_type"`
	EncryptedData string  `json:"encrypted_data"` // hex-encoded
	Nonce         string  `json:"nonce"`           // hex-encoded
	BaseVersion   int     `json:"base_version"`    // client's known version
	FolderID      *string `json:"folder_id,omitempty"`
	IsDeleted     bool    `json:"is_deleted"`
	IsNew         bool    `json:"is_new"` // true = insert, false = update
}

// ConflictEntry represents a sync conflict.
type ConflictEntry struct {
	EntryID       string    `json:"entry_id"`
	ServerVersion int       `json:"server_version"`
	ClientVersion int       `json:"client_version"`
	ServerData    SyncEntry `json:"server_data"`
	ClientData    SyncEntry `json:"client_data"`
}

// ResolveRequest is the payload for resolving a conflict.
type ResolveRequest struct {
	EntryID       string `json:"entry_id"`
	Resolution    string `json:"resolution"` // "keep_server", "keep_client", "merge"
	EncryptedData string `json:"encrypted_data,omitempty"` // hex, required for "merge"
	Nonce         string `json:"nonce,omitempty"`           // hex, required for "merge"
}

// PushResponse is returned from a push operation.
type PushResponse struct {
	Applied   int             `json:"applied"`
	Conflicts []ConflictEntry `json:"conflicts"`
}

// Service provides sync operations.
type Service struct {
	vaultRepo db.VaultRepository
	syncRepo  db.SyncRepository
}

// NewService creates a new sync Service.
func NewService(vaultRepo db.VaultRepository, syncRepo db.SyncRepository) *Service {
	return &Service{
		vaultRepo: vaultRepo,
		syncRepo:  syncRepo,
	}
}

// Pull returns all vault entries changed since lastSyncAt and updates the sync cursor.
func (s *Service) Pull(ctx context.Context, userID, deviceID string, lastSyncAt time.Time) (SyncResponse, error) {
	entries, err := s.vaultRepo.ListEntriesForSync(ctx, userID, lastSyncAt)
	if err != nil {
		return SyncResponse{}, fmt.Errorf("list entries for sync: %w", err)
	}

	syncAt := time.Now().UTC()

	syncEntries := make([]SyncEntry, len(entries))
	for i, e := range entries {
		syncEntries[i] = toSyncEntry(e)
	}

	// Update sync cursor
	if err := s.syncRepo.UpsertSyncCursor(ctx, userID, deviceID, syncAt); err != nil {
		return SyncResponse{}, fmt.Errorf("update sync cursor: %w", err)
	}

	return SyncResponse{
		Entries: syncEntries,
		SyncAt:  syncAt,
	}, nil
}

// Push applies client changes, returning conflicts for version mismatches.
func (s *Service) Push(ctx context.Context, userID, deviceID string, changes []VaultEntryChange) (PushResponse, error) {
	var conflicts []ConflictEntry
	applied := 0

	for _, change := range changes {
		encData, err := hex.DecodeString(change.EncryptedData)
		if err != nil {
			return PushResponse{}, fmt.Errorf("invalid encrypted_data hex for entry %s", change.ID)
		}
		nonce, err := hex.DecodeString(change.Nonce)
		if err != nil {
			return PushResponse{}, fmt.Errorf("invalid nonce hex for entry %s", change.ID)
		}

		if change.IsNew {
			// New entry — insert
			entry := db.VaultEntry{
				ID:            change.ID,
				UserID:        userID,
				EntryType:     change.EntryType,
				EncryptedData: encData,
				Nonce:         nonce,
				FolderID:      change.FolderID,
				IsDeleted:     change.IsDeleted,
			}
			if _, err := s.vaultRepo.CreateEntry(ctx, entry); err != nil {
				// If duplicate, treat as conflict
				if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
					serverEntry, getErr := s.vaultRepo.GetEntryByID(ctx, change.ID)
					if getErr == nil {
						conflicts = append(conflicts, ConflictEntry{
							EntryID:       change.ID,
							ServerVersion: serverEntry.Version,
							ClientVersion: change.BaseVersion,
							ServerData:    toSyncEntry(serverEntry),
							ClientData: SyncEntry{
								ID:            change.ID,
								EntryType:     change.EntryType,
								EncryptedData: change.EncryptedData,
								Nonce:         change.Nonce,
								Version:       change.BaseVersion,
								FolderID:      change.FolderID,
								IsDeleted:     change.IsDeleted,
							},
						})
					}
					continue
				}
				return PushResponse{}, fmt.Errorf("create entry %s: %w", change.ID, err)
			}
			applied++
			continue
		}

		// Existing entry — check version
		serverEntry, err := s.vaultRepo.GetEntryByID(ctx, change.ID)
		if err != nil {
			return PushResponse{}, fmt.Errorf("get entry %s: %w", change.ID, err)
		}

		// Verify ownership
		if serverEntry.UserID != userID {
			return PushResponse{}, fmt.Errorf("entry %s does not belong to user", change.ID)
		}

		if serverEntry.Version != change.BaseVersion {
			// Version conflict
			conflicts = append(conflicts, ConflictEntry{
				EntryID:       change.ID,
				ServerVersion: serverEntry.Version,
				ClientVersion: change.BaseVersion,
				ServerData:    toSyncEntry(serverEntry),
				ClientData: SyncEntry{
					ID:            change.ID,
					EntryType:     change.EntryType,
					EncryptedData: change.EncryptedData,
					Nonce:         change.Nonce,
					Version:       change.BaseVersion,
					FolderID:      change.FolderID,
					IsDeleted:     change.IsDeleted,
				},
			})
			continue
		}

		// Version matches — apply update
		updated := db.VaultEntry{
			ID:            change.ID,
			UserID:        userID,
			EntryType:     change.EntryType,
			EncryptedData: encData,
			Nonce:         nonce,
			FolderID:      change.FolderID,
			IsDeleted:     change.IsDeleted,
		}

		if _, err := s.vaultRepo.UpdateEntryVersioned(ctx, updated, change.BaseVersion); err != nil {
			// Race condition — another update happened between check and apply
			conflicts = append(conflicts, ConflictEntry{
				EntryID:       change.ID,
				ServerVersion: serverEntry.Version,
				ClientVersion: change.BaseVersion,
				ServerData:    toSyncEntry(serverEntry),
				ClientData: SyncEntry{
					ID:            change.ID,
					EntryType:     change.EntryType,
					EncryptedData: change.EncryptedData,
					Nonce:         change.Nonce,
					Version:       change.BaseVersion,
					FolderID:      change.FolderID,
					IsDeleted:     change.IsDeleted,
				},
			})
			continue
		}

		applied++
	}

	return PushResponse{
		Applied:   applied,
		Conflicts: conflicts,
	}, nil
}

// ResolveConflict resolves a sync conflict by applying the chosen resolution.
func (s *Service) ResolveConflict(ctx context.Context, userID string, req ResolveRequest) error {
	switch req.Resolution {
	case "keep_server":
		// Nothing to do — server already has the correct version
		return nil

	case "keep_client", "merge":
		encData, err := hex.DecodeString(req.EncryptedData)
		if err != nil {
			return fmt.Errorf("invalid encrypted_data hex")
		}
		nonce, err := hex.DecodeString(req.Nonce)
		if err != nil {
			return fmt.Errorf("invalid nonce hex")
		}

		// Get current server entry for version
		serverEntry, err := s.vaultRepo.GetEntryByID(ctx, req.EntryID)
		if err != nil {
			return fmt.Errorf("get entry: %w", err)
		}
		if serverEntry.UserID != userID {
			return fmt.Errorf("entry does not belong to user")
		}

		updated := db.VaultEntry{
			ID:            req.EntryID,
			UserID:        userID,
			EntryType:     serverEntry.EntryType,
			EncryptedData: encData,
			Nonce:         nonce,
			FolderID:      serverEntry.FolderID,
			IsDeleted:     serverEntry.IsDeleted,
		}

		if _, err := s.vaultRepo.UpdateEntryVersioned(ctx, updated, serverEntry.Version); err != nil {
			return fmt.Errorf("apply resolution: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("invalid resolution: %s (must be keep_server, keep_client, or merge)", req.Resolution)
	}
}

func toSyncEntry(e db.VaultEntry) SyncEntry {
	return SyncEntry{
		ID:            e.ID,
		EntryType:     e.EntryType,
		EncryptedData: hex.EncodeToString(e.EncryptedData),
		Nonce:         hex.EncodeToString(e.Nonce),
		Version:       e.Version,
		FolderID:      e.FolderID,
		IsDeleted:     e.IsDeleted,
		IsFavorite:    e.IsFavorite,
		IsArchived:    e.IsArchived,
		DeletedAt:     e.DeletedAt,
		UpdatedAt:     e.UpdatedAt,
	}
}
