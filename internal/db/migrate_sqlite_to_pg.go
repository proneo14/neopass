package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// MigrationResult holds counts from a SQLite-to-PostgreSQL migration.
type MigrationResult struct {
	Users        int `json:"users"`
	Organizations int `json:"organizations"`
	OrgMembers   int `json:"org_members"`
	Folders      int `json:"folders"`
	VaultEntries int `json:"vault_entries"`
	TOTPSecrets  int `json:"totp_secrets"`
	SharedTOTP   int `json:"shared_2fa"`
	RecoveryCodes int `json:"recovery_codes"`
	Sessions     int `json:"sessions"`
	AuditLog     int `json:"audit_log"`
	SyncCursors  int `json:"sync_cursors"`
	Invitations  int `json:"invitations"`
}

// MigrateSQLiteToPg copies all data from a SQLite database to a PostgreSQL database.
// The PostgreSQL database must already have its schema set up (migrations applied).
// This runs inside a PostgreSQL transaction — atomic (all or nothing).
func MigrateSQLiteToPg(ctx context.Context, sqliteDB *sql.DB, pgPool *pgxpool.Pool) (MigrationResult, error) {
	var result MigrationResult

	tx, err := pgPool.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("begin pg transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Users
	rows, err := sqliteDB.QueryContext(ctx,
		`SELECT id, email, auth_hash, salt, kdf_params, public_key, encrypted_private_key, created_at, updated_at FROM users`)
	if err != nil {
		return result, fmt.Errorf("query sqlite users: %w", err)
	}
	for rows.Next() {
		var id, email, kdfStr, createdStr, updatedStr string
		var authHash, salt, pubKey, encPrivKey []byte
		if err := rows.Scan(&id, &email, &authHash, &salt, &kdfStr, &pubKey, &encPrivKey, &createdStr, &updatedStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite user: %w", err)
		}
		createdAt := parseTimePg(createdStr)
		updatedAt := parseTimePg(updatedStr)
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (id, email, auth_hash, salt, kdf_params, public_key, encrypted_private_key, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9)
			 ON CONFLICT (id) DO NOTHING`,
			id, email, authHash, salt, kdfStr, pubKey, encPrivKey, createdAt, updatedAt,
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg user %s: %w", id, err)
		}
		result.Users++
	}
	rows.Close()

	// 2. Organizations
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT id, name, org_public_key, encrypted_org_private_key, policy, created_at FROM organizations`)
	if err != nil {
		return result, fmt.Errorf("query sqlite orgs: %w", err)
	}
	for rows.Next() {
		var id, name, createdStr string
		var orgPubKey, encOrgPrivKey []byte
		var policyStr *string
		if err := rows.Scan(&id, &name, &orgPubKey, &encOrgPrivKey, &policyStr, &createdStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite org: %w", err)
		}
		createdAt := parseTimePg(createdStr)
		var policyJSON *string
		if policyStr != nil {
			policyJSON = policyStr
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name, org_public_key, encrypted_org_private_key, policy, created_at)
			 VALUES ($1, $2, $3, $4, $5::jsonb, $6)
			 ON CONFLICT (id) DO NOTHING`,
			id, name, orgPubKey, encOrgPrivKey, policyJSON, createdAt,
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg org %s: %w", id, err)
		}
		result.Organizations++
	}
	rows.Close()

	// 3. Org Members
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT org_id, user_id, role, escrow_blob, joined_at FROM org_members`)
	if err != nil {
		return result, fmt.Errorf("query sqlite org_members: %w", err)
	}
	for rows.Next() {
		var orgID, userID, role, joinedStr string
		var escrow []byte
		if err := rows.Scan(&orgID, &userID, &role, &escrow, &joinedStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite org_member: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO org_members (org_id, user_id, role, escrow_blob, joined_at) VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (org_id, user_id) DO NOTHING`,
			orgID, userID, role, escrow, parseTimePg(joinedStr),
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg org_member: %w", err)
		}
		result.OrgMembers++
	}
	rows.Close()

	// 4. Folders
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT id, user_id, name_encrypted, parent_id FROM folders`)
	if err != nil {
		return result, fmt.Errorf("query sqlite folders: %w", err)
	}
	for rows.Next() {
		var id, userID string
		var nameEnc []byte
		var parentID *string
		if err := rows.Scan(&id, &userID, &nameEnc, &parentID); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite folder: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO folders (id, user_id, name_encrypted, parent_id) VALUES ($1, $2, $3, $4)
			 ON CONFLICT (id) DO NOTHING`,
			id, userID, nameEnc, parentID,
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg folder %s: %w", id, err)
		}
		result.Folders++
	}
	rows.Close()

	// 5. Vault Entries
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, created_at, updated_at
		 FROM vault_entries`)
	if err != nil {
		return result, fmt.Errorf("query sqlite vault_entries: %w", err)
	}
	for rows.Next() {
		var id, userID, entryType, createdStr, updatedStr string
		var orgID, folderID *string
		var encData, nonce []byte
		var version, isDeleted int
		if err := rows.Scan(&id, &userID, &orgID, &entryType, &encData, &nonce, &version, &folderID, &isDeleted, &createdStr, &updatedStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite vault_entry: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO vault_entries (id, user_id, org_id, entry_type, encrypted_data, nonce, version, folder_id, is_deleted, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			 ON CONFLICT (id) DO NOTHING`,
			id, userID, orgID, entryType, encData, nonce, version, folderID, isDeleted != 0,
			parseTimePg(createdStr), parseTimePg(updatedStr),
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg vault_entry %s: %w", id, err)
		}
		result.VaultEntries++
	}
	rows.Close()

	// 6. TOTP Secrets
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT id, user_id, encrypted_secret, verified, created_at FROM totp_secrets`)
	if err != nil {
		return result, fmt.Errorf("query sqlite totp_secrets: %w", err)
	}
	for rows.Next() {
		var id, userID, createdStr string
		var encSecret []byte
		var verified int
		if err := rows.Scan(&id, &userID, &encSecret, &verified, &createdStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite totp_secret: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO totp_secrets (id, user_id, encrypted_secret, verified, created_at) VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (user_id) DO NOTHING`,
			id, userID, encSecret, verified != 0, parseTimePg(createdStr),
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg totp_secret %s: %w", id, err)
		}
		result.TOTPSecrets++
	}
	rows.Close()

	// 7. Shared 2FA
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT id, from_user_id, to_user_id, encrypted_totp_secret, expires_at, claimed, created_at FROM shared_2fa`)
	if err != nil {
		return result, fmt.Errorf("query sqlite shared_2fa: %w", err)
	}
	for rows.Next() {
		var id, fromID, toID, expiresStr, createdStr string
		var encSecret []byte
		var claimed int
		if err := rows.Scan(&id, &fromID, &toID, &encSecret, &expiresStr, &claimed, &createdStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite shared_2fa: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO shared_2fa (id, from_user_id, to_user_id, encrypted_totp_secret, expires_at, claimed, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING`,
			id, fromID, toID, encSecret, parseTimePg(expiresStr), claimed != 0, parseTimePg(createdStr),
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg shared_2fa %s: %w", id, err)
		}
		result.SharedTOTP++
	}
	rows.Close()

	// 8. Recovery Codes
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT id, user_id, code_hash, used FROM recovery_codes`)
	if err != nil {
		return result, fmt.Errorf("query sqlite recovery_codes: %w", err)
	}
	for rows.Next() {
		var id, userID string
		var codeHash []byte
		var used int
		if err := rows.Scan(&id, &userID, &codeHash, &used); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite recovery_code: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO recovery_codes (id, user_id, code_hash, used) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`,
			id, userID, codeHash, used != 0,
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg recovery_code %s: %w", id, err)
		}
		result.RecoveryCodes++
	}
	rows.Close()

	// 9. Audit Log
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT id, actor_id, target_id, action, details, created_at FROM audit_log`)
	if err != nil {
		return result, fmt.Errorf("query sqlite audit_log: %w", err)
	}
	for rows.Next() {
		var id, action, createdStr string
		var actorID, targetID, detailsStr *string
		if err := rows.Scan(&id, &actorID, &targetID, &action, &detailsStr, &createdStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite audit_log: %w", err)
		}
		var detailsJSON json.RawMessage
		if detailsStr != nil {
			detailsJSON = json.RawMessage(*detailsStr)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_log (id, actor_id, target_id, action, details, created_at) VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (id) DO NOTHING`,
			id, actorID, targetID, action, detailsJSON, parseTimePg(createdStr),
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg audit_log %s: %w", id, err)
		}
		result.AuditLog++
	}
	rows.Close()

	// 10. Sync Cursors
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT user_id, device_id, last_sync_at FROM sync_cursors`)
	if err != nil {
		return result, fmt.Errorf("query sqlite sync_cursors: %w", err)
	}
	for rows.Next() {
		var userID, deviceID, lastSyncStr string
		if err := rows.Scan(&userID, &deviceID, &lastSyncStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite sync_cursor: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO sync_cursors (user_id, device_id, last_sync_at) VALUES ($1, $2, $3)
			 ON CONFLICT (user_id, device_id) DO NOTHING`,
			userID, deviceID, parseTimePg(lastSyncStr),
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg sync_cursor: %w", err)
		}
		result.SyncCursors++
	}
	rows.Close()

	// 11. Invitations
	rows, err = sqliteDB.QueryContext(ctx,
		`SELECT id, org_id, email, role, invited_by, accepted, created_at FROM invitations`)
	if err != nil {
		return result, fmt.Errorf("query sqlite invitations: %w", err)
	}
	for rows.Next() {
		var id, orgID, email, role, invitedBy, createdStr string
		var accepted int
		if err := rows.Scan(&id, &orgID, &email, &role, &invitedBy, &accepted, &createdStr); err != nil {
			rows.Close()
			return result, fmt.Errorf("scan sqlite invitation: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO invitations (id, org_id, email, role, invited_by, accepted, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING`,
			id, orgID, email, role, invitedBy, accepted != 0, parseTimePg(createdStr),
		); err != nil {
			rows.Close()
			return result, fmt.Errorf("insert pg invitation %s: %w", id, err)
		}
		result.Invitations++
	}
	rows.Close()

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("commit migration transaction: %w", err)
	}

	log.Info().
		Int("users", result.Users).
		Int("vault_entries", result.VaultEntries).
		Int("folders", result.Folders).
		Int("organizations", result.Organizations).
		Msg("SQLite to PostgreSQL migration completed")

	return result, nil
}

func parseTimePg(s string) time.Time {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t, _ = time.Parse(time.RFC3339, s)
		}
	}
	return t
}
