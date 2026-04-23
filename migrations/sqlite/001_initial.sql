-- Quantum-Safe Password Manager: SQLite Schema
-- Equivalent to PostgreSQL migrations 001 + 002 + 003

-- ============================================================================
-- Users
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id                    TEXT PRIMARY KEY,
    email                 TEXT UNIQUE NOT NULL,
    auth_hash             BLOB NOT NULL,
    salt                  BLOB NOT NULL,
    kdf_params            TEXT NOT NULL DEFAULT '{"memory":65536,"iterations":3,"parallelism":4}',
    public_key            BLOB,
    encrypted_private_key BLOB,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Organizations
-- ============================================================================
CREATE TABLE IF NOT EXISTS organizations (
    id                         TEXT PRIMARY KEY,
    name                       TEXT NOT NULL,
    org_public_key             BLOB NOT NULL,
    encrypted_org_private_key  BLOB NOT NULL,
    policy                     TEXT,
    created_at                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Organization Members
-- ============================================================================
CREATE TABLE IF NOT EXISTS org_members (
    org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    escrow_blob BLOB NOT NULL,
    joined_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (org_id, user_id)
);

-- ============================================================================
-- Folders
-- ============================================================================
CREATE TABLE IF NOT EXISTS folders (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_encrypted BLOB NOT NULL,
    parent_id      TEXT REFERENCES folders(id) ON DELETE CASCADE
);

-- ============================================================================
-- Vault Entries
-- ============================================================================
CREATE TABLE IF NOT EXISTS vault_entries (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id         TEXT REFERENCES organizations(id) ON DELETE SET NULL,
    entry_type     TEXT NOT NULL CHECK (entry_type IN ('login', 'secure_note', 'credit_card', 'identity')),
    encrypted_data BLOB NOT NULL,
    nonce          BLOB NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    folder_id      TEXT REFERENCES folders(id) ON DELETE SET NULL,
    is_deleted     INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- TOTP Secrets
-- ============================================================================
CREATE TABLE IF NOT EXISTS totp_secrets (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    encrypted_secret BLOB NOT NULL,
    verified         INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Shared 2FA
-- ============================================================================
CREATE TABLE IF NOT EXISTS shared_2fa (
    id                    TEXT PRIMARY KEY,
    from_user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_totp_secret BLOB NOT NULL,
    expires_at            TEXT NOT NULL,
    claimed               INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Recovery Codes
-- ============================================================================
CREATE TABLE IF NOT EXISTS recovery_codes (
    id        TEXT PRIMARY KEY,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BLOB NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0
);

-- ============================================================================
-- Sessions
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  BLOB NOT NULL,
    device_info TEXT,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Audit Log
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id         TEXT PRIMARY KEY,
    actor_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_id  TEXT,
    action     TEXT NOT NULL,
    details    TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Sync Cursors
-- ============================================================================
CREATE TABLE IF NOT EXISTS sync_cursors (
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL,
    last_sync_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (user_id, device_id)
);

-- ============================================================================
-- Invitations
-- ============================================================================
CREATE TABLE IF NOT EXISTS invitations (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    invited_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    accepted   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Passkey Credentials (WebAuthn passkeys stored in the vault for websites)
-- ============================================================================
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id                    TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id         BLOB NOT NULL UNIQUE,
    rp_id                 TEXT NOT NULL,
    rp_name               TEXT,
    user_handle           BLOB NOT NULL,
    username              TEXT,
    display_name          TEXT,
    public_key_cbor       BLOB NOT NULL,
    encrypted_private_key BLOB NOT NULL,
    private_key_nonce     BLOB NOT NULL,
    sign_count            INTEGER NOT NULL DEFAULT 0,
    aaguid                BLOB,
    transports            TEXT,
    discoverable          INTEGER NOT NULL DEFAULT 1,
    backed_up             INTEGER NOT NULL DEFAULT 0,
    algorithm             INTEGER NOT NULL DEFAULT -7,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at          TEXT
);

-- ============================================================================
-- Hardware Auth Keys (for vault login 2FA)
-- ============================================================================
CREATE TABLE IF NOT EXISTS hardware_auth_keys (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BLOB NOT NULL UNIQUE,
    public_key_cbor BLOB NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    aaguid          BLOB,
    transports      TEXT,
    name            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at    TEXT
);

-- ============================================================================
-- Schema Migrations tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_vault_entries_user_updated ON vault_entries (user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor           ON audit_log (actor_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_target          ON audit_log (target_id, created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash       ON sessions (token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at       ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_invitations_org_email     ON invitations (org_id, email);
CREATE INDEX IF NOT EXISTS idx_passkey_cred_rp_user      ON passkey_credentials (rp_id, user_id);
CREATE INDEX IF NOT EXISTS idx_passkey_cred_cred_id      ON passkey_credentials (credential_id);
CREATE INDEX IF NOT EXISTS idx_hw_auth_keys_user         ON hardware_auth_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_hw_auth_keys_cred_id      ON hardware_auth_keys (credential_id);

-- ============================================================================
-- Updated-at triggers
-- ============================================================================
CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
    AFTER UPDATE ON users
    FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_vault_entries_updated_at
    AFTER UPDATE ON vault_entries
    FOR EACH ROW
BEGIN
    UPDATE vault_entries SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;
