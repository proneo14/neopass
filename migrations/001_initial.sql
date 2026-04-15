-- Quantum-Safe Password Manager: Initial Schema
-- Migration 001

BEGIN;

-- ============================================================================
-- Users
-- ============================================================================
CREATE TABLE users (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 TEXT        UNIQUE NOT NULL,
    auth_hash             BYTEA       NOT NULL,
    salt                  BYTEA       NOT NULL,
    kdf_params            JSONB       NOT NULL DEFAULT '{"memory":65536,"iterations":3,"parallelism":4}',
    public_key            BYTEA,
    encrypted_private_key BYTEA,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- Organizations
-- ============================================================================
CREATE TABLE organizations (
    id                         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name                       TEXT        NOT NULL,
    org_public_key             BYTEA       NOT NULL,
    encrypted_org_private_key  BYTEA       NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- Organization Members
-- ============================================================================
CREATE TABLE org_members (
    org_id      UUID  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     UUID  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT  NOT NULL CHECK (role IN ('admin', 'member')),
    escrow_blob BYTEA NOT NULL,
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

-- ============================================================================
-- Folders (created before vault_entries so FK can reference it)
-- ============================================================================
CREATE TABLE folders (
    id             UUID  PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_encrypted BYTEA NOT NULL,
    parent_id      UUID  REFERENCES folders(id) ON DELETE CASCADE
);

-- ============================================================================
-- Vault Entries
-- ============================================================================
CREATE TABLE vault_entries (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id         UUID        REFERENCES organizations(id) ON DELETE SET NULL,
    entry_type     TEXT        NOT NULL CHECK (entry_type IN ('login', 'secure_note', 'credit_card', 'identity')),
    encrypted_data BYTEA       NOT NULL,
    nonce          BYTEA       NOT NULL,
    version        INT         NOT NULL DEFAULT 1,
    folder_id      UUID        REFERENCES folders(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- TOTP Secrets
-- ============================================================================
CREATE TABLE totp_secrets (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    encrypted_secret BYTEA       NOT NULL,
    verified         BOOLEAN     NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- Shared 2FA
-- ============================================================================
CREATE TABLE shared_2fa (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    from_user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_totp_secret BYTEA       NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    claimed               BOOLEAN     NOT NULL DEFAULT false,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- Recovery Codes
-- ============================================================================
CREATE TABLE recovery_codes (
    id        UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id   UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BYTEA   NOT NULL,
    used      BOOLEAN NOT NULL DEFAULT false
);

-- ============================================================================
-- Sessions
-- ============================================================================
CREATE TABLE sessions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  BYTEA       NOT NULL,
    device_info TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- Audit Log
-- ============================================================================
CREATE TABLE audit_log (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID        REFERENCES users(id) ON DELETE SET NULL,
    target_id  UUID,
    action     TEXT        NOT NULL,
    details    JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- Sync Cursors
-- ============================================================================
CREATE TABLE sync_cursors (
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL,
    last_sync_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id)
);

-- ============================================================================
-- Indexes
-- ============================================================================
CREATE INDEX idx_vault_entries_user_updated ON vault_entries (user_id, updated_at);
CREATE INDEX idx_audit_log_actor           ON audit_log (actor_id, created_at);
CREATE INDEX idx_audit_log_target          ON audit_log (target_id, created_at);
CREATE INDEX idx_sessions_token_hash       ON sessions (token_hash);
CREATE INDEX idx_sessions_expires_at       ON sessions (expires_at);

-- ============================================================================
-- Updated-at trigger (auto-set updated_at on row modification)
-- ============================================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_vault_entries_updated_at
    BEFORE UPDATE ON vault_entries
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
