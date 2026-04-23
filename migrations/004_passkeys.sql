-- Passkey credentials (WebAuthn passkeys stored in the vault for websites)
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id         BYTEA NOT NULL UNIQUE,
    rp_id                 TEXT NOT NULL,
    rp_name               TEXT,
    user_handle           BYTEA NOT NULL,
    username              TEXT,
    display_name          TEXT,
    public_key_cbor       BYTEA NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    private_key_nonce     BYTEA NOT NULL,
    sign_count            INT NOT NULL DEFAULT 0,
    aaguid                BYTEA,
    transports            TEXT[],
    discoverable          BOOLEAN NOT NULL DEFAULT true,
    backed_up             BOOLEAN NOT NULL DEFAULT false,
    algorithm             INT NOT NULL DEFAULT -7,
    created_at            TIMESTAMPTZ DEFAULT now(),
    last_used_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_rp_user ON passkey_credentials (rp_id, user_id);
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_cred_id ON passkey_credentials (credential_id);

-- Hardware auth keys (for vault login 2FA, not website passkeys)
CREATE TABLE IF NOT EXISTS hardware_auth_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BYTEA NOT NULL UNIQUE,
    public_key_cbor BYTEA NOT NULL,
    sign_count      INT NOT NULL DEFAULT 0,
    aaguid          BYTEA,
    transports      TEXT[],
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hardware_auth_keys_user ON hardware_auth_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_hardware_auth_keys_cred_id ON hardware_auth_keys (credential_id);
