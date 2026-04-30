-- Emergency access: allows trusted contacts to request vault access after a waiting period
CREATE TABLE IF NOT EXISTS emergency_access (
    id TEXT PRIMARY KEY CHECK(length(id) = 36),
    grantor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    grantee_email TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('invited', 'accepted', 'recovery_initiated', 'recovery_approved', 'recovery_rejected', 'expired')),
    access_type TEXT NOT NULL CHECK (access_type IN ('view', 'takeover')),
    wait_time_days INTEGER NOT NULL DEFAULT 7,
    encrypted_key BLOB,
    key_nonce BLOB,
    recovery_initiated_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_emergency_grantor ON emergency_access(grantor_id);
CREATE INDEX IF NOT EXISTS idx_emergency_grantee ON emergency_access(grantee_id);
