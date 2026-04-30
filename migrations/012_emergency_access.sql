-- Emergency access: allows trusted contacts to request vault access after a waiting period
CREATE TABLE IF NOT EXISTS emergency_access (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    grantor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_id UUID REFERENCES users(id) ON DELETE SET NULL,
    grantee_email TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('invited', 'accepted', 'recovery_initiated', 'recovery_approved', 'recovery_rejected', 'expired')),
    access_type TEXT NOT NULL CHECK (access_type IN ('view', 'takeover')),
    wait_time_days INT NOT NULL DEFAULT 7,
    encrypted_key BYTEA,
    key_nonce BYTEA,
    recovery_initiated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_emergency_grantor ON emergency_access(grantor_id);
CREATE INDEX idx_emergency_grantee ON emergency_access(grantee_id);
