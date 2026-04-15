-- Migration 002: Add policy column, invitations table for admin system
BEGIN;

-- Policy column on organizations
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS policy JSONB;

-- Invitations table
CREATE TABLE IF NOT EXISTS invitations (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email      TEXT        NOT NULL,
    role       TEXT        NOT NULL CHECK (role IN ('admin', 'member')),
    invited_by UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    accepted   BOOLEAN     NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_invitations_org_email ON invitations (org_id, email);

COMMIT;
