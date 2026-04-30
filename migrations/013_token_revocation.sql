-- Add token revocation timestamp to users table.
-- When set, any JWT issued before this timestamp is considered invalid.
ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_revoked_at TIMESTAMPTZ;
