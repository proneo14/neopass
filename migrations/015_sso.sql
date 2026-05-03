-- SSO & SCIM support for organizations (enterprise feature).

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_config JSONB;
-- sso_config schema:
-- {
--   "provider": "saml" | "oidc",
--   "saml": { "entity_id": "", "sso_url": "", "certificate": "", "name_id_format": "" },
--   "oidc": { "issuer": "", "client_id": "", "client_secret_encrypted": "", "redirect_uri": "", "scopes": [] },
--   "auto_enroll": true
-- }

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS scim_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS scim_token_hash BYTEA;

ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_external_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso_external ON users(sso_external_id) WHERE sso_external_id IS NOT NULL;
