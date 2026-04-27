-- 009_secure_send.sql — Secure Send: time-limited encrypted sharing via unique links

CREATE TABLE sends (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  slug TEXT NOT NULL UNIQUE,
  send_type TEXT NOT NULL CHECK (send_type IN ('text', 'file')),
  encrypted_data BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  encrypted_name BYTEA,
  name_nonce BYTEA,
  password_hash BYTEA,
  max_access_count INT,
  access_count INT NOT NULL DEFAULT 0,
  file_name TEXT,
  file_size INT,
  expires_at TIMESTAMPTZ NOT NULL,
  disabled BOOLEAN NOT NULL DEFAULT false,
  hide_email BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_sends_user ON sends(user_id);
CREATE INDEX idx_sends_slug ON sends(slug);
CREATE INDEX idx_sends_expires ON sends(expires_at);
