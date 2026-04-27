-- 004_secure_send.sql — Secure Send: time-limited encrypted sharing via unique links

CREATE TABLE IF NOT EXISTS sends (
  id TEXT PRIMARY KEY CHECK(length(id) = 36),
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  slug TEXT NOT NULL UNIQUE,
  send_type TEXT NOT NULL CHECK (send_type IN ('text', 'file')),
  encrypted_data BLOB NOT NULL,
  nonce BLOB NOT NULL,
  encrypted_name BLOB,
  name_nonce BLOB,
  password_hash BLOB,
  max_access_count INTEGER,
  access_count INTEGER NOT NULL DEFAULT 0,
  file_name TEXT,
  file_size INTEGER,
  expires_at TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  hide_email INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || 'Z')
);

CREATE INDEX IF NOT EXISTS idx_sends_user ON sends(user_id);
CREATE INDEX IF NOT EXISTS idx_sends_slug ON sends(slug);
CREATE INDEX IF NOT EXISTS idx_sends_expires ON sends(expires_at);
