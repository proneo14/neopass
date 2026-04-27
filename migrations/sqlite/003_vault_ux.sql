-- Migration 003: Add favorites, archive, and trash support
ALTER TABLE vault_entries ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vault_entries ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vault_entries ADD COLUMN deleted_at TEXT;

-- Set deleted_at for already soft-deleted entries
UPDATE vault_entries SET deleted_at = updated_at WHERE is_deleted = 1 AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_vault_entries_favorites ON vault_entries(user_id, is_favorite);
CREATE INDEX IF NOT EXISTS idx_vault_entries_archived ON vault_entries(user_id, is_archived);
CREATE INDEX IF NOT EXISTS idx_vault_entries_trash ON vault_entries(user_id, deleted_at);
