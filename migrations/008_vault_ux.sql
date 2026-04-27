-- 008_vault_ux.sql — Add favorites, archive, and trash with auto-purge support

ALTER TABLE vault_entries ADD COLUMN is_favorite BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vault_entries ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vault_entries ADD COLUMN deleted_at TIMESTAMPTZ;

-- Set deleted_at for already soft-deleted entries
UPDATE vault_entries SET deleted_at = updated_at WHERE is_deleted = true AND deleted_at IS NULL;

CREATE INDEX idx_vault_entries_favorites ON vault_entries(user_id, is_favorite) WHERE is_favorite = true;
CREATE INDEX idx_vault_entries_archived ON vault_entries(user_id, is_archived) WHERE is_archived = true;
CREATE INDEX idx_vault_entries_trash ON vault_entries(user_id, deleted_at) WHERE is_deleted = true;
