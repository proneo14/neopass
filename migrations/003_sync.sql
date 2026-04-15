-- Migration 003: Sync support — soft-delete flag on vault_entries
BEGIN;

ALTER TABLE vault_entries ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT false;

COMMIT;
