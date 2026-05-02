-- 014_ssh_keys.sql: Add ssh_key to vault_entries entry_type constraint

-- PostgreSQL: update CHECK constraint
ALTER TABLE vault_entries DROP CONSTRAINT IF EXISTS vault_entries_entry_type_check;
ALTER TABLE vault_entries ADD CONSTRAINT vault_entries_entry_type_check
  CHECK (entry_type IN ('login', 'secure_note', 'credit_card', 'identity', 'ssh_key'));

-- SQLite: no ALTER CHECK support; SQLite does not enforce CHECK constraints by default.
