-- Migration 006: Add per-admin encrypted org key to org_members.
-- This allows any admin (not just the org creator) to decrypt the org private key
-- for vault access and escrow operations.
BEGIN;

ALTER TABLE org_members ADD COLUMN IF NOT EXISTS encrypted_org_key BYTEA;

COMMIT;
