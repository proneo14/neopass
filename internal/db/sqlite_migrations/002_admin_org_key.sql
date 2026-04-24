-- Migration 002: Add per-admin encrypted org key to org_members
ALTER TABLE org_members ADD COLUMN encrypted_org_key BLOB;
