-- Collection entries store their own encrypted copy (encrypted with collection key)
-- so all collection members can decrypt entries regardless of who owns the original
ALTER TABLE collection_entries ADD COLUMN encrypted_data BYTEA;
ALTER TABLE collection_entries ADD COLUMN nonce BYTEA;
ALTER TABLE collection_entries ADD COLUMN entry_type TEXT NOT NULL DEFAULT 'login';
