-- Collection entries store their own encrypted copy (encrypted with collection key)
ALTER TABLE collection_entries ADD COLUMN encrypted_data BLOB;
ALTER TABLE collection_entries ADD COLUMN nonce BLOB;
ALTER TABLE collection_entries ADD COLUMN entry_type TEXT NOT NULL DEFAULT 'login';
