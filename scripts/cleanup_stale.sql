-- Clean up stale collections after takeover broke all encrypted keys
-- The collection member encrypted_key values were encrypted with the old X25519 pubkey

-- Remove all collection entries (the entry data references are just IDs, but they belong to broken collections)
DELETE FROM collection_entries;

-- Remove all collection members (encrypted keys are undecryptable)
DELETE FROM collection_members;

-- Remove the collections themselves
DELETE FROM collections;

-- Remove any stale emergency access records
DELETE FROM emergency_access;

-- Verify cleanup
SELECT 'collections' as tbl, count(*) FROM collections
UNION ALL SELECT 'collection_members', count(*) FROM collection_members
UNION ALL SELECT 'collection_entries', count(*) FROM collection_entries
UNION ALL SELECT 'emergency_access', count(*) FROM emergency_access;
