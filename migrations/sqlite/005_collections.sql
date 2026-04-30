-- Collections: shared vaults within an organization (SQLite version)
CREATE TABLE IF NOT EXISTS collections (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name_encrypted BLOB NOT NULL,
    name_nonce BLOB NOT NULL,
    external_id TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
);

CREATE TABLE IF NOT EXISTS collection_members (
    collection_id TEXT REFERENCES collections(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    encrypted_key BLOB NOT NULL,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'write', 'manage')),
    PRIMARY KEY (collection_id, user_id)
);

CREATE TABLE IF NOT EXISTS collection_entries (
    collection_id TEXT REFERENCES collections(id) ON DELETE CASCADE,
    entry_id TEXT REFERENCES vault_entries(id) ON DELETE CASCADE,
    PRIMARY KEY (collection_id, entry_id)
);

CREATE INDEX IF NOT EXISTS idx_collections_org ON collections(org_id);
CREATE INDEX IF NOT EXISTS idx_collection_members_user ON collection_members(user_id);
CREATE INDEX IF NOT EXISTS idx_collection_entries_entry ON collection_entries(entry_id);
