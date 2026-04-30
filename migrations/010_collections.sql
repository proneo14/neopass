-- Collections: shared vaults within an organization
CREATE TABLE collections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name_encrypted BYTEA NOT NULL,
    name_nonce BYTEA NOT NULL,
    external_id TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Per-member access to a collection with their encrypted copy of the collection key
CREATE TABLE collection_members (
    collection_id UUID REFERENCES collections(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    encrypted_key BYTEA NOT NULL,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'write', 'manage')),
    PRIMARY KEY (collection_id, user_id)
);

-- Junction table: entries can belong to multiple collections
CREATE TABLE collection_entries (
    collection_id UUID REFERENCES collections(id) ON DELETE CASCADE,
    entry_id UUID REFERENCES vault_entries(id) ON DELETE CASCADE,
    PRIMARY KEY (collection_id, entry_id)
);

CREATE INDEX idx_collections_org ON collections(org_id);
CREATE INDEX idx_collection_members_user ON collection_members(user_id);
CREATE INDEX idx_collection_entries_entry ON collection_entries(entry_id);
