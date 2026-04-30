import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import { useVaultStore } from '../../store/vaultStore';

interface CollectionItem {
  id: string;
  org_id: string;
  name_encrypted: string;
  name_nonce: string;
  encrypted_key: string;
  member_count: number;
  entry_count: number;
  external_id?: string;
  created_at: string;
  updated_at: string;
}

interface CollectionMember {
  collection_id: string;
  user_id: string;
  email: string;
  encrypted_key: string;
  permission: string;
}

interface Props {
  orgId: string;
}

export function CollectionsPanel({ orgId }: Props) {
  const [collections, setCollections] = useState<CollectionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState('');
  const [creating, setCreating] = useState(false);
  const [selectedCollection, setSelectedCollection] = useState<string | null>(null);
  const [members, setMembers] = useState<CollectionMember[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [addMemberEmail, setAddMemberEmail] = useState('');
  const [addMemberPerm, setAddMemberPerm] = useState('read');
  const [addingMember, setAddingMember] = useState(false);
  const [orgMembers, setOrgMembers] = useState<Array<{ user_id: string; email: string; role: string }>>([]);
  const [memberSuggestions, setMemberSuggestions] = useState<Array<{ user_id: string; email: string }>>([]);
  const [selectedMemberId, setSelectedMemberId] = useState<string | null>(null);
  const [renamingCollection, setRenamingCollection] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [renaming, setRenaming] = useState(false);

  const { token, masterKeyHex, userId } = useAuthStore();
  const bumpCollectionsVersion = useVaultStore((s) => s.bumpCollectionsVersion);
  const navigate = useNavigate();
  const location = useLocation();

  const loadCollections = useCallback(async () => {
    if (!token || !orgId) return;
    setLoading(true);
    setError('');
    try {
      const result = await window.api.collections.listOrg(token, orgId) as CollectionItem[] | { error: string };
      if ('error' in result) {
        setError(result.error);
      } else {
        setCollections(result);
      }
    } catch {
      setError('Failed to load collections');
    } finally {
      setLoading(false);
    }
  }, [token, orgId]);

  useEffect(() => { loadCollections(); }, [loadCollections]);

  // Load org members for the add-member search
  useEffect(() => {
    if (!token || !orgId) return;
    (async () => {
      try {
        const result = await window.api.admin.listMembers(token, orgId) as Array<{ user_id: string; email: string; role: string }> | { error: string };
        if (!('error' in result) && Array.isArray(result)) {
          setOrgMembers(result);
        }
      } catch { /* ignore */ }
    })();
  }, [token, orgId]);

  const loadMembers = async (collId: string) => {
    if (!token) return;
    setLoadingMembers(true);
    try {
      const result = await window.api.collections.getMembers(token, collId) as CollectionMember[] | { error: string };
      if (!('error' in result)) {
        setMembers(result);
      }
    } catch { /* ignore */ }
    setLoadingMembers(false);
  };

  const handleSelectCollection = (collId: string) => {
    if (selectedCollection === collId) {
      setSelectedCollection(null);
      setMembers([]);
    } else {
      setSelectedCollection(collId);
      loadMembers(collId);
    }
  };

  const handleCreate = async () => {
    if (!token || !masterKeyHex || !createName.trim()) return;
    setCreating(true);
    setError('');
    try {
      // Generate a random collection key (32 bytes)
      const collKeyArray = new Uint8Array(32);
      crypto.getRandomValues(collKeyArray);
      const collKeyHex = Array.from(collKeyArray).map(b => b.toString(16).padStart(2, '0')).join('');

      // Encrypt the collection name with the COLLECTION key (so all members can decrypt)
      const encResult = await window.api.vault.encrypt(collKeyHex, createName.trim()) as { encrypted_data: string; nonce: string };

      // Encrypt the collection key with the user's master key
      const encKeyResult = await window.api.vault.encrypt(masterKeyHex, collKeyHex) as { encrypted_data: string; nonce: string };
      // Store as nonce + encrypted_data concatenated
      const encryptedKeyHex = encKeyResult.nonce + encKeyResult.encrypted_data;

      const result = await window.api.collections.create(token, orgId, {
        name_encrypted: encResult.encrypted_data,
        name_nonce: encResult.nonce,
        encrypted_key: encryptedKeyHex,
      }) as { id?: string; error?: string };

      if (result.error) {
        setError(result.error);
      } else {
        setCreateName('');
        setShowCreate(false);
        loadCollections();
        bumpCollectionsVersion();
      }
    } catch {
      setError('Failed to create collection');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (collId: string) => {
    if (!token) return;
    try {
      const result = await window.api.collections.delete(token, collId) as { status?: string; error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setConfirmDelete(null);
        if (selectedCollection === collId) {
          setSelectedCollection(null);
          setMembers([]);
        }
        // Redirect away from vault collection view if this collection was being viewed
        if (location.pathname === `/vault/collection/${collId}`) {
          navigate('/vault');
        }
        loadCollections();
        bumpCollectionsVersion();
      }
    } catch {
      setError('Failed to delete collection');
    }
  };

  const handleRemoveMember = async (collId: string, userId: string) => {
    if (!token) return;
    try {
      await window.api.collections.removeMember(token, collId, userId);
      loadMembers(collId);
      loadCollections();
    } catch { /* ignore */ }
  };

  const handleChangePermission = async (collId: string, userId: string, permission: string) => {
    if (!token) return;
    try {
      await window.api.collections.updatePermission(token, collId, userId, permission);
      loadMembers(collId);
    } catch { /* ignore */ }
  };

  const handleRename = async (collId: string) => {
    if (!token || !masterKeyHex || !renameValue.trim()) return;
    setRenaming(true);
    try {
      const coll = collections.find(c => c.id === collId);
      if (!coll?.encrypted_key) return;
      const ekNonce = coll.encrypted_key.slice(0, 24);
      const ekCipher = coll.encrypted_key.slice(24);
      const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext: string };
      const encResult = await window.api.vault.encrypt(collKeyDec.plaintext, renameValue.trim()) as { encrypted_data: string; nonce: string };
      const result = await window.api.collections.update(token, collId, {
        name_encrypted: encResult.encrypted_data,
        name_nonce: encResult.nonce,
      }) as { error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setRenamingCollection(null);
        setRenameValue('');
        loadCollections();
        bumpCollectionsVersion();
      }
    } catch {
      setError('Failed to rename collection');
    } finally {
      setRenaming(false);
    }
  };

  // Decrypt collection name
  const [decryptedNames, setDecryptedNames] = useState<Record<string, string>>({});
  useEffect(() => {
    if (!masterKeyHex || collections.length === 0) return;
    (async () => {
      const names: Record<string, string> = {};
      for (const c of collections) {
        try {
          // Decrypt collection key with master key, then decrypt name with collection key
          if (c.encrypted_key) {
            const ekNonce = c.encrypted_key.slice(0, 24);
            const ekCipher = c.encrypted_key.slice(24);
            const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext: string };
            const dec = await window.api.vault.decrypt(collKeyDec.plaintext, c.name_encrypted, c.name_nonce) as { plaintext: string };
            names[c.id] = dec.plaintext;
          } else {
            names[c.id] = '(no access)';
          }
        } catch {
          names[c.id] = '(encrypted)';
        }
      }
      setDecryptedNames(names);
    })();
  }, [collections, masterKeyHex]);

  if (loading) {
    return <div className="text-surface-400 text-sm">Loading collections...</div>;
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-surface-200">Collections ({collections.length})</h2>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent-600 hover:bg-accent-500 text-white transition-colors"
        >
          + Create Collection
        </button>
      </div>

      {showCreate && (
        <div className="p-4 rounded-lg bg-surface-800 border border-surface-700 space-y-3">
          <input
            type="text"
            value={createName}
            onChange={(e) => setCreateName(e.target.value)}
            placeholder="Collection name"
            className="w-full px-3 py-2 text-sm rounded-md bg-surface-900 border border-surface-600 text-surface-100 placeholder-surface-500 focus:outline-none focus:border-accent-500"
          />
          <div className="flex gap-2">
            <button
              onClick={handleCreate}
              disabled={creating || !createName.trim()}
              className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent-600 hover:bg-accent-500 text-white disabled:opacity-50 transition-colors"
            >
              {creating ? 'Creating...' : 'Create'}
            </button>
            <button
              onClick={() => { setShowCreate(false); setCreateName(''); }}
              className="px-3 py-1.5 text-xs rounded-md text-surface-400 hover:text-surface-200 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {collections.length === 0 && !showCreate && (
        <div className="text-center py-8 text-surface-400 text-sm">
          No collections yet. Create one to start sharing vault entries.
        </div>
      )}

      <div className="space-y-1">
        {collections.map((coll) => (
          <div key={coll.id} className="rounded-lg bg-surface-800 border border-surface-700">
            <div
              className="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-surface-750 transition-colors"
              onClick={() => handleSelectCollection(coll.id)}
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-sm">📁</span>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-surface-100 truncate">
                    {decryptedNames[coll.id] ?? '...'}
                  </div>
                  <div className="text-xs text-surface-400">
                    {coll.member_count} member{coll.member_count !== 1 ? 's' : ''} · {coll.entry_count} entr{coll.entry_count !== 1 ? 'ies' : 'y'}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0 ml-2">
                <span className="text-surface-500 text-xs">{selectedCollection === coll.id ? '▲' : '▼'}</span>
                {confirmDelete === coll.id ? (
                  <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                    <span className="text-xs text-red-400">Delete?</span>
                    <button onClick={() => handleDelete(coll.id)} className="px-2 py-0.5 text-xs rounded bg-red-600 hover:bg-red-500 text-white">Yes</button>
                    <button onClick={() => setConfirmDelete(null)} className="px-2 py-0.5 text-xs rounded text-surface-400 hover:text-surface-200">No</button>
                  </div>
                ) : (
                  <button
                    onClick={(e) => { e.stopPropagation(); setConfirmDelete(coll.id); }}
                    className="text-surface-500 hover:text-red-400 transition-colors"
                    title="Delete collection"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                  </button>
                )}
              </div>
            </div>

            {selectedCollection === coll.id && (
              <div className="border-t border-surface-700 px-4 py-3 space-y-3">
                {/* Rename section */}
                <div className="text-xs font-medium text-surface-300 uppercase tracking-wide">Name</div>
                {renamingCollection === coll.id ? (
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') handleRename(coll.id); if (e.key === 'Escape') setRenamingCollection(null); }}
                      autoFocus
                      className="flex-1 px-2 py-1.5 text-xs rounded bg-surface-900 border border-surface-600 text-surface-100 focus:outline-none focus:border-accent-500"
                    />
                    <button
                      onClick={() => handleRename(coll.id)}
                      disabled={renaming || !renameValue.trim()}
                      className="px-2 py-1 text-xs rounded bg-accent-600 hover:bg-accent-500 text-white disabled:opacity-50"
                    >
                      {renaming ? '...' : 'Save'}
                    </button>
                    <button
                      onClick={() => setRenamingCollection(null)}
                      className="px-2 py-1 text-xs text-surface-400 hover:text-surface-200"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-surface-200">{decryptedNames[coll.id] ?? '...'}</span>
                    <button
                      onClick={() => { setRenamingCollection(coll.id); setRenameValue(decryptedNames[coll.id] ?? ''); }}
                      className="text-xs text-accent-400 hover:text-accent-300 transition-colors"
                    >
                      Edit
                    </button>
                  </div>
                )}

                <div className="text-xs font-medium text-surface-300 uppercase tracking-wide">Members</div>
                {loadingMembers ? (
                  <div className="text-xs text-surface-400">Loading members...</div>
                ) : (
                  <div className="space-y-2">
                    {members.map((m) => (
                      <div key={m.user_id} className="flex items-center justify-between py-1">
                        <span className="text-sm text-surface-200">{m.email}</span>
                        <div className="flex items-center gap-2">
                          <select
                            value={m.permission}
                            onChange={(e) => handleChangePermission(coll.id, m.user_id, e.target.value)}
                            className="text-xs px-2 py-1 rounded bg-surface-900 border border-surface-600 text-surface-200"
                          >
                            <option value="read">Read</option>
                            <option value="manage">Manage</option>
                          </select>
                          <button
                            onClick={() => handleRemoveMember(coll.id, m.user_id)}
                            className="text-xs text-red-400 hover:text-red-300"
                          >
                            Remove
                          </button>
                        </div>
                      </div>
                    ))}
                    {members.length === 0 && (
                      <div className="text-xs text-surface-400">No members</div>
                    )}
                  </div>
                )}

                {/* Add member */}
                <div className="pt-2 border-t border-surface-700">
                  <div className="text-xs font-medium text-surface-300 mb-2">Add Member</div>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <input
                        type="text"
                        value={addMemberEmail}
                        onChange={(e) => {
                          const val = e.target.value;
                          setAddMemberEmail(val);
                          setSelectedMemberId(null);
                          const existing = members.map(m => m.user_id);
                          setMemberSuggestions(
                            orgMembers.filter(m =>
                              m.email.toLowerCase().includes(val.toLowerCase()) &&
                              !existing.includes(m.user_id)
                            ).slice(0, 5)
                          );
                        }}
                        onFocus={() => {
                          const existing = members.map(m => m.user_id);
                          setMemberSuggestions(
                            orgMembers.filter(m =>
                              m.email.toLowerCase().includes(addMemberEmail.toLowerCase()) &&
                              !existing.includes(m.user_id)
                            ).slice(0, 5)
                          );
                        }}
                        onBlur={() => {
                          // Delay to allow click on suggestion
                          setTimeout(() => setMemberSuggestions([]), 150);
                        }}
                        placeholder="Search by email..."
                        className="w-full px-2 py-1.5 text-xs rounded bg-surface-900 border border-surface-600 text-surface-100 placeholder-surface-500 focus:outline-none focus:border-accent-500"
                      />
                      {memberSuggestions.length > 0 && (
                        <div className="absolute z-10 top-full left-0 right-0 mt-1 bg-surface-800 border border-surface-600 rounded shadow-lg max-h-32 overflow-y-auto">
                          {memberSuggestions.map((s) => (
                            <button
                              key={s.user_id}
                              onMouseDown={(e) => {
                                e.preventDefault();
                                setAddMemberEmail(s.email);
                                setSelectedMemberId(s.user_id);
                                setMemberSuggestions([]);
                              }}
                              className="w-full text-left px-3 py-1.5 text-xs text-surface-200 hover:bg-surface-700 transition-colors"
                            >
                              {s.email}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                    <select
                      value={addMemberPerm}
                      onChange={(e) => setAddMemberPerm(e.target.value)}
                      className="text-xs px-2 py-1.5 rounded bg-surface-900 border border-surface-600 text-surface-200"
                    >
                      <option value="read">Read</option>
                      <option value="manage">Manage</option>
                    </select>
                    <button
                      onClick={async () => {
                        const targetUserId = selectedMemberId || orgMembers.find(m => m.email === addMemberEmail.trim())?.user_id;
                        if (!token || !targetUserId || !masterKeyHex) return;
                        setAddingMember(true);
                        try {
                          // Server handles escrow-based key re-encryption
                          const result = await window.api.collections.addMember(token, coll.id, {
                            user_id: targetUserId,
                            permission: addMemberPerm,
                            master_key: masterKeyHex,
                          }) as { error?: string; status?: string };
                          if (result.error) {
                            setError(result.error);
                          } else {
                            setAddMemberEmail('');
                            setSelectedMemberId(null);
                            setMemberSuggestions([]);
                            loadMembers(coll.id);
                            loadCollections();
                            bumpCollectionsVersion();
                          }
                        } catch (e) {
                          setError('Failed to add member');
                        }
                        setAddingMember(false);
                      }}
                      disabled={addingMember || (!selectedMemberId && !orgMembers.find(m => m.email === addMemberEmail.trim()))}
                      className="px-3 py-1.5 text-xs font-medium rounded bg-accent-600 hover:bg-accent-500 text-white disabled:opacity-50"
                    >
                      {addingMember ? '...' : 'Add'}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
