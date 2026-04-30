import React, { useState, useMemo, useRef, useEffect } from 'react';
import { useNavigate, useParams, useLocation } from 'react-router-dom';
import { useVaultStore } from '../store/vaultStore';
import { useAuthStore } from '../store/authStore';
import { ENTRY_TYPE_ICONS, ENTRY_TYPE_LABELS } from '../types/vault';
import { PasswordGenerator } from '../components/PasswordGenerator';
import { RepromptDialog } from '../components/RepromptDialog';
import type { VaultEntry } from '../types/vault';

const ENTRY_TYPES = ['login', 'secure_note', 'credit_card', 'identity'] as const;

function ContextMenu({
  x,
  y,
  onClose,
  onCopyUsername,
  onCopyPassword,
  onEdit,
  onDelete,
  hasCredentials,
  isFavorite,
  onToggleFavorite,
  onArchive,
  onUnarchive,
  isArchived,
  isTrash,
  onRestore,
  onPermanentDelete,
  onClone,
  readOnly = false,
}: {
  x: number;
  y: number;
  onClose: () => void;
  onCopyUsername: () => void;
  onCopyPassword: () => void;
  onEdit: () => void;
  onDelete: () => void;
  hasCredentials: boolean;
  isFavorite: boolean;
  onToggleFavorite: () => void;
  onArchive: () => void;
  onUnarchive: () => void;
  isArchived: boolean;
  isTrash: boolean;
  onRestore: () => void;
  onPermanentDelete: () => void;
  onClone: () => void;
  readOnly?: boolean;
}) {
  const menuRef = React.useRef<HTMLDivElement>(null);
  const [pos, setPos] = React.useState({ left: x, top: y });

  React.useEffect(() => {
    const handler = () => onClose();
    window.addEventListener('click', handler);
    return () => window.removeEventListener('click', handler);
  }, [onClose]);

  React.useEffect(() => {
    const el = menuRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    let newTop = y;
    let newLeft = x;
    if (y + rect.height > window.innerHeight) {
      newTop = Math.max(0, y - rect.height);
    }
    if (x + rect.width > window.innerWidth) {
      newLeft = Math.max(0, x - rect.width);
    }
    if (newTop !== pos.top || newLeft !== pos.left) {
      setPos({ left: newLeft, top: newTop });
    }
  }, [x, y]);

  return (
    <div
      ref={menuRef}
      className="fixed bg-surface-800 border border-surface-600 rounded-md shadow-xl py-1 z-50 min-w-[160px]"
      style={{ left: pos.left, top: pos.top }}
    >
      {isTrash ? (
        <>
          <button onClick={onRestore} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
            Restore
          </button>
          <button onClick={onPermanentDelete} className="w-full text-left px-3 py-1.5 text-sm text-red-400 hover:bg-surface-700 transition-colors">
            Delete forever
          </button>
        </>
      ) : (
        <>
          {hasCredentials && (
            <>
              <button onClick={onCopyUsername} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
                Copy username
              </button>
              <button onClick={onCopyPassword} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
                Copy password
              </button>
              <div className="border-t border-surface-700 my-1" />
            </>
          )}
          <button onClick={onToggleFavorite} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
            {isFavorite ? 'Remove favorite' : 'Add to favorites'}
          </button>
          {!readOnly && (
            <>
              {isArchived ? (
                <button onClick={onUnarchive} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
                  Unarchive
                </button>
              ) : (
                <button onClick={onArchive} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
                  Archive
                </button>
              )}
              <button onClick={onEdit} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
                Edit
              </button>
              <button onClick={onClone} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
                Clone
              </button>
              <button onClick={onDelete} className="w-full text-left px-3 py-1.5 text-sm text-red-400 hover:bg-surface-700 transition-colors">
                Delete
              </button>
            </>
          )}
        </>
      )}
    </div>
  );
}

function AddEntryDropdown({ onClose, onSelect }: { onClose: () => void; onSelect: (type: string) => void }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [onClose]);

  return (
    <div ref={ref} className="absolute right-0 top-full mt-1 bg-surface-800 border border-surface-600 rounded-md shadow-xl py-1 z-50 min-w-[180px]">
      {ENTRY_TYPES.map((type) => (
        <button
          key={type}
          onClick={() => onSelect(type)}
          className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-surface-200 hover:bg-surface-700 transition-colors text-left"
        >
          <span>{ENTRY_TYPE_ICONS[type]}</span>
          <span>{ENTRY_TYPE_LABELS[type]}</span>
        </button>
      ))}
    </div>
  );
}

const FIELD_DEFS: Record<string, { key: string; label: string; type?: string }[]> = {
  login: [
    { key: 'name', label: 'Name' },
    { key: 'username', label: 'Username' },
    { key: 'password', label: 'Password', type: 'password' },
    { key: 'uri', label: 'Website' },
    { key: 'notes', label: 'Notes', type: 'textarea' },
  ],
  secure_note: [
    { key: 'name', label: 'Name' },
    { key: 'content', label: 'Content', type: 'textarea' },
  ],
  credit_card: [
    { key: 'name', label: 'Name' },
    { key: 'number', label: 'Card Number' },
    { key: 'expiry', label: 'Expiry' },
    { key: 'cvv', label: 'CVV', type: 'password' },
    { key: 'cardholder', label: 'Cardholder' },
  ],
  identity: [
    { key: 'name', label: 'Name' },
    { key: 'firstName', label: 'First Name' },
    { key: 'lastName', label: 'Last Name' },
    { key: 'email', label: 'Email' },
    { key: 'phone', label: 'Phone' },
    { key: 'address', label: 'Address' },
  ],
};

function NewEntryModal({ entryType, onCancel, onSave }: {
  entryType: string;
  onCancel: () => void;
  onSave: (type: string, fields: Record<string, string>) => void;
}) {
  const fieldDefs = FIELD_DEFS[entryType] ?? [];
  const [fields, setFields] = useState<Record<string, string>>(
    Object.fromEntries(fieldDefs.map((f) => [f.key, '']))
  );
  const [showGenerator, setShowGenerator] = useState(false);

  const update = (key: string, val: string) => setFields((prev) => ({ ...prev, [key]: val }));

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onCancel}>
      <div className="bg-surface-900 rounded-lg w-[480px] max-h-[85vh] overflow-auto shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 px-5 pt-5 pb-3 border-b border-surface-800">
          <span className="text-lg">{ENTRY_TYPE_ICONS[entryType]}</span>
          <h3 className="text-sm font-semibold text-surface-100">New {ENTRY_TYPE_LABELS[entryType]}</h3>
        </div>

        <div className="px-5 py-4 space-y-3">
          {fieldDefs.map((f) => (
            <div key={f.key}>
              <label className="block text-xs text-surface-400 mb-1">{f.label}</label>
              {f.type === 'textarea' ? (
                <textarea
                  value={fields[f.key]} onChange={(e) => update(f.key, e.target.value)} rows={3}
                  className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 resize-none"
                  placeholder={f.label}
                />
              ) : f.key === 'password' ? (
                <>
                  <div className="flex gap-2">
                    <input
                      type="text" value={fields[f.key]} onChange={(e) => update(f.key, e.target.value)}
                      className="flex-1 px-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-100 text-sm font-mono placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
                      placeholder={f.label}
                    />
                    <button
                      type="button" onClick={() => setShowGenerator(!showGenerator)}
                      className="px-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-400 hover:text-accent-400 text-sm transition-colors"
                    >
                      Generate
                    </button>
                  </div>
                  {showGenerator && (
                    <div className="mt-2 p-4 bg-surface-800 rounded-lg">
                      <PasswordGenerator onUse={(pw) => { update('password', pw); setShowGenerator(false); }} />
                    </div>
                  )}
                </>
              ) : (
                <input
                  type={f.type ?? 'text'} value={fields[f.key]} onChange={(e) => update(f.key, e.target.value)}
                  className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
                  placeholder={f.label}
                />
              )}
            </div>
          ))}


        </div>

        <div className="flex gap-2 px-5 pb-5">
          <button onClick={onCancel} className="flex-1 py-2 rounded-md bg-surface-800 text-surface-400 text-sm hover:bg-surface-700 transition-colors">
            Cancel
          </button>
          <button
            onClick={() => onSave(entryType, fields)}
            disabled={!fields.name?.trim()}
            className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

export function Vault() {
  const navigate = useNavigate();
  const location = useLocation();
  const { collId } = useParams<{ collId?: string }>();
  const { entries, entryFields, addEntry, removeEntry, searchQuery, setSearchQuery, sortBy, setSortBy, selectedTypeFilter, setSelectedTypeFilter, updateEntry, isRepromptApproved, approveReprompt } = useVaultStore();
  const { token, masterKeyHex } = useAuthStore();

  // Derive filter and collection from URL path
  const selectedCollectionId = collId ?? null;
  const collPermissionRef = React.useRef<string | null>(null);
  const activeFilter: 'all' | 'favorites' | 'archived' | 'trash' =
    location.pathname === '/vault/favorites' ? 'favorites' :
    location.pathname === '/vault/archived' ? 'archived' :
    location.pathname === '/vault/trash' ? 'trash' : 'all';
  const [showAddDropdown, setShowAddDropdown] = useState(false);
  const [newEntryType, setNewEntryType] = useState<string | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; entryId: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const loadingRef = useRef(false);
  const [showRepromptDialog, setShowRepromptDialog] = useState(false);
  const [pendingRepromptAction, setPendingRepromptAction] = useState<(() => void) | null>(null);
  const [pendingRepromptEntryId, setPendingRepromptEntryId] = useState<string | null>(null);

  const filterTitle = selectedCollectionId ? 'Collection' : activeFilter === 'favorites' ? 'Favorites' : activeFilter === 'archived' ? 'Archive' : activeFilter === 'trash' ? 'Trash' : 'Vault';

  /** Require re-auth before executing an action on a reprompt-protected entry. */
  const withReprompt = (entryId: string, action: () => void) => {
    const fields = entryFields[entryId];
    const hasReprompt = fields?._reprompt === '1';
    if (!hasReprompt || isRepromptApproved(entryId)) {
      action();
      return;
    }
    setPendingRepromptEntryId(entryId);
    setPendingRepromptAction(() => action);
    setShowRepromptDialog(true);
  };

  const handleRepromptVerified = () => {
    if (pendingRepromptEntryId) approveReprompt(pendingRepromptEntryId);
    setShowRepromptDialog(false);
    if (pendingRepromptAction) {
      pendingRepromptAction();
      setPendingRepromptAction(null);
    }
    setPendingRepromptEntryId(null);
  };

  // Load entries from backend on mount, then poll
  useEffect(() => {
    if (!token || !masterKeyHex) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);

    // Clear entries immediately when switching views to prevent stale data flash
    useVaultStore.getState().setEntries([]);

    // Check for pending vault import from org leave
    window.api.vault.importExport(token).then((res) => {
      if (res.imported && res.imported > 0) {
        console.log(`[vault] Auto-imported ${res.imported} entries from org export`);
      }
    }).catch(() => {});

    const loadVault = async () => {
      if (loadingRef.current) return; // Skip if a load is already in flight
      loadingRef.current = true;
      try {
        // If a collection is selected, load collection entries instead
        if (selectedCollectionId) {
          // First, get the collection key by finding it in the user's collections
          const userColls = await window.api.collections.listUser(token) as Array<{
            id: string;
            encrypted_key: string;
            permission: string;
          }> | { error: string };
          if (!Array.isArray(userColls)) return;
          const thisColl = userColls.find(c => c.id === selectedCollectionId);
          if (!thisColl || !thisColl.encrypted_key) return;
          collPermissionRef.current = thisColl.permission;

          // Decrypt collection key with master key
          const ekNonce = thisColl.encrypted_key.slice(0, 24);
          const ekCipher = thisColl.encrypted_key.slice(24);
          const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext?: string; error?: string };
          if (collKeyDec.error || !collKeyDec.plaintext) return;
          const collKeyHex = collKeyDec.plaintext;

          if (cancelled) return;

          const collResult = await window.api.collections.listEntries(token, selectedCollectionId) as { error?: string } | Array<{ entry_id: string; entry_type: string; encrypted_data: string; nonce: string }>;
          if (!Array.isArray(collResult)) {
            // Don't clear entries on transient errors — keep stale data visible
            return;
          }
          if (cancelled) return;

          const loadedEntries: VaultEntry[] = [];
          const loadedFields: Record<string, Record<string, string>> = {};

          for (const entry of collResult) {
            if (!entry.encrypted_data || !entry.nonce) continue;
            // Decrypt with COLLECTION key, not master key
            const decResult = await window.api.vault.decrypt(collKeyHex, entry.encrypted_data, entry.nonce);
            if (decResult.error || !decResult.plaintext) continue;

            try {
              const parsed = JSON.parse(decResult.plaintext) as Record<string, unknown>;
              const fields: Record<string, string> = {};
              for (const [k, v] of Object.entries(parsed)) {
                if (k === 'passwordHistory') {
                  fields._passwordHistory = JSON.stringify(v);
                } else if (k === 'uris') {
                  fields._uris = JSON.stringify(v);
                } else if (k === 'reprompt') {
                  fields._reprompt = String(v === 1 || v === '1' ? '1' : '0');
                } else {
                  fields[k] = String(v ?? '');
                }
              }
              loadedEntries.push({
                id: entry.entry_id,
                entry_type: entry.entry_type as VaultEntry['entry_type'],
                encrypted_data: entry.encrypted_data,
                nonce: entry.nonce,
                version: 0,
                folder_id: null,
                is_favorite: false,
                is_archived: false,
                deleted_at: null,
                created_at: '',
                updated_at: '',
              });
              loadedFields[entry.entry_id] = fields;
            } catch { /* skip malformed */ }
          }

          if (!cancelled) {
            useVaultStore.getState().setEntries(loadedEntries);
            for (const [id, f] of Object.entries(loadedFields)) {
              useVaultStore.getState().updateEntryFields(id, f);
            }
            setLoading(false);
          }
          return;
        }

        // Build query params based on active filter
        let filterParam: string | undefined;
        if (activeFilter === 'favorites') filterParam = 'favorite=true';
        else if (activeFilter === 'archived') filterParam = 'filter=archived';
        else if (activeFilter === 'trash') filterParam = 'filter=trash';

        const listResult = await window.api.vault.list(token, filterParam) as { error?: string } | Array<{ id: string; entry_type: string; encrypted_data: string; nonce: string; folder_id: string | null; version: number; is_favorite?: boolean; is_archived?: boolean; deleted_at?: string | null; created_at: string; updated_at: string }>;
        if (!Array.isArray(listResult)) {
          console.error('[vault] list returned non-array:', listResult);
          // Don't clear entries on transient errors — keep stale data visible
          return;
        }
        if (cancelled) return;

        const loadedEntries: VaultEntry[] = [];
        const loadedFields: Record<string, Record<string, string>> = {};

        // Re-use already-decrypted fields to avoid redundant decrypt calls
        const existingFields = useVaultStore.getState().entryFields;

        for (const summary of listResult) {
          // If we already have this entry decrypted at the same version, skip re-fetching
          const existingEntry = useVaultStore.getState().entries.find(e => e.id === summary.id);
          if (existingEntry && existingEntry.version === summary.version && existingFields[summary.id]) {
            loadedEntries.push(existingEntry);
            loadedFields[summary.id] = existingFields[summary.id];
            continue;
          }

          // Encrypted data is included in list response — decrypt directly, no separate fetch needed
          if (!summary.encrypted_data || !summary.nonce) continue;
          const decResult = await window.api.vault.decrypt(masterKeyHex, summary.encrypted_data, summary.nonce);
          if (decResult.error || !decResult.plaintext) continue;

          try {
            const parsed = JSON.parse(decResult.plaintext) as Record<string, unknown>;
            // Extract structured data into prefixed string fields
            const fields: Record<string, string> = {};
            for (const [k, v] of Object.entries(parsed)) {
              if (k === 'passwordHistory') {
                fields._passwordHistory = JSON.stringify(v);
              } else if (k === 'uris') {
                fields._uris = JSON.stringify(v);
              } else if (k === 'reprompt') {
                fields._reprompt = String(v === 1 || v === '1' ? '1' : '0');
              } else {
                fields[k] = String(v ?? '');
              }
            }
            loadedEntries.push({
              id: summary.id,
              entry_type: summary.entry_type as VaultEntry['entry_type'],
              encrypted_data: summary.encrypted_data,
              nonce: summary.nonce,
              version: summary.version,
              folder_id: summary.folder_id ?? null,
              is_favorite: summary.is_favorite ?? false,
              is_archived: summary.is_archived ?? false,
              deleted_at: summary.deleted_at ?? null,
              created_at: summary.created_at,
              updated_at: summary.updated_at,
            });
            loadedFields[summary.id] = fields;
          } catch { /* skip entries that fail to parse */ }
        }

        if (!cancelled) {
          useVaultStore.getState().setEntries(loadedEntries);
          for (const [id, fields] of Object.entries(loadedFields)) {
            useVaultStore.getState().updateEntryFields(id, fields);
          }
        }
      } finally {
        loadingRef.current = false;
        if (!cancelled) setLoading(false);
      }
    };

    loadVault();
    const interval = setInterval(loadVault, 10000);

    return () => { cancelled = true; loadingRef.current = false; clearInterval(interval); };
  }, [token, masterKeyHex, activeFilter, selectedCollectionId]);



  const filtered = useMemo(() => {
    let result = entries;

    if (selectedTypeFilter) {
      result = result.filter((e) => e.entry_type === selectedTypeFilter);
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter((e) => {
        const f = entryFields[e.id];
        const name = (f?.name ?? '').toLowerCase();
        const user = (f?.username ?? f?.email ?? '').toLowerCase();
        return name.includes(q) || user.includes(q) || e.entry_type.includes(q);
      });
    }

    result = [...result].sort((a, b) => {
      if (sortBy === 'updated_at') return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
      if (sortBy === 'entry_type') return a.entry_type.localeCompare(b.entry_type);
      const nameA = entryFields[a.id]?.name ?? '';
      const nameB = entryFields[b.id]?.name ?? '';
      return nameA.localeCompare(nameB);
    });

    return result;
  }, [entries, entryFields, searchQuery, sortBy, selectedTypeFilter]);

  const handleContextMenu = (e: React.MouseEvent, entryId: string) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, entryId });
  };

  const handleAddEntry = (type: string) => {
    setShowAddDropdown(false);
    setNewEntryType(type);
  };

  const handleSaveNewEntry = async (type: string, fields: Record<string, string>) => {
    if (!token || !masterKeyHex) return;

    // Build the plaintext object, converting uri to uris array for login entries
    const plaintextObj: Record<string, unknown> = { ...fields };
    if (type === 'login' && fields.uri) {
      plaintextObj.uris = [{ uri: fields.uri, match: 'base_domain' }];
    }

    const plaintext = JSON.stringify(plaintextObj);
    const encResult = await window.api.vault.encrypt(masterKeyHex, plaintext);
    if (encResult.error) return;

    // Save to backend
    const createResult = await window.api.vault.create(token, {
      entry_type: type,
      encrypted_data: encResult.encrypted_data,
      nonce: encResult.nonce,
    }) as { id: string; entry_type: string; encrypted_data: string; nonce: string; version: number; folder_id: string | null; created_at: string; updated_at: string; error?: string };

    if (createResult.error) return;

    const newEntry: VaultEntry = {
      id: createResult.id,
      entry_type: createResult.entry_type as VaultEntry['entry_type'],
      encrypted_data: createResult.encrypted_data,
      nonce: createResult.nonce,
      version: createResult.version,
      folder_id: createResult.folder_id ?? null,
      is_favorite: false,
      is_archived: false,
      deleted_at: null,
      created_at: createResult.created_at,
      updated_at: createResult.updated_at,
    };
    addEntry(newEntry, fields);
    setNewEntryType(null);

    // If creating from a collection view, also add the entry to that collection
    if (selectedCollectionId) {
      try {
        const userColls = await window.api.collections.listUser(token) as Array<{
          id: string; encrypted_key: string; permission: string;
        }> | { error: string };
        if (Array.isArray(userColls)) {
          const coll = userColls.find(c => c.id === selectedCollectionId);
          if (coll?.encrypted_key) {
            const ekNonce = coll.encrypted_key.slice(0, 24);
            const ekCipher = coll.encrypted_key.slice(24);
            const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext: string };
            const collEnc = await window.api.vault.encrypt(collKeyDec.plaintext, plaintext) as { encrypted_data: string; nonce: string };
            await window.api.collections.addEntry(token, selectedCollectionId, createResult.id, {
              entry_type: type,
              encrypted_data: collEnc.encrypted_data,
              nonce: collEnc.nonce,
            });
          }
        }
      } catch { /* best-effort */ }
    }
  };

  const formatDate = (iso: string) => {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays}d ago`;
    return d.toLocaleDateString();
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-lg font-semibold text-surface-100">{filterTitle}</h1>
        {activeFilter !== 'trash' && !(selectedCollectionId && collPermissionRef.current === 'read') && (
          <div className="relative">
            <button
              onClick={() => setShowAddDropdown(!showAddDropdown)}
              className="px-3 py-1.5 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors"
            >
              + Add Entry
            </button>
            {showAddDropdown && (
              <AddEntryDropdown onClose={() => setShowAddDropdown(false)} onSelect={handleAddEntry} />
            )}
          </div>
        )}
      </div>

      {/* Search + Filters */}
      <div className="flex gap-2 mb-4">
        <div className="flex-1 relative">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-surface-500 text-sm">🔍</span>
          <input
            type="text"
            placeholder="Search vault…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
          />
        </div>

        {/* Sort */}
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as 'name' | 'updated_at' | 'entry_type')}
          className="px-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-300 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
        >
          <option value="updated_at">Modified</option>
          <option value="name">Name</option>
          <option value="entry_type">Type</option>
        </select>
      </div>

      {/* Type filter pills */}
      <div className="flex gap-1.5 mb-4">
        <button
          onClick={() => setSelectedTypeFilter(null)}
          className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
            !selectedTypeFilter ? 'bg-accent-600 text-white' : 'bg-surface-800 text-surface-400 hover:bg-surface-700'
          }`}
        >
          All
        </button>
        {ENTRY_TYPES.map((type) => (
          <button
            key={type}
            onClick={() => setSelectedTypeFilter(selectedTypeFilter === type ? null : type)}
            className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
              selectedTypeFilter === type ? 'bg-accent-600 text-white' : 'bg-surface-800 text-surface-400 hover:bg-surface-700'
            }`}
          >
            {ENTRY_TYPE_ICONS[type]} {ENTRY_TYPE_LABELS[type]}
          </button>
        ))}
      </div>

      {/* Entry list */}
      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-20 text-surface-500">
            <p className="text-sm">Loading vault…</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-surface-500">
            <span className="text-5xl mb-4">🔐</span>
            <p className="text-sm">{searchQuery ? 'No matching entries' : 'Your vault is empty'}</p>
            <p className="text-xs mt-1">
              {searchQuery ? 'Try a different search term' : 'Add your first entry to get started'}
            </p>
          </div>
        ) : (
          <div className="space-y-1">
            {filtered.map((entry) => {
              const f = entryFields[entry.id];
              return (
                <div
                  key={entry.id}
                  onClick={() => navigate(`/vault/${entry.id}`, selectedCollectionId ? { state: { collectionId: selectedCollectionId, collectionPermission: collPermissionRef.current } } : undefined)}
                  onContextMenu={(e) => handleContextMenu(e, entry.id)}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-md hover:bg-surface-800/60 cursor-pointer transition-colors group"
                >
                  <span className="text-lg w-8 text-center shrink-0">
                    {ENTRY_TYPE_ICONS[entry.entry_type]}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-surface-100 truncate">
                      {f?.name ?? 'Untitled'}
                    </p>
                    {(f?.username || f?.email) && (
                      <p className="text-xs text-surface-500 truncate">{f.username || f.email}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {f?._reprompt === '1' && <span className="text-surface-500 text-[11px]" title="Master password re-prompt enabled">🔒</span>}
                    {selectedCollectionId && <span className="text-surface-500 text-[11px]" title="Shared collection entry">🔗</span>}
                    {entry.is_favorite && <svg className="w-3.5 h-3.5 text-amber-400" viewBox="0 0 20 20" fill="currentColor"><path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.286 3.957a1 1 0 00.95.69h4.162c.969 0 1.371 1.24.588 1.81l-3.37 2.448a1 1 0 00-.364 1.118l1.287 3.957c.3.921-.755 1.688-1.54 1.118l-3.37-2.448a1 1 0 00-1.176 0l-3.37 2.448c-.784.57-1.838-.197-1.539-1.118l1.287-3.957a1 1 0 00-.364-1.118L2.065 9.384c-.783-.57-.38-1.81.588-1.81h4.162a1 1 0 00.95-.69l1.284-3.957z" /></svg>}
                    <span className="text-xs text-surface-600 group-hover:text-surface-400 transition-colors">
                      {formatDate(entry.updated_at)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* New entry modal */}
      {newEntryType && (
        <NewEntryModal
          entryType={newEntryType}
          onCancel={() => setNewEntryType(null)}
          onSave={handleSaveNewEntry}
        />
      )}

      {/* Modals */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          hasCredentials={entries.find((e) => e.id === contextMenu.entryId)?.entry_type === 'login'}
          isFavorite={entries.find((e) => e.id === contextMenu.entryId)?.is_favorite ?? false}
          isArchived={activeFilter === 'archived'}
          isTrash={activeFilter === 'trash'}
          readOnly={selectedCollectionId != null && collPermissionRef.current === 'read'}
          onClose={() => setContextMenu(null)}
          onCopyUsername={() => {
            navigator.clipboard.writeText(entryFields[contextMenu.entryId]?.username ?? '');
            setContextMenu(null);
          }}
          onCopyPassword={() => {
            const eid = contextMenu.entryId;
            setContextMenu(null);
            withReprompt(eid, async () => {
              await window.api.clipboard.copySecure(entryFields[eid]?.password ?? '');
            });
          }}
          onToggleFavorite={async () => {
            if (token) {
              const entry = entries.find((e) => e.id === contextMenu.entryId);
              if (entry) {
                await window.api.vault.setFavorite(token, contextMenu.entryId, !entry.is_favorite);
                updateEntry({ ...entry, is_favorite: !entry.is_favorite });
              }
            }
            setContextMenu(null);
          }}
          onArchive={async () => {
            if (token) {
              await window.api.vault.setArchived(token, contextMenu.entryId, true);
              removeEntry(contextMenu.entryId);
            }
            setContextMenu(null);
          }}
          onUnarchive={async () => {
            if (token) {
              await window.api.vault.setArchived(token, contextMenu.entryId, false);
              removeEntry(contextMenu.entryId);
            }
            setContextMenu(null);
          }}
          onRestore={async () => {
            if (token) {
              await window.api.vault.restore(token, contextMenu.entryId);
              removeEntry(contextMenu.entryId);
            }
            setContextMenu(null);
          }}
          onPermanentDelete={async () => {
            if (token) {
              await window.api.vault.permanentDelete(token, contextMenu.entryId);
              removeEntry(contextMenu.entryId);
            }
            setContextMenu(null);
          }}
          onEdit={() => {
            navigate(`/vault/${contextMenu.entryId}`, { state: { edit: true, ...(selectedCollectionId ? { collectionId: selectedCollectionId, collectionPermission: collPermissionRef.current } : {}) } });
            setContextMenu(null);
          }}
          onClone={async () => {
            if (token && masterKeyHex) {
              try {
                const cloneResult = await window.api.vault.clone(token, contextMenu.entryId) as { id: string; entry_type: string; encrypted_data: string; nonce: string; version: number; folder_id: string | null; created_at: string; updated_at: string; error?: string };
                if (cloneResult.error || !cloneResult.id) {
                  console.error('[clone] clone API failed:', cloneResult.error);
                  setContextMenu(null);
                  return;
                }
                // Decrypt, modify name, re-encrypt, update
                const decResult = await window.api.vault.decrypt(masterKeyHex, cloneResult.encrypted_data, cloneResult.nonce);
                if (decResult.error || !decResult.plaintext) {
                  console.error('[clone] decrypt failed:', decResult.error);
                  setContextMenu(null);
                  return;
                }
                const parsed = JSON.parse(decResult.plaintext);
                parsed.name = `Copy of ${parsed.name || 'Untitled'}`;
                delete parsed.passwordHistory;
                const newPlaintext = JSON.stringify(parsed);
                const encResult = await window.api.vault.encrypt(masterKeyHex, newPlaintext);
                if (encResult.error) {
                  console.error('[clone] encrypt failed:', encResult.error);
                  setContextMenu(null);
                  return;
                }
                const updateResult = await window.api.vault.update(token, cloneResult.id, {
                  entry_type: cloneResult.entry_type,
                  encrypted_data: encResult.encrypted_data,
                  nonce: encResult.nonce,
                }) as { version: number; updated_at: string; error?: string };
                if (updateResult.error) {
                  console.error('[clone] update failed:', updateResult.error);
                }
                // Build the decrypted fields for the store
                const cloneFields: Record<string, string> = {};
                for (const [k, v] of Object.entries(parsed)) {
                  if (k === 'uris') {
                    cloneFields._uris = JSON.stringify(v);
                    if (Array.isArray(v) && v.length > 0) cloneFields.uri = (v as { uri: string }[])[0].uri;
                  } else if (k === 'passwordHistory') {
                    cloneFields._passwordHistory = JSON.stringify(v);
                  } else if (typeof v === 'string') {
                    cloneFields[k] = v;
                  } else {
                    cloneFields[k] = JSON.stringify(v);
                  }
                }
                // Add cloned entry to the vault store so EntryDetail can find it
                const clonedEntry: VaultEntry = {
                  id: cloneResult.id,
                  entry_type: cloneResult.entry_type as VaultEntry['entry_type'],
                  encrypted_data: encResult.encrypted_data,
                  nonce: encResult.nonce,
                  version: updateResult.version ?? cloneResult.version,
                  folder_id: cloneResult.folder_id ?? null,
                  is_favorite: false,
                  is_archived: false,
                  deleted_at: null,
                  created_at: cloneResult.created_at,
                  updated_at: updateResult.updated_at ?? cloneResult.updated_at,
                };
                addEntry(clonedEntry, cloneFields);
                navigate(`/vault/${cloneResult.id}`, { state: { edit: true } });
              } catch (err) {
                console.error('[clone] unexpected error:', err);
              }
            }
            setContextMenu(null);
          }}
          onDelete={async () => {
            if (token) {
              await window.api.vault.delete(token, contextMenu.entryId);
            }
            removeEntry(contextMenu.entryId);
            setContextMenu(null);
          }}
        />
      )}

      {/* Reprompt dialog (for context menu copy password) */}
      {showRepromptDialog && (
        <RepromptDialog
          onVerified={handleRepromptVerified}
          onCancel={() => {
            setShowRepromptDialog(false);
            setPendingRepromptAction(null);
            setPendingRepromptEntryId(null);
          }}
        />
      )}
    </div>
  );
}
