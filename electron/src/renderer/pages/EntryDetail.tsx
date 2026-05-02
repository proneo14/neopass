import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { PasswordGenerator } from '../components/PasswordGenerator';
import { UsernameGenerator } from '../components/UsernameGenerator';
import { RepromptDialog } from '../components/RepromptDialog';
import { ENTRY_TYPE_ICONS, ENTRY_TYPE_LABELS } from '../types/vault';
import type { LoginURI, PasswordHistoryEntry } from '../types/vault';
import { useVaultStore } from '../store/vaultStore';
import { useAuthStore } from '../store/authStore';
import { generateTOTP, getTimeRemaining } from '../utils/totp';

const MATCH_MODES: { value: LoginURI['match']; label: string }[] = [
  { value: 'base_domain', label: 'Base domain' },
  { value: 'host', label: 'Host' },
  { value: 'starts_with', label: 'Starts with' },
  { value: 'regex', label: 'Regex' },
  { value: 'exact', label: 'Exact' },
  { value: 'never', label: 'Never' },
];

const FIELD_LABELS: Record<string, string> = {
  name: 'Name', username: 'Username', password: 'Password', uri: 'Website',
  notes: 'Notes', content: 'Content', number: 'Card Number', expiry: 'Expiry',
  cvv: 'CVV', cardholder: 'Cardholder', firstName: 'First Name', lastName: 'Last Name',
  email: 'Email', phone: 'Phone', address: 'Address', totp: 'Authenticator Key',
  privateKey: 'Private Key', publicKey: 'Public Key', fingerprint: 'Fingerprint',
  keyType: 'Key Type', passphrase: 'Passphrase',
};

/** Fixed display order per entry type (fields not listed here appear at the end). */
const FIELD_ORDER: Record<string, string[]> = {
  login: ['uri', 'username', 'email', 'password', 'notes', 'totp'],
  secure_note: ['content', 'notes'],
  credit_card: ['number', 'expiry', 'cvv', 'cardholder', 'notes'],
  identity: ['firstName', 'lastName', 'email', 'phone', 'address', 'notes'],
  ssh_key: ['publicKey', 'privateKey', 'fingerprint', 'keyType', 'passphrase', 'notes'],
};

const SENSITIVE_FIELDS = new Set(['password', 'cvv', 'number', 'content', 'totp', 'privateKey', 'passphrase']);

function CopyButton({ value, sensitive = false, onBeforeCopy }: { value: string; sensitive?: boolean; onBeforeCopy?: (proceed: () => void) => void }) {
  const [copied, setCopied] = useState(false);
  const doCopy = async () => {
    if (sensitive) {
      await window.api.clipboard.copySecure(value);
    } else {
      await navigator.clipboard.writeText(value);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  const handleCopy = () => {
    if (onBeforeCopy) {
      onBeforeCopy(doCopy);
    } else {
      doCopy();
    }
  };
  return (
    <button onClick={handleCopy} className="text-xs text-surface-500 hover:text-accent-400 transition-colors shrink-0">
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  );
}

/** Live TOTP code display with countdown dial — refreshes every 30 s. */
function TOTPDisplay({ secret }: { secret: string }) {
  const [code, setCode] = useState('------');
  const [timeRemaining, setTimeRemaining] = useState(30);
  const [copied, setCopied] = useState(false);
  const period = 30;

  useEffect(() => {
    let active = true;

    const updateCode = async () => {
      try {
        const c = await generateTOTP(secret, period);
        if (active) setCode(c);
      } catch {
        if (active) setCode('ERROR');
      }
    };

    const tick = () => {
      const rem = getTimeRemaining(period);
      if (active) setTimeRemaining(rem);
      // Generate new code when period rolls over
      if (rem === period) updateCode();
    };

    updateCode();
    tick();
    const interval = setInterval(tick, 1000);
    return () => { active = false; clearInterval(interval); };
  }, [secret]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const radius = 12;
  const circumference = 2 * Math.PI * radius;
  const progress = timeRemaining / period;
  const strokeDashoffset = circumference * (1 - progress);
  const isLow = timeRemaining <= 5;

  return (
    <div className="flex items-center gap-3 py-2.5 border-b border-surface-800 last:border-0">
      <span className="text-xs text-surface-500 w-24 shrink-0 pt-0.5">One-Time Code</span>
      <div className="flex items-center gap-3 flex-1">
        <span className={`text-xl font-mono font-semibold tracking-[0.25em] ${isLow ? 'text-red-400' : 'text-accent-400'}`}>
          {code.slice(0, 3)}&nbsp;{code.slice(3)}
        </span>
        <svg width="30" height="30" viewBox="0 0 30 30" className="shrink-0">
          <circle cx="15" cy="15" r={radius} fill="none" stroke="#334155" strokeWidth="2.5" />
          <circle
            cx="15" cy="15" r={radius}
            fill="none"
            stroke={isLow ? '#ef4444' : '#818cf8'}
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            transform="rotate(-90 15 15)"
            style={{ transition: 'stroke-dashoffset 1s linear' }}
          />
          <text x="15" y="15" textAnchor="middle" dominantBaseline="central" fontSize="9" fill={isLow ? '#ef4444' : '#94a3b8'}>
            {timeRemaining}
          </text>
        </svg>
      </div>
      <button
        onClick={handleCopy}
        className="text-xs text-surface-500 hover:text-accent-400 transition-colors shrink-0"
      >
        {copied ? '✓ Copied' : 'Copy'}
      </button>
    </div>
  );
}

/** Tag editing / display component for vault entries. */
function TagsSection({ editing, editFields, setEditFields, fields }: {
  editing: boolean;
  editFields: Record<string, string>;
  setEditFields: (f: Record<string, string>) => void;
  fields: Record<string, string>;
}) {
  const [tagInput, setTagInput] = useState('');
  const entryFields = useVaultStore((s) => s.entryFields);

  const currentTags: string[] = (() => {
    const src = editing ? editFields._tags : fields._tags;
    if (!src) return [];
    try { return JSON.parse(src); } catch { return []; }
  })();

  // All tags across all entries for auto-suggest
  const allTags = React.useMemo(() => {
    const set = new Set<string>();
    for (const f of Object.values(entryFields)) {
      if (!f?._tags) continue;
      try {
        const tags: string[] = JSON.parse(f._tags);
        tags.forEach((t) => set.add(t));
      } catch { /* skip */ }
    }
    return Array.from(set).sort();
  }, [entryFields]);

  const suggestions = tagInput.trim()
    ? allTags.filter((t) => t.toLowerCase().includes(tagInput.toLowerCase()) && !currentTags.includes(t))
    : [];

  const addTag = (tag: string) => {
    const trimmed = tag.trim().toLowerCase();
    if (!trimmed || currentTags.includes(trimmed) || currentTags.length >= 10) return;
    const next = [...currentTags, trimmed];
    setEditFields({ ...editFields, _tags: JSON.stringify(next) });
    setTagInput('');
  };

  const removeTag = (tag: string) => {
    const next = currentTags.filter((t) => t !== tag);
    setEditFields({ ...editFields, _tags: JSON.stringify(next) });
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addTag(tagInput);
    }
  };

  if (!editing && currentTags.length === 0) return null;

  return (
    <div className="mt-3">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-xs text-surface-500">🏷️</span>
        <span className="text-xs text-surface-400 font-medium">Tags</span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {currentTags.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-accent-600/15 text-accent-400 text-xs"
          >
            {tag}
            {editing && (
              <button onClick={() => removeTag(tag)} className="text-accent-400/60 hover:text-accent-400 ml-0.5">×</button>
            )}
          </span>
        ))}
        {editing && currentTags.length < 10 && (
          <div className="relative">
            <input
              type="text"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Add tag…"
              className="px-2 py-0.5 rounded-md bg-surface-800 border border-surface-700 text-surface-100 text-xs placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 w-24"
            />
            {suggestions.length > 0 && (
              <div className="absolute top-full left-0 mt-1 bg-surface-800 border border-surface-700 rounded-md shadow-lg z-10 max-h-32 overflow-auto">
                {suggestions.slice(0, 5).map((s) => (
                  <button
                    key={s}
                    onClick={() => addTag(s)}
                    className="w-full text-left px-2 py-1 text-xs text-surface-200 hover:bg-surface-700"
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export function EntryDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { entries, entryFields, updateEntryFields, updateEntry, removeEntry, isRepromptApproved, approveReprompt, healthFlags } = useVaultStore();
  const { token, masterKeyHex, orgId } = useAuthStore();
  const routeState = location.state as { edit?: boolean; collectionId?: string; collectionPermission?: string } | null;
  const sourceCollectionId = routeState?.collectionId ?? null;
  const collectionPermission = routeState?.collectionPermission ?? null;
  const isReadOnlyCollection = sourceCollectionId != null && collectionPermission === 'read';
  const [editing, setEditing] = useState(!!routeState?.edit && !isReadOnlyCollection);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showUsernameGen, setShowUsernameGen] = useState(false);
  const [revealedFields, setRevealedFields] = useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmPermanent, setConfirmPermanent] = useState(false);
  const [showPasswordHistory, setShowPasswordHistory] = useState(false);
  const [revealedHistoryPasswords, setRevealedHistoryPasswords] = useState<Set<number>>(new Set());
  const [showRepromptDialog, setShowRepromptDialog] = useState(false);
  const [pendingRepromptAction, setPendingRepromptAction] = useState<(() => void) | null>(null);

  const vaultEntry = id ? entries.find((e) => e.id === id) : null;
  const fields = id ? entryFields[id] : null;
  const isTrash = vaultEntry?.deleted_at != null;

  // Reprompt: entry-level flag stored in encrypted blob as "_reprompt"
  const hasReprompt = fields?._reprompt === '1';
  const repromptCleared = id ? isRepromptApproved(id) : false;

  /** Require re-auth before executing an action on a reprompt-protected entry. */
  const withReprompt = (action: () => void) => {
    if (!hasReprompt || repromptCleared) {
      action();
      return;
    }
    setPendingRepromptAction(() => action);
    setShowRepromptDialog(true);
  };

  const handleRepromptVerified = () => {
    if (id) approveReprompt(id);
    setShowRepromptDialog(false);
    if (pendingRepromptAction) {
      pendingRepromptAction();
      setPendingRepromptAction(null);
    }
  };

  // Parse structured data from fields (password history, URIs)
  const passwordHistory: PasswordHistoryEntry[] = fields ? (() => {
    try { return JSON.parse(fields._passwordHistory || '[]'); } catch { return []; }
  })() : [];
  const uris: LoginURI[] = fields ? (() => {
    try { return JSON.parse(fields._uris || '[]'); } catch { return []; }
  })() : [];

  if (!vaultEntry || !fields) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-surface-500">
        <span className="text-5xl mb-4">🔍</span>
        <p className="text-sm">Entry not found</p>
        <button onClick={() => navigate('/vault')} className="mt-3 text-xs text-accent-400 hover:text-accent-300">
          Back to vault
        </button>
      </div>
    );
  }

  const entryType = vaultEntry.entry_type;
  const [editFields, setEditFields] = useState(() => {
    // Ensure all standard fields exist for this entry type so they appear in edit mode
    const base = { ...fields };
    for (const key of FIELD_ORDER[entryType] ?? []) {
      if (!(key in base)) base[key] = '';
    }
    // Ensure reprompt flag is present
    if (!('_reprompt' in base)) base._reprompt = '0';
    return base;
  });

  // URIs state for editing (login entries only)
  const [editURIs, setEditURIs] = useState<LoginURI[]>(() =>
    uris.length > 0 ? uris : (fields.uri ? [{ uri: fields.uri, match: 'base_domain' }] : [{ uri: '', match: 'base_domain' }])
  );

  // Fixed field display order: use the type-specific order, then any remaining keys
  const typeOrder = FIELD_ORDER[entryType] ?? [];
  const allKeys = [...new Set([...Object.keys(fields), ...typeOrder])];
  const fieldOrder = [
    ...typeOrder.filter((k) => allKeys.includes(k)),
    ...allKeys.filter((k) => !typeOrder.includes(k) && k !== 'name'),
  ];

  // Auto-sync: if this entry is in a collection and the collection copy was edited
  // by another member, pull those changes into the owner's vault
  useEffect(() => {
    if (!id || !token || !masterKeyHex || !orgId || sourceCollectionId || !vaultEntry) return;
    let cancelled = false;
    (async () => {
      try {
        const colls = await window.api.collections.getEntryCollections(token, id) as Array<{
          id: string; encrypted_key: string;
        }> | { error: string };
        if (!Array.isArray(colls) || colls.length === 0 || cancelled) return;

        // Use the first collection that has a key
        for (const c of colls) {
          if (!c.encrypted_key || cancelled) continue;
          // Decrypt collection key
          const ekNonce = c.encrypted_key.slice(0, 24);
          const ekCipher = c.encrypted_key.slice(24);
          const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext?: string };
          if (!collKeyDec.plaintext || cancelled) continue;

          // Fetch collection entries to find this entry
          const collEntries = await window.api.collections.listEntries(token, c.id) as Array<{
            entry_id: string; entry_type: string; encrypted_data: string; nonce: string;
          }> | { error: string };
          if (!Array.isArray(collEntries) || cancelled) continue;
          const collEntry = collEntries.find(e => e.entry_id === id);
          if (!collEntry?.encrypted_data) continue;

          // Decrypt collection copy
          const collDec = await window.api.vault.decrypt(collKeyDec.plaintext, collEntry.encrypted_data, collEntry.nonce) as { plaintext?: string };
          if (!collDec.plaintext || cancelled) continue;

          // Decrypt vault copy
          const vaultDec = await window.api.vault.decrypt(masterKeyHex, vaultEntry.encrypted_data, vaultEntry.nonce) as { plaintext?: string };
          if (!vaultDec.plaintext || cancelled) continue;

          // Compare — if different, sync collection → vault
          if (collDec.plaintext !== vaultDec.plaintext) {
            const encResult = await window.api.vault.encrypt(masterKeyHex, collDec.plaintext) as { encrypted_data: string; nonce: string; error?: string };
            if (encResult.error || cancelled) continue;

            const updateResult = await window.api.vault.update(token, id, {
              entry_type: vaultEntry.entry_type,
              encrypted_data: encResult.encrypted_data,
              nonce: encResult.nonce,
            }) as { version?: number; updated_at?: string; error?: string };

            if (!updateResult.error && !cancelled) {
              // Update local state with synced data
              const parsed = JSON.parse(collDec.plaintext) as Record<string, unknown>;
              const syncedFields: Record<string, string> = {};
              for (const [k, v] of Object.entries(parsed)) {
                if (k === 'passwordHistory') syncedFields._passwordHistory = JSON.stringify(v);
                else if (k === 'uris') syncedFields._uris = JSON.stringify(v);
                else if (k === 'reprompt') syncedFields._reprompt = v === 1 || v === '1' ? '1' : '0';
                else syncedFields[k] = String(v ?? '');
              }
              updateEntryFields(id, syncedFields);
              updateEntry({
                ...vaultEntry,
                encrypted_data: encResult.encrypted_data,
                nonce: encResult.nonce,
                version: updateResult.version ?? vaultEntry.version,
                updated_at: updateResult.updated_at ?? vaultEntry.updated_at,
              });
            }
          }
          break; // only need to check one collection
        }
      } catch { /* sync is best-effort */ }
    })();
    return () => { cancelled = true; };
  }, [id, token, masterKeyHex, orgId]);

  const toggleReveal = (field: string) => {
    const doToggle = () => {
      setRevealedFields((prev) => {
        const next = new Set(prev);
        if (next.has(field)) next.delete(field);
        else next.add(field);
        return next;
      });
    };
    // Gate reveal of sensitive fields behind reprompt
    if (SENSITIVE_FIELDS.has(field) && !revealedFields.has(field)) {
      withReprompt(doToggle);
    } else {
      doToggle();
    }
  };

  const handleSave = async () => {
    if (!id || !token || !masterKeyHex) return;

    // Strip empty optional fields before persisting
    const cleanFields: Record<string, string> = {};
    for (const [k, v] of Object.entries(editFields)) {
      if (v || k === 'name') cleanFields[k] = v;
    }

    // Password history: if password changed on a login entry, add old one to history
    if (entryType === 'login' && fields.password && cleanFields.password !== fields.password) {
      const history: PasswordHistoryEntry[] = [...passwordHistory];
      history.unshift({ password: fields.password, date: new Date().toISOString() });
      // Keep max 10 entries
      cleanFields._passwordHistory = JSON.stringify(history.slice(0, 10));
    } else if (passwordHistory.length > 0) {
      cleanFields._passwordHistory = JSON.stringify(passwordHistory);
    }

    // Multiple URIs: save the array for login entries
    if (entryType === 'login') {
      const validURIs = editURIs.filter(u => u.uri.trim());
      if (validURIs.length > 0) {
        cleanFields._uris = JSON.stringify(validURIs);
        // Keep legacy uri field as primary for backward compatibility
        cleanFields.uri = validURIs[0].uri;
      }
      // Also persist the uris array as top-level "uris" in the JSON for server-side matching
      if (validURIs.length > 0) {
        cleanFields._uris = JSON.stringify(validURIs);
      }
    }

    // Rebuild the full plaintext object including structured fields
    const plaintextObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(cleanFields)) {
      if (k === '_passwordHistory') {
        plaintextObj.passwordHistory = JSON.parse(v);
      } else if (k === '_uris') {
        plaintextObj.uris = JSON.parse(v);
      } else if (k === '_reprompt') {
        plaintextObj.reprompt = v === '1' ? 1 : 0;
      } else if (k === '_tags') {
        plaintextObj.tags = JSON.parse(v);
      } else {
        plaintextObj[k] = v;
      }
    }

    const plaintext = JSON.stringify(plaintextObj);
    const encResult = await window.api.vault.encrypt(masterKeyHex, plaintext);
    if (encResult.error) return;

    // If viewing from a collection, update the collection copy first
    if (sourceCollectionId && orgId) {
      try {
        const userColls = await window.api.collections.listUser(token) as Array<{
          id: string; encrypted_key: string;
        }> | { error: string };
        if (Array.isArray(userColls)) {
          const coll = userColls.find(c => c.id === sourceCollectionId);
          if (coll?.encrypted_key) {
            const ekNonce = coll.encrypted_key.slice(0, 24);
            const ekCipher = coll.encrypted_key.slice(24);
            const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext: string };
            const collEnc = await window.api.vault.encrypt(collKeyDec.plaintext, plaintext) as { encrypted_data: string; nonce: string };
            await window.api.collections.addEntry(token, sourceCollectionId, id, {
              entry_type: vaultEntry.entry_type,
              encrypted_data: collEnc.encrypted_data,
              nonce: collEnc.nonce,
            });
          }
        }
      } catch { /* collection update failed */ }
    }

    // Try to update the vault copy (succeeds only if current user owns the entry)
    const updateResult = await window.api.vault.update(token, id, {
      entry_type: vaultEntry.entry_type,
      encrypted_data: encResult.encrypted_data,
      nonce: encResult.nonce,
    }) as { id: string; entry_type: string; encrypted_data: string; nonce: string; version: number; folder_id: string | null; created_at: string; updated_at: string; error?: string };

    if (!updateResult.error) {
      updateEntryFields(id, cleanFields);
      updateEntry({
        ...vaultEntry,
        encrypted_data: encResult.encrypted_data,
        nonce: encResult.nonce,
        version: updateResult.version,
        updated_at: updateResult.updated_at,
      });

      // Sync to all other collections containing this entry
      if (orgId) {
        try {
          const colls = await window.api.collections.getEntryCollections(token, id) as Array<{
            id: string; encrypted_key: string;
          }> | { error: string };
          if (Array.isArray(colls)) {
            for (const c of colls) {
              if (!c.encrypted_key || c.id === sourceCollectionId) continue;
              const ekNonce = c.encrypted_key.slice(0, 24);
              const ekCipher = c.encrypted_key.slice(24);
              const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext: string };
              const collEnc = await window.api.vault.encrypt(collKeyDec.plaintext, plaintext) as { encrypted_data: string; nonce: string };
              await window.api.collections.addEntry(token, c.id, id, {
                entry_type: vaultEntry.entry_type,
                encrypted_data: collEnc.encrypted_data,
                nonce: collEnc.nonce,
              });
            }
          }
        } catch { /* best-effort */ }
      }
    } else if (sourceCollectionId) {
      // Vault update failed (not owner) but collection copy was updated
      updateEntryFields(id, cleanFields);
    }
    setEditing(false);
  };

  const handleCancel = () => {
    const base = { ...fields };
    for (const key of FIELD_ORDER[entryType] ?? []) {
      if (!(key in base)) base[key] = '';
    }
    if (!('_reprompt' in base)) base._reprompt = '0';
    setEditFields(base);
    setEditURIs(uris.length > 0 ? uris : (fields.uri ? [{ uri: fields.uri, match: 'base_domain' }] : [{ uri: '', match: 'base_domain' }]));
    setEditing(false);
  };

  const formatDate = (iso: string) => {
    if (!iso) return '—';
    const d = new Date(iso);
    return isNaN(d.getTime()) ? '—' : d.toLocaleString();
  };

  return (
    <div className="max-w-2xl">
      {/* Back + header */}
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={() => navigate(-1)}
          className="text-surface-400 hover:text-surface-200 transition-colors text-sm"
        >
          ← Back
        </button>
      </div>

      <div className="flex items-center gap-3 mb-6">
        <span className="text-2xl">{ENTRY_TYPE_ICONS[entryType]}</span>
        <div>
          {editing ? (
            <input
              type="text"
              value={editFields.name ?? ''}
              onChange={(e) => setEditFields({ ...editFields, name: e.target.value })}
              className="text-lg font-semibold text-surface-100 bg-transparent border-b border-surface-600 focus:border-accent-500 focus:outline-none w-full"
              placeholder="Entry name"
            />
          ) : (
            <h1 className="text-lg font-semibold text-surface-100">{fields.name}</h1>
          )}
          <span className="text-xs text-surface-500">
            {ENTRY_TYPE_LABELS[entryType]}
            {vaultEntry.is_archived && ' · Archived'}
            {isTrash && ' · In Trash'}
          </span>
        </div>
        <div className="flex-1" />
        {!isTrash && (
          <button
            onClick={async () => {
              if (token && id) {
                const newFav = !vaultEntry.is_favorite;
                await window.api.vault.setFavorite(token, id, newFav);
                updateEntry({ ...vaultEntry, is_favorite: newFav });
              }
            }}
            className="p-1.5 rounded-md hover:bg-surface-800 transition-colors"
            title={vaultEntry.is_favorite ? 'Remove from favorites' : 'Add to favorites'}
          >
            <svg className={`w-5 h-5 ${vaultEntry.is_favorite ? 'text-amber-400' : 'text-surface-500 hover:text-surface-300'}`} viewBox="0 0 20 20" fill={vaultEntry.is_favorite ? 'currentColor' : 'none'} stroke="currentColor" strokeWidth={vaultEntry.is_favorite ? 0 : 1.5}>
              <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.286 3.957a1 1 0 00.95.69h4.162c.969 0 1.371 1.24.588 1.81l-3.37 2.448a1 1 0 00-.364 1.118l1.287 3.957c.3.921-.755 1.688-1.54 1.118l-3.37-2.448a1 1 0 00-1.176 0l-3.37 2.448c-.784.57-1.838-.197-1.539-1.118l1.287-3.957a1 1 0 00-.364-1.118L2.065 9.384c-.783-.57-.38-1.81.588-1.81h4.162a1 1 0 00.95-.69l1.284-3.957z" />
            </svg>
          </button>
        )}
        {isTrash ? (
          <div className="flex gap-2">
            <button
              onClick={async () => {
                if (token && id) {
                  await window.api.vault.restore(token, id);
                  removeEntry(id);
                  navigate('/vault');
                }
              }}
              className="px-3 py-1.5 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors"
            >
              Restore
            </button>
            <button
              onClick={() => setConfirmPermanent(true)}
              className="px-3 py-1.5 rounded-md bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors"
            >
              Delete Forever
            </button>
          </div>
        ) : !editing ? (
          <div className="flex items-center gap-2">
            {isReadOnlyCollection && (
              <span className="text-xs text-amber-400 bg-amber-400/10 px-2 py-1 rounded">Read-only</span>
            )}
            <button
              onClick={() => setEditing(true)}
              disabled={isReadOnlyCollection}
              className="px-3 py-1.5 rounded-md bg-surface-800 hover:bg-surface-700 text-surface-300 text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Edit
            </button>
          </div>
        ) : (
          <div className="flex gap-2">
            <button onClick={handleCancel} className="px-3 py-1.5 rounded-md bg-surface-800 hover:bg-surface-700 text-surface-400 text-sm transition-colors">
              Cancel
            </button>
            <button onClick={handleSave} className="px-3 py-1.5 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
              Save
            </button>
          </div>
        )}
      </div>

      {/* Health warnings */}
      {id && healthFlags[id] && !editing && (
        <div className="space-y-2">
          {healthFlags[id].breached && (
            <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-500/10 border border-red-500/20">
              <span>🔴</span>
              <div className="flex-1">
                <p className="text-sm text-red-400 font-medium">Password exposed in data breach</p>
                <p className="text-xs text-red-400/70">
                  Found in {healthFlags[id].breachCount?.toLocaleString()} breaches. Change this password immediately.
                </p>
              </div>
            </div>
          )}
          {healthFlags[id].weak && (
            <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-orange-500/10 border border-orange-500/20">
              <span>⚠️</span>
              <p className="text-sm text-orange-400">Weak password — consider using a stronger, generated password</p>
            </div>
          )}
          {healthFlags[id].reused && (
            <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-orange-500/10 border border-orange-500/20">
              <span>♻️</span>
              <p className="text-sm text-orange-400">This password is reused across multiple entries</p>
            </div>
          )}
          {healthFlags[id].insecureUri && (
            <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <span>🔗</span>
              <p className="text-sm text-yellow-400">This site uses HTTP — your credentials may be sent in plain text</p>
            </div>
          )}
        </div>
      )}

      {/* Fields */}
      <div className="space-y-1 bg-surface-900/50 rounded-lg p-4">
        {/* Reprompt toggle (edit mode) / indicator (view mode) */}
        {editing ? (
          <div className="flex items-center justify-between py-2.5 border-b border-surface-800">
            <div className="flex items-center gap-2">
              <span className="text-xs text-surface-500">🔒</span>
              <span className="text-xs text-surface-400">Master password re-prompt</span>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={editFields._reprompt === '1'}
                onChange={(e) =>
                  setEditFields({ ...editFields, _reprompt: e.target.checked ? '1' : '0' })
                }
                className="sr-only peer"
              />
              <div className="w-8 h-4 bg-surface-700 peer-focus:outline-none rounded-full peer peer-checked:bg-accent-500 transition-colors">
                <div className={`w-3.5 h-3.5 bg-white rounded-full shadow transform transition-transform mt-[1px] ${editFields._reprompt === '1' ? 'translate-x-[17px]' : 'translate-x-[1px]'}`} />
              </div>
            </label>
          </div>
        ) : hasReprompt ? (
          <div className="flex items-center gap-2 py-2 px-1 mb-1">
            <span className="text-xs">🔒</span>
            <span className="text-[10px] text-surface-500">Re-authentication required for sensitive fields</span>
          </div>
        ) : null}

        {fieldOrder.map((key) => {
          if (key === 'name') return null;
          // Skip internal metadata fields
          if (key.startsWith('_')) return null;
          // In view mode, skip rendering the raw totp field — we show TOTPDisplay instead
          if (key === 'totp' && !editing && fields[key]) return null;

          // SSH key: key type as badge in view mode
          if (key === 'keyType' && entryType === 'ssh_key' && !editing) {
            const kt = fields[key];
            if (!kt) return null;
            const badgeLabel = kt === 'ed25519' ? 'Ed25519' : kt === 'rsa' ? 'RSA-4096' : kt === 'ecdsa' ? 'ECDSA' : kt;
            return (
              <div key={key} className="flex items-center gap-3 py-2.5 border-b border-surface-800">
                <span className="text-xs text-surface-500 w-24 shrink-0 pt-0.5">Key Type</span>
                <span className="px-2.5 py-1 rounded-full bg-accent-500/20 text-accent-300 text-xs font-medium">{badgeLabel}</span>
              </div>
            );
          }

          // SSH key: fingerprint as read-only monospace in view mode
          if (key === 'fingerprint' && entryType === 'ssh_key' && !editing) {
            const fp = fields[key];
            if (!fp) return null;
            return (
              <div key={key} className="flex items-center gap-3 py-2.5 border-b border-surface-800">
                <span className="text-xs text-surface-500 w-24 shrink-0 pt-0.5">Fingerprint</span>
                <span className="flex-1 text-sm text-surface-300 font-mono break-all select-all">{fp}</span>
                <CopyButton value={fp} />
              </div>
            );
          }

          // SSH key: publicKey with prominent copy button and monospace textarea view
          if (key === 'publicKey' && entryType === 'ssh_key' && !editing) {
            const pk = fields[key];
            if (!pk) return null;
            return (
              <div key={key} className="py-2.5 border-b border-surface-800">
                <div className="flex items-center gap-3 mb-1">
                  <span className="text-xs text-surface-500 w-24 shrink-0">Public Key</span>
                  <div className="flex-1" />
                  <button
                    onClick={async () => {
                      await navigator.clipboard.writeText(pk);
                    }}
                    className="px-3 py-1 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-xs font-medium transition-colors"
                  >
                    Copy Public Key
                  </button>
                </div>
                <pre className="ml-[108px] text-xs text-surface-300 font-mono bg-surface-800 rounded-md p-2 whitespace-pre-wrap break-all select-all max-h-24 overflow-auto">{pk}</pre>
              </div>
            );
          }

          // For login entries, render multi-URI section instead of single uri field
          if (key === 'uri' && entryType === 'login') {
            const displayURIs = uris.length > 0 ? uris : (fields.uri ? [{ uri: fields.uri, match: 'base_domain' as const }] : []);
            return (
              <div key="uris" className="py-2.5 border-b border-surface-800">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-xs text-surface-500 w-24 shrink-0">Websites</span>
                  {editing && (
                    <button
                      onClick={() => setEditURIs([...editURIs, { uri: '', match: 'base_domain' }])}
                      className="text-xs text-accent-400 hover:text-accent-300 transition-colors"
                    >
                      + Add URI
                    </button>
                  )}
                </div>
                {editing ? (
                  <div className="space-y-2 ml-[108px]">
                    {editURIs.map((u, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <input
                          type="text"
                          value={u.uri}
                          onChange={(e) => {
                            const next = [...editURIs];
                            next[idx] = { ...next[idx], uri: e.target.value };
                            setEditURIs(next);
                          }}
                          placeholder="https://example.com"
                          className="flex-1 px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
                        />
                        <select
                          value={u.match || 'base_domain'}
                          onChange={(e) => {
                            const next = [...editURIs];
                            next[idx] = { ...next[idx], match: e.target.value as LoginURI['match'] };
                            setEditURIs(next);
                          }}
                          className="px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-300 text-xs focus:outline-none focus:ring-2 focus:ring-accent-500"
                        >
                          {MATCH_MODES.map((m) => (
                            <option key={m.value} value={m.value}>{m.label}</option>
                          ))}
                        </select>
                        {editURIs.length > 1 && (
                          <button
                            onClick={() => setEditURIs(editURIs.filter((_, i) => i !== idx))}
                            className="text-xs text-red-400 hover:text-red-300 transition-colors px-1"
                          >
                            ✕
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                ) : displayURIs.length > 0 ? (
                  <div className="space-y-1 ml-[108px]">
                    {displayURIs.map((u, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <span className="flex-1 text-sm text-accent-400 break-all">{u.uri}</span>
                        {u.match && u.match !== 'base_domain' && (
                          <span className="text-[10px] text-surface-600 bg-surface-800 px-1.5 py-0.5 rounded">
                            {MATCH_MODES.find(m => m.value === u.match)?.label ?? u.match}
                          </span>
                        )}
                        <CopyButton value={u.uri} />
                        <button
                          onClick={() => window.api.openExternal(u.uri.startsWith('http') ? u.uri : `https://${u.uri}`)}
                          className="text-xs text-surface-500 hover:text-accent-400 transition-colors"
                          title="Open in browser"
                        >
                          ↗
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <span className="text-sm text-surface-500 ml-[108px]">—</span>
                )}
              </div>
            );
          }

          const isSensitive = SENSITIVE_FIELDS.has(key);
          const revealed = revealedFields.has(key);
          const value = editing ? editFields[key] : fields[key];
          // Hide empty fields that aren't part of the type's standard layout
          const isStandardField = (FIELD_ORDER[entryType] ?? []).includes(key);
          if (!editing && !value && !isStandardField) return null;
          const displayValue = isSensitive && !revealed ? '•'.repeat(Math.min((value || '').length, 20)) : (value || '');

          return (
            <div key={key} className="flex items-start gap-3 py-2.5 border-b border-surface-800 last:border-0">
              <span className="text-xs text-surface-500 w-24 shrink-0 pt-0.5">{FIELD_LABELS[key] ?? key}</span>

              {editing ? (
                key === 'notes' || key === 'content' ? (
                  <textarea
                    value={editFields[key]}
                    onChange={(e) => setEditFields({ ...editFields, [key]: e.target.value })}
                    rows={3}
                    className="flex-1 px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500 resize-none"
                  />
                ) : key === 'username' && entryType === 'login' ? (
                  <div className="flex-1 space-y-2">
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={editFields[key]}
                        onChange={(e) => setEditFields({ ...editFields, [key]: e.target.value })}
                        className="flex-1 px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
                      />
                      <button
                        type="button"
                        onClick={() => setShowUsernameGen(!showUsernameGen)}
                        className="px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-400 hover:text-accent-400 text-xs transition-colors"
                      >
                        Generate
                      </button>
                    </div>
                    {showUsernameGen && (
                      <div className="p-3 bg-surface-900/50 rounded-lg">
                        <UsernameGenerator onUse={(u) => { setEditFields({ ...editFields, username: u }); setShowUsernameGen(false); }} />
                      </div>
                    )}
                  </div>
                ) : key === 'password' && entryType === 'login' ? (
                  <div className="flex-1 space-y-2">
                    <div className="flex gap-2">
                      <input
                        type={isSensitive && !revealed ? 'password' : 'text'}
                        value={editFields[key]}
                        onChange={(e) => setEditFields({ ...editFields, [key]: e.target.value })}
                        className="flex-1 px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
                      />
                      <button
                        type="button"
                        onClick={() => setShowGenerator(!showGenerator)}
                        className="px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-400 hover:text-accent-400 text-xs transition-colors"
                      >
                        Generate
                      </button>
                    </div>
                    {showGenerator && (
                      <div className="p-3 bg-surface-900/50 rounded-lg">
                        <PasswordGenerator onUse={(pw) => { setEditFields({ ...editFields, password: pw }); setShowGenerator(false); }} />
                      </div>
                    )}
                  </div>
                ) : (
                  <input
                    type={isSensitive && !revealed ? 'password' : 'text'}
                    value={editFields[key]}
                    onChange={(e) => setEditFields({ ...editFields, [key]: e.target.value })}
                    className="flex-1 px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
                  />
                )
              ) : key === 'notes' || key === 'content' ? (
                <p className="flex-1 text-sm text-surface-300 whitespace-pre-wrap break-all">{displayValue}</p>
              ) : (
                <span className="flex-1 text-sm text-surface-200 font-mono break-all">{displayValue}</span>
              )}

              <div className="flex gap-2 shrink-0">
                {isSensitive && (
                  <button
                    onClick={() => toggleReveal(key)}
                    className="text-xs text-surface-500 hover:text-surface-300 transition-colors"
                  >
                    {revealed ? 'Hide' : 'Show'}
                  </button>
                )}
                <CopyButton
                  value={value}
                  sensitive={isSensitive}
                  onBeforeCopy={isSensitive && hasReprompt && !repromptCleared ? (proceed) => withReprompt(proceed) : undefined}
                />
              </div>
            </div>
          );
        })}
        {/* Live TOTP code — shown when the entry has a totp secret and not editing */}
        {!editing && fields.totp && <TOTPDisplay secret={fields.totp} />}
      </div>

      {/* Tags */}
      <TagsSection editing={editing} editFields={editFields} setEditFields={setEditFields} fields={fields} />

      {/* Password History (for login entries, view mode only) */}
      {entryType === 'login' && !editing && passwordHistory.length > 0 && (
        <div className="mt-4">
          <button
            onClick={() => setShowPasswordHistory(!showPasswordHistory)}
            className="text-xs text-surface-500 hover:text-surface-300 transition-colors flex items-center gap-1"
          >
            <span className="text-[10px]">{showPasswordHistory ? '▼' : '▶'}</span>
            Password History ({passwordHistory.length})
          </button>
          {showPasswordHistory && (
            <div className="mt-2 space-y-1 bg-surface-900/50 rounded-lg p-3">
              {passwordHistory.map((entry, idx) => (
                <div key={idx} className="flex items-center gap-3 py-1.5 border-b border-surface-800 last:border-0">
                  <span className="text-xs text-surface-500 w-32 shrink-0">
                    {new Date(entry.date).toLocaleDateString()} {new Date(entry.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                  <span className="flex-1 text-sm text-surface-300 font-mono">
                    {revealedHistoryPasswords.has(idx) ? entry.password : '•'.repeat(Math.min(entry.password.length, 20))}
                  </span>
                  <button
                    onClick={() => {
                      const next = new Set(revealedHistoryPasswords);
                      if (next.has(idx)) next.delete(idx); else next.add(idx);
                      setRevealedHistoryPasswords(next);
                    }}
                    className="text-xs text-surface-500 hover:text-surface-300 transition-colors"
                    title={revealedHistoryPasswords.has(idx) ? 'Hide' : 'Show'}
                  >
                    {revealedHistoryPasswords.has(idx) ? 'Hide' : 'Show'}
                  </button>
                  <CopyButton value={entry.password} sensitive />
                </div>
              ))}
            </div>
          )}
        </div>
      )}



      {/* Timestamps */}
      <div className="mt-6 pt-4 border-t border-surface-800 flex gap-6 text-xs text-surface-600">
        <span>Created: {formatDate(vaultEntry.created_at)}</span>
        <span>Modified: {formatDate(vaultEntry.updated_at)}</span>
      </div>

      {/* Collections */}
      <EntryCollections entryId={id ?? ''} readOnly={isReadOnlyCollection} />

      {/* Delete / Archive */}
      {!isTrash && !isReadOnlyCollection && (
        <div className="mt-6 pt-4 border-t border-surface-800 flex items-center gap-4">
          {!vaultEntry.is_archived ? (
            <button
              onClick={async () => {
                if (token && id) {
                  await window.api.vault.setArchived(token, id, true);
                  removeEntry(id);
                  navigate('/vault');
                }
              }}
              className="text-sm text-surface-400 hover:text-surface-200 transition-colors"
            >
              Archive
            </button>
          ) : (
            <button
              onClick={async () => {
                if (token && id) {
                  await window.api.vault.setArchived(token, id, false);
                  updateEntry({ ...vaultEntry, is_archived: false });
                }
              }}
              className="text-sm text-accent-400 hover:text-accent-300 transition-colors"
            >
              Unarchive
            </button>
          )}
          {!confirmDelete ? (
            <button
              onClick={() => setConfirmDelete(true)}
              className="text-sm text-red-400 hover:text-red-300 transition-colors"
            >
              Delete entry
            </button>
          ) : (
            <div className="flex items-center gap-3">
              <span className="text-sm text-red-400">Move to trash?</span>
              <button
                onClick={async () => {
                  if (token && id) {
                    await window.api.vault.delete(token, id);
                    removeEntry(id);
                    navigate('/vault');
                  }
                }}
                className="px-3 py-1 rounded-md bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors"
              >
                Confirm
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="px-3 py-1 rounded-md bg-surface-800 hover:bg-surface-700 text-surface-400 text-sm transition-colors"
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      )}

      {/* Permanent delete confirmation for trash items */}
      {confirmPermanent && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-surface-900 rounded-lg p-6 max-w-sm shadow-2xl">
            <h3 className="text-sm font-semibold text-surface-100 mb-2">Delete Forever?</h3>
            <p className="text-xs text-surface-400 mb-4">This entry will be permanently deleted and cannot be recovered.</p>
            <div className="flex gap-2">
              <button
                onClick={() => setConfirmPermanent(false)}
                className="flex-1 py-2 rounded-md bg-surface-800 text-surface-400 text-sm hover:bg-surface-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  if (token && id) {
                    await window.api.vault.permanentDelete(token, id);
                    removeEntry(id);
                    navigate('/vault');
                  }
                }}
                className="flex-1 py-2 rounded-md bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors"
              >
                Delete Forever
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reprompt dialog */}
      {showRepromptDialog && (
        <RepromptDialog
          onVerified={handleRepromptVerified}
          onCancel={() => {
            setShowRepromptDialog(false);
            setPendingRepromptAction(null);
          }}
        />
      )}
    </div>
  );
}

// Shows which collections an entry belongs to
function EntryCollections({ entryId, readOnly = false }: { entryId: string; readOnly?: boolean }) {
  const { token, masterKeyHex, orgId } = useAuthStore();
  const [collections, setCollections] = useState<Array<{ id: string; name: string }>>([]);
  const [allCollections, setAllCollections] = useState<Array<{ id: string; name: string; encrypted_key: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [addError, setAddError] = useState('');
  const collectionsVersion = useVaultStore((s) => s.collectionsVersion);
  const bumpCollectionsVersion = useVaultStore((s) => s.bumpCollectionsVersion);
  const entryFields = useVaultStore((s) => s.entryFields);
  const entries = useVaultStore((s) => s.entries);

  // Helper: decrypt collection name using collection key
  const decryptCollName = async (c: { name_encrypted: string; name_nonce: string; encrypted_key: string }) => {
    if (!masterKeyHex || !c.encrypted_key) return '(encrypted)';
    try {
      const ekNonce = c.encrypted_key.slice(0, 24);
      const ekCipher = c.encrypted_key.slice(24);
      const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext: string };
      const dec = await window.api.vault.decrypt(collKeyDec.plaintext, c.name_encrypted, c.name_nonce) as { plaintext: string };
      return dec.plaintext;
    } catch {
      return '(encrypted)';
    }
  };

  const loadEntryCollections = async () => {
    if (!token || !entryId || !orgId) return;
    setLoading(true);
    try {
      const result = await window.api.collections.getEntryCollections(token, entryId) as Array<{
        id: string;
        name_encrypted: string;
        name_nonce: string;
        encrypted_key: string;
      }> | { error: string };
      if ('error' in result || !Array.isArray(result)) {
        setLoading(false);
        return;
      }
      const items: { id: string; name: string }[] = [];
      for (const c of result) {
        items.push({ id: c.id, name: await decryptCollName(c) });
      }
      setCollections(items);
    } catch { /* ignore */ }
    setLoading(false);
  };

  useEffect(() => {
    loadEntryCollections();
  }, [token, entryId, masterKeyHex, orgId]);

  // Load all user's collections for the "add to collection" dropdown
  useEffect(() => {
    if (!token || !masterKeyHex || !orgId) return;
    (async () => {
      try {
        const result = await window.api.collections.listUser(token) as Array<{
          id: string;
          name_encrypted: string;
          name_nonce: string;
          encrypted_key: string;
        }> | { error: string };
        if ('error' in result || !Array.isArray(result)) return;
        const items: { id: string; name: string; encrypted_key: string }[] = [];
        for (const c of result) {
          items.push({ id: c.id, name: await decryptCollName(c), encrypted_key: c.encrypted_key });
        }
        setAllCollections(items);
      } catch { /* ignore */ }
    })();
  }, [token, masterKeyHex, orgId, collectionsVersion]);

  const handleAdd = async (collId: string) => {
    if (!token || !masterKeyHex) return;
    setAddError('');
    try {
      // Find the vault entry and its decrypted fields
      const vaultEntry = entries.find(e => e.id === entryId);
      const fields = entryFields[entryId];
      if (!vaultEntry || !fields) {
        setAddError('Entry data not available');
        return;
      }

      // Find the collection to get its encrypted key
      const coll = allCollections.find(c => c.id === collId);
      if (!coll || !coll.encrypted_key) {
        setAddError('Collection key not available');
        return;
      }

      // Decrypt the collection key with master key
      const ekNonce = coll.encrypted_key.slice(0, 24);
      const ekCipher = coll.encrypted_key.slice(24);
      const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext: string };
      const collKeyHex = collKeyDec.plaintext;

      // Build the plaintext data from fields (reconstruct the original JSON)
      const plainData: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(fields)) {
        if (k === '_passwordHistory') {
          try { plainData.passwordHistory = JSON.parse(v); } catch { /* skip */ }
        } else if (k === '_uris') {
          try { plainData.uris = JSON.parse(v); } catch { /* skip */ }
        } else if (k === '_reprompt') {
          plainData.reprompt = v === '1' ? 1 : 0;
        } else {
          plainData[k] = v;
        }
      }

      // Encrypt the entry data with the collection key
      const encResult = await window.api.vault.encrypt(collKeyHex, JSON.stringify(plainData)) as { encrypted_data: string; nonce: string };

      // Send to server with encrypted data
      const result = await window.api.collections.addEntry(token, collId, entryId, {
        entry_type: vaultEntry.entry_type,
        encrypted_data: encResult.encrypted_data,
        nonce: encResult.nonce,
      }) as { status?: string; error?: string };

      if (result.error) {
        setAddError(result.error);
        return;
      }

      setShowAdd(false);
      loadEntryCollections();
      bumpCollectionsVersion();
    } catch {
      setAddError('Failed to add to collection');
    }
  };

  const handleRemove = async (collId: string) => {
    if (!token) return;
    try {
      await window.api.collections.removeEntry(token, collId, entryId);
      loadEntryCollections();
    } catch { /* ignore */ }
  };

  if (!orgId) return null;

  const assignedIds = new Set(collections.map(c => c.id));
  const available = allCollections.filter(c => !assignedIds.has(c.id));

  return (
    <div className="mt-4 pt-4 border-t border-surface-800">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs font-medium text-surface-400 uppercase tracking-wide">Collections</div>
        {!readOnly && available.length > 0 && (
          <button
            onClick={() => setShowAdd(!showAdd)}
            className="text-xs text-accent-400 hover:text-accent-300"
          >
            {showAdd ? 'Cancel' : '+ Add to Collection'}
          </button>
        )}
      </div>
      {loading ? (
        <span className="text-xs text-surface-500">Loading...</span>
      ) : (
        <>
          {addError && (
            <div className="text-xs text-red-400 mb-2">{addError}</div>
          )}
          {collections.length === 0 && !showAdd && (
            <div className="text-xs text-surface-500 italic">Not in any collection</div>
          )}
          <div className="flex flex-wrap gap-2">
            {collections.map((c) => (
              <span key={c.id} className="inline-flex items-center gap-1 px-2 py-1 rounded bg-surface-800 text-xs text-surface-300">
                <span>📁</span> {c.name}
                {!readOnly && <button onClick={() => handleRemove(c.id)} className="ml-1 text-surface-500 hover:text-red-400" title="Remove from collection">×</button>}
              </span>
            ))}
          </div>
          {showAdd && (
            <div className="mt-2 space-y-1">
              {available.map((c) => (
                <button
                  key={c.id}
                  onClick={() => handleAdd(c.id)}
                  className="w-full text-left px-3 py-1.5 text-xs rounded bg-surface-800 hover:bg-surface-700 text-surface-200 transition-colors"
                >
                  📁 {c.name}
                </button>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
