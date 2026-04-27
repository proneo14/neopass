import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { PasswordGenerator } from '../components/PasswordGenerator';
import { ENTRY_TYPE_ICONS, ENTRY_TYPE_LABELS } from '../types/vault';
import { useVaultStore } from '../store/vaultStore';
import { useAuthStore } from '../store/authStore';
import { generateTOTP, getTimeRemaining } from '../utils/totp';

const FIELD_LABELS: Record<string, string> = {
  name: 'Name', username: 'Username', password: 'Password', uri: 'Website',
  notes: 'Notes', content: 'Content', number: 'Card Number', expiry: 'Expiry',
  cvv: 'CVV', cardholder: 'Cardholder', firstName: 'First Name', lastName: 'Last Name',
  email: 'Email', phone: 'Phone', address: 'Address', totp: 'Authenticator Key',
};

/** Fixed display order per entry type (fields not listed here appear at the end). */
const FIELD_ORDER: Record<string, string[]> = {
  login: ['uri', 'username', 'email', 'password', 'notes', 'totp'],
  secure_note: ['content', 'notes'],
  credit_card: ['number', 'expiry', 'cvv', 'cardholder', 'notes'],
  identity: ['firstName', 'lastName', 'email', 'phone', 'address', 'notes'],
};

const SENSITIVE_FIELDS = new Set(['password', 'cvv', 'number', 'content', 'totp']);

function CopyButton({ value, sensitive = false }: { value: string; sensitive?: boolean }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    if (sensitive) {
      await window.api.clipboard.copySecure(value);
    } else {
      await navigator.clipboard.writeText(value);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
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

export function EntryDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { entries, entryFields, updateEntryFields, updateEntry, removeEntry } = useVaultStore();
  const { token, masterKeyHex } = useAuthStore();
  const [editing, setEditing] = useState(!!(location.state as { edit?: boolean } | null)?.edit);
  const [showGenerator, setShowGenerator] = useState(false);
  const [revealedFields, setRevealedFields] = useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmPermanent, setConfirmPermanent] = useState(false);

  const vaultEntry = id ? entries.find((e) => e.id === id) : null;
  const fields = id ? entryFields[id] : null;
  const isTrash = vaultEntry?.deleted_at != null;

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
    return base;
  });

  // Fixed field display order: use the type-specific order, then any remaining keys
  const typeOrder = FIELD_ORDER[entryType] ?? [];
  const allKeys = [...new Set([...Object.keys(fields), ...typeOrder])];
  const fieldOrder = [
    ...typeOrder.filter((k) => allKeys.includes(k)),
    ...allKeys.filter((k) => !typeOrder.includes(k) && k !== 'name'),
  ];

  const toggleReveal = (field: string) => {
    setRevealedFields((prev) => {
      const next = new Set(prev);
      if (next.has(field)) next.delete(field);
      else next.add(field);
      return next;
    });
  };

  const handleSave = async () => {
    if (!id || !token || !masterKeyHex) return;

    // Strip empty optional fields before persisting
    const cleanFields: Record<string, string> = {};
    for (const [k, v] of Object.entries(editFields)) {
      if (v || k === 'name') cleanFields[k] = v;
    }

    // Encrypt the updated fields
    const plaintext = JSON.stringify(cleanFields);
    const encResult = await window.api.vault.encrypt(masterKeyHex, plaintext);
    if (encResult.error) return;

    // Save to backend
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
    }
    setEditing(false);
  };

  const handleCancel = () => {
    const base = { ...fields };
    for (const key of FIELD_ORDER[entryType] ?? []) {
      if (!(key in base)) base[key] = '';
    }
    setEditFields(base);
    setEditing(false);
  };

  const formatDate = (iso: string) => new Date(iso).toLocaleString();

  return (
    <div className="max-w-2xl">
      {/* Back + header */}
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={() => navigate('/vault')}
          className="text-surface-400 hover:text-surface-200 transition-colors text-sm"
        >
          ← Back
        </button>
      </div>

      <div className="flex items-center gap-3 mb-6">
        <span className="text-2xl">{ENTRY_TYPE_ICONS[entryType]}</span>
        <div>
          <h1 className="text-lg font-semibold text-surface-100">{fields.name}</h1>
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
          <button
            onClick={() => setEditing(true)}
            className="px-3 py-1.5 rounded-md bg-surface-800 hover:bg-surface-700 text-surface-300 text-sm transition-colors"
          >
            Edit
          </button>
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

      {/* Fields */}
      <div className="space-y-1 bg-surface-900/50 rounded-lg p-4">
        {fieldOrder.map((key) => {
          if (key === 'name') return null;
          // In view mode, skip rendering the raw totp field — we show TOTPDisplay instead
          if (key === 'totp' && !editing && fields[key]) return null;
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
                ) : (
                  <input
                    type={isSensitive && !revealed ? 'password' : 'text'}
                    value={editFields[key]}
                    onChange={(e) => setEditFields({ ...editFields, [key]: e.target.value })}
                    className="flex-1 px-2 py-1 rounded bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
                  />
                )
              ) : key === 'uri' ? (
                <span className="flex-1 text-sm text-accent-400 break-all">{value}</span>
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
                <CopyButton value={value} sensitive={isSensitive} />
              </div>
            </div>
          );
        })}
        {/* Live TOTP code — shown when the entry has a totp secret and not editing */}
        {!editing && fields.totp && <TOTPDisplay secret={fields.totp} />}
      </div>

      {/* Password generator (for login entries in edit mode) */}
      {entryType === 'login' && editing && (
        <div className="mt-4">
          <button
            onClick={() => setShowGenerator(!showGenerator)}
            className="text-xs text-accent-400 hover:text-accent-300 transition-colors"
          >
            {showGenerator ? 'Hide password generator' : 'Generate new password'}
          </button>
          {showGenerator && (
            <div className="mt-3 p-4 bg-surface-900/50 rounded-lg">
              <PasswordGenerator onUse={(pw) => { setEditFields({ ...editFields, password: pw }); setShowGenerator(false); }} />
            </div>
          )}
        </div>
      )}

      {/* Timestamps */}
      <div className="mt-6 pt-4 border-t border-surface-800 flex gap-6 text-xs text-surface-600">
        <span>Created: {formatDate(vaultEntry.created_at)}</span>
        <span>Modified: {formatDate(vaultEntry.updated_at)}</span>
      </div>

      {/* Delete / Archive */}
      {!isTrash && (
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
    </div>
  );
}
