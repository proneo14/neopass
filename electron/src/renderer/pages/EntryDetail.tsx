import React, { useState } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { PasswordGenerator } from '../components/PasswordGenerator';
import { ENTRY_TYPE_ICONS, ENTRY_TYPE_LABELS } from '../types/vault';
import { useVaultStore } from '../store/vaultStore';
import { useAuthStore } from '../store/authStore';

const FIELD_LABELS: Record<string, string> = {
  name: 'Name', username: 'Username', password: 'Password', uri: 'Website',
  notes: 'Notes', content: 'Content', number: 'Card Number', expiry: 'Expiry',
  cvv: 'CVV', cardholder: 'Cardholder', firstName: 'First Name', lastName: 'Last Name',
  email: 'Email', phone: 'Phone', address: 'Address',
};

/** Fixed display order per entry type (fields not listed here appear at the end). */
const FIELD_ORDER: Record<string, string[]> = {
  login: ['uri', 'username', 'email', 'password', 'notes'],
  secure_note: ['content', 'notes'],
  credit_card: ['number', 'expiry', 'cvv', 'cardholder', 'notes'],
  identity: ['firstName', 'lastName', 'email', 'phone', 'address', 'notes'],
};

const SENSITIVE_FIELDS = new Set(['password', 'cvv', 'number', 'content']);

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

  const vaultEntry = id ? entries.find((e) => e.id === id) : null;
  const fields = id ? entryFields[id] : null;

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
  const [editFields, setEditFields] = useState(fields);

  // Fixed field display order: use the type-specific order, then any remaining keys
  const typeOrder = FIELD_ORDER[entryType] ?? [];
  const allKeys = Object.keys(fields);
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

    // Encrypt the updated fields
    const plaintext = JSON.stringify(editFields);
    const encResult = await window.api.vault.encrypt(masterKeyHex, plaintext);
    if (encResult.error) return;

    // Save to backend
    const updateResult = await window.api.vault.update(token, id, {
      entry_type: vaultEntry.entry_type,
      encrypted_data: encResult.encrypted_data,
      nonce: encResult.nonce,
    }) as { id: string; entry_type: string; encrypted_data: string; nonce: string; version: number; folder_id: string | null; created_at: string; updated_at: string; error?: string };

    if (!updateResult.error) {
      updateEntryFields(id, editFields);
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
    setEditFields(fields);
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
          <span className="text-xs text-surface-500">{ENTRY_TYPE_LABELS[entryType]}</span>
        </div>
        <div className="flex-1" />
        {!editing ? (
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
          const isSensitive = SENSITIVE_FIELDS.has(key);
          const revealed = revealedFields.has(key);
          const value = editing ? editFields[key] : fields[key];
          const displayValue = isSensitive && !revealed ? '•'.repeat(Math.min(value.length, 20)) : value;

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

      {/* Delete */}
      <div className="mt-6 pt-4 border-t border-surface-800">
        {!confirmDelete ? (
          <button
            onClick={() => setConfirmDelete(true)}
            className="text-sm text-red-400 hover:text-red-300 transition-colors"
          >
            Delete entry
          </button>
        ) : (
          <div className="flex items-center gap-3">
            <span className="text-sm text-red-400">Delete this entry?</span>
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
    </div>
  );
}
