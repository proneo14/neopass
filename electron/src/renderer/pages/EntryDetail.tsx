import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { PasswordGenerator } from '../components/PasswordGenerator';
import { ENTRY_TYPE_ICONS, ENTRY_TYPE_LABELS } from '../types/vault';
import { useVaultStore } from '../store/vaultStore';

const FIELD_LABELS: Record<string, string> = {
  name: 'Name', username: 'Username', password: 'Password', uri: 'Website',
  notes: 'Notes', content: 'Content', number: 'Card Number', expiry: 'Expiry',
  cvv: 'CVV', cardholder: 'Cardholder', firstName: 'First Name', lastName: 'Last Name',
  email: 'Email', phone: 'Phone', address: 'Address',
};

const SENSITIVE_FIELDS = new Set(['password', 'cvv', 'number', 'content']);

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(value);
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
  const { entries, entryFields, updateEntryFields } = useVaultStore();
  const [editing, setEditing] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [revealedFields, setRevealedFields] = useState<Set<string>>(new Set());

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
  const fieldOrder = Object.keys(fields);

  const toggleReveal = (field: string) => {
    setRevealedFields((prev) => {
      const next = new Set(prev);
      if (next.has(field)) next.delete(field);
      else next.add(field);
      return next;
    });
  };

  const handleSave = () => {
    if (id) updateEntryFields(id, editFields);
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
                <CopyButton value={value} />
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
    </div>
  );
}
