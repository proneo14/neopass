import React, { useState, useMemo, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useVaultStore } from '../store/vaultStore';
import { ENTRY_TYPE_ICONS, ENTRY_TYPE_LABELS } from '../types/vault';
import { PasswordGenerator } from '../components/PasswordGenerator';
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
}: {
  x: number;
  y: number;
  onClose: () => void;
  onCopyUsername: () => void;
  onCopyPassword: () => void;
  onEdit: () => void;
  onDelete: () => void;
  hasCredentials: boolean;
}) {
  React.useEffect(() => {
    const handler = () => onClose();
    window.addEventListener('click', handler);
    return () => window.removeEventListener('click', handler);
  }, [onClose]);

  return (
    <div
      className="fixed bg-surface-800 border border-surface-600 rounded-md shadow-xl py-1 z-50 min-w-[160px]"
      style={{ left: x, top: y }}
    >
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
      <button onClick={onEdit} className="w-full text-left px-3 py-1.5 text-sm text-surface-200 hover:bg-surface-700 transition-colors">
        Edit
      </button>
      <button onClick={onDelete} className="w-full text-left px-3 py-1.5 text-sm text-red-400 hover:bg-surface-700 transition-colors">
        Delete
      </button>
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
  const { entries, entryFields, addEntry, searchQuery, setSearchQuery, sortBy, setSortBy, selectedTypeFilter, setSelectedTypeFilter } = useVaultStore();
  const [showAddDropdown, setShowAddDropdown] = useState(false);
  const [newEntryType, setNewEntryType] = useState<string | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; entryId: string } | null>(null);

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

  const handleSaveNewEntry = (type: string, fields: Record<string, string>) => {
    const now = new Date().toISOString();
    const newEntry: VaultEntry = {
      id: crypto.randomUUID(),
      entry_type: type as VaultEntry['entry_type'],
      encrypted_data: '',
      nonce: '',
      version: 1,
      folder_id: null,
      created_at: now,
      updated_at: now,
    };
    addEntry(newEntry, fields);
    setNewEntryType(null);
  };

  const formatDate = (iso: string) => {
    const d = new Date(iso);
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
        <h1 className="text-lg font-semibold text-surface-100">Vault</h1>
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
        {filtered.length === 0 ? (
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
                  onClick={() => navigate(`/vault/${entry.id}`)}
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
                  <span className="text-xs text-surface-600 shrink-0 group-hover:text-surface-400 transition-colors">
                    {formatDate(entry.updated_at)}
                  </span>
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
          onClose={() => setContextMenu(null)}
          onCopyUsername={() => {
            navigator.clipboard.writeText(entryFields[contextMenu.entryId]?.username ?? '');
            setContextMenu(null);
          }}
          onCopyPassword={() => {
            navigator.clipboard.writeText(entryFields[contextMenu.entryId]?.password ?? '');
            setContextMenu(null);
          }}
          onEdit={() => {
            navigate(`/vault/${contextMenu.entryId}`);
            setContextMenu(null);
          }}
          onDelete={() => {
            setContextMenu(null);
          }}
        />
      )}
    </div>
  );
}
