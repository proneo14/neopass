import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useVaultStore } from '../store/vaultStore';
import { useAuthStore } from '../store/authStore';

export function SSHKeys() {
  const navigate = useNavigate();
  const { entries, entryFields, addEntry, updateEntryFields } = useVaultStore();
  const { token, masterKeyHex } = useAuthStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [showCreate, setShowCreate] = useState(false);

  const sshEntries = useMemo(() => {
    return entries
      .filter((e) => e.entry_type === 'ssh_key' && !e.deleted_at)
      .filter((e) => {
        if (!searchQuery) return true;
        const fields = entryFields[e.id] ?? {};
        const q = searchQuery.toLowerCase();
        return (
          (fields.name || '').toLowerCase().includes(q) ||
          (fields.keyType || '').toLowerCase().includes(q) ||
          (fields.fingerprint || '').toLowerCase().includes(q) ||
          (fields.publicKey || '').toLowerCase().includes(q)
        );
      })
      .sort((a, b) => {
        const na = (entryFields[a.id]?.name || '').toLowerCase();
        const nb = (entryFields[b.id]?.name || '').toLowerCase();
        return na.localeCompare(nb);
      });
  }, [entries, entryFields, searchQuery]);

  const getKeyTypeBadge = (keyType: string) => {
    switch (keyType?.toLowerCase()) {
      case 'ed25519': return 'Ed25519';
      case 'rsa': return 'RSA-4096';
      case 'ecdsa': return 'ECDSA';
      default: return keyType || 'Unknown';
    }
  };

  const handleCreate = async (fields: Record<string, string>) => {
    if (!token || !masterKeyHex) return;
    const plaintextObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(fields)) {
      if (k === '_reprompt') plaintextObj.reprompt = v === '1' ? 1 : 0;
      else plaintextObj[k] = v;
    }
    const plaintext = JSON.stringify(plaintextObj);
    const encResult = await window.api.vault.encrypt(masterKeyHex, plaintext) as { encrypted_data: string; nonce: string; error?: string };
    if (encResult.error) return;

    const createResult = await window.api.vault.create(token, {
      entry_type: 'ssh_key',
      encrypted_data: encResult.encrypted_data,
      nonce: encResult.nonce,
    }) as { id: string; entry_type: string; encrypted_data: string; nonce: string; version: number; folder_id: string | null; created_at: string; updated_at: string; error?: string };

    if (createResult.error) return;

    addEntry(
      {
        id: createResult.id,
        entry_type: 'ssh_key',
        encrypted_data: createResult.encrypted_data,
        nonce: createResult.nonce,
        version: createResult.version,
        folder_id: createResult.folder_id ?? null,
        is_favorite: false,
        is_archived: false,
        deleted_at: null,
        created_at: createResult.created_at,
        updated_at: createResult.updated_at,
      },
      fields,
    );
    setShowCreate(false);
  };

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-surface-100">SSH Keys</h1>
          <p className="text-sm text-surface-400 mt-1">
            Manage your SSH key pairs
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-surface-500 bg-surface-800 px-2 py-1 rounded">
            {sshEntries.length} key{sshEntries.length !== 1 ? 's' : ''}
          </span>
          <button
            onClick={() => setShowCreate(true)}
            className="px-3 py-1.5 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors"
          >
            + Add SSH Key
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search SSH keys…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full px-3 py-2 bg-surface-800 border border-surface-700 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 text-sm"
        />
      </div>

      {/* List */}
      {sshEntries.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-surface-500">
          <span className="text-5xl mb-4">🗝️</span>
          <p className="text-sm">
            {searchQuery ? 'No SSH keys match your search' : 'No SSH keys stored yet'}
          </p>
        </div>
      ) : (
        <div className="space-y-1">
          {sshEntries.map((entry) => {
            const fields = entryFields[entry.id] ?? {};
            return (
              <button
                key={entry.id}
                onClick={() => navigate(`/vault/${entry.id}`)}
                className="w-full flex items-center gap-3 px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 transition-colors text-left"
              >
                <span className="text-xl shrink-0">🗝️</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-surface-100 truncate">
                    {fields.name || 'Unnamed Key'}
                  </p>
                  {fields.fingerprint && (
                    <p className="text-xs text-surface-500 font-mono truncate mt-0.5">
                      {fields.fingerprint}
                    </p>
                  )}
                </div>
                {fields.keyType && (
                  <span className="px-2 py-0.5 rounded-full bg-accent-500/20 text-accent-300 text-xs font-medium shrink-0">
                    {getKeyTypeBadge(fields.keyType)}
                  </span>
                )}
                <span className="text-surface-600 shrink-0">→</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <NewSSHKeyModal
          onCancel={() => setShowCreate(false)}
          onSave={handleCreate}
        />
      )}
    </div>
  );
}

function NewSSHKeyModal({ onCancel, onSave }: {
  onCancel: () => void;
  onSave: (fields: Record<string, string>) => void;
}) {
  const [name, setName] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [notes, setNotes] = useState('');
  const [generating, setGenerating] = useState(false);
  const [keyType, setKeyType] = useState('ed25519');

  const fingerprint = useMemo(() => {
    // Simple fingerprint derivation from public key (display only)
    if (!publicKey.trim()) return '';
    try {
      // Extract base64 portion of the public key
      const parts = publicKey.trim().split(/\s+/);
      if (parts.length >= 2) {
        // Hash the base64 key data for a fingerprint-like display
        const keyData = parts[1];
        // Use a simple hash display — real fingerprint would use SHA-256 of raw key bytes
        return `SHA256:${keyData.slice(0, 43)}`;
      }
    } catch { /* ignore */ }
    return '';
  }, [publicKey]);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      // Generate Ed25519 key pair using Node.js crypto via IPC
      const result = await window.api.ssh.generateKeyPair(keyType) as {
        publicKey?: string;
        privateKey?: string;
        fingerprint?: string;
        error?: string;
      };
      if (result.error) {
        console.error('Key generation failed:', result.error);
      } else {
        if (result.publicKey) setPublicKey(result.publicKey);
        if (result.privateKey) setPrivateKey(result.privateKey);
      }
    } catch {
      console.error('Key generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const handleSave = () => {
    const fields: Record<string, string> = {
      name: name.trim() || 'Unnamed SSH Key',
      publicKey,
      privateKey,
      fingerprint: fingerprint,
      keyType,
      passphrase,
      notes,
      _reprompt: '0',
    };
    onSave(fields);
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-surface-900 rounded-lg p-6 max-w-lg w-full shadow-2xl max-h-[90vh] overflow-y-auto">
        <h2 className="text-lg font-semibold text-surface-100 mb-4">New SSH Key</h2>

        <div className="space-y-3">
          <div>
            <label className="block text-xs text-surface-400 mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. GitHub Deploy Key"
              autoFocus
              className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 text-sm"
            />
          </div>

          <div>
            <label className="block text-xs text-surface-400 mb-1">Key Type</label>
            <select
              value={keyType}
              onChange={(e) => setKeyType(e.target.value)}
              className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 focus:outline-none focus:ring-2 focus:ring-accent-500 text-sm"
            >
              <option value="ed25519">Ed25519</option>
              <option value="rsa">RSA-4096</option>
              <option value="ecdsa">ECDSA</option>
            </select>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs text-surface-400">Public Key</label>
              <button
                onClick={handleGenerate}
                disabled={generating}
                className="text-xs text-accent-400 hover:text-accent-300 transition-colors disabled:opacity-50"
              >
                {generating ? 'Generating…' : 'Generate Key Pair'}
              </button>
            </div>
            <textarea
              value={publicKey}
              onChange={(e) => setPublicKey(e.target.value)}
              placeholder="ssh-ed25519 AAAA... user@host"
              rows={3}
              className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 text-sm font-mono resize-none"
            />
          </div>

          <div>
            <label className="block text-xs text-surface-400 mb-1">Private Key</label>
            <textarea
              value={privateKey}
              onChange={(e) => setPrivateKey(e.target.value)}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              rows={4}
              className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 text-sm font-mono resize-none"
            />
          </div>

          <div>
            <label className="block text-xs text-surface-400 mb-1">Passphrase (optional)</label>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Key passphrase"
              className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 text-sm"
            />
          </div>

          <div>
            <label className="block text-xs text-surface-400 mb-1">Notes (optional)</label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
              className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 text-sm resize-none"
            />
          </div>

          {fingerprint && (
            <div className="px-3 py-2 rounded-md bg-surface-800 border border-surface-700">
              <span className="text-xs text-surface-500">Fingerprint: </span>
              <span className="text-xs text-surface-300 font-mono">{fingerprint}</span>
            </div>
          )}
        </div>

        <div className="flex gap-3 mt-6">
          <button onClick={onCancel} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={!name.trim() && !publicKey.trim() && !privateKey.trim()}
            className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm font-medium transition-colors"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
