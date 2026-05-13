import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../store/authStore';
import type { PasskeyCredential, HardwareAuthKey } from '../types/passkey';

interface GroupedPasskeys {
  rpId: string;
  rpName: string;
  passkeys: PasskeyCredential[];
}

function TrashIcon({ className }: { className?: string }) {
  return (
    <svg className={className || 'w-4 h-4'} fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
    </svg>
  );
}

export function Passkeys() {
  const { token } = useAuthStore();
  const [passkeys, setPasskeys] = useState<PasskeyCredential[]>([]);
  const [hardwareKeys, setHardwareKeys] = useState<HardwareAuthKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<'passkeys' | 'hardware'>('passkeys');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [selectedPasskey, setSelectedPasskey] = useState<PasskeyCredential | null>(null);

  const fetchPasskeys = useCallback(async () => {
    if (!token) return;
    try {
      const result = await window.api.passkey.list(token);
      if (Array.isArray(result)) {
        setPasskeys(result);
      }
    } catch {
      setError('Failed to load passkeys');
    }
  }, [token]);

  const fetchHardwareKeys = useCallback(async () => {
    if (!token) return;
    try {
      const result = await window.api.passkey.listHardwareKeys(token);
      if (Array.isArray(result)) {
        setHardwareKeys(result);
      }
    } catch {
      // Hardware keys may not be available
    }
  }, [token]);

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchPasskeys(), fetchHardwareKeys()]).finally(() => setLoading(false));
  }, [fetchPasskeys, fetchHardwareKeys]);

  const handleDeletePasskey = async (id: string) => {
    if (!token) return;
    try {
      await window.api.passkey.delete(token, id);
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
      setConfirmDelete(null);
    } catch {
      setError('Failed to delete passkey');
    }
  };

  const handleDeleteHardwareKey = async (id: string) => {
    if (!token) return;
    try {
      await window.api.passkey.deleteHardwareKey(token, id);
      setHardwareKeys((prev) => prev.filter((k) => k.id !== id));
      setConfirmDelete(null);
    } catch {
      setError('Failed to delete hardware key');
    }
  };

  const toggleGroup = (rpId: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(rpId)) {
        next.delete(rpId);
      } else {
        next.add(rpId);
      }
      return next;
    });
  };

  // Group passkeys by RP ID
  const grouped: GroupedPasskeys[] = React.useMemo(() => {
    const map = new Map<string, GroupedPasskeys>();
    const filtered = passkeys.filter(
      (p) =>
        !searchQuery ||
        p.rp_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.rp_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.username.toLowerCase().includes(searchQuery.toLowerCase())
    );
    for (const p of filtered) {
      if (!map.has(p.rp_id)) {
        map.set(p.rp_id, { rpId: p.rp_id, rpName: p.rp_name || p.rp_id, passkeys: [] });
      }
      map.get(p.rp_id)!.passkeys.push(p);
    }
    return Array.from(map.values()).sort((a, b) => a.rpName.localeCompare(b.rpName));
  }, [passkeys, searchQuery]);

  const filteredHardwareKeys = hardwareKeys.filter(
    (k) =>
      !searchQuery ||
      k.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    try {
      return new Date(dateStr).toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    } catch {
      return dateStr;
    }
  };

  const algorithmLabel = (alg: number) => {
    switch (alg) {
      case -7: return 'ES256';
      case -8: return 'EdDSA';
      case -257: return 'RS256';
      default: return `Alg ${alg}`;
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-surface-100">Passkeys</h1>
          <p className="text-sm text-surface-400 mt-1">
            Manage your passkeys and hardware security keys
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-surface-500 bg-surface-800 px-2 py-1 rounded">
            {passkeys.length} passkey{passkeys.length !== 1 ? 's' : ''}
          </span>
          {hardwareKeys.length > 0 && (
            <span className="text-xs text-surface-500 bg-surface-800 px-2 py-1 rounded">
              {hardwareKeys.length} hardware key{hardwareKeys.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {error}
          <button onClick={() => setError('')} className="ml-2 text-red-300 hover:text-red-200">
            ✕
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-surface-900 rounded-lg p-1">
        <button
          onClick={() => setActiveTab('passkeys')}
          className={`flex-1 px-4 py-2 text-sm font-medium rounded-md transition-colors ${
            activeTab === 'passkeys'
              ? 'bg-accent-600/20 text-accent-400'
              : 'text-surface-400 hover:text-surface-200'
          }`}
        >
          🔐 Passkeys
        </button>
        <button
          onClick={() => setActiveTab('hardware')}
          className={`flex-1 px-4 py-2 text-sm font-medium rounded-md transition-colors ${
            activeTab === 'hardware'
              ? 'bg-accent-600/20 text-accent-400'
              : 'text-surface-400 hover:text-surface-200'
          }`}
        >
          🔑 Hardware Keys
        </button>
      </div>

      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          placeholder={activeTab === 'passkeys' ? 'Search passkeys by site or username...' : 'Search hardware keys...'}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full px-4 py-2 bg-surface-800 border border-surface-700 rounded-lg text-surface-200 placeholder-surface-500 text-sm focus:outline-none focus:border-accent-500"
        />
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20 text-surface-400">
          <svg className="animate-spin h-6 w-6 mr-2" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading...
        </div>
      ) : activeTab === 'passkeys' ? (
        /* Passkeys Tab */
        grouped.length === 0 ? (
          <div className="text-center py-20">
            <div className="text-4xl mb-4">🔐</div>
            <h3 className="text-lg font-medium text-surface-300 mb-2">No Passkeys Yet</h3>
            <p className="text-sm text-surface-500 max-w-md mx-auto">
              Passkeys will appear here when you create them on websites using the NeoPass browser extension.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {grouped.map((group) => (
              <div key={group.rpId} className="bg-surface-900 rounded-lg border border-surface-700 overflow-hidden">
                {/* Group header */}
                <button
                  onClick={() => toggleGroup(group.rpId)}
                  className="w-full flex items-center justify-between px-4 py-3 hover:bg-surface-800 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-surface-700 flex items-center justify-center">
                      <img
                        src={`https://www.google.com/s2/favicons?domain=${group.rpId}&sz=32`}
                        alt=""
                        className="w-5 h-5"
                        onError={(e) => {
                          (e.target as HTMLImageElement).style.display = 'none';
                        }}
                      />
                    </div>
                    <div className="text-left">
                      <div className="text-sm font-medium text-surface-200">{group.rpName}</div>
                      <div className="text-xs text-surface-500">{group.rpId}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-surface-500 bg-surface-800 px-2 py-0.5 rounded">
                      {group.passkeys.length}
                    </span>
                    <span className={`text-surface-400 transition-transform ${expandedGroups.has(group.rpId) ? 'rotate-90' : ''}`}>
                      ▶
                    </span>
                  </div>
                </button>

                {/* Group content */}
                {expandedGroups.has(group.rpId) && (
                  <div className="border-t border-surface-700">
                    {group.passkeys.map((passkey) => (
                      <div
                        key={passkey.id}
                        onClick={() => setSelectedPasskey(passkey)}
                        className="flex items-center justify-between px-4 py-3 border-b border-surface-800 last:border-b-0 hover:bg-surface-800/50 cursor-pointer"
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm text-surface-200 truncate">
                              {passkey.username || passkey.display_name || 'Unnamed'}
                            </span>
                            <span className="text-[10px] text-surface-500 bg-surface-700 px-1.5 py-0.5 rounded font-mono">
                              {algorithmLabel(passkey.algorithm)}
                            </span>
                            {passkey.discoverable && (
                              <span className="text-[10px] text-accent-400 bg-accent-600/10 px-1.5 py-0.5 rounded">
                                Discoverable
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-xs text-surface-500">
                            <span>Created {formatDate(passkey.created_at)}</span>
                            <span>Used {formatDate(passkey.last_used_at)}</span>
                            <span>Sign count: {passkey.sign_count}</span>
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-1 ml-3" onClick={(e) => e.stopPropagation()}>
                          {confirmDelete === passkey.id ? (
                            <>
                              <button
                                onClick={() => handleDeletePasskey(passkey.id)}
                                className="px-2 py-1 text-xs bg-red-600 text-white rounded hover:bg-red-500"
                              >
                                Confirm
                              </button>
                              <button
                                onClick={() => setConfirmDelete(null)}
                                className="px-2 py-1 text-xs text-surface-400 hover:text-surface-200"
                              >
                                Cancel
                              </button>
                            </>
                          ) : (
                            <button
                              onClick={() => setConfirmDelete(passkey.id)}
                              className="p-1.5 text-surface-500 hover:text-red-400 transition-colors rounded hover:bg-surface-700"
                              title="Delete passkey"
                            >
                              <TrashIcon />
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )
      ) : (
        /* Hardware Keys Tab */
        filteredHardwareKeys.length === 0 ? (
          <div className="text-center py-20">
            <div className="text-4xl mb-4">🔑</div>
            <h3 className="text-lg font-medium text-surface-300 mb-2">No Hardware Keys</h3>
            <p className="text-sm text-surface-500 max-w-md mx-auto">
              Register a hardware security key (YubiKey, Titan, etc.) to use as a second factor for vault login.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {filteredHardwareKeys.map((key) => (
              <div
                key={key.id}
                className="flex items-center justify-between px-4 py-3 bg-surface-900 rounded-lg border border-surface-700 hover:bg-surface-800/50"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-surface-700 flex items-center justify-center text-lg">
                    🔑
                  </div>
                  <div>
                    <div className="text-sm font-medium text-surface-200">{key.name}</div>
                    <div className="flex items-center gap-3 mt-0.5 text-xs text-surface-500">
                      <span>Registered {formatDate(key.created_at)}</span>
                      <span>Last used {formatDate(key.last_used_at)}</span>
                      <span>Sign count: {key.sign_count}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1">
                  {confirmDelete === key.id ? (
                    <>
                      <button
                        onClick={() => handleDeleteHardwareKey(key.id)}
                        className="px-2 py-1 text-xs bg-red-600 text-white rounded hover:bg-red-500"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={() => setConfirmDelete(null)}
                        className="px-2 py-1 text-xs text-surface-400 hover:text-surface-200"
                      >
                        Cancel
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => setConfirmDelete(key.id)}
                      className="p-1.5 text-surface-500 hover:text-red-400 transition-colors rounded hover:bg-surface-700"
                      title="Remove hardware key"
                    >
                      <TrashIcon />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )
      )}

      {/* Passkey Detail Modal */}
      {selectedPasskey && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedPasskey(null)}>
          <div className="bg-surface-900 border border-surface-700 rounded-xl w-full max-w-lg mx-4 p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-surface-700 flex items-center justify-center">
                  <img
                    src={`https://www.google.com/s2/favicons?domain=${selectedPasskey.rp_id}&sz=32`}
                    alt=""
                    className="w-6 h-6"
                    onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
                  />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-surface-100">{selectedPasskey.rp_name || selectedPasskey.rp_id}</h3>
                  <p className="text-xs text-surface-500">{selectedPasskey.rp_id}</p>
                </div>
              </div>
              <button onClick={() => setSelectedPasskey(null)} className="text-surface-400 hover:text-surface-200 text-xl leading-none">&times;</button>
            </div>

            <div className="space-y-3">
              <DetailRow label="Username" value={selectedPasskey.username || '—'} />
              <DetailRow label="Display Name" value={selectedPasskey.display_name || '—'} />
              <DetailRow label="Algorithm" value={algorithmLabel(selectedPasskey.algorithm)} />
              <DetailRow label="Discoverable" value={selectedPasskey.discoverable ? 'Yes' : 'No'} />
              <DetailRow label="Backed Up" value={selectedPasskey.backed_up ? 'Yes' : 'No'} />
              <DetailRow label="Created" value={formatDate(selectedPasskey.created_at)} />
              <DetailRow label="Last Used" value={formatDate(selectedPasskey.last_used_at)} />
              <DetailRow label="Sign Count" value={String(selectedPasskey.sign_count)} />
              <DetailRow label="Credential ID" value={selectedPasskey.credential_id} mono />
            </div>

            <div className="flex justify-end mt-6 gap-2">
              <button
                onClick={() => {
                  setConfirmDelete(selectedPasskey.id);
                  setSelectedPasskey(null);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors"
              >
                <TrashIcon className="w-4 h-4" />
                Delete
              </button>
              <button
                onClick={() => setSelectedPasskey(null)}
                className="px-4 py-1.5 text-sm bg-surface-700 text-surface-200 rounded-lg hover:bg-surface-600 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between py-2 border-b border-surface-800 last:border-b-0">
      <span className="text-xs text-surface-500 w-28 flex-shrink-0">{label}</span>
      <span className={`text-sm text-surface-200 text-right break-all ${mono ? 'font-mono text-xs' : ''}`}>{value}</span>
    </div>
  );
}
