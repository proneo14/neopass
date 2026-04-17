import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';
import type { OrgMember, DecryptedEntry } from '../../types/admin';

interface Props {
  orgId: string;
}

const ENTRY_ICONS: Record<string, string> = {
  login: '🔑',
  secure_note: '📝',
  credit_card: '💳',
  identity: '👤',
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

export function VaultAccessPanel({ orgId }: Props) {
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [selectedUser, setSelectedUser] = useState<OrgMember | null>(null);
  const [entries, setEntries] = useState<DecryptedEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [accessLoading, setAccessLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [showResetPassword, setShowResetPassword] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [resetting, setResetting] = useState(false);
  const [expandedEntry, setExpandedEntry] = useState<string | null>(null);
  const [revealedFields, setRevealedFields] = useState<Set<string>>(new Set());

  const { token, masterKeyHex } = useAuthStore();

  const loadMembers = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const result = await window.api.admin.listMembers(token, orgId) as OrgMember[] | { error: string };
      if ('error' in result) {
        setError(result.error);
      } else {
        setMembers(result);
      }
    } catch {
      setError('Failed to load members');
    } finally {
      setLoading(false);
    }
  }, [token, orgId]);

  useEffect(() => { loadMembers(); }, [loadMembers]);

  const handleAccessVault = async (member: OrgMember) => {
    if (!token || !masterKeyHex) return;
    setSelectedUser(member);
    setAccessLoading(true);
    setError('');
    setEntries([]);
    setExpandedEntry(null);
    setRevealedFields(new Set());
    try {
      const result = await window.api.admin.accessVault(token, orgId, member.user_id, masterKeyHex) as DecryptedEntry[] | { error: string };
      if ('error' in result) {
        setError(result.error);
      } else {
        setEntries(result);
      }
    } catch {
      setError('Failed to access vault');
    } finally {
      setAccessLoading(false);
    }
  };

  const toggleReveal = (entryId: string, fieldKey: string) => {
    const key = `${entryId}:${fieldKey}`;
    setRevealedFields((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const handleResetPassword = async () => {
    if (!token || !masterKeyHex || !selectedUser || !newPassword) return;
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (newPassword.length < 10) {
      setError('Password must be at least 10 characters');
      return;
    }
    setResetting(true);
    setError('');
    try {
      const result = await window.api.admin.resetPassword(token, orgId, selectedUser.user_id, {
        master_key: masterKeyHex,
        target_email: selectedUser.email || '',
        new_password: newPassword,
      }) as { error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setSuccessMsg(`Password reset for ${selectedUser.email || selectedUser.user_id}. They will need to log in with the new password.`);
        setShowResetPassword(false);
        setNewPassword('');
        setConfirmPassword('');
      }
    } catch {
      setError('Failed to reset password');
    } finally {
      setResetting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-6 w-6 border-2 border-accent-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Warning Banner */}
      <div className="bg-amber-500/10 border border-amber-500/30 text-amber-400 text-sm px-4 py-3 rounded-lg flex items-start gap-2">
        <span className="text-lg leading-none">⚠️</span>
        <div>
          <div className="font-medium">Sensitive Operation</div>
          <div className="text-xs text-amber-400/70 mt-0.5">
            All vault access is logged and audited. Only access user vaults when necessary.
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-sm px-4 py-2 rounded-lg">
          {error}
        </div>
      )}
      {successMsg && (
        <div className="bg-green-500/10 border border-green-500/30 text-green-400 text-sm px-4 py-2 rounded-lg">
          {successMsg}
        </div>
      )}

      <div className="flex gap-6">
        {/* Member Selector */}
        <div className="w-64 shrink-0">
          <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium mb-3">Select User</h2>
          <div className="bg-surface-800 rounded-xl divide-y divide-surface-700">
            {members.map((member) => (
              <button
                key={member.user_id}
                onClick={() => handleAccessVault(member)}
                className={`w-full text-left px-4 py-3 transition-colors ${
                  selectedUser?.user_id === member.user_id
                    ? 'bg-accent-600/10 text-accent-400'
                    : 'text-surface-300 hover:bg-surface-700/50'
                }`}
              >
                <div className="text-sm">{member.email || member.user_id}</div>
                <div className="text-xs text-surface-500">{member.role}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Vault Contents */}
        <div className="flex-1 min-w-0">
          {!selectedUser ? (
            <div className="flex items-center justify-center py-16 text-surface-500 text-sm">
              Select a user to view their vault
            </div>
          ) : accessLoading ? (
            <div className="flex items-center justify-center py-16">
              <div className="animate-spin rounded-full h-6 w-6 border-2 border-accent-500 border-t-transparent" />
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium">
                  {selectedUser.email || selectedUser.user_id}'s Vault ({entries.length} entries)
                </h2>
                <button
                  onClick={() => { setShowResetPassword(true); setError(''); }}
                  className="text-xs text-red-400 hover:text-red-300 transition-colors"
                >
                  Reset Master Password
                </button>
              </div>

              {entries.length === 0 ? (
                <div className="bg-surface-800 rounded-xl p-8 text-center text-surface-500 text-sm">
                  No vault entries found.
                </div>
              ) : (
                <div className="bg-surface-800 rounded-xl divide-y divide-surface-700">
                  {entries.map((entry) => {
                    const data = entry.data as Record<string, string>;
                    return (
                      <div key={entry.id} className="px-4 py-3">
                        <button
                          onClick={() => setExpandedEntry(expandedEntry === entry.id ? null : entry.id)}
                          className="w-full flex items-center justify-between text-left"
                        >
                          <div className="flex items-center gap-2">
                            <span>{ENTRY_ICONS[entry.entry_type] || '📄'}</span>
                            <span className="text-sm text-surface-100">
                              {data?.name || entry.entry_type}
                            </span>
                            <span className="text-xs text-surface-500">v{entry.version}</span>
                          </div>
                          <span className="text-xs text-surface-500">
                            {expandedEntry === entry.id ? '▼' : '▶'}
                          </span>
                        </button>
                        {expandedEntry === entry.id && (
                          <div className="mt-3 pl-7 space-y-2">
                            {Object.entries(data).map(([key, value]) => {
                              if (!value || key === 'name') return null;
                              const isSensitive = SENSITIVE_FIELDS.has(key);
                              const revealKey = `${entry.id}:${key}`;
                              const revealed = revealedFields.has(revealKey);
                              const displayValue = isSensitive && !revealed
                                ? '•'.repeat(Math.min(String(value).length, 20))
                                : String(value);
                              return (
                                <div key={key} className="flex items-center justify-between text-sm">
                                  <span className="text-surface-500 text-xs w-24">{key}</span>
                                  <div className="flex items-center gap-2 flex-1 min-w-0">
                                    <span className={`text-xs truncate ${isSensitive && !revealed ? 'text-surface-500 font-mono tracking-wider' : 'text-surface-300'}`}>
                                      {displayValue}
                                    </span>
                                    <div className="flex gap-2 shrink-0">
                                      {isSensitive && (
                                        <button
                                          onClick={() => toggleReveal(entry.id, key)}
                                          className="text-xs text-surface-500 hover:text-surface-300 transition-colors"
                                        >
                                          {revealed ? 'Hide' : 'Show'}
                                        </button>
                                      )}
                                      <CopyButton value={String(value)} sensitive={isSensitive} />
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Reset Password Modal */}
      {showResetPassword && selectedUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowResetPassword(false)}>
          <div className="bg-surface-800 rounded-xl p-6 w-full max-w-md space-y-4" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-medium text-surface-100">Reset Master Password</h3>
            <p className="text-xs text-surface-400">
              Reset the master password for <span className="text-surface-200">{selectedUser.email || selectedUser.user_id}</span>.
              This will re-encrypt all their vault entries with a new key.
            </p>
            <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-xs px-3 py-2 rounded-lg space-y-1">
              <div className="font-medium">Warning: Irreversible action</div>
              <ul className="list-disc list-inside text-red-400/80">
                <li>All existing sessions for this user will be invalidated</li>
                <li>The user must log in with the new password</li>
                <li>This action is logged in the audit trail</li>
              </ul>
            </div>
            <div className="space-y-2">
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="New master password (min 10 characters)"
                className="w-full bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
                autoFocus
              />
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
                className="w-full bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
              />
              {newPassword && confirmPassword && newPassword !== confirmPassword && (
                <p className="text-xs text-red-400">Passwords do not match</p>
              )}
              {newPassword && newPassword.length < 10 && (
                <p className="text-xs text-amber-400">Password must be at least 10 characters</p>
              )}
            </div>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => { setShowResetPassword(false); setNewPassword(''); setConfirmPassword(''); }}
                className="text-sm text-surface-400 hover:text-surface-200 px-4 py-2 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleResetPassword}
                disabled={resetting || !newPassword || !confirmPassword || newPassword !== confirmPassword || newPassword.length < 10}
                className="bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-sm rounded-lg px-4 py-2 transition-colors"
              >
                {resetting ? 'Resetting...' : 'Reset Password'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
