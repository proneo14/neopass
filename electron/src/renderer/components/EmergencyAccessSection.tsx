import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthStore } from '../store/authStore';

interface EmergencyAccessRecord {
  id: string;
  grantor_id: string;
  grantee_id?: string;
  grantee_email: string;
  grantor_email?: string;
  status: string;
  access_type: string;
  wait_time_days: number;
  recovery_initiated_at?: string;
  created_at: string;
  updated_at: string;
}

interface VaultEntry {
  id: string;
  entry_type: string;
  encrypted_data: string;
  nonce: string;
  version: number;
  is_favorite: boolean;
  is_archived: boolean;
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    invited: 'bg-blue-500/20 text-blue-400',
    accepted: 'bg-green-500/20 text-green-400',
    recovery_initiated: 'bg-yellow-500/20 text-yellow-400',
    recovery_approved: 'bg-emerald-500/20 text-emerald-400',
    recovery_rejected: 'bg-red-500/20 text-red-400',
    expired: 'bg-surface-600/30 text-surface-400',
  };
  const labels: Record<string, string> = {
    invited: 'Invited',
    accepted: 'Ready',
    recovery_initiated: 'Recovery Initiated',
    recovery_approved: 'Approved',
    recovery_rejected: 'Rejected',
    expired: 'Expired',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full ${colors[status] || 'bg-surface-600 text-surface-300'}`}>
      {labels[status] || status}
    </span>
  );
}

function Countdown({ initiatedAt, waitDays }: { initiatedAt: string; waitDays: number }) {
  const [remaining, setRemaining] = useState('');

  useEffect(() => {
    const update = () => {
      const deadline = new Date(initiatedAt);
      deadline.setDate(deadline.getDate() + waitDays);
      const now = new Date();
      const diff = deadline.getTime() - now.getTime();
      if (diff <= 0) {
        setRemaining('Access available now');
        return;
      }
      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      setRemaining(`${days}d ${hours}h ${minutes}m remaining`);
    };
    update();
    const interval = setInterval(update, 60000);
    return () => clearInterval(interval);
  }, [initiatedAt, waitDays]);

  return <span className="text-xs text-yellow-400">{remaining}</span>;
}

export function EmergencyAccessSection() {
  const { token, userId, masterKeyHex } = useAuthStore();
  const [granted, setGranted] = useState<EmergencyAccessRecord[]>([]);
  const [trusted, setTrusted] = useState<EmergencyAccessRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionLoading, setActionLoading] = useState('');

  // Invite form state
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteAccessType, setInviteAccessType] = useState<'view' | 'takeover'>('view');
  const [inviteWaitDays, setInviteWaitDays] = useState(7);
  const [inviteError, setInviteError] = useState('');

  // Vault viewer state
  const [viewingVault, setViewingVault] = useState<{
    email: string;
    entries: Array<VaultEntry & { decryptedData?: Record<string, unknown> }>;
  } | null>(null);

  // Takeover modal state
  const [takeoverTarget, setTakeoverTarget] = useState<{ id: string; email: string } | null>(null);
  const [takeoverPassword, setTakeoverPassword] = useState('');
  const [takeoverConfirm, setTakeoverConfirm] = useState('');
  const [takeoverLoading, setTakeoverLoading] = useState(false);
  const [takeoverError, setTakeoverError] = useState('');

  const loadData = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const [grantedRes, trustedRes] = await Promise.all([
        window.api.emergencyAccess.listGranted(token),
        window.api.emergencyAccess.listTrusted(token),
      ]);
      const grantedData = grantedRes as EmergencyAccessRecord[] | { error: string };
      const trustedData = trustedRes as EmergencyAccessRecord[] | { error: string };
      if ('error' in grantedData) throw new Error(grantedData.error);
      if ('error' in trustedData) throw new Error(trustedData.error);
      setGranted(Array.isArray(grantedData) ? grantedData : []);
      setTrusted(Array.isArray(trustedData) ? trustedData : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load emergency access data');
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Initial load + poll every 5 seconds for real-time updates
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    loadData();
    pollRef.current = setInterval(() => {
      if (!token) return;
      Promise.all([
        window.api.emergencyAccess.listGranted(token),
        window.api.emergencyAccess.listTrusted(token),
      ]).then(([grantedRes, trustedRes]) => {
        const grantedData = grantedRes as EmergencyAccessRecord[] | { error: string };
        const trustedData = trustedRes as EmergencyAccessRecord[] | { error: string };
        if (!('error' in grantedData)) setGranted(Array.isArray(grantedData) ? grantedData : []);
        if (!('error' in trustedData)) setTrusted(Array.isArray(trustedData) ? trustedData : []);
      }).catch(() => {});
    }, 5000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [loadData, token]);

  // Auto-confirm key exchange for contacts that need it (grantor side)
  // Triggers for: accepted, recovery_initiated, recovery_approved (any state where key hasn't been shared yet)
  const confirmedRef = useRef(new Set<string>());
  useEffect(() => {
    if (!token || !masterKeyHex) return;
    const needsConfirm = granted.filter(ea =>
      ['accepted', 'recovery_initiated', 'recovery_approved'].includes(ea.status) &&
      !confirmedRef.current.has(ea.id)
    );
    for (const ea of needsConfirm) {
      confirmedRef.current.add(ea.id);
      window.api.emergencyAccess.autoConfirm(token, ea.id, masterKeyHex)
        .then((res) => {
          const r = res as Record<string, unknown>;
          if (r?.error && !(r.error as string).includes('already confirmed')) {
            setError(`Key exchange failed: ${r.error}`);
          } else {
            loadData();
          }
        })
        .catch((err) => setError(`Key exchange error: ${err}`));
    }
  }, [granted, token, masterKeyHex, loadData]);

  const handleInvite = async () => {
    if (!token || !inviteEmail.trim()) return;
    setInviteError('');
    setActionLoading('invite');
    try {
      const res = await window.api.emergencyAccess.invite(token, {
        email: inviteEmail.trim(),
        access_type: inviteAccessType,
        wait_time_days: inviteWaitDays,
      }) as Record<string, unknown>;
      if (res.error) throw new Error(res.error as string);
      setShowInviteForm(false);
      setInviteEmail('');
      setInviteAccessType('view');
      setInviteWaitDays(7);
      await loadData();
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : 'Failed to invite');
    } finally {
      setActionLoading('');
    }
  };

  const handleAction = async (id: string, action: string) => {
    if (!token) return;
    setActionLoading(id);
    try {
      let res: Record<string, unknown>;
      switch (action) {
        case 'accept':
          res = await window.api.emergencyAccess.accept(token, id) as Record<string, unknown>;
          break;
        case 'initiate':
          res = await window.api.emergencyAccess.initiate(token, id) as Record<string, unknown>;
          break;
        case 'approve':
          res = await window.api.emergencyAccess.approve(token, id) as Record<string, unknown>;
          break;
        case 'reject':
          res = await window.api.emergencyAccess.reject(token, id) as Record<string, unknown>;
          break;
        case 'delete':
          res = await window.api.emergencyAccess.delete(token, id) as Record<string, unknown>;
          break;
        default:
          return;
      }
      if (res.error) throw new Error(res.error as string);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${action}`);
    } finally {
      setActionLoading('');
    }
  };

  // Expanded entries in vault viewer and revealed password fields
  const [expandedEntries, setExpandedEntries] = useState<Set<string>>(new Set());
  const [revealedFields, setRevealedFields] = useState<Set<string>>(new Set());

  const toggleExpand = (id: string) => {
    setExpandedEntries(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleReveal = (key: string) => {
    setRevealedFields(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  const SENSITIVE_FIELDS = new Set(['password', 'cardNumber', 'cvv', 'securityCode', 'pin', 'totp', 'notes']);

  return (
    <section>
      <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Emergency Access</h2>

      {error && (
        <div className="mb-3 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-md text-sm text-red-400">
          {error}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-surface-500">Loading…</div>
      ) : (
        <div className="space-y-4">
          {/* Trusted Contacts — people who can access MY vault */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-surface-300">Trusted Contacts</h3>
              <button
                onClick={() => setShowInviteForm(!showInviteForm)}
                className="text-xs text-accent-400 hover:text-accent-300 transition-colors"
              >
                {showInviteForm ? 'Cancel' : '+ Add Contact'}
              </button>
            </div>
            <p className="text-xs text-surface-500 mb-2">
              People who can request emergency access to your vault after a waiting period.
            </p>

            {showInviteForm && (
              <div className="mb-3 p-3 bg-surface-800 rounded-lg space-y-3">
                <div>
                  <label className="block text-xs text-surface-400 mb-1">Email</label>
                  <input
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    placeholder="trusted@example.com"
                    className="w-full px-3 py-2 bg-surface-900 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
                  />
                </div>
                <div className="flex gap-3">
                  <div className="flex-1">
                    <label className="block text-xs text-surface-400 mb-1">Access Type</label>
                    <select
                      value={inviteAccessType}
                      onChange={(e) => setInviteAccessType(e.target.value as 'view' | 'takeover')}
                      className="w-full px-3 py-2 bg-surface-900 border border-surface-600 rounded-md text-surface-100 text-sm focus:outline-none focus:ring-1 focus:ring-accent-500"
                    >
                      <option value="view">View Only</option>
                      <option value="takeover">Takeover</option>
                    </select>
                  </div>
                  <div className="flex-1">
                    <label className="block text-xs text-surface-400 mb-1">Wait Period</label>
                    <div className="flex items-center gap-2">
                      <input
                        type="range"
                        min={1}
                        max={30}
                        value={inviteWaitDays}
                        onChange={(e) => setInviteWaitDays(Number(e.target.value))}
                        className="flex-1"
                      />
                      <span className="text-sm text-surface-300 w-14 text-right">{inviteWaitDays}d</span>
                    </div>
                  </div>
                </div>
                {inviteAccessType === 'takeover' && (
                  <p className="text-xs text-yellow-400">
                    Takeover allows the contact to reset your master password and take control of your account.
                  </p>
                )}
                {inviteError && <p className="text-xs text-red-400">{inviteError}</p>}
                <button
                  onClick={handleInvite}
                  disabled={!inviteEmail.trim() || actionLoading === 'invite'}
                  className="px-4 py-2 bg-accent-600 hover:bg-accent-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
                >
                  {actionLoading === 'invite' ? 'Inviting…' : 'Send Invitation'}
                </button>
              </div>
            )}

            {granted.length === 0 ? (
              <p className="text-xs text-surface-600 italic">No trusted contacts configured.</p>
            ) : (
              <div className="space-y-2">
                {granted.map((ea) => (
                  <div key={ea.id} className="px-3 py-2 bg-surface-800 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        <span className="text-sm text-surface-200 truncate">{ea.grantee_email}</span>
                        <StatusBadge status={ea.status} />
                      </div>
                    </div>
                    <div className="flex items-center justify-between mt-1.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-surface-500">
                          {ea.access_type === 'takeover' ? 'Takeover' : 'View only'} · {ea.wait_time_days}d wait
                        </span>
                        {ea.status === 'recovery_initiated' && ea.recovery_initiated_at && (
                          <Countdown initiatedAt={ea.recovery_initiated_at} waitDays={ea.wait_time_days} />
                        )}
                      </div>
                      <div className="flex gap-2">
                        {ea.status === 'recovery_initiated' && (
                          <>
                            <button
                              onClick={() => handleAction(ea.id, 'approve')}
                              disabled={actionLoading === ea.id}
                              className="text-xs px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded disabled:opacity-50 transition-colors"
                            >
                              Approve
                            </button>
                            <button
                              onClick={() => handleAction(ea.id, 'reject')}
                              disabled={actionLoading === ea.id}
                              className="text-xs px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded disabled:opacity-50 transition-colors"
                            >
                              Reject
                            </button>
                          </>
                        )}
                        <button
                          onClick={() => handleAction(ea.id, 'delete')}
                          disabled={actionLoading === ea.id}
                          className="text-xs px-2 py-1 text-red-400 hover:text-red-300 transition-colors"
                          title="Revoke access"
                        >
                          Revoke
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* People Who Trust Me — vaults I can access */}
          <div>
            <h3 className="text-sm font-medium text-surface-300 mb-2">People Who Trust Me</h3>
            <p className="text-xs text-surface-500 mb-2">
              Users who have granted you emergency access to their vault.
            </p>

            {trusted.length === 0 ? (
              <p className="text-xs text-surface-600 italic">No one has granted you emergency access.</p>
            ) : (
              <div className="space-y-2">
                {trusted.map((ea) => (
                  <div key={ea.id} className="flex items-center justify-between px-3 py-2 bg-surface-800 rounded-lg">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-surface-200 truncate">{ea.grantor_email || ea.grantee_email}</span>
                        <StatusBadge status={ea.status} />
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-xs text-surface-500">
                          {ea.access_type === 'takeover' ? 'Takeover' : 'View only'} · {ea.wait_time_days}d wait
                        </span>
                        {ea.status === 'recovery_initiated' && ea.recovery_initiated_at && (
                          <Countdown initiatedAt={ea.recovery_initiated_at} waitDays={ea.wait_time_days} />
                        )}
                      </div>
                    </div>
                    <div className="flex gap-1 ml-2">
                      {ea.status === 'invited' && (
                        <button
                          onClick={() => handleAction(ea.id, 'accept')}
                          disabled={actionLoading === ea.id}
                          className="text-xs px-2 py-1 bg-accent-600 hover:bg-accent-700 text-white rounded disabled:opacity-50 transition-colors"
                        >
                          Accept
                        </button>
                      )}
                      {(ea.status === 'accepted' || ea.status === 'recovery_rejected') && (
                        <button
                          onClick={() => handleAction(ea.id, 'initiate')}
                          disabled={actionLoading === ea.id}
                          className="text-xs px-2 py-1 bg-yellow-600 hover:bg-yellow-700 text-white rounded disabled:opacity-50 transition-colors"
                        >
                          Request Access
                        </button>
                      )}
                      {(ea.status === 'recovery_approved' ||
                        (ea.status === 'recovery_initiated' && ea.recovery_initiated_at &&
                          new Date(ea.recovery_initiated_at).getTime() + ea.wait_time_days * 86400000 <= Date.now())) && (
                        <>
                          <button
                            onClick={async () => {
                              setActionLoading(ea.id);
                              try {
                                const res = await window.api.emergencyAccess.decryptVault(token!, ea.id, masterKeyHex!);
                                const data = res as { entries?: Array<Record<string, unknown>>; decrypted?: boolean; error?: string };
                                if (data.error) {
                                  setError(data.error);
                                } else {
                                  const entries = (data.entries || []).map(e => ({
                                    ...e,
                                    decryptedData: e.data as Record<string, unknown> | undefined,
                                  } as VaultEntry & { decryptedData?: Record<string, unknown> }));
                                  setViewingVault({ email: ea.grantor_email || ea.grantee_email, entries });
                                }
                              } catch (err) {
                                setError(err instanceof Error ? err.message : 'Failed to load vault');
                              } finally {
                                setActionLoading('');
                              }
                            }}
                            disabled={actionLoading === ea.id}
                            className="text-xs px-2 py-1 bg-emerald-600 hover:bg-emerald-700 text-white rounded disabled:opacity-50 transition-colors"
                          >
                            View Vault
                          </button>
                          {ea.access_type === 'takeover' && (
                            <button
                              onClick={() => {
                                setTakeoverTarget({ id: ea.id, email: ea.grantor_email || ea.grantee_email });
                                setTakeoverPassword('');
                                setTakeoverConfirm('');
                                setTakeoverError('');
                              }}
                              disabled={actionLoading === ea.id}
                              className="text-xs px-2 py-1 bg-red-600 hover:bg-red-700 text-white rounded disabled:opacity-50 transition-colors"
                            >
                              Takeover
                            </button>
                          )}
                        </>
                      )}
                      <button
                        onClick={() => handleAction(ea.id, 'delete')}
                        disabled={actionLoading === ea.id}
                        className="text-xs px-2 py-1 text-red-400 hover:text-red-300 transition-colors"
                        title="Decline"
                      >
                        Decline
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Emergency Vault Viewer Modal */}
      {viewingVault && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-surface-800 rounded-xl shadow-xl w-full max-w-2xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-surface-700">
              <h3 className="text-lg font-semibold text-surface-100">
                Emergency Vault — {viewingVault.email}
              </h3>
              <button
                onClick={() => setViewingVault(null)}
                className="text-surface-400 hover:text-surface-200 text-xl leading-none"
              >
                ×
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              {(() => {
                const decCount = viewingVault.entries.filter(e => e.decryptedData).length;
                const total = viewingVault.entries.length;
                return decCount > 0 ? (
                  <p className="text-xs text-emerald-400 mb-3">
                    {decCount} of {total} entries decrypted successfully.
                  </p>
                ) : (
                  <p className="text-xs text-surface-500 mb-3">
                    {total} encrypted entries. Key exchange not completed — grantor must log in to share vault key.
                  </p>
                );
              })()}
              {viewingVault.entries.length === 0 ? (
                <p className="text-sm text-surface-500 text-center py-8">No vault entries found.</p>
              ) : (
                <div className="space-y-2">
                  {viewingVault.entries.map((entry, idx) => {
                    const typeLabels: Record<string, { label: string; icon: string }> = {
                      login: { label: 'Login', icon: '🔑' },
                      note: { label: 'Secure Note', icon: '📝' },
                      card: { label: 'Card', icon: '💳' },
                      identity: { label: 'Identity', icon: '👤' },
                      secure_note: { label: 'Secure Note', icon: '📝' },
                    };
                    const t = typeLabels[entry.entry_type] || { label: entry.entry_type, icon: '📄' };
                    const dec = entry.decryptedData as Record<string, unknown> | undefined;
                    return (
                      <div key={entry.id || idx} className="px-4 py-3 bg-surface-900 rounded-lg">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-base">{t.icon}</span>
                          <span className="text-sm font-medium text-surface-200">
                            {(dec?.name as string) || `${t.label} #${idx + 1}`}
                          </span>
                          {!dec && <span className="text-xs text-surface-600">🔒 Encrypted</span>}
                        </div>
                        {dec && (
                          <div className="pl-7 space-y-1.5">
                            {Object.entries(dec).map(([key, value]) => {
                              if (!value || key === 'name' || key === 'uris' || key === 'passwordHistory' || key === 'reprompt') return null;
                              const isSensitive = SENSITIVE_FIELDS.has(key);
                              const revealKey = `${entry.id}:${key}`;
                              const revealed = revealedFields.has(revealKey);
                              const strVal = typeof value === 'object' ? JSON.stringify(value) : String(value);
                              const displayValue = isSensitive && !revealed
                                ? '•'.repeat(Math.min(strVal.length, 20))
                                : strVal;
                              return (
                                <div key={key} className="flex items-center text-sm gap-2">
                                  <span className="text-surface-500 text-xs w-20 shrink-0">{key}</span>
                                  <span className={`text-xs flex-1 truncate ${isSensitive && !revealed ? 'text-surface-500 font-mono tracking-wider' : 'text-surface-300'}`}>
                                    {displayValue}
                                  </span>
                                  {isSensitive && (
                                    <button
                                      onClick={() => toggleReveal(revealKey)}
                                      className="text-xs text-surface-500 hover:text-surface-300 transition-colors shrink-0"
                                    >
                                      {revealed ? 'Hide' : 'Show'}
                                    </button>
                                  )}
                                </div>
                              );
                            })}
                            {Array.isArray(dec.uris) && (dec.uris as Array<{ uri: string }>).map((u, i) => (
                              <div key={`uri-${i}`} className="flex items-center text-sm gap-2">
                                <span className="text-surface-500 text-xs w-20 shrink-0">uri</span>
                                <span className="text-xs text-accent-400 truncate flex-1">{u.uri}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
            <div className="px-5 py-3 border-t border-surface-700 text-right">
              <button
                onClick={() => setViewingVault(null)}
                className="px-4 py-2 bg-surface-700 hover:bg-surface-600 text-surface-200 text-sm rounded-md transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Takeover Confirmation Modal */}
      {takeoverTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-surface-800 rounded-xl shadow-xl w-full max-w-md p-6">
            <h3 className="text-lg font-semibold text-surface-100 mb-2">Account Takeover</h3>
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
              <p className="text-sm text-red-400 font-medium mb-1">⚠️ This action is irreversible</p>
              <p className="text-xs text-red-300/80">
                You are about to take over <strong>{takeoverTarget.email}</strong>&apos;s account.
                Their master password will be reset and all vault entries re-encrypted with your new password.
                The original owner will be locked out.
              </p>
            </div>
            <div className="space-y-3 mb-4">
              <div>
                <label className="block text-xs text-surface-400 mb-1">New Master Password for their account</label>
                <input
                  type="password"
                  value={takeoverPassword}
                  onChange={(e) => setTakeoverPassword(e.target.value)}
                  placeholder="New master password"
                  className="w-full px-3 py-2 bg-surface-900 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-red-500 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-surface-400 mb-1">Confirm Password</label>
                <input
                  type="password"
                  value={takeoverConfirm}
                  onChange={(e) => setTakeoverConfirm(e.target.value)}
                  placeholder="Confirm password"
                  className="w-full px-3 py-2 bg-surface-900 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-red-500 text-sm"
                />
              </div>
            </div>
            {takeoverError && <p className="text-xs text-red-400 mb-3">{takeoverError}</p>}
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setTakeoverTarget(null)}
                disabled={takeoverLoading}
                className="px-4 py-2 bg-surface-700 hover:bg-surface-600 text-surface-200 text-sm rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  if (!takeoverPassword || takeoverPassword.length < 8) {
                    setTakeoverError('Password must be at least 8 characters');
                    return;
                  }
                  if (takeoverPassword !== takeoverConfirm) {
                    setTakeoverError('Passwords do not match');
                    return;
                  }
                  setTakeoverLoading(true);
                  setTakeoverError('');
                  try {
                    const res = await window.api.emergencyAccess.performTakeover(
                      token!, takeoverTarget.id, masterKeyHex!, takeoverTarget.email, takeoverPassword
                    );
                    const data = res as Record<string, unknown>;
                    if (data.error) {
                      setTakeoverError(data.error as string);
                    } else {
                      setTakeoverTarget(null);
                      await loadData();
                    }
                  } catch (err) {
                    setTakeoverError(err instanceof Error ? err.message : 'Takeover failed');
                  } finally {
                    setTakeoverLoading(false);
                  }
                }}
                disabled={takeoverLoading || !takeoverPassword || !takeoverConfirm}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
              >
                {takeoverLoading ? 'Taking over…' : 'Confirm Takeover'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
