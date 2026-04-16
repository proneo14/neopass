import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';
import type { OrgMember } from '../../types/admin';

interface Props {
  orgId: string;
}

interface ShareRecord {
  shareId: string;
  toUser: string;
  expiresIn: string;
  status: 'pending' | 'shared';
  createdAt: string;
}

const EXPIRY_OPTIONS = [
  { value: 15, label: '15 minutes' },
  { value: 60, label: '1 hour' },
  { value: 1440, label: '24 hours' },
];

export function TwoFactorSharePanel({ orgId }: Props) {
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [expiresInMin, setExpiresInMin] = useState(60);
  const [loading, setLoading] = useState(true);
  const [sharing, setSharing] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [shares, setShares] = useState<ShareRecord[]>([]);

  const { token } = useAuthStore();

  const loadMembers = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const result = await window.api.admin.listMembers(token, orgId) as OrgMember[] | { error: string };
      if (!('error' in result)) {
        setMembers(result);
      }
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, [token, orgId]);

  useEffect(() => { loadMembers(); }, [loadMembers]);

  const handleShare = async () => {
    if (!token || !selectedUserId || !totpSecret.trim()) return;
    setSharing(true);
    setError('');
    setSuccess('');
    try {
      const port = await window.api.getSidecarPort();
      const backendUrl = port ? `http://127.0.0.1:${port}` : '';
      // Use direct fetch since we don't have an IPC for this endpoint
      const res = await fetch(`${backendUrl || ''}/api/v1/auth/2fa/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          to_user_id: selectedUserId,
          totp_secret: totpSecret.trim(),
          expires_in_minutes: expiresInMin,
        }),
      });
      const result = await res.json() as { share_id?: string; error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        const member = members.find(m => m.user_id === selectedUserId);
        setShares(prev => [{
          shareId: result.share_id || '',
          toUser: member?.email || selectedUserId,
          expiresIn: EXPIRY_OPTIONS.find(o => o.value === expiresInMin)?.label || `${expiresInMin}min`,
          status: 'shared',
          createdAt: new Date().toISOString(),
        }, ...prev]);
        setSuccess(`2FA secret shared with ${member?.email || selectedUserId}`);
        setTotpSecret('');
        setSelectedUserId('');
      }
    } catch {
      setError('Failed to share 2FA secret');
    } finally {
      setSharing(false);
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
    <div className="space-y-6">
      <div>
        <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium mb-1">Share 2FA Secret</h2>
        <p className="text-xs text-surface-500">
          Securely share a TOTP secret with a team member. The secret is encrypted with the recipient's public key.
        </p>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-sm px-4 py-2 rounded-lg">
          {error}
        </div>
      )}
      {success && (
        <div className="bg-green-500/10 border border-green-500/30 text-green-400 text-sm px-4 py-2 rounded-lg">
          {success}
        </div>
      )}

      {/* Share Form */}
      <div className="bg-surface-800 rounded-xl p-5 space-y-4">
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-surface-400 mb-1">Recipient</label>
            <select
              value={selectedUserId}
              onChange={(e) => setSelectedUserId(e.target.value)}
              className="w-full bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
            >
              <option value="">Select a member...</option>
              {members.map((m) => (
                <option key={m.user_id} value={m.user_id}>
                  {m.email || m.user_id} ({m.role})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs text-surface-400 mb-1">TOTP Secret or URI</label>
            <input
              type="text"
              value={totpSecret}
              onChange={(e) => setTotpSecret(e.target.value)}
              placeholder="otpauth://totp/... or base32 secret"
              className="w-full bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs text-surface-400 mb-1">Expiration</label>
            <div className="flex gap-2">
              {EXPIRY_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setExpiresInMin(opt.value)}
                  className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                    expiresInMin === opt.value
                      ? 'border-accent-500 bg-accent-600/10 text-accent-400'
                      : 'border-surface-600 text-surface-400 hover:border-surface-500'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <button
          onClick={handleShare}
          disabled={sharing || !selectedUserId || !totpSecret.trim()}
          className="w-full bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm rounded-lg px-4 py-2.5 transition-colors"
        >
          {sharing ? 'Sharing...' : 'Share Securely'}
        </button>
      </div>

      {/* Shared History */}
      {shares.length > 0 && (
        <div>
          <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium mb-3">Recent Shares</h2>
          <div className="bg-surface-800 rounded-xl divide-y divide-surface-700">
            {shares.map((share) => (
              <div key={share.shareId} className="flex items-center justify-between px-4 py-3">
                <div>
                  <div className="text-sm text-surface-200">{share.toUser}</div>
                  <div className="text-xs text-surface-500">
                    Expires in {share.expiresIn} · {new Date(share.createdAt).toLocaleTimeString()}
                  </div>
                </div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 text-green-400">
                  {share.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
