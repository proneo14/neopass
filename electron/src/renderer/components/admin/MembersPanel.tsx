import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';
import type { OrgMember, Invitation } from '../../types/admin';

interface Props {
  orgId: string;
}

export function MembersPanel({ orgId }: Props) {
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [inviteSuccess, setInviteSuccess] = useState('');
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('member');
  const [inviting, setInviting] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);

  const { token, userId } = useAuthStore();

  const loadData = useCallback(async () => {
    if (!token || !orgId) return;
    setLoading(true);
    setError('');
    try {
      const [membersResult, invResult] = await Promise.all([
        window.api.admin.listMembers(token, orgId),
        window.api.admin.listInvitations(token, orgId),
      ]);

      const mr = membersResult as OrgMember[] | { error: string };
      if ('error' in mr) {
        setError(mr.error);
      } else {
        setMembers(mr);
      }

      const ir = invResult as Invitation[] | { error: string };
      if (!('error' in ir)) {
        setInvitations(ir);
      }
    } catch {
      setError('Failed to load members');
    } finally {
      setLoading(false);
    }
  }, [token, orgId]);

  useEffect(() => { loadData(); }, [loadData]);

  const handleInvite = async () => {
    if (!token || !inviteEmail.trim()) return;
    setInviting(true);
    setError('');
    setInviteSuccess('');
    try {
      const result = await window.api.admin.inviteUser(token, orgId, inviteEmail.trim(), inviteRole) as { error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setInviteSuccess(`Invitation sent to ${inviteEmail.trim()}. They must register with this email, then accept from Settings → Organization.`);
        setShowInvite(false);
        setInviteEmail('');
        setInviteRole('member');
        await loadData();
      }
    } catch {
      setError('Failed to invite user');
    } finally {
      setInviting(false);
    }
  };

  const handleRemove = async (targetUserId: string) => {
    if (!token) return;
    setError('');
    try {
      const result = await window.api.admin.removeMember(token, orgId, targetUserId) as { error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setConfirmRemove(null);
        await loadData();
      }
    } catch {
      setError('Failed to remove member');
    }
  };

  const pendingInvitations = invitations.filter((inv) => !inv.accepted);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-6 w-6 border-2 border-accent-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-sm px-4 py-2 rounded-lg">
          {error}
        </div>
      )}
      {inviteSuccess && (
        <div className="bg-green-500/10 border border-green-500/30 text-green-400 text-sm px-4 py-2 rounded-lg">
          {inviteSuccess}
        </div>
      )}

      {/* Invite Button */}
      <div className="flex items-center justify-between">
        <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium">
          Organization Members ({members.length})
        </h2>
        <button
          onClick={() => setShowInvite(true)}
          className="bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
        >
          Invite User
        </button>
      </div>

      {/* Invite Form */}
      {showInvite && (
        <div className="bg-surface-800 rounded-xl p-4 space-y-3">
          <h3 className="text-sm font-medium text-surface-200">Invite New Member</h3>
          <p className="text-xs text-surface-500">
            The invited user must first register an account with this email address, then accept the invitation from their <span className="text-surface-300">Settings → Organization</span> page.
          </p>
          <div className="flex gap-3">
            <input
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleInvite()}
              placeholder="user@example.com"
              className="flex-1 bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
              autoFocus
            />
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value)}
              className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleInvite}
              disabled={inviting || !inviteEmail.trim()}
              className="bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
            >
              {inviting ? 'Sending...' : 'Send Invite'}
            </button>
            <button
              onClick={() => { setShowInvite(false); setInviteEmail(''); }}
              className="text-sm text-surface-400 hover:text-surface-200 px-3 py-1.5 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Members + Pending Invitations (unified list) */}
      <div className="bg-surface-800 rounded-xl divide-y divide-surface-700">
        {members.length === 0 && pendingInvitations.length === 0 ? (
          <div className="p-8 text-center text-surface-500 text-sm">
            No members yet. Invite someone to get started.
          </div>
        ) : (
          <>
            {members.map((member) => (
              <div key={member.user_id} className="flex items-center justify-between px-4 py-3 hover:bg-surface-700/50 transition-colors">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-accent-600/20 flex items-center justify-center text-accent-400 text-sm font-medium">
                    {(member.email || member.user_id).charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-sm text-surface-100">
                      {member.email || member.user_id}
                      {member.user_id === userId && (
                        <span className="ml-2 text-xs text-surface-500">(you)</span>
                      )}
                    </div>
                    <div className="text-xs text-surface-500">
                      Joined {new Date(member.joined_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              <div className="flex items-center gap-3">
                <span className={`text-xs px-2 py-0.5 rounded-full ${
                  member.role === 'admin'
                    ? 'bg-amber-500/10 text-amber-400'
                    : 'bg-surface-600/50 text-surface-400'
                }`}>
                  {member.role}
                </span>
                {member.user_id !== userId && (
                  confirmRemove === member.user_id ? (
                    <div className="flex gap-1">
                      <button
                        onClick={() => handleRemove(member.user_id)}
                        className="text-xs text-red-400 hover:text-red-300 px-2 py-1 transition-colors"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={() => setConfirmRemove(null)}
                        className="text-xs text-surface-500 hover:text-surface-300 px-2 py-1 transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setConfirmRemove(member.user_id)}
                      className="text-xs text-surface-500 hover:text-red-400 transition-colors"
                    >
                      Remove
                    </button>
                  )
                )}
              </div>
            </div>
            ))}
            {pendingInvitations.map((inv) => (
              <div key={inv.id} className="flex items-center justify-between px-4 py-3 opacity-70">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-surface-600/50 flex items-center justify-center text-surface-400 text-sm font-medium">
                    {inv.email.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-sm text-surface-300">{inv.email}</div>
                    <div className="text-xs text-surface-500">
                      Invited {new Date(inv.created_at).toLocaleDateString()} · {inv.role}
                    </div>
                  </div>
                </div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400">
                  pending invite
                </span>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
