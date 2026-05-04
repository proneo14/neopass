import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';
import type { Group, GroupMember, OrgMember } from '../../types/admin';

interface Props {
  orgId: string;
}

export function GroupsPanel({ orgId }: Props) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [editingName, setEditingName] = useState<{ id: string; name: string } | null>(null);
  // Expanded group for member management
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const [groupMembers, setGroupMembers] = useState<GroupMember[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  const [addMemberUserId, setAddMemberUserId] = useState('');

  const { token } = useAuthStore();

  const loadGroups = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const [groupsResult, membersResult] = await Promise.all([
        window.api.admin.listGroups(token, orgId),
        window.api.admin.listMembers(token, orgId),
      ]);
      const gr = groupsResult as Group[] | { error: string };
      if ('error' in gr) { setError(gr.error); } else { setGroups(gr); }
      const mr = membersResult as OrgMember[] | { error: string };
      if (!('error' in mr)) { setMembers(mr); }
    } catch {
      setError('Failed to load groups');
    } finally {
      setLoading(false);
    }
  }, [token, orgId]);

  useEffect(() => { loadGroups(); }, [loadGroups]);

  const loadGroupMembers = useCallback(async (groupId: string) => {
    if (!token) return;
    setLoadingMembers(true);
    try {
      const result = await window.api.admin.listGroupMembers(token, orgId, groupId) as GroupMember[] | { error: string };
      if ('error' in result) { setError(result.error); } else { setGroupMembers(result); }
    } catch {
      setError('Failed to load group members');
    } finally {
      setLoadingMembers(false);
    }
  }, [token, orgId]);

  const toggleExpand = (groupId: string) => {
    if (expandedGroup === groupId) {
      setExpandedGroup(null);
      setGroupMembers([]);
    } else {
      setExpandedGroup(groupId);
      loadGroupMembers(groupId);
    }
  };

  const handleCreate = async () => {
    if (!token || !newGroupName.trim()) return;
    setSaving(true);
    setError('');
    try {
      const result = await window.api.admin.createGroup(token, orgId, newGroupName.trim()) as { error?: string };
      if (result?.error) { setError(result.error); return; }
      setShowCreate(false);
      setNewGroupName('');
      await loadGroups();
    } catch {
      setError('Failed to create group');
    } finally {
      setSaving(false);
    }
  };

  const handleRename = async () => {
    if (!token || !editingName) return;
    setError('');
    try {
      const result = await window.api.admin.updateGroup(token, orgId, editingName.id, editingName.name.trim()) as { error?: string };
      if (result?.error) { setError(result.error); return; }
      setEditingName(null);
      await loadGroups();
    } catch {
      setError('Failed to rename group');
    }
  };

  const handleDelete = async (groupId: string) => {
    if (!token) return;
    setError('');
    try {
      const result = await window.api.admin.deleteGroup(token, orgId, groupId) as { error?: string };
      if (result?.error) { setError(result.error); return; }
      setConfirmDelete(null);
      if (expandedGroup === groupId) { setExpandedGroup(null); setGroupMembers([]); }
      await loadGroups();
    } catch {
      setError('Failed to delete group');
    }
  };

  const handleAddMember = async (groupId: string) => {
    if (!token || !addMemberUserId) return;
    setError('');
    try {
      const result = await window.api.admin.addGroupMember(token, orgId, groupId, addMemberUserId) as { error?: string };
      if (result?.error) { setError(result.error); return; }
      setAddMemberUserId('');
      await loadGroupMembers(groupId);
    } catch {
      setError('Failed to add member');
    }
  };

  const handleRemoveMember = async (groupId: string, userId: string) => {
    if (!token) return;
    setError('');
    try {
      const result = await window.api.admin.removeGroupMember(token, orgId, groupId, userId) as { error?: string };
      if (result?.error) { setError(result.error); return; }
      await loadGroupMembers(groupId);
    } catch {
      setError('Failed to remove member');
    }
  };

  // Members that are NOT in the current group
  const availableMembers = members.filter(
    (m) => !groupMembers.some((gm) => gm.user_id === m.user_id)
  );

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

      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium">
          Groups ({groups.length})
        </h2>
        <div className="flex gap-2">
          <button
            onClick={() => loadGroups()}
            className="text-surface-400 hover:text-surface-200 text-sm px-2 py-1.5 transition-colors"
            title="Refresh"
          >
            ↻
          </button>
          {!showCreate && (
            <button
              onClick={() => setShowCreate(true)}
              className="bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
            >
              Create Group
            </button>
          )}
        </div>
      </div>

      {/* Create Form */}
      {showCreate && (
        <div className="bg-surface-800 rounded-xl p-4 space-y-3">
          <h3 className="text-sm font-medium text-surface-200">Create New Group</h3>
          <p className="text-xs text-surface-500">
            Groups let you assign collections and permissions to multiple users at once. Groups also sync with SCIM directory providers.
          </p>
          <div className="flex gap-3">
            <input
              type="text"
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
              placeholder="Group name"
              className="flex-1 bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
              autoFocus
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleCreate}
              disabled={saving || !newGroupName.trim()}
              className="bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
            >
              {saving ? 'Creating...' : 'Create Group'}
            </button>
            <button
              onClick={() => { setShowCreate(false); setNewGroupName(''); }}
              className="text-sm text-surface-400 hover:text-surface-200 px-3 py-1.5 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Groups List */}
      <div className="bg-surface-800 rounded-xl divide-y divide-surface-700">
        {groups.length === 0 ? (
          <div className="p-8 text-center text-surface-500 text-sm">
            No groups yet. Create a group to manage collection access for multiple users.
          </div>
        ) : (
          groups.map((group) => (
            <div key={group.id}>
              <div className="px-4 py-3 hover:bg-surface-700/50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 cursor-pointer" onClick={() => toggleExpand(group.id)}>
                    <div className="w-8 h-8 rounded-full bg-accent-600/20 flex items-center justify-center text-accent-400 text-sm font-medium">
                      {group.name.charAt(0).toUpperCase()}
                    </div>
                    <div>
                      {editingName?.id === group.id ? (
                        <div className="flex items-center gap-2">
                          <input
                            type="text"
                            value={editingName.name}
                            onChange={(e) => setEditingName({ ...editingName, name: e.target.value })}
                            onKeyDown={(e) => { if (e.key === 'Enter') handleRename(); if (e.key === 'Escape') setEditingName(null); }}
                            className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded px-2 py-0.5 focus:outline-none focus:border-accent-500 w-40"
                            autoFocus
                            onClick={(e) => e.stopPropagation()}
                          />
                          <button onClick={(e) => { e.stopPropagation(); handleRename(); }} className="text-xs text-accent-400 hover:text-accent-300">Save</button>
                          <button onClick={(e) => { e.stopPropagation(); setEditingName(null); }} className="text-xs text-surface-500">Cancel</button>
                        </div>
                      ) : (
                        <div className="text-sm text-surface-100">{group.name}</div>
                      )}
                      <div className="text-xs text-surface-500">
                        Created {new Date(group.created_at).toLocaleDateString()}
                        {group.external_id && <span className="ml-2 text-accent-400/60">SCIM</span>}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => toggleExpand(group.id)}
                      className="text-xs text-surface-400 hover:text-surface-200 px-2 py-1 transition-colors"
                    >
                      {expandedGroup === group.id ? '▼' : '▶'} Members
                    </button>
                    <button
                      onClick={() => setEditingName({ id: group.id, name: group.name })}
                      className="text-xs text-surface-400 hover:text-accent-400 transition-colors px-2 py-1"
                    >
                      Rename
                    </button>
                    {confirmDelete === group.id ? (
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleDelete(group.id)}
                          className="text-xs text-red-400 hover:text-red-300 px-2 py-1 transition-colors"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setConfirmDelete(null)}
                          className="text-xs text-surface-500 hover:text-surface-300 px-2 py-1 transition-colors"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setConfirmDelete(group.id)}
                        className="text-xs text-surface-500 hover:text-red-400 transition-colors px-2 py-1"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Expanded: Group Members */}
              {expandedGroup === group.id && (
                <div className="px-4 pb-4 bg-surface-900/30">
                  {loadingMembers ? (
                    <div className="flex justify-center py-4">
                      <div className="animate-spin rounded-full h-4 w-4 border-2 border-accent-500 border-t-transparent" />
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {/* Add member */}
                      <div className="flex gap-2 items-center py-2">
                        <select
                          value={addMemberUserId}
                          onChange={(e) => setAddMemberUserId(e.target.value)}
                          className="flex-1 bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-1.5 focus:outline-none focus:border-accent-500"
                        >
                          <option value="">Add a member...</option>
                          {availableMembers.map((m) => (
                            <option key={m.user_id} value={m.user_id}>
                              {m.email || m.user_id}
                            </option>
                          ))}
                        </select>
                        <button
                          onClick={() => handleAddMember(group.id)}
                          disabled={!addMemberUserId}
                          className="bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-xs rounded-lg px-3 py-1.5 transition-colors"
                        >
                          Add
                        </button>
                      </div>

                      {/* Current members */}
                      {groupMembers.length === 0 ? (
                        <div className="text-xs text-surface-500 py-2">No members in this group.</div>
                      ) : (
                        groupMembers.map((gm) => (
                          <div key={gm.user_id} className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-surface-800/50">
                            <div className="flex items-center gap-2">
                              <div className="w-6 h-6 rounded-full bg-surface-600/50 flex items-center justify-center text-surface-300 text-xs">
                                {(gm.email || gm.user_id).charAt(0).toUpperCase()}
                              </div>
                              <span className="text-sm text-surface-200">{gm.email || gm.user_id}</span>
                            </div>
                            <button
                              onClick={() => handleRemoveMember(group.id, gm.user_id)}
                              className="text-xs text-surface-500 hover:text-red-400 transition-colors"
                            >
                              Remove
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
