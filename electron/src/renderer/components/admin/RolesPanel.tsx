import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';
import type { Role } from '../../types/admin';
import { ALL_PERMISSIONS } from '../../types/admin';

interface Props {
  orgId: string;
}

const EMPTY_ROLE = { name: '', description: '', permissions: [] as string[] };

export function RolesPanel({ orgId }: Props) {
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [formData, setFormData] = useState(EMPTY_ROLE);
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const { token } = useAuthStore();

  const loadRoles = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const result = await window.api.admin.listRoles(token, orgId) as Role[] | { error: string };
      if ('error' in result) {
        setError(result.error);
      } else {
        setRoles(result);
      }
    } catch {
      setError('Failed to load roles');
    } finally {
      setLoading(false);
    }
  }, [token, orgId]);

  useEffect(() => { loadRoles(); }, [loadRoles]);

  const togglePermission = (key: string) => {
    setFormData((prev) => {
      if (key === '*') {
        // Toggle superadmin: if already has *, remove it; otherwise set to just *
        return {
          ...prev,
          permissions: prev.permissions.includes('*') ? [] : ['*'],
        };
      }
      // Don't allow toggling individual permissions when superadmin is active
      if (prev.permissions.includes('*')) return prev;
      return {
        ...prev,
        permissions: prev.permissions.includes(key)
          ? prev.permissions.filter((p) => p !== key)
          : [...prev.permissions, key],
      };
    });
  };

  const handleSave = async () => {
    if (!token || !formData.name.trim()) return;
    if (formData.permissions.length === 0) {
      setError('At least one permission is required');
      return;
    }
    // Warn if removing * from built-in Admin
    if (editingRole?.is_builtin && editingRole.name === 'Admin' && !formData.permissions.includes('*')) {
      setError('The built-in Admin role must keep the * (superadmin) permission');
      return;
    }
    setSaving(true);
    setError('');
    try {
      if (editingRole) {
        const result = await window.api.admin.updateRole(token, orgId, editingRole.id, formData) as { error?: string };
        if (result?.error) { setError(result.error); return; }
      } else {
        const result = await window.api.admin.createRole(token, orgId, formData) as { error?: string };
        if (result?.error) { setError(result.error); return; }
      }
      setShowCreate(false);
      setEditingRole(null);
      setFormData(EMPTY_ROLE);
      await loadRoles();
    } catch {
      setError('Failed to save role');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (roleId: string) => {
    if (!token) return;
    setError('');
    try {
      const result = await window.api.admin.deleteRole(token, orgId, roleId) as { error?: string };
      if (result?.error) { setError(result.error); return; }
      setConfirmDelete(null);
      await loadRoles();
    } catch {
      setError('Failed to delete role');
    }
  };

  const startEdit = (role: Role) => {
    setEditingRole(role);
    setFormData({ name: role.name, description: role.description || '', permissions: [...role.permissions] });
    setShowCreate(true);
  };

  const cancelEdit = () => {
    setEditingRole(null);
    setShowCreate(false);
    setFormData(EMPTY_ROLE);
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
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-sm px-4 py-2 rounded-lg">
          {error}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium">
          Custom Roles ({roles.length})
        </h2>
        <div className="flex gap-2">
          <button
            onClick={() => loadRoles()}
            className="text-surface-400 hover:text-surface-200 text-sm px-2 py-1.5 transition-colors"
            title="Refresh"
          >
            ↻
          </button>
          {!showCreate && (
            <button
              onClick={() => { setFormData(EMPTY_ROLE); setEditingRole(null); setShowCreate(true); }}
              className="bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
            >
              Create Role
            </button>
          )}
        </div>
      </div>

      {/* Create / Edit Form */}
      {showCreate && (
        <div className="bg-surface-800 rounded-xl p-4 space-y-4">
          <h3 className="text-sm font-medium text-surface-200">
            {editingRole ? `Edit Role: ${editingRole.name}` : 'Create New Role'}
          </h3>

          <div className="space-y-3">
            <div>
              <label className="block text-xs text-surface-400 mb-1">Role Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData((p) => ({ ...p, name: e.target.value }))}
                placeholder="e.g. Auditor"
                className="w-full bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
                disabled={editingRole?.is_builtin}
              />
            </div>
            <div>
              <label className="block text-xs text-surface-400 mb-1">Description</label>
              <input
                type="text"
                value={formData.description}
                onChange={(e) => setFormData((p) => ({ ...p, description: e.target.value }))}
                placeholder="Optional description"
                className="w-full bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
              />
            </div>
          </div>

          {/* Permission checkboxes */}
          <div>
            <label className="block text-xs text-surface-400 mb-2">Permissions</label>
            <div className="grid grid-cols-2 gap-2">
              {ALL_PERMISSIONS.map(({ key, label }) => (
                <label
                  key={key}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-900/50 hover:bg-surface-700/50 cursor-pointer transition-colors"
                >
                  <input
                    type="checkbox"
                    checked={formData.permissions.includes(key) || formData.permissions.includes('*')}
                    onChange={() => togglePermission(key)}
                    disabled={formData.permissions.includes('*') && key !== '*'}
                    className="rounded border-surface-600 text-accent-500 focus:ring-accent-500 focus:ring-offset-0 bg-surface-800"
                  />
                  <div>
                    <div className="text-sm text-surface-200">{key}</div>
                    <div className="text-xs text-surface-500">{label}</div>
                  </div>
                </label>
              ))}
              {/* Superadmin wildcard */}
              <label className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-900/50 hover:bg-surface-700/50 cursor-pointer transition-colors col-span-2 border border-amber-500/20">
                <input
                  type="checkbox"
                  checked={formData.permissions.includes('*')}
                  onChange={() => togglePermission('*')}
                  className="rounded border-surface-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-0 bg-surface-800"
                />
                <div>
                  <div className="text-sm text-amber-400">* (Superadmin)</div>
                  <div className="text-xs text-surface-500">All permissions — full administrative access</div>
                </div>
              </label>
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={handleSave}
              disabled={saving || !formData.name.trim()}
              className="bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
            >
              {saving ? 'Saving...' : editingRole ? 'Update Role' : 'Create Role'}
            </button>
            <button
              onClick={cancelEdit}
              className="text-sm text-surface-400 hover:text-surface-200 px-3 py-1.5 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Roles List */}
      <div className="bg-surface-800 rounded-xl divide-y divide-surface-700">
        {roles.length === 0 ? (
          <div className="p-8 text-center text-surface-500 text-sm">
            No custom roles yet.
          </div>
        ) : (
          roles.map((role) => (
            <div key={role.id} className="px-4 py-3 hover:bg-surface-700/50 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                    role.is_builtin
                      ? 'bg-amber-500/20 text-amber-400'
                      : 'bg-accent-600/20 text-accent-400'
                  }`}>
                    {role.name.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-sm text-surface-100">
                      {role.name}
                      {role.is_builtin && (
                        <span className="ml-2 text-xs text-amber-400/70 bg-amber-500/10 px-1.5 py-0.5 rounded">built-in</span>
                      )}
                    </div>
                    {role.description && (
                      <div className="text-xs text-surface-500">{role.description}</div>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => startEdit(role)}
                    className="text-xs text-surface-400 hover:text-accent-400 transition-colors px-2 py-1"
                  >
                    Edit
                  </button>
                  {!role.is_builtin && (
                    confirmDelete === role.id ? (
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleDelete(role.id)}
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
                        onClick={() => setConfirmDelete(role.id)}
                        className="text-xs text-surface-500 hover:text-red-400 transition-colors px-2 py-1"
                      >
                        Delete
                      </button>
                    )
                  )}
                </div>
              </div>
              {/* Permission badges */}
              <div className="mt-2 flex flex-wrap gap-1">
                {role.permissions.includes('*') ? (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400">
                    All permissions
                  </span>
                ) : (
                  role.permissions.map((p) => (
                    <span key={p} className="text-xs px-2 py-0.5 rounded-full bg-surface-600/50 text-surface-400">
                      {p}
                    </span>
                  ))
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
