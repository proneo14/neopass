import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';
import type { OrgPolicy } from '../../types/admin';

interface Props {
  orgId: string;
}

export function PoliciesPanel({ orgId }: Props) {
  const [policy, setPolicy] = useState<OrgPolicy>({
    require_2fa: false,
    min_password_length: 12,
    rotation_days: 0,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [confirmSave, setConfirmSave] = useState(false);

  const { token } = useAuthStore();

  const loadPolicy = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const result = await window.api.admin.getPolicy(token, orgId) as OrgPolicy & { error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setPolicy({
          require_2fa: result.require_2fa ?? false,
          min_password_length: result.min_password_length || 12,
          rotation_days: result.rotation_days ?? 0,
        });
      }
    } catch { /* use defaults */ }
    finally { setLoading(false); }
  }, [token, orgId]);

  useEffect(() => { loadPolicy(); }, [loadPolicy]);

  const handleSave = async () => {
    if (!token) return;
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const result = await window.api.admin.setPolicy(token, orgId, policy as unknown as Record<string, unknown>) as { error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setSuccess('Policy updated successfully');
        setConfirmSave(false);
      }
    } catch {
      setError('Failed to update policy');
    } finally {
      setSaving(false);
    }
  };

  const ROTATION_OPTIONS = [
    { value: 0, label: 'Disabled' },
    { value: 30, label: '30 days' },
    { value: 60, label: '60 days' },
    { value: 90, label: '90 days' },
    { value: 180, label: '180 days' },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-6 w-6 border-2 border-accent-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-xl">
      <div>
        <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium mb-1">Security Policies</h2>
        <p className="text-xs text-surface-500">
          Configure organization-wide security requirements for all members.
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

      <div className="bg-surface-800 rounded-xl divide-y divide-surface-700">
        {/* Require 2FA */}
        <div className="flex items-center justify-between px-5 py-4">
          <div>
            <div className="text-sm text-surface-100">Require Two-Factor Authentication</div>
            <div className="text-xs text-surface-500 mt-0.5">
              All members must enable TOTP before accessing their vault
            </div>
          </div>
          <button
            onClick={() => setPolicy({ ...policy, require_2fa: !policy.require_2fa })}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
              policy.require_2fa ? 'bg-accent-600' : 'bg-surface-600'
            }`}
          >
            <span
              className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${
                policy.require_2fa ? 'translate-x-4' : 'translate-x-1'
              }`}
            />
          </button>
        </div>

        {/* Min Password Length */}
        <div className="px-5 py-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-surface-100">Minimum Password Length</div>
              <div className="text-xs text-surface-500 mt-0.5">
                Enforce a minimum master password length for all members
              </div>
            </div>
            <span className="text-sm text-accent-400 font-medium tabular-nums w-8 text-right">
              {policy.min_password_length}
            </span>
          </div>
          <input
            type="range"
            min={8}
            max={32}
            value={policy.min_password_length}
            onChange={(e) => setPolicy({ ...policy, min_password_length: parseInt(e.target.value) })}
            className="w-full h-1 bg-surface-600 rounded-full appearance-none cursor-pointer accent-accent-500"
          />
          <div className="flex justify-between text-xs text-surface-600">
            <span>8</span>
            <span>16</span>
            <span>24</span>
            <span>32</span>
          </div>
        </div>

        {/* Password Rotation */}
        <div className="px-5 py-4 space-y-3">
          <div>
            <div className="text-sm text-surface-100">Password Rotation Period</div>
            <div className="text-xs text-surface-500 mt-0.5">
              Require members to change their master password periodically
            </div>
          </div>
          <div className="flex gap-2">
            {ROTATION_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setPolicy({ ...policy, rotation_days: opt.value })}
                className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                  policy.rotation_days === opt.value
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

      {/* Save */}
      {confirmSave ? (
        <div className="bg-surface-800 rounded-xl p-4 space-y-3">
          <p className="text-sm text-surface-200">
            Apply these policy changes to all organization members?
          </p>
          <div className="flex gap-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm rounded-lg px-4 py-2 transition-colors"
            >
              {saving ? 'Saving...' : 'Confirm'}
            </button>
            <button
              onClick={() => setConfirmSave(false)}
              className="text-sm text-surface-400 hover:text-surface-200 px-4 py-2 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={() => setConfirmSave(true)}
          className="bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-lg px-6 py-2.5 transition-colors"
        >
          Save Policies
        </button>
      )}
    </div>
  );
}
