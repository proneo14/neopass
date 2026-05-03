import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';

interface Props {
  orgId: string;
}

export function SCIMPanel({ orgId }: Props) {
  const [enabled, setEnabled] = useState(false);
  const [hasToken, setHasToken] = useState(false);
  const [endpoint, setEndpoint] = useState('');
  const [generatedToken, setGeneratedToken] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const { token } = useAuthStore();

  const loadConfig = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const result = await window.api.admin.getSCIMConfig(token, orgId) as {
        scim_enabled?: boolean;
        has_token?: boolean;
        endpoint?: string;
        error?: string;
      };
      if (result.error) {
        setError(result.error);
      } else {
        setEnabled(result.scim_enabled ?? false);
        setHasToken(result.has_token ?? false);
        setEndpoint(result.endpoint ?? '');
      }
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, [token, orgId]);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  const handleToggle = async () => {
    if (!token) return;
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const newEnabled = !enabled;
      const result = await window.api.admin.setSCIMConfig(token, orgId, { enabled: newEnabled }) as { error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setEnabled(newEnabled);
        setSuccess(newEnabled ? 'SCIM enabled' : 'SCIM disabled');
      }
    } catch {
      setError('Failed to update SCIM configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleGenerateToken = async () => {
    if (!token) return;
    setGenerating(true);
    setError('');
    setGeneratedToken('');
    try {
      const result = await window.api.admin.generateSCIMToken(token, orgId) as {
        token?: string;
        error?: string;
      };
      if (result.error) {
        setError(result.error);
      } else if (result.token) {
        setGeneratedToken(result.token);
        setHasToken(true);
        setSuccess('SCIM token generated. Copy it now — it will not be shown again.');
      }
    } catch {
      setError('Failed to generate SCIM token');
    } finally {
      setGenerating(false);
    }
  };

  const copyToken = async () => {
    try {
      await navigator.clipboard.writeText(generatedToken);
      setSuccess('Token copied to clipboard');
    } catch { /* ignore */ }
  };

  if (loading) {
    return <div className="text-sm text-surface-400">Loading SCIM configuration...</div>;
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h2 className="text-base font-semibold text-surface-100">Directory Sync (SCIM)</h2>
        <p className="text-xs text-surface-400 mt-1">
          Enable SCIM 2.0 provisioning to automatically sync users from your identity provider
          (Okta, Azure AD, OneLogin, etc.) to this organization.
        </p>
      </div>

      {error && (
        <div className="text-sm text-red-400 bg-red-400/10 px-3 py-2 rounded-md">{error}</div>
      )}
      {success && (
        <div className="text-sm text-green-400 bg-green-400/10 px-3 py-2 rounded-md">{success}</div>
      )}

      {/* Enable toggle */}
      <div className="flex items-center justify-between p-4 rounded-lg bg-surface-800/50 border border-surface-700">
        <div>
          <p className="text-sm text-surface-200 font-medium">SCIM Provisioning</p>
          <p className="text-xs text-surface-500 mt-0.5">
            {enabled ? 'Enabled — IdP can provision and deprovision users' : 'Disabled'}
          </p>
        </div>
        <button
          onClick={handleToggle}
          disabled={saving}
          className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            enabled
              ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
              : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
          } disabled:opacity-50`}
        >
          {saving ? '...' : enabled ? 'Disable' : 'Enable'}
        </button>
      </div>

      {/* SCIM Endpoint */}
      {endpoint && (
        <div>
          <label className="block text-xs font-medium text-surface-400 mb-1">SCIM Endpoint URL</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={`${window.location.origin}${endpoint}`}
              readOnly
              className="flex-1 px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-300 text-xs font-mono focus:outline-none"
            />
            <button
              onClick={() => navigator.clipboard.writeText(`${window.location.origin}${endpoint}`)}
              className="px-3 py-2 rounded-md bg-surface-700 text-surface-300 text-xs hover:bg-surface-600 transition-colors"
            >
              Copy
            </button>
          </div>
        </div>
      )}

      {/* Token management */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-surface-200 font-medium">Bearer Token</p>
            <p className="text-xs text-surface-500 mt-0.5">
              {hasToken ? 'A SCIM token has been generated' : 'No SCIM token configured'}
            </p>
          </div>
          <button
            onClick={handleGenerateToken}
            disabled={generating}
            className="px-3 py-1.5 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-xs font-medium transition-colors disabled:opacity-50"
          >
            {generating ? 'Generating...' : hasToken ? 'Regenerate Token' : 'Generate Token'}
          </button>
        </div>

        {generatedToken && (
          <div className="p-3 rounded-md bg-yellow-500/10 border border-yellow-500/30">
            <p className="text-xs text-yellow-400 font-medium mb-2">
              ⚠️ Copy this token now — it will not be shown again.
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={generatedToken}
                readOnly
                className="flex-1 px-2 py-1.5 rounded bg-surface-900 border border-surface-600 text-surface-200 text-xs font-mono"
              />
              <button
                onClick={copyToken}
                className="px-3 py-1.5 rounded-md bg-yellow-600 hover:bg-yellow-500 text-white text-xs font-medium transition-colors"
              >
                Copy
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Info */}
      <div className="p-3 rounded-md bg-surface-800/50 border border-surface-700">
        <p className="text-xs text-surface-400">
          <strong className="text-surface-300">How it works:</strong> Configure SCIM in your identity provider
          (Okta, Azure AD, OneLogin, etc.) using the endpoint URL and bearer token above. When users are
          provisioned, they receive an invitation to join the organization. When deprovisioned, their
          org membership and sessions are revoked.
        </p>
      </div>
    </div>
  );
}
