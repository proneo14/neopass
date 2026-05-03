import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';

interface Props {
  orgId: string;
}

interface SSOConfigState {
  enabled: boolean;
  provider: 'saml' | 'oidc' | '';
  saml: {
    entity_id: string;
    sso_url: string;
    certificate: string;
    name_id_format: string;
  };
  oidc: {
    issuer: string;
    client_id: string;
    client_secret: string;
    redirect_uri: string;
    scopes: string;
  };
  auto_enroll: boolean;
}

const defaultState: SSOConfigState = {
  enabled: false,
  provider: '',
  saml: { entity_id: '', sso_url: '', certificate: '', name_id_format: '' },
  oidc: { issuer: '', client_id: '', client_secret: '', redirect_uri: '', scopes: 'openid email profile' },
  auto_enroll: false,
};

export function SSOPanel({ orgId }: Props) {
  const [config, setConfig] = useState<SSOConfigState>(defaultState);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const { token } = useAuthStore();

  const loadConfig = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const result = await window.api.admin.getSSOConfig(token, orgId) as {
        sso_enabled?: boolean;
        sso_config?: { provider?: string; saml?: Record<string, string>; oidc?: Record<string, string>; auto_enroll?: boolean };
        error?: string;
      };
      if (result.error) {
        setError(result.error);
      } else {
        const cfg = result.sso_config;
        setConfig({
          enabled: result.sso_enabled ?? false,
          provider: (cfg?.provider as 'saml' | 'oidc') || '',
          saml: {
            entity_id: cfg?.saml?.entity_id ?? '',
            sso_url: cfg?.saml?.sso_url ?? '',
            certificate: cfg?.saml?.certificate ?? '',
            name_id_format: cfg?.saml?.name_id_format ?? '',
          },
          oidc: {
            issuer: cfg?.oidc?.issuer ?? '',
            client_id: cfg?.oidc?.client_id ?? '',
            client_secret: '', // never returned from server
            redirect_uri: cfg?.oidc?.redirect_uri ?? '',
            scopes: cfg?.oidc?.scopes ?? 'openid email profile',
          },
          auto_enroll: cfg?.auto_enroll ?? false,
        });
      }
    } catch { /* use defaults */ }
    finally { setLoading(false); }
  }, [token, orgId]);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  const handleSave = async () => {
    if (!token || !config.provider) return;
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const ssoConfig: Record<string, unknown> = {
        provider: config.provider,
        auto_enroll: config.auto_enroll,
      };
      if (config.provider === 'saml') {
        ssoConfig.saml = config.saml;
      } else {
        ssoConfig.oidc = {
          ...config.oidc,
          scopes: config.oidc.scopes.split(/[,\s]+/).filter(Boolean),
        };
      }

      const result = await window.api.admin.setSSOConfig(token, orgId, {
        enabled: config.enabled,
        config: ssoConfig,
      }) as { error?: string };
      if (result.error) {
        setError(result.error);
      } else {
        setSuccess('SSO configuration saved');
      }
    } catch {
      setError('Failed to save SSO configuration');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="text-sm text-surface-400">Loading SSO configuration...</div>;
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h2 className="text-base font-semibold text-surface-100">Single Sign-On (SSO)</h2>
        <p className="text-xs text-surface-400 mt-1">
          Configure SAML 2.0 or OpenID Connect SSO for your organization.
          SSO authenticates users but does not unlock the vault — the master password is still required.
        </p>
      </div>

      {error && (
        <div className="text-sm text-red-400 bg-red-400/10 px-3 py-2 rounded-md">{error}</div>
      )}
      {success && (
        <div className="text-sm text-green-400 bg-green-400/10 px-3 py-2 rounded-md">{success}</div>
      )}

      {/* Enable toggle */}
      <label className="flex items-center gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={config.enabled}
          onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
          className="w-4 h-4 rounded border-surface-600 bg-surface-800 text-accent-500 focus:ring-accent-500"
        />
        <span className="text-sm text-surface-200">Enable SSO</span>
      </label>

      {/* Provider selector */}
      <div>
        <label className="block text-xs font-medium text-surface-400 mb-1">Provider</label>
        <select
          value={config.provider}
          onChange={(e) => setConfig({ ...config, provider: e.target.value as 'saml' | 'oidc' })}
          className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
        >
          <option value="">Select provider...</option>
          <option value="saml">SAML 2.0</option>
          <option value="oidc">OpenID Connect</option>
        </select>
      </div>

      {/* SAML config */}
      {config.provider === 'saml' && (
        <div className="space-y-4 p-4 rounded-lg bg-surface-800/50 border border-surface-700">
          <h3 className="text-sm font-medium text-surface-200">SAML 2.0 Configuration</h3>
          <div>
            <label className="block text-xs text-surface-400 mb-1">Entity ID (SP)</label>
            <input
              type="text"
              value={config.saml.entity_id}
              onChange={(e) => setConfig({ ...config, saml: { ...config.saml, entity_id: e.target.value } })}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
              placeholder="https://your-domain.com/sso/saml"
            />
          </div>
          <div>
            <label className="block text-xs text-surface-400 mb-1">SSO URL (IdP Login URL)</label>
            <input
              type="url"
              value={config.saml.sso_url}
              onChange={(e) => setConfig({ ...config, saml: { ...config.saml, sso_url: e.target.value } })}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
              placeholder="https://idp.example.com/saml/sso"
            />
          </div>
          <div>
            <label className="block text-xs text-surface-400 mb-1">IdP Certificate (PEM)</label>
            <textarea
              value={config.saml.certificate}
              onChange={(e) => setConfig({ ...config, saml: { ...config.saml, certificate: e.target.value } })}
              rows={4}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-accent-500"
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
            />
          </div>
          <div>
            <label className="block text-xs text-surface-400 mb-1">NameID Format</label>
            <input
              type="text"
              value={config.saml.name_id_format}
              onChange={(e) => setConfig({ ...config, saml: { ...config.saml, name_id_format: e.target.value } })}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
              placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            />
          </div>
        </div>
      )}

      {/* OIDC config */}
      {config.provider === 'oidc' && (
        <div className="space-y-4 p-4 rounded-lg bg-surface-800/50 border border-surface-700">
          <h3 className="text-sm font-medium text-surface-200">OpenID Connect Configuration</h3>
          <div>
            <label className="block text-xs text-surface-400 mb-1">Issuer URL</label>
            <input
              type="url"
              value={config.oidc.issuer}
              onChange={(e) => setConfig({ ...config, oidc: { ...config.oidc, issuer: e.target.value } })}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
              placeholder="https://accounts.google.com"
            />
          </div>
          <div>
            <label className="block text-xs text-surface-400 mb-1">Client ID</label>
            <input
              type="text"
              value={config.oidc.client_id}
              onChange={(e) => setConfig({ ...config, oidc: { ...config.oidc, client_id: e.target.value } })}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
            />
          </div>
          <div>
            <label className="block text-xs text-surface-400 mb-1">Client Secret</label>
            <input
              type="password"
              value={config.oidc.client_secret}
              onChange={(e) => setConfig({ ...config, oidc: { ...config.oidc, client_secret: e.target.value } })}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
              placeholder="••••••••"
            />
          </div>
          <div>
            <label className="block text-xs text-surface-400 mb-1">Redirect URI</label>
            <input
              type="url"
              value={config.oidc.redirect_uri}
              onChange={(e) => setConfig({ ...config, oidc: { ...config.oidc, redirect_uri: e.target.value } })}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
              placeholder="https://your-domain.com/api/v1/sso/{orgId}/callback"
            />
          </div>
          <div>
            <label className="block text-xs text-surface-400 mb-1">Scopes (space-separated)</label>
            <input
              type="text"
              value={config.oidc.scopes}
              onChange={(e) => setConfig({ ...config, oidc: { ...config.oidc, scopes: e.target.value } })}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500"
              placeholder="openid email profile"
            />
          </div>
        </div>
      )}

      {/* Auto-enroll toggle */}
      <label className="flex items-center gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={config.auto_enroll}
          onChange={(e) => setConfig({ ...config, auto_enroll: e.target.checked })}
          className="w-4 h-4 rounded border-surface-600 bg-surface-800 text-accent-500 focus:ring-accent-500"
        />
        <div>
          <span className="text-sm text-surface-200">Auto-enroll authenticated users</span>
          <p className="text-xs text-surface-500 mt-0.5">
            Automatically add users to the organization when they authenticate via SSO for the first time.
          </p>
        </div>
      </label>

      {/* Save button */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleSave}
          disabled={saving || !config.provider}
          className="px-4 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving ? 'Saving...' : 'Save Configuration'}
        </button>
      </div>
    </div>
  );
}
