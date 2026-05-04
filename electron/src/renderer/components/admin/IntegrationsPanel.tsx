import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';
import type { Webhook, WebhookDelivery } from '../../types/admin';

interface Props {
  orgId: string;
}

const EVENT_TYPES = [
  { value: '*', label: 'All events' },
  { value: 'org_created', label: 'Organization created' },
  { value: 'user_invited', label: 'User invited' },
  { value: 'user_joined', label: 'User joined' },
  { value: 'user_removed', label: 'User removed' },
  { value: 'vault_accessed', label: 'Vault accessed' },
  { value: 'password_changed_by_admin', label: 'Password reset by admin' },
  { value: 'policy_updated', label: 'Policy updated' },
];

const EXPORT_FORMATS = [
  { value: 'json', label: 'JSON (NDJSON)' },
  { value: 'cef', label: 'CEF (ArcSight)' },
  { value: 'syslog', label: 'Syslog (RFC 5424)' },
];

const STATUS_COLORS: Record<string, string> = {
  delivered: 'text-green-400 bg-green-500/10',
  failed: 'text-red-400 bg-red-500/10',
  pending: 'text-amber-400 bg-amber-500/10',
};

export function IntegrationsPanel({ orgId }: Props) {
  // --- Export state ---
  const [exportFormat, setExportFormat] = useState('json');
  const [exportFrom, setExportFrom] = useState('');
  const [exportTo, setExportTo] = useState('');
  const [exporting, setExporting] = useState(false);
  const [exportResult, setExportResult] = useState('');

  // --- Webhook state ---
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loadingWebhooks, setLoadingWebhooks] = useState(true);
  const [error, setError] = useState('');
  const [showCreateWebhook, setShowCreateWebhook] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookEvents, setWebhookEvents] = useState<string[]>(['*']);
  const [creatingWebhook, setCreatingWebhook] = useState(false);
  const [webhookSecret, setWebhookSecret] = useState('');
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [expandedDeliveries, setExpandedDeliveries] = useState<string | null>(null);
  const [testingWebhook, setTestingWebhook] = useState<string | null>(null);

  const { token } = useAuthStore();

  // --- Export ---
  const handleExport = async () => {
    if (!token) return;
    setExporting(true);
    setExportResult('');
    setError('');
    try {
      const params: Record<string, unknown> = { format: exportFormat };
      if (exportFrom) params.from = exportFrom;
      if (exportTo) params.to = exportTo;
      const result = await window.api.admin.exportEvents(token, orgId, params) as string | { error: string };
      if (typeof result === 'object' && 'error' in result) {
        setError(result.error);
      } else {
        setExportResult(typeof result === 'string' ? result : JSON.stringify(result, null, 2));
      }
    } catch {
      setError('Export failed');
    } finally {
      setExporting(false);
    }
  };

  const downloadExport = () => {
    if (!exportResult) return;
    const ext = exportFormat === 'json' ? 'ndjson' : 'log';
    const blob = new Blob([exportResult], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-export-${new Date().toISOString().slice(0, 10)}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // --- Webhooks ---
  const loadWebhooks = useCallback(async () => {
    if (!token) return;
    setLoadingWebhooks(true);
    setError('');
    try {
      const result = await window.api.admin.listWebhooks(token, orgId) as Webhook[] | { error: string };
      if ('error' in result) { setError(result.error); } else { setWebhooks(result); }
    } catch {
      setError('Failed to load webhooks');
    } finally {
      setLoadingWebhooks(false);
    }
  }, [token, orgId]);

  useEffect(() => { loadWebhooks(); }, [loadWebhooks]);

  const toggleEvent = (event: string) => {
    if (event === '*') {
      setWebhookEvents(['*']);
      return;
    }
    setWebhookEvents((prev) => {
      const without = prev.filter((e) => e !== '*' && e !== event);
      if (prev.includes(event)) return without.length > 0 ? without : ['*'];
      return [...without, event];
    });
  };

  const handleCreateWebhook = async () => {
    if (!token || !webhookUrl.trim()) return;
    setCreatingWebhook(true);
    setError('');
    setWebhookSecret('');
    try {
      const result = await window.api.admin.createWebhook(token, orgId, {
        url: webhookUrl.trim(),
        events: webhookEvents,
      }) as { secret?: string; error?: string };
      if (result?.error) { setError(result.error); return; }
      if (result?.secret) {
        setWebhookSecret(result.secret);
      }
      setWebhookUrl('');
      setWebhookEvents(['*']);
      await loadWebhooks();
    } catch {
      setError('Failed to create webhook');
    } finally {
      setCreatingWebhook(false);
    }
  };

  const handleDeleteWebhook = async (id: string) => {
    if (!token) return;
    setError('');
    try {
      const result = await window.api.admin.deleteWebhook(token, orgId, id) as { error?: string };
      if (result?.error) { setError(result.error); return; }
      setConfirmDelete(null);
      await loadWebhooks();
    } catch {
      setError('Failed to delete webhook');
    }
  };

  const handleToggleWebhook = async (id: string, enabled: boolean) => {
    if (!token) return;
    setError('');
    try {
      const result = await window.api.admin.toggleWebhook(token, orgId, id, enabled) as { error?: string };
      if (result?.error) { setError(result.error); return; }
      await loadWebhooks();
    } catch {
      setError('Failed to toggle webhook');
    }
  };

  const handleTestWebhook = async (id: string) => {
    if (!token) return;
    setTestingWebhook(id);
    setError('');
    try {
      const result = await window.api.admin.testWebhook(token, orgId, id) as { error?: string };
      if (result?.error) { setError(result.error); }
      await loadWebhooks();
    } catch {
      setError('Failed to test webhook');
    } finally {
      setTestingWebhook(null);
    }
  };

  return (
    <div className="space-y-8">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-sm px-4 py-2 rounded-lg">
          {error}
        </div>
      )}

      {/* ─── Event Log Export ─── */}
      <section className="space-y-4">
        <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium">
          Event Log Export (SIEM)
        </h2>
        <div className="bg-surface-800 rounded-xl p-4 space-y-4">
          <p className="text-xs text-surface-500">
            Export audit log events in SIEM-compatible formats. Use NDJSON for Splunk/Elastic, CEF for ArcSight, or Syslog for generic tools.
          </p>

          <div className="flex flex-wrap gap-3">
            <div>
              <label className="block text-xs text-surface-400 mb-1">Format</label>
              <select
                value={exportFormat}
                onChange={(e) => setExportFormat(e.target.value)}
                className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
              >
                {EXPORT_FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>{f.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-surface-400 mb-1">From</label>
              <input
                type="date"
                value={exportFrom}
                onChange={(e) => setExportFrom(e.target.value)}
                className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
              />
            </div>
            <div>
              <label className="block text-xs text-surface-400 mb-1">To</label>
              <input
                type="date"
                value={exportTo}
                onChange={(e) => setExportTo(e.target.value)}
                className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
              />
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleExport}
              disabled={exporting}
              className="bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
            >
              {exporting ? 'Exporting...' : 'Export Events'}
            </button>
            {exportResult && (
              <button
                onClick={downloadExport}
                className="text-sm text-accent-400 hover:text-accent-300 transition-colors"
              >
                ⬇ Download file
              </button>
            )}
          </div>

          {/* Preview */}
          {exportResult && (
            <div className="mt-2">
              <div className="text-xs text-surface-500 mb-1">Preview (first 2000 chars):</div>
              <pre className="bg-surface-900 rounded-lg p-3 text-xs text-surface-300 max-h-60 overflow-auto whitespace-pre-wrap font-mono">
                {exportResult.slice(0, 2000)}
                {exportResult.length > 2000 && '\n... (truncated)'}
              </pre>
            </div>
          )}
        </div>
      </section>

      {/* ─── Webhooks ─── */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xs uppercase tracking-wider text-surface-500 font-medium">
            Webhooks ({webhooks.length})
          </h2>
          <div className="flex gap-2">
            <button
              onClick={() => loadWebhooks()}
              className="text-surface-400 hover:text-surface-200 text-sm px-2 py-1.5 transition-colors"
              title="Refresh"
            >
              ↻
            </button>
            {!showCreateWebhook && (
              <button
                onClick={() => setShowCreateWebhook(true)}
                className="bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
              >
                Add Webhook
              </button>
            )}
          </div>
        </div>

        {/* Webhook secret display */}
        {webhookSecret && (
          <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4 space-y-2">
            <div className="text-sm font-medium text-green-400">Webhook Created Successfully</div>
            <p className="text-xs text-surface-400">
              Copy this signing secret now — it won't be shown again. Use it to verify HMAC-SHA256 signatures on incoming payloads.
            </p>
            <code className="block bg-surface-900 rounded px-3 py-2 text-sm text-green-300 font-mono break-all select-all">
              {webhookSecret}
            </code>
            <button
              onClick={() => setWebhookSecret('')}
              className="text-xs text-surface-500 hover:text-surface-300 transition-colors"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Create webhook form */}
        {showCreateWebhook && (
          <div className="bg-surface-800 rounded-xl p-4 space-y-4">
            <h3 className="text-sm font-medium text-surface-200">Add Webhook Endpoint</h3>
            <p className="text-xs text-surface-500">
              Webhook payloads are signed with HMAC-SHA256. You'll receive the signing secret after creation.
            </p>
            <div>
              <label className="block text-xs text-surface-400 mb-1">Endpoint URL</label>
              <input
                type="url"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="https://your-siem.example.com/webhook"
                className="w-full bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent-500"
                autoFocus
              />
            </div>
            <div>
              <label className="block text-xs text-surface-400 mb-2">Events to subscribe</label>
              <div className="flex flex-wrap gap-2">
                {EVENT_TYPES.map(({ value, label }) => (
                  <button
                    key={value}
                    onClick={() => toggleEvent(value)}
                    className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
                      webhookEvents.includes(value) || (value !== '*' && webhookEvents.includes('*'))
                        ? 'border-accent-500 bg-accent-600/20 text-accent-300'
                        : 'border-surface-600 text-surface-400 hover:border-surface-500'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleCreateWebhook}
                disabled={creatingWebhook || !webhookUrl.trim()}
                className="bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm rounded-lg px-4 py-1.5 transition-colors"
              >
                {creatingWebhook ? 'Creating...' : 'Create Webhook'}
              </button>
              <button
                onClick={() => { setShowCreateWebhook(false); setWebhookUrl(''); setWebhookEvents(['*']); }}
                className="text-sm text-surface-400 hover:text-surface-200 px-3 py-1.5 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Webhooks list */}
        <div className="bg-surface-800 rounded-xl divide-y divide-surface-700">
          {loadingWebhooks ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-6 w-6 border-2 border-accent-500 border-t-transparent" />
            </div>
          ) : webhooks.length === 0 ? (
            <div className="p-8 text-center text-surface-500 text-sm">
              No webhooks configured. Add one to push audit events to your SIEM.
            </div>
          ) : (
            webhooks.map((wh) => (
              <div key={wh.id}>
                <div className="px-4 py-3 hover:bg-surface-700/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${wh.enabled ? 'bg-green-400' : 'bg-surface-500'}`} />
                      <div className="min-w-0">
                        <div className="text-sm text-surface-100 truncate font-mono">{wh.url}</div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-xs text-surface-500">
                            {wh.events.includes('*') ? 'All events' : wh.events.join(', ')}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                      <button
                        onClick={() => handleTestWebhook(wh.id)}
                        disabled={testingWebhook === wh.id}
                        className="text-xs text-accent-400 hover:text-accent-300 px-2 py-1 transition-colors disabled:opacity-50"
                      >
                        {testingWebhook === wh.id ? 'Sending...' : 'Test'}
                      </button>
                      <button
                        onClick={() => handleToggleWebhook(wh.id, !wh.enabled)}
                        className={`text-xs px-2 py-1 transition-colors ${wh.enabled ? 'text-amber-400 hover:text-amber-300' : 'text-green-400 hover:text-green-300'}`}
                      >
                        {wh.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        onClick={() => setExpandedDeliveries(expandedDeliveries === wh.id ? null : wh.id)}
                        className="text-xs text-surface-400 hover:text-surface-200 px-2 py-1 transition-colors"
                      >
                        {expandedDeliveries === wh.id ? '▼' : '▶'} Deliveries
                      </button>
                      {confirmDelete === wh.id ? (
                        <div className="flex gap-1">
                          <button
                            onClick={() => handleDeleteWebhook(wh.id)}
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
                          onClick={() => setConfirmDelete(wh.id)}
                          className="text-xs text-surface-500 hover:text-red-400 transition-colors px-2 py-1"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* Recent Deliveries */}
                {expandedDeliveries === wh.id && wh.recent_deliveries && (
                  <div className="px-4 pb-3 bg-surface-900/30">
                    {wh.recent_deliveries.length === 0 ? (
                      <div className="text-xs text-surface-500 py-2">No recent deliveries.</div>
                    ) : (
                      <div className="divide-y divide-surface-700/50">
                        {wh.recent_deliveries.map((d: WebhookDelivery) => (
                          <div key={d.id} className="flex items-center justify-between py-2 text-xs">
                            <div className="flex items-center gap-2">
                              <span className={`px-1.5 py-0.5 rounded ${STATUS_COLORS[d.status] || 'text-surface-400'}`}>
                                {d.status}
                              </span>
                              <span className="text-surface-400 font-mono">{d.event_id.slice(0, 8)}</span>
                            </div>
                            <div className="flex items-center gap-3 text-surface-500">
                              {d.response_code && <span>HTTP {d.response_code}</span>}
                              <span>{d.attempts} attempt{d.attempts !== 1 ? 's' : ''}</span>
                              <span>{d.last_attempt_at ? new Date(d.last_attempt_at).toLocaleString() : '-'}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
