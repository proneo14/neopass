import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../../store/authStore';
import type { AuditEntry } from '../../types/admin';

interface Props {
  orgId: string;
}

const ACTION_COLORS: Record<string, string> = {
  vault_accessed: 'text-red-400 bg-red-500/10',
  password_changed_by_admin: 'text-red-400 bg-red-500/10',
  user_removed: 'text-orange-400 bg-orange-500/10',
  policy_updated: 'text-orange-400 bg-orange-500/10',
  org_created: 'text-blue-400 bg-blue-500/10',
  user_invited: 'text-blue-400 bg-blue-500/10',
  user_joined: 'text-blue-400 bg-blue-500/10',
};

const ACTION_SEVERITY: Record<string, 'info' | 'warning' | 'critical'> = {
  org_created: 'info',
  user_invited: 'info',
  user_joined: 'info',
  policy_updated: 'warning',
  user_removed: 'warning',
  vault_accessed: 'critical',
  password_changed_by_admin: 'critical',
};

const SEVERITY_DOT: Record<string, string> = {
  info: 'bg-blue-400',
  warning: 'bg-orange-400',
  critical: 'bg-red-400',
};

const ACTION_TYPES = [
  { value: '', label: 'All actions' },
  { value: 'org_created', label: 'Org Created' },
  { value: 'user_invited', label: 'User Invited' },
  { value: 'user_joined', label: 'User Joined' },
  { value: 'user_removed', label: 'User Removed' },
  { value: 'vault_accessed', label: 'Vault Accessed' },
  { value: 'password_changed_by_admin', label: 'Password Reset' },
  { value: 'policy_updated', label: 'Policy Updated' },
];

export function AuditLogPanel({ orgId }: Props) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');

  const { token } = useAuthStore();

  const loadAuditLog = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const filters: Record<string, string> = {};
      if (actionFilter) filters.action = actionFilter;
      if (actorFilter) filters.actor_id = actorFilter;
      if (fromDate) filters.from = new Date(fromDate).toISOString();
      if (toDate) filters.to = new Date(toDate + 'T23:59:59').toISOString();
      filters.limit = '100';

      const result = await window.api.admin.getAuditLog(token, orgId, filters) as AuditEntry[] | { error: string };
      if ('error' in result) {
        setError(result.error);
      } else {
        setEntries(result);
      }
    } catch {
      setError('Failed to load audit log');
    } finally {
      setLoading(false);
    }
  }, [token, orgId, actionFilter, actorFilter, fromDate, toDate]);

  useEffect(() => { loadAuditLog(); }, [loadAuditLog]);

  const handleExportCSV = () => {
    const headers = ['Timestamp', 'Action', 'Actor', 'Target', 'Details'];
    const rows = entries.map((e) => [
      new Date(e.created_at).toISOString(),
      e.action,
      e.actor_id || '',
      e.target_id || '',
      e.details ? JSON.stringify(e.details) : '',
    ]);
    const csv = [headers, ...rows].map((row) => row.map((cell) => `"${cell.replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-end gap-3 flex-wrap">
        <div>
          <label className="block text-xs text-surface-500 mb-1">Action</label>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-1.5 focus:outline-none focus:border-accent-500"
          >
            {ACTION_TYPES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-surface-500 mb-1">Actor ID</label>
          <input
            type="text"
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            placeholder="Filter by actor..."
            className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-1.5 w-48 focus:outline-none focus:border-accent-500"
          />
        </div>
        <div>
          <label className="block text-xs text-surface-500 mb-1">From</label>
          <input
            type="date"
            value={fromDate}
            onChange={(e) => setFromDate(e.target.value)}
            className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-1.5 focus:outline-none focus:border-accent-500"
          />
        </div>
        <div>
          <label className="block text-xs text-surface-500 mb-1">To</label>
          <input
            type="date"
            value={toDate}
            onChange={(e) => setToDate(e.target.value)}
            className="bg-surface-900 border border-surface-600 text-surface-100 text-sm rounded-lg px-3 py-1.5 focus:outline-none focus:border-accent-500"
          />
        </div>
        <button
          onClick={handleExportCSV}
          disabled={entries.length === 0}
          className="text-xs text-surface-400 hover:text-surface-200 disabled:opacity-50 border border-surface-600 rounded-lg px-3 py-1.5 transition-colors"
        >
          Export CSV
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 text-sm px-4 py-2 rounded-lg">
          {error}
        </div>
      )}

      {/* Audit Table */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-6 w-6 border-2 border-accent-500 border-t-transparent" />
        </div>
      ) : entries.length === 0 ? (
        <div className="bg-surface-800 rounded-xl p-12 text-center text-surface-500 text-sm">
          No audit log entries found.
        </div>
      ) : (
        <div className="bg-surface-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-surface-500 uppercase tracking-wider border-b border-surface-700">
                <th className="text-left px-4 py-3 w-8"></th>
                <th className="text-left px-4 py-3">Timestamp</th>
                <th className="text-left px-4 py-3">Action</th>
                <th className="text-left px-4 py-3">Actor</th>
                <th className="text-left px-4 py-3">Target</th>
                <th className="text-left px-4 py-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-700/50">
              {entries.map((entry) => {
                const severity = ACTION_SEVERITY[entry.action] || 'info';
                const colorClass = ACTION_COLORS[entry.action] || 'text-surface-400 bg-surface-600/50';
                return (
                  <tr key={entry.id} className="hover:bg-surface-700/30 transition-colors">
                    <td className="px-4 py-2.5">
                      <span className={`inline-block w-2 h-2 rounded-full ${SEVERITY_DOT[severity]}`} />
                    </td>
                    <td className="px-4 py-2.5 text-surface-400 text-xs whitespace-nowrap">
                      {new Date(entry.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${colorClass}`}>
                        {entry.action.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-surface-300 text-xs font-mono truncate max-w-[120px]">
                      {entry.actor_id ? entry.actor_id.slice(0, 8) + '...' : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-surface-300 text-xs font-mono truncate max-w-[120px]">
                      {entry.target_id ? entry.target_id.slice(0, 8) + '...' : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-surface-500 text-xs truncate max-w-[200px]">
                      {entry.details ? JSON.stringify(entry.details) : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="text-xs text-surface-600 text-center">
        Showing {entries.length} entries
      </div>
    </div>
  );
}
