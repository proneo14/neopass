import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../store/authStore';
import { useSyncStore } from '../store/syncStore';
import { performSync } from '../utils/sync';

interface SyncDevice {
  device_id: string;
  last_sync_at: string;
}

const AUTO_SYNC_OPTIONS = [
  { value: 0, label: 'Manual only' },
  { value: 10, label: '10 seconds' },
  { value: 30, label: '30 seconds' },
  { value: 60, label: '1 minute' },
  { value: 300, label: '5 minutes' },
];

export function SyncSettings({ onClose }: { onClose: () => void }) {
  const { token, masterKeyHex } = useAuthStore();
  const { deviceId, lastSyncAt, status, statusMessage, autoSyncInterval, setDeviceId, setAutoSyncInterval } = useSyncStore();
  const [devices, setDevices] = useState<SyncDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [deletingDevice, setDeletingDevice] = useState('');
  const [syncResultMsg, setSyncResultMsg] = useState('');

  const loadDevices = useCallback(async () => {
    if (!token) return;
    try {
      const result = await window.api.sync.listDevices(token) as SyncDevice[] | { error: string };
      if (Array.isArray(result)) {
        setDevices(result);
      }
    } catch { /* ignore */ }
  }, [token]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      if (!deviceId) {
        const id = await window.api.sync.getDeviceId();
        setDeviceId(id);
      }
      await loadDevices();
      setLoading(false);
    })();
  }, [token, deviceId, setDeviceId, loadDevices]);

  const handleSyncNow = async () => {
    if (!token || !masterKeyHex || !deviceId) return;
    setSyncResultMsg('');
    const result = await performSync(token, masterKeyHex, deviceId);
    if (result.error) {
      setSyncResultMsg('');
    } else {
      const parts: string[] = [];
      if (result.pulled > 0) parts.push(`${result.pulled} updated`);
      if (result.deleted > 0) parts.push(`${result.deleted} removed`);
      setSyncResultMsg(parts.length > 0 ? parts.join(', ') : '');
      await loadDevices();
    }
  };

  const handleDeleteDevice = async (delId: string) => {
    if (!token) return;
    setDeletingDevice(delId);
    try {
      const result = await window.api.sync.deleteDevice(token, delId) as { status?: string; error?: string };
      if (result.error) {
        useSyncStore.getState().setStatus('error', result.error);
      } else {
        setDevices(prev => prev.filter(d => d.device_id !== delId));
      }
    } catch {
      useSyncStore.getState().setStatus('error', 'Failed to remove device');
    } finally {
      setDeletingDevice('');
    }
  };

  const formatTime = (iso: string) => {
    try {
      const d = new Date(iso);
      const now = new Date();
      const diffMs = now.getTime() - d.getTime();
      const diffMin = Math.floor(diffMs / 60000);
      if (diffMin < 1) return 'just now';
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHr = Math.floor(diffMin / 60);
      if (diffHr < 24) return `${diffHr}h ago`;
      const diffDays = Math.floor(diffHr / 24);
      if (diffDays < 7) return `${diffDays}d ago`;
      return d.toLocaleDateString();
    } catch {
      return 'unknown';
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface-800 rounded-lg shadow-2xl w-[460px] max-h-[80vh] overflow-hidden flex flex-col" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-surface-700">
          <h2 className="text-sm font-semibold text-surface-100">Sync Settings</h2>
          <button onClick={onClose} className="text-surface-500 hover:text-surface-300 transition-colors text-lg">✕</button>
        </div>

        <div className="flex-1 overflow-auto p-5 space-y-5">
          {/* Sync Status */}
          <section>
            <h3 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Sync Status</h3>
            <div className="bg-surface-900 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-surface-200">This device</p>
                  <p className="text-xs text-surface-500 font-mono">{deviceId || '—'}</p>
                </div>
                <div className={`w-2.5 h-2.5 rounded-full ${
                  status === 'syncing' ? 'bg-yellow-500 animate-pulse' :
                  status === 'error' ? 'bg-red-500' :
                  lastSyncAt ? 'bg-green-500' : 'bg-surface-600'
                }`} title={status === 'syncing' ? 'Syncing…' : lastSyncAt ? 'Synced' : 'Never synced'} />
              </div>

              <div className="flex items-center justify-between">
                <p className="text-xs text-surface-400">
                  Last sync: {lastSyncAt ? formatTime(lastSyncAt) : 'Never'}
                </p>
                <button
                  onClick={handleSyncNow}
                  disabled={status === 'syncing' || loading}
                  className="px-3 py-1.5 bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-xs rounded-md transition-colors flex items-center gap-1.5"
                >
                  {status === 'syncing' ? (
                    <>
                      <span className="inline-block w-3 h-3 border border-white border-t-transparent rounded-full animate-spin" />
                      Syncing…
                    </>
                  ) : (
                    'Sync Now'
                  )}
                </button>
              </div>

              {status === 'success' && statusMessage && (
                <p className="text-xs text-green-400">Synced — {statusMessage}</p>
              )}
              {syncResultMsg && status === 'success' && (
                <p className="text-xs text-green-400/70">{syncResultMsg}</p>
              )}
              {status === 'error' && statusMessage && (
                <p className="text-xs text-red-400">{statusMessage}</p>
              )}
            </div>
          </section>

          {/* Auto-Sync Interval */}
          <section>
            <h3 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Auto-Sync</h3>
            <div className="bg-surface-900 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <p className="text-sm text-surface-200">Sync interval</p>
                <select
                  value={autoSyncInterval}
                  onChange={e => setAutoSyncInterval(Number(e.target.value))}
                  className="bg-surface-800 border border-surface-700 text-surface-200 text-xs rounded px-2 py-1 focus:outline-none focus:border-accent-600"
                >
                  {AUTO_SYNC_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
              <p className="text-xs text-surface-500 mt-2">
                {autoSyncInterval === 0
                  ? 'Sync only when you click "Sync Now".'
                  : `Automatically syncs every ${AUTO_SYNC_OPTIONS.find(o => o.value === autoSyncInterval)?.label ?? autoSyncInterval + 's'}.`}
              </p>
            </div>
          </section>

          {/* Registered Devices */}
          <section>
            <h3 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">
              Registered Devices ({devices.length})
            </h3>
            {loading ? (
              <div className="text-center py-6">
                <span className="inline-block w-5 h-5 border-2 border-accent-600 border-t-transparent rounded-full animate-spin" />
              </div>
            ) : devices.length === 0 ? (
              <div className="bg-surface-900 rounded-lg p-4 text-center">
                <p className="text-sm text-surface-500">No devices have synced yet.</p>
                <p className="text-xs text-surface-600 mt-1">Click "Sync Now" to register this device.</p>
              </div>
            ) : (
              <div className="space-y-1">
                {devices.map(device => {
                  const isCurrent = device.device_id === deviceId;
                  return (
                    <div
                      key={device.device_id}
                      className={`flex items-center justify-between px-3 py-2.5 rounded-md ${isCurrent ? 'bg-accent-900/20 border border-accent-700/30' : 'bg-surface-900'}`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span className="text-lg">{isCurrent ? '💻' : '📱'}</span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="text-sm text-surface-200 font-mono truncate">{device.device_id}</p>
                            {isCurrent && (
                              <span className="text-[10px] bg-accent-700/30 text-accent-300 px-1.5 py-0.5 rounded font-medium shrink-0">
                                This device
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-surface-500">Last sync: {formatTime(device.last_sync_at)}</p>
                        </div>
                      </div>
                      {!isCurrent && (
                        <button
                          onClick={() => handleDeleteDevice(device.device_id)}
                          disabled={deletingDevice === device.device_id}
                          className="text-xs text-red-400/70 hover:text-red-400 disabled:opacity-50 transition-colors shrink-0 ml-2"
                          title="Remove device"
                        >
                          {deletingDevice === device.device_id ? '…' : '✕'}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
            <p className="text-xs text-surface-600 mt-2">
              Removing a device clears its sync cursor. It will perform a full sync next time.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
