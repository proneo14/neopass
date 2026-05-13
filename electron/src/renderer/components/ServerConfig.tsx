import React, { useState, useEffect } from 'react';
import { useAuthStore } from '../store/authStore';

type ServerMode = 'local' | 'remote';

export function ServerConfig({ onClose }: { onClose: () => void }) {
  const { token, logout } = useAuthStore();
  const [mode, setMode] = useState<ServerMode>('local');
  const [serverUrl, setServerUrl] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);
  const [switching, setSwitching] = useState(false);
  const [testResult, setTestResult] = useState<{ success?: boolean; error?: string } | null>(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    (async () => {
      setLoading(true);
      const cfg = await window.api.server.getConfig();
      setMode(cfg.mode);
      setServerUrl(cfg.serverUrl);
      setUrlInput(cfg.serverUrl);
      setLoading(false);
    })();
  }, []);

  const handleTest = async () => {
    if (!urlInput.trim()) return;
    setTesting(true);
    setTestResult(null);
    const result = await window.api.server.testConnection(urlInput.trim());
    setTestResult(result);
    setTesting(false);
  };

  const handleSwitchToRemote = async () => {
    if (!urlInput.trim()) return;
    setSwitching(true);
    setError('');
    setSuccess('');

    const result = await window.api.server.setRemote(urlInput.trim());
    if (result.error) {
      setError(result.error);
      setSwitching(false);
      return;
    }

    setMode('remote');
    setServerUrl(urlInput.trim());
    setSuccess('Switched to remote server. You will be logged out — please register or log in on the new server.');
    setSwitching(false);

    // Log the user out after a short delay so they re-authenticate against the new server
    setTimeout(() => { logout(); }, 3000);
  };

  const handleSwitchToLocal = async () => {
    setSwitching(true);
    setError('');
    setSuccess('');

    const result = await window.api.server.setLocal();
    if (result.error) {
      setError(result.error);
      setSwitching(false);
      return;
    }

    setMode('local');
    setServerUrl('');
    setUrlInput('');
    setSuccess('Switched to local mode. You will be logged out — please log in to your local vault.');
    setSwitching(false);

    setTimeout(() => { logout(); }, 3000);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface-800 rounded-lg shadow-2xl w-[520px] max-h-[85vh] overflow-hidden flex flex-col" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-surface-700">
          <h2 className="text-sm font-semibold text-surface-100">Server Configuration</h2>
          <button onClick={onClose} className="text-surface-500 hover:text-surface-300 transition-colors text-lg">✕</button>
        </div>

        <div className="flex-1 overflow-auto p-5 space-y-5">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <span className="inline-block w-5 h-5 border-2 border-accent-600 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : (
            <>
              {/* Current Mode Display */}
              <section>
                <h3 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Current Mode</h3>
                <div className="bg-surface-900 rounded-lg p-4 flex items-center gap-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${mode === 'local' ? 'bg-blue-500' : 'bg-green-500'}`} />
                  <div>
                    <p className="text-sm font-medium text-surface-200">
                      {mode === 'local' ? 'Local (This Device Only)' : 'Remote Server (Multi-Device)'}
                    </p>
                    <p className="text-xs text-surface-500 mt-0.5">
                      {mode === 'local'
                        ? 'Your vault is stored locally on this device using an embedded server.'
                        : `Connected to ${serverUrl}`}
                    </p>
                  </div>
                </div>
              </section>

              {/* Mode Selection */}
              {mode === 'local' ? (
                <section>
                  <h3 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">
                    Enable Multi-Device Sync
                  </h3>
                  <div className="bg-surface-900 rounded-lg p-4 space-y-4">
                    <p className="text-xs text-surface-400">
                      To sync your vault across multiple devices, connect to a remote NeoPass server.
                      All devices using the same server and account will stay in sync automatically.
                    </p>

                    <div>
                      <label className="text-xs text-surface-400 block mb-1">Server URL</label>
                      <div className="flex gap-2">
                        <input
                          type="url"
                          placeholder="https://pass.yourdomain.com"
                          value={urlInput}
                          onChange={e => { setUrlInput(e.target.value); setTestResult(null); }}
                          className="flex-1 bg-surface-800 border border-surface-700 text-surface-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-accent-600 placeholder-surface-600"
                        />
                        <button
                          onClick={handleTest}
                          disabled={testing || !urlInput.trim()}
                          className="px-3 py-2 bg-surface-700 hover:bg-surface-600 disabled:opacity-50 text-surface-300 text-xs rounded transition-colors"
                        >
                          {testing ? 'Testing…' : 'Test'}
                        </button>
                      </div>
                      {testResult && (
                        <p className={`text-xs mt-1.5 ${testResult.success ? 'text-green-400' : 'text-red-400'}`}>
                          {testResult.success ? 'Connection successful' : testResult.error}
                        </p>
                      )}
                    </div>

                    <button
                      onClick={handleSwitchToRemote}
                      disabled={switching || !urlInput.trim() || !testResult?.success}
                      className="w-full py-2 bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm rounded-md transition-colors"
                    >
                      {switching ? 'Switching…' : 'Connect to Remote Server'}
                    </button>

                    <div className="border-t border-surface-700 pt-3">
                      <p className="text-xs text-surface-500">
                        <strong className="text-surface-400">Note:</strong> Your local vault data will be preserved as a backup.
                        After switching, you'll need to register or log in on the remote server.
                        You can import your local data using the Import feature.
                      </p>
                    </div>
                  </div>
                </section>
              ) : (
                <section>
                  <h3 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">
                    Switch to Local Mode
                  </h3>
                  <div className="bg-surface-900 rounded-lg p-4 space-y-4">
                    <p className="text-xs text-surface-400">
                      Disconnect from the remote server and use a local vault on this device only.
                      Multi-device sync will stop working.
                    </p>
                    <button
                      onClick={handleSwitchToLocal}
                      disabled={switching}
                      className="w-full py-2 bg-surface-700 hover:bg-surface-600 disabled:opacity-50 text-surface-300 text-sm rounded-md transition-colors"
                    >
                      {switching ? 'Switching…' : 'Switch to Local Mode'}
                    </button>
                  </div>
                </section>
              )}

              {/* How It Works */}
              <section>
                <h3 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">How It Works</h3>
                <div className="bg-surface-900 rounded-lg p-4 space-y-2">
                  <div className="flex items-start gap-2">
                    <span className="text-surface-500 text-sm mt-0.5">1.</span>
                    <p className="text-xs text-surface-400">
                      <strong className="text-surface-300">Local mode</strong> — Your vault is stored on this device. No server setup needed. Data doesn't leave your machine.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-surface-500 text-sm mt-0.5">2.</span>
                    <p className="text-xs text-surface-400">
                      <strong className="text-surface-300">Remote mode</strong> — All devices connect to the same server. The server only stores encrypted blobs — it never sees your passwords.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-surface-500 text-sm mt-0.5">3.</span>
                    <p className="text-xs text-surface-400">
                      <strong className="text-surface-300">Zero-knowledge</strong> — Your master key is derived locally and never sent to the server. Even the server operator cannot read your vault.
                    </p>
                  </div>
                </div>
              </section>

              {/* Status messages */}
              {success && (
                <div className="bg-green-900/20 border border-green-700/30 rounded-lg px-4 py-3">
                  <p className="text-xs text-green-400">{success}</p>
                </div>
              )}
              {error && (
                <div className="bg-red-900/20 border border-red-700/30 rounded-lg px-4 py-3">
                  <p className="text-xs text-red-400">{error}</p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
