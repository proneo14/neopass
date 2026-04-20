import React, { useEffect, useState } from 'react';
import { browserAPI, extractDomain } from '../lib/browser-api';
import type {
  Credential,
  StatusResponseMessage,
  CredentialsResponseMessage,
} from '../lib/messages';

type AppStatus = 'loading' | 'locked' | 'unlocked' | 'no-desktop-app';
type View = 'list' | 'detail';

export function Popup() {
  const [status, setStatus] = useState<AppStatus>('loading');
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [currentDomain, setCurrentDomain] = useState<string>('');
  const [view, setView] = useState<View>('list');
  const [selectedCred, setSelectedCred] = useState<Credential | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    init();

    // Poll server status every 3s so extension mirrors app lock/unlock in real time
    const interval = setInterval(async () => {
      try {
        const resp = (await browserAPI.runtime.sendMessage({
          type: 'getStatus',
        })) as StatusResponseMessage | null;

        if (!resp || resp.status === 'no-desktop-app') {
          setStatus('no-desktop-app');
          setCredentials([]);
        } else if (resp.status === 'locked') {
          setStatus('locked');
          setCredentials([]);
        } else if (resp.status === 'unlocked') {
          // If we were locked and now unlocked, re-init to fetch credentials
          setStatus((prev) => {
            if (prev !== 'unlocked') {
              init();
            }
            return 'unlocked';
          });
        }
      } catch {
        // ignore polling errors
      }
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  async function init() {
    // Get current tab domain
    const tabs = await browserAPI.tabs.query({
      active: true,
      currentWindow: true,
    });
    const url = tabs[0]?.url ?? '';
    // Don't try to match credentials for browser internal pages
    const isInternalPage = url.startsWith('chrome://') || url.startsWith('edge://') || url.startsWith('about:') || url.startsWith('chrome-extension://');
    const domain = isInternalPage ? '' : (extractDomain(url) ?? '');
    setCurrentDomain(domain);

    // Check connection status
    let statusResponse: StatusResponseMessage | null = null;
    try {
      statusResponse = (await browserAPI.runtime.sendMessage({
        type: 'getStatus',
      })) as StatusResponseMessage;
    } catch {
      // Native host not available
    }

    if (!statusResponse || statusResponse.status === 'no-desktop-app') {
      setStatus('no-desktop-app');
      return;
    }

    if (statusResponse.status === 'locked') {
      setStatus('locked');
      return;
    }

    setStatus('unlocked');

    // Fetch all credentials (server returns all with matched flag)
    const credResponse = (await browserAPI.runtime.sendMessage({
      type: 'requestCredentials',
      domain: domain || '_all_',
    })) as CredentialsResponseMessage;

    setCredentials(credResponse?.credentials ?? []);
  }

  async function handleFill(credential: Credential) {
    // Fire-and-forget: background handles the fill after popup closes.
    // Don't await — close immediately so the page regains focus.
    browserAPI.runtime.sendMessage({
      type: 'fillCredential',
      username: credential.username,
      password: credential.password,
    });
    window.close();
  }

  async function handleCheckStatus() {
    // Re-check server status — if desktop app has been unlocked, session is back
    setStatus('loading');
    await init();
  }

  async function handleOpenApp() {
    try {
      await browserAPI.runtime.sendMessage({ type: 'openApp' });
    } catch {
      // Best effort
    }
  }

  function handleSelectCred(cred: Credential) {
    setSelectedCred(cred);
    setShowPassword(false);
    setView('detail');
  }

  function handleBackToList() {
    setView('list');
    setSelectedCred(null);
    setShowPassword(false);
  }

  const [copiedField, setCopiedField] = useState<string | null>(null);

  async function handleCopy(text: string, field: string) {
    try {
      await browserAPI.runtime.sendMessage({ type: 'secureCopy', text });
    } catch {
      await navigator.clipboard.writeText(text);
    }
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 1500);
  }

  if (status === 'loading') {
    return (
      <div className="flex items-center justify-center h-96 bg-surface-950 text-surface-100">
        <div className="animate-pulse text-surface-400">Loading...</div>
      </div>
    );
  }

  if (status === 'no-desktop-app') {
    return (
      <div className="flex flex-col items-center justify-center h-96 bg-surface-950 text-surface-100 p-6">
        <div className="text-4xl mb-4">🔌</div>
        <h2 className="text-lg font-semibold mb-2">Desktop App Not Running</h2>
        <p className="text-sm text-surface-400 text-center mb-4">
          The Quantum Password Manager desktop app must be running to use this
          extension.
        </p>
        <p className="text-xs text-surface-500 text-center">
          Launch the desktop app and try again.
        </p>
      </div>
    );
  }

  if (status === 'locked') {
    return (
      <div className="flex flex-col items-center justify-center h-96 bg-surface-950 text-surface-100 p-6">
        <div className="text-4xl mb-4">🔒</div>
        <h2 className="text-lg font-semibold mb-3">Vault Locked</h2>
        <p className="text-sm text-surface-400 text-center mb-5">
          Open the desktop app and log in to unlock.
        </p>
        <div className="flex flex-col gap-2 w-full max-w-[200px]">
          <button
            onClick={handleOpenApp}
            className="px-6 py-2 bg-accent-500 hover:bg-accent-600 text-white rounded-lg transition-colors font-medium"
          >
            Open App
          </button>
          <button
            onClick={handleCheckStatus}
            className="px-4 py-1.5 text-sm text-surface-400 hover:text-surface-200 transition-colors"
          >
            Check Again
          </button>
        </div>
      </div>
    );
  }

  // Detail view
  if (view === 'detail' && selectedCred) {
    return (
      <div className="flex flex-col h-full bg-surface-950 text-surface-100">
        {/* Header */}
        <div className="px-4 py-3 border-b border-surface-800 flex items-center gap-3">
          <button onClick={handleBackToList} className="text-surface-400 hover:text-surface-200 text-sm">
            ← Back
          </button>
          <span className="text-sm font-medium text-surface-100 truncate flex-1">
            {selectedCred.name || selectedCred.domain}
          </span>
        </div>

        {/* Fields */}
        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
          {/* Name */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-500 block mb-1">Name</label>
            <div className="flex items-center justify-between">
              <span className="text-sm text-surface-100">{selectedCred.name || '—'}</span>
              {selectedCred.name && <button onClick={() => handleCopy(selectedCred.name, 'name')} className={`text-[10px] transition-colors ${copiedField === 'name' ? 'text-green-400' : 'text-surface-500 hover:text-accent-400'}`}>{copiedField === 'name' ? 'Copied!' : 'Copy'}</button>}
            </div>
          </div>

          {/* Username */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-500 block mb-1">Username</label>
            <div className="flex items-center justify-between">
              <span className="text-sm text-surface-100">{selectedCred.username || '—'}</span>
              {selectedCred.username && <button onClick={() => handleCopy(selectedCred.username, 'username')} className={`text-[10px] transition-colors ${copiedField === 'username' ? 'text-green-400' : 'text-surface-500 hover:text-accent-400'}`}>{copiedField === 'username' ? 'Copied!' : 'Copy'}</button>}
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-500 block mb-1">Password</label>
            <div className="flex items-center justify-between">
              <span className="text-sm text-surface-100 font-mono">
                {showPassword ? selectedCred.password : '••••••••••••'}
              </span>
              <div className="flex gap-2">
                <button onClick={() => setShowPassword(!showPassword)} className="text-[10px] text-surface-500 hover:text-accent-400">
                  {showPassword ? 'Hide' : 'Show'}
                </button>
                <button onClick={() => handleCopy(selectedCred.password, 'password')} className={`text-[10px] transition-colors ${copiedField === 'password' ? 'text-green-400' : 'text-surface-500 hover:text-accent-400'}`}>{copiedField === 'password' ? 'Copied!' : 'Copy'}</button>
              </div>
            </div>
          </div>

          {/* Website */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-500 block mb-1">Website</label>
            <div className="flex items-center justify-between">
              <span className="text-sm text-accent-400">{selectedCred.uri || '—'}</span>
              {selectedCred.uri && <button onClick={() => handleCopy(selectedCred.uri, 'uri')} className={`text-[10px] transition-colors ${copiedField === 'uri' ? 'text-green-400' : 'text-surface-500 hover:text-accent-400'}`}>{copiedField === 'uri' ? 'Copied!' : 'Copy'}</button>}
            </div>
          </div>

          {/* Notes */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-500 block mb-1">Notes</label>
            <span className="text-sm text-surface-300">{selectedCred.notes || '—'}</span>
          </div>
        </div>

        {/* Fill button */}
        <div className="px-4 py-3 border-t border-surface-800">
          <button
            onClick={() => handleFill(selectedCred)}
            className="w-full py-2 bg-accent-500 hover:bg-accent-600 text-white rounded-lg transition-colors text-sm font-medium"
          >
            Fill on Page
          </button>
        </div>
      </div>
    );
  }

  const matchedCreds = credentials.filter((c) => c.matched);
  const otherCreds = credentials.filter((c) => !c.matched);

  // Unlocked state
  return (
    <div className="flex flex-col h-full bg-surface-950 text-surface-100">
      {/* Header */}
      <div className="px-4 py-3 border-b border-surface-800">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-accent-400 text-sm font-bold">QPM</span>
            <span className="text-xs text-surface-500">•</span>
            <span className="text-sm text-surface-300 truncate max-w-[200px]">
              {currentDomain || 'No domain'}
            </span>
          </div>
          <button
            onClick={handleOpenApp}
            className="text-xs text-surface-400 hover:text-surface-200 transition-colors"
            title="Open desktop app"
          >
            Open App
          </button>
        </div>
      </div>

      {/* Credentials list */}
      <div className="flex-1 overflow-y-auto">
        {credentials.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 px-4">
            <div className="text-3xl mb-3">🔑</div>
            <p className="text-sm text-surface-400 text-center">
              No saved logins
            </p>
          </div>
        ) : (
          <div>
            {/* Matched credentials for current site */}
            {matchedCreds.length > 0 && (
              <div>
                <div className="px-4 py-1.5 text-[10px] uppercase tracking-wider text-accent-400 font-semibold bg-surface-900/50">
                  For this site
                </div>
                {matchedCreds.map((cred) => (
                  <div
                    key={cred.id}
                    onClick={() => handleSelectCred(cred)}
                    className="flex items-center justify-between px-4 py-2.5 hover:bg-surface-900 transition-colors cursor-pointer group"
                  >
                    <div className="flex-1 min-w-0 mr-3">
                      <p className="text-sm font-medium text-surface-100 truncate">
                        {cred.name || cred.domain}
                      </p>
                      <p className="text-xs text-surface-400 truncate">
                        {cred.username}
                      </p>
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleFill(cred); }}
                      className="px-3 py-1 text-xs bg-accent-500 hover:bg-accent-600 text-white rounded transition-colors opacity-0 group-hover:opacity-100"
                    >
                      Fill
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* All other credentials */}
            {otherCreds.length > 0 && (
              <div>
                <div className="px-4 py-1.5 text-[10px] uppercase tracking-wider text-surface-500 font-semibold bg-surface-900/50">
                  {matchedCreds.length > 0 ? 'Other logins' : 'All logins'}
                </div>
                {otherCreds.map((cred) => (
                  <div
                    key={cred.id}
                    onClick={() => handleSelectCred(cred)}
                    className="flex items-center justify-between px-4 py-2.5 hover:bg-surface-900 transition-colors cursor-pointer group"
                  >
                    <div className="flex-1 min-w-0 mr-3">
                      <p className="text-sm font-medium text-surface-100 truncate">
                        {cred.name || cred.domain}
                      </p>
                      <p className="text-xs text-surface-400 truncate">
                        {cred.username}{cred.domain ? ` · ${cred.domain}` : ''}
                      </p>
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleFill(cred); }}
                      className="px-3 py-1 text-xs bg-surface-700 hover:bg-surface-600 text-white rounded transition-colors opacity-0 group-hover:opacity-100"
                    >
                      Fill
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
