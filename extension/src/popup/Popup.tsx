import React, { useEffect, useState } from 'react';
import { browserAPI, extractDomain } from '../lib/browser-api';
import type {
  Credential,
  StatusResponseMessage,
  CredentialsResponseMessage,
} from '../lib/messages';

type AppStatus = 'loading' | 'locked' | 'unlocked' | 'no-desktop-app';

export function Popup() {
  const [status, setStatus] = useState<AppStatus>('loading');
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [currentDomain, setCurrentDomain] = useState<string>('');

  useEffect(() => {
    init();
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

    // Fetch credentials for current domain
    if (domain) {
      const credResponse = (await browserAPI.runtime.sendMessage({
        type: 'requestCredentials',
        domain,
      })) as CredentialsResponseMessage;

      setCredentials(credResponse?.credentials ?? []);
    }
  }

  async function handleFill(credential: Credential) {
    const tabs = await browserAPI.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (tabs[0]?.id !== undefined) {
      await browserAPI.tabs.sendMessage(tabs[0].id, {
        type: 'autofill',
        username: credential.username,
        password: credential.password,
      });
      window.close();
    }
  }

  async function handleLock() {
    // Lock via server — clears session; user must unlock from desktop app
    await browserAPI.runtime.sendMessage({ type: 'lock' });
    setStatus('locked');
    setCredentials([]);
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
            onClick={handleLock}
            className="text-surface-400 hover:text-surface-200 transition-colors text-sm"
            title="Lock vault"
          >
            🔒
          </button>
        </div>
      </div>

      {/* Credentials list */}
      <div className="flex-1 overflow-y-auto">
        {credentials.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 px-4">
            <div className="text-3xl mb-3">🔑</div>
            <p className="text-sm text-surface-400 text-center">
              No saved logins for {currentDomain || 'this site'}
            </p>
          </div>
        ) : (
          <div className="py-2">
            {credentials.map((cred) => (
              <div
                key={cred.id}
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
                  onClick={() => handleFill(cred)}
                  className="px-3 py-1 text-xs bg-accent-500 hover:bg-accent-600 text-white rounded transition-colors opacity-0 group-hover:opacity-100"
                >
                  Fill
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Bottom toolbar */}
      <div className="px-4 py-3 border-t border-surface-800 flex items-center justify-between">
        <button
          onClick={handleOpenApp}
          className="text-xs text-surface-400 hover:text-surface-200 transition-colors"
          title="Open desktop app"
        >
          Open App
        </button>
      </div>
    </div>
  );
}
