import React, { useEffect, useState } from 'react';
import { browserAPI, extractDomain } from '../lib/browser-api';
import { CredentialItem } from './components/CredentialItem';
import type {
  Credential,
  StatusResponseMessage,
  CredentialsResponseMessage,
  PasskeyInfo,
} from '../lib/messages';

type AppStatus = 'loading' | 'locked' | 'unlocked' | 'no-desktop-app';
type View = 'list' | 'detail' | 'passkeyDetail';

export function Popup() {
  const [status, setStatus] = useState<AppStatus>('loading');
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [repromptMode, setRepromptMode] = useState(false);
  const [repromptPassword, setRepromptPassword] = useState('');
  const [repromptError, setRepromptError] = useState('');
  const [repromptLoading, setRepromptLoading] = useState(false);
  const [pendingRepromptAction, setPendingRepromptAction] = useState<(() => void) | null>(null);
  const [repromptVerified, setRepromptVerified] = useState(false);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [currentDomain, setCurrentDomain] = useState<string>('');
  const [view, setView] = useState<View>('list');
  const [selectedCred, setSelectedCred] = useState<Credential | null>(null);
  const [selectedPasskey, setSelectedPasskey] = useState<PasskeyInfo | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  // Apply theme class to <html> element
  useEffect(() => {
    const html = document.documentElement;
    if (theme === 'dark') {
      html.classList.add('dark');
      html.style.background = '#0f172a';
    } else {
      html.classList.remove('dark');
      html.style.background = '#ffffff';
    }
  }, [theme]);

  useEffect(() => {
    init();

    // Listen for passkey creation notifications from background
    function onMessage(msg: { type?: string; rpId?: string }) {
      if (msg?.type === 'passkeyCreated') {
        setNotification(`Passkey saved for ${msg.rpId || 'site'}`);
        // Refresh passkey list
        if (currentDomain) {
          browserAPI.runtime.sendMessage({ type: 'passkeyList', rpId: currentDomain })
            .then((r: any) => setPasskeys(r?.passkeys ?? []))
            .catch(() => {});
        }
        setTimeout(() => setNotification(null), 4000);
      }
    }
    browserAPI.runtime.onMessage.addListener(onMessage);

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
        // Sync theme from desktop app
        if (resp?.theme) {
          setTheme(resp.theme);
        }
      } catch {
        // ignore polling errors
      }
    }, 3000);

    return () => {
      clearInterval(interval);
      browserAPI.runtime.onMessage.removeListener(onMessage);
    };
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

    if (statusResponse.theme) {
      setTheme(statusResponse.theme);
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

    // Fetch passkeys for current domain
    if (domain) {
      try {
        const pkResponse = await browserAPI.runtime.sendMessage({
          type: 'passkeyList',
          rpId: domain,
        }) as { passkeys?: PasskeyInfo[]; error?: string };
        setPasskeys(pkResponse?.passkeys ?? []);
      } catch {
        // Passkey listing may not be available
      }
    }
  }

  /** Gate an action behind reprompt verification if the credential requires it. */
  function withReprompt(credential: Credential, action: () => void) {
    if (!credential.reprompt) {
      action();
      return;
    }
    setPendingRepromptAction(() => action);
    setRepromptMode(true);
    setRepromptPassword('');
    setRepromptError('');
  }

  async function handleRepromptSubmit() {
    if (!repromptPassword.trim()) return;
    setRepromptLoading(true);
    setRepromptError('');
    try {
      const result = await browserAPI.runtime.sendMessage({
        type: 'verifyMasterPassword',
        email: '', // Server will use session email
        password: repromptPassword,
      }) as { verified?: boolean; error?: string };
      if (result?.verified) {
        setRepromptPassword('');
        setRepromptMode(false);
        setRepromptVerified(true);
        if (pendingRepromptAction) {
          pendingRepromptAction();
          setPendingRepromptAction(null);
        }
      } else {
        setRepromptError(result?.error || 'Incorrect password');
      }
    } catch {
      setRepromptError('Verification failed');
    } finally {
      setRepromptLoading(false);
    }
  }

  async function handleFill(credential: Credential) {
    const doFill = () => {
      browserAPI.runtime.sendMessage({
        type: 'fillCredential',
        username: credential.username,
        password: credential.password,
      });
      window.close();
    };
    withReprompt(credential, doFill);
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
    setRepromptVerified(false);
    if (cred.reprompt) {
      // Show detail view but gate sensitive fields behind reprompt
      setView('detail');
    } else {
      setView('detail');
    }
  }

  function handleSelectPasskey(pk: PasskeyInfo) {
    setSelectedPasskey(pk);
    setView('passkeyDetail');
  }

  function handleBackToList() {
    setView('list');
    setSelectedCred(null);
    setSelectedPasskey(null);
    setShowPassword(false);
  }

  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showGenerator, setShowGenerator] = useState(false);
  const [genLength, setGenLength] = useState(20);
  const [genUppercase, setGenUppercase] = useState(true);
  const [genLowercase, setGenLowercase] = useState(true);
  const [genDigits, setGenDigits] = useState(true);
  const [genSymbols, setGenSymbols] = useState(true);
  const [generatedPassword, setGeneratedPassword] = useState('');

  async function handleCopy(text: string, field: string) {
    try {
      await browserAPI.runtime.sendMessage({ type: 'secureCopy', text });
    } catch {
      await navigator.clipboard.writeText(text);
    }
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 1500);
  }

  async function handleLock() {
    try {
      await browserAPI.runtime.sendMessage({ type: 'lock' });
    } catch {
      // best effort
    }
    setStatus('locked');
    setCredentials([]);
  }

  function generatePassword() {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    let charset = '';
    if (genUppercase) charset += upper;
    if (genLowercase) charset += lower;
    if (genDigits) charset += digits;
    if (genSymbols) charset += symbols;
    if (!charset) charset = lower + digits;
    const arr = new Uint32Array(genLength);
    crypto.getRandomValues(arr);
    const pw = Array.from(arr, (v) => charset[v % charset.length]).join('');
    setGeneratedPassword(pw);
  }

  if (status === 'loading') {
    return (
      <div className="flex items-center justify-center h-96 bg-white dark:bg-surface-950 text-surface-900 dark:text-surface-100">
        <div className="animate-pulse text-surface-500 dark:text-surface-400">Loading...</div>
      </div>
    );
  }

  if (status === 'no-desktop-app') {
    return (
      <div className="flex flex-col items-center justify-center h-96 bg-white dark:bg-surface-950 text-surface-900 dark:text-surface-100 p-6">
        <div className="text-4xl mb-4">🔌</div>
        <h2 className="text-lg font-semibold mb-2">Desktop App Not Running</h2>
        <p className="text-sm text-surface-500 dark:text-surface-400 text-center mb-4">
          The LGI Pass desktop app must be running to use this
          extension.
        </p>
        <p className="text-xs text-surface-600 dark:text-surface-500 text-center">
          Launch the desktop app and try again.
        </p>
      </div>
    );
  }

  if (status === 'locked') {
    return (
      <div className="flex flex-col items-center justify-center h-96 bg-white dark:bg-surface-950 text-surface-900 dark:text-surface-100 p-6">
        <div className="text-4xl mb-4">🔒</div>
        <h2 className="text-lg font-semibold mb-3">Vault Locked</h2>
        <p className="text-sm text-surface-500 dark:text-surface-400 text-center mb-5">
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
            className="px-4 py-1.5 text-sm text-surface-500 dark:text-surface-400 hover:text-surface-800 dark:hover:text-surface-200 transition-colors"
          >
            Check Again
          </button>
        </div>
      </div>
    );
  }

  // Detail view
  if (view === 'detail' && selectedCred) {
    const needsReprompt = !!selectedCred.reprompt && !repromptVerified;
    return (
      <div className="flex flex-col h-full bg-white dark:bg-surface-950 text-surface-900 dark:text-surface-100">
        {/* Header */}
        <div className="px-4 py-3 border-b border-surface-200 dark:border-surface-800 flex items-center gap-3">
          <button onClick={handleBackToList} className="text-surface-500 dark:text-surface-400 hover:text-surface-800 dark:hover:text-surface-200 text-sm">
            ← Back
          </button>
          <span className="text-sm font-medium text-surface-900 dark:text-surface-100 truncate flex-1">
            {selectedCred.name || selectedCred.domain}
          </span>
        </div>

        {needsReprompt ? (
          /* Reprompt gate — hide all sensitive fields until re-authenticated */
          <div className="flex-1 flex flex-col items-center justify-center px-6 py-8">
            <div className="text-3xl mb-3">🔒</div>
            <p className="text-sm text-surface-600 dark:text-surface-300 text-center mb-4">
              This entry requires re-authentication to view
            </p>
            <form onSubmit={(e) => { e.preventDefault(); handleRepromptSubmit(); }} className="w-full max-w-[240px] space-y-2">
              <input
                type="password"
                value={repromptPassword}
                onChange={(e) => setRepromptPassword(e.target.value)}
                placeholder="Master password"
                autoFocus
                className="w-full px-3 py-2 bg-surface-100 dark:bg-surface-800 border border-surface-300 dark:border-surface-700 rounded text-sm text-surface-900 dark:text-surface-100 placeholder-surface-400 dark:placeholder-surface-500 focus:outline-none focus:border-accent-500"
              />
              {repromptError && <p className="text-xs text-red-500 dark:text-red-400">{repromptError}</p>}
              <button
                type="submit"
                disabled={repromptLoading}
                className="w-full py-2 bg-accent-500 hover:bg-accent-600 disabled:opacity-50 text-white rounded text-sm font-medium transition-colors"
              >
                {repromptLoading ? 'Verifying...' : 'Unlock'}
              </button>
            </form>
          </div>
        ) : (
        /* Fields — shown after reprompt verified (or if no reprompt required) */
        <>
        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
          {/* Name */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Name</label>
            <div className="flex items-center justify-between">
              <span className="text-sm text-surface-900 dark:text-surface-100">{selectedCred.name || '—'}</span>
              {selectedCred.name && <button onClick={() => handleCopy(selectedCred.name, 'name')} className={`text-[10px] transition-colors ${copiedField === 'name' ? 'text-green-600 dark:text-green-400' : 'text-surface-500 hover:text-accent-400'}`}>{copiedField === 'name' ? 'Copied!' : 'Copy'}</button>}
            </div>
          </div>

          {/* Username */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Username</label>
            <div className="flex items-center justify-between">
              <span className="text-sm text-surface-900 dark:text-surface-100">{selectedCred.username || '—'}</span>
              {selectedCred.username && <button onClick={() => handleCopy(selectedCred.username, 'username')} className={`text-[10px] transition-colors ${copiedField === 'username' ? 'text-green-600 dark:text-green-400' : 'text-surface-500 hover:text-accent-400'}`}>{copiedField === 'username' ? 'Copied!' : 'Copy'}</button>}
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Password</label>
            <div className="flex items-center justify-between">
              <span className="text-sm text-surface-900 dark:text-surface-100 font-mono">
                {showPassword ? selectedCred.password : '••••••••••••'}
              </span>
              <div className="flex gap-2">
                <button onClick={() => setShowPassword(!showPassword)} className="text-[10px] text-surface-500 hover:text-accent-400">
                  {showPassword ? 'Hide' : 'Show'}
                </button>
                <button onClick={() => handleCopy(selectedCred.password, 'password')} className={`text-[10px] transition-colors ${copiedField === 'password' ? 'text-green-600 dark:text-green-400' : 'text-surface-500 hover:text-accent-400'}`}>{copiedField === 'password' ? 'Copied!' : 'Copy'}</button>
              </div>
            </div>
          </div>

          {/* Website */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Website</label>
            <div className="flex items-center justify-between">
              <span className="text-sm text-accent-400">{selectedCred.uri || '—'}</span>
              {selectedCred.uri && <button onClick={() => handleCopy(selectedCred.uri, 'uri')} className={`text-[10px] transition-colors ${copiedField === 'uri' ? 'text-green-600 dark:text-green-400' : 'text-surface-500 hover:text-accent-400'}`}>{copiedField === 'uri' ? 'Copied!' : 'Copy'}</button>}
            </div>
          </div>

          {/* Notes */}
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Notes</label>
            <span className="text-sm text-surface-700 dark:text-surface-300">{selectedCred.notes || '—'}</span>
          </div>
        </div>

        {/* Fill button */}
        <div className="px-4 py-3 border-t border-surface-200 dark:border-surface-800">
          <button
            onClick={() => handleFill(selectedCred)}
            className="w-full py-2 bg-accent-500 hover:bg-accent-600 text-white rounded-lg transition-colors text-sm font-medium"
          >
            Fill on Page
          </button>
        </div>
        </>
        )}
      </div>
    );
  }

  // Passkey detail view
  if (view === 'passkeyDetail' && selectedPasskey) {
    return (
      <div className="flex flex-col h-full bg-white dark:bg-surface-950 text-surface-900 dark:text-surface-100">
        <div className="px-4 py-3 border-b border-surface-200 dark:border-surface-800 flex items-center gap-3">
          <button onClick={handleBackToList} className="text-surface-500 dark:text-surface-400 hover:text-surface-800 dark:hover:text-surface-200 text-sm">
            ← Back
          </button>
          <span className="text-sm font-medium text-surface-900 dark:text-surface-100 truncate flex-1">
            Passkey — {selectedPasskey.rpName || selectedPasskey.rpId}
          </span>
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Website</label>
            <span className="text-sm text-surface-900 dark:text-surface-100">{selectedPasskey.rpName || selectedPasskey.rpId}</span>
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">RP ID</label>
            <span className="text-sm text-surface-900 dark:text-surface-100">{selectedPasskey.rpId}</span>
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Username</label>
            <span className="text-sm text-surface-900 dark:text-surface-100">{selectedPasskey.username || '—'}</span>
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Display Name</label>
            <span className="text-sm text-surface-900 dark:text-surface-100">{selectedPasskey.displayName || '—'}</span>
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Created</label>
            <span className="text-sm text-surface-900 dark:text-surface-100">{selectedPasskey.createdAt ? new Date(selectedPasskey.createdAt).toLocaleDateString() : '—'}</span>
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 block mb-1">Credential ID</label>
            <span className="text-xs text-surface-500 dark:text-surface-400 font-mono break-all">{selectedPasskey.credentialId}</span>
          </div>
        </div>
      </div>
    );
  }

  const filtered = searchQuery.trim()
    ? credentials.filter((c) => {
        const q = searchQuery.toLowerCase();
        return (c.name?.toLowerCase().includes(q) || c.username?.toLowerCase().includes(q) || c.domain?.toLowerCase().includes(q) || c.uri?.toLowerCase().includes(q));
      })
    : credentials;
  const matchedCreds = filtered.filter((c) => c.matched);
  const otherCreds = filtered.filter((c) => !c.matched);

  // Sort favorites first within each group
  const sortFavFirst = (a: Credential, b: Credential) =>
    (b.is_favorite ? 1 : 0) - (a.is_favorite ? 1 : 0);
  matchedCreds.sort(sortFavFirst);
  otherCreds.sort(sortFavFirst);

  // Unlocked state
  return (
    <div className="flex flex-col h-full bg-white dark:bg-surface-950 text-surface-900 dark:text-surface-100">
      {/* Header – sticky */}
      <div className="px-4 py-3 border-b border-surface-200 dark:border-surface-800 shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-accent-400 text-sm font-bold">LGI Pass</span>
            <span className="text-xs text-surface-400 dark:text-surface-500">•</span>
            <span className="text-sm text-surface-600 dark:text-surface-300 truncate max-w-[200px]">
              {currentDomain || 'No domain'}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => { setShowGenerator(!showGenerator); if (!generatedPassword) generatePassword(); }}
              className="text-xs text-surface-500 dark:text-surface-400 hover:text-surface-800 dark:hover:text-surface-200 transition-colors"
              title="Password generator"
            >
              ⚡
            </button>
            <button
              onClick={handleLock}
              className="text-xs text-surface-500 dark:text-surface-400 hover:text-surface-800 dark:hover:text-surface-200 transition-colors"
              title="Lock vault"
            >
              🔒
            </button>
            <button
              onClick={handleOpenApp}
              className="text-xs text-surface-500 dark:text-surface-400 hover:text-surface-800 dark:hover:text-surface-200 transition-colors"
              title="Open desktop app"
            >
              Open App
            </button>
          </div>
        </div>
        {/* Search bar */}
        <div className="mt-2">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search vault…"
            className="w-full px-3 py-1.5 bg-surface-100 dark:bg-surface-800 border border-surface-300 dark:border-surface-700 rounded text-sm text-surface-900 dark:text-surface-100 placeholder-surface-400 dark:placeholder-surface-500 focus:outline-none focus:border-accent-500"
          />
        </div>
      </div>

      {/* Password generator panel */}
      {showGenerator && (
        <div className="px-4 py-3 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-900 space-y-2 shrink-0">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-surface-700 dark:text-surface-300">Password Generator</span>
            <button onClick={() => setShowGenerator(false)} className="text-xs text-surface-500 hover:text-surface-800 dark:hover:text-surface-200">✕</button>
          </div>
          <div className="font-mono text-sm text-surface-900 dark:text-surface-100 bg-surface-100 dark:bg-surface-800 rounded px-2 py-1.5 break-all select-all">
            {generatedPassword}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={generatePassword} className="px-2 py-1 text-xs bg-accent-500 hover:bg-accent-600 text-white rounded transition-colors">
              Regenerate
            </button>
            <button onClick={() => handleCopy(generatedPassword, 'generated')} className={`px-2 py-1 text-xs rounded transition-colors ${copiedField === 'generated' ? 'text-green-600 dark:text-green-400 bg-surface-100 dark:bg-surface-800' : 'text-surface-700 dark:text-surface-300 bg-surface-100 dark:bg-surface-800 hover:text-surface-900 dark:hover:text-surface-100'}`}>
              {copiedField === 'generated' ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="flex items-center gap-3">
            <label className="text-xs text-surface-500 dark:text-surface-400 flex items-center gap-1">
              Length
              <input type="range" min={8} max={64} value={genLength} onChange={(e) => { setGenLength(+e.target.value); }} onMouseUp={generatePassword} className="w-16 accent-accent-500" />
              <span className="text-surface-700 dark:text-surface-300 w-5 text-right">{genLength}</span>
            </label>
          </div>
          <div className="flex gap-3 text-xs text-surface-500 dark:text-surface-400">
            <label className="flex items-center gap-1"><input type="checkbox" checked={genUppercase} onChange={(e) => { setGenUppercase(e.target.checked); }} className="accent-accent-500" />A-Z</label>
            <label className="flex items-center gap-1"><input type="checkbox" checked={genLowercase} onChange={(e) => { setGenLowercase(e.target.checked); }} className="accent-accent-500" />a-z</label>
            <label className="flex items-center gap-1"><input type="checkbox" checked={genDigits} onChange={(e) => { setGenDigits(e.target.checked); }} className="accent-accent-500" />0-9</label>
            <label className="flex items-center gap-1"><input type="checkbox" checked={genSymbols} onChange={(e) => { setGenSymbols(e.target.checked); }} className="accent-accent-500" />!@#</label>
          </div>
        </div>
      )}

      {/* Credentials list */}
      <div className="flex-1 overflow-y-auto">
        {credentials.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 px-4">
            <div className="text-3xl mb-3">🔑</div>
            <p className="text-sm text-surface-500 dark:text-surface-400 text-center">
              No saved logins
            </p>
          </div>
        ) : (
          <div>
            {/* Matched credentials for current site */}
            {matchedCreds.length > 0 && (
              <div>
                <div className="px-4 py-1.5 text-[10px] uppercase tracking-wider text-accent-400 font-semibold bg-surface-50 dark:bg-surface-900/50">
                  For this site
                </div>
                {matchedCreds.map((cred) => (
                  <CredentialItem
                    key={cred.id}
                    credential={cred}
                    onSelect={handleSelectCred}
                    onFill={handleFill}
                  />
                ))}
              </div>
            )}

            {/* All other credentials */}
            {otherCreds.length > 0 && (
              <div>
                <div className="px-4 py-1.5 text-[10px] uppercase tracking-wider text-surface-600 dark:text-surface-500 font-semibold bg-surface-50 dark:bg-surface-900/50">
                  {matchedCreds.length > 0 ? 'Other logins' : 'All logins'}
                </div>
                {otherCreds.map((cred) => (
                  <CredentialItem
                    key={cred.id}
                    credential={cred}
                    showDomain
                    onSelect={handleSelectCred}
                    onFill={handleFill}
                    fillButtonClass="bg-surface-300 hover:bg-surface-400 dark:bg-surface-700 dark:hover:bg-surface-600"
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Passkeys for current site */}
        {passkeys.length > 0 && (
          <div>
            <div className="px-4 py-1.5 text-[10px] uppercase tracking-wider text-accent-400 font-semibold bg-surface-50 dark:bg-surface-900/50">
              Passkeys{currentDomain ? ` for ${currentDomain}` : ''}
            </div>
            {passkeys.map((pk) => (
              <div
                key={pk.credentialId}
                onClick={() => handleSelectPasskey(pk)}
                className="flex items-center justify-between px-4 py-2.5 hover:bg-surface-100 dark:hover:bg-surface-900 transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-2.5 flex-1 min-w-0">
                  <span className="text-lg">🪪</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-surface-900 dark:text-surface-100 truncate">
                      {pk.username || pk.displayName || 'Passkey'}
                    </p>
                    <p className="text-xs text-surface-500 dark:text-surface-400 truncate">
                      {pk.rpName || pk.rpId}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Notification banner */}
      {notification && (
        <div className="px-4 py-2 bg-green-100 dark:bg-green-600/20 border-t border-green-300 dark:border-green-500/30 text-green-700 dark:text-green-400 text-xs text-center shrink-0">
          {notification}
        </div>
      )}

      {/* Reprompt overlay */}
      {repromptMode && (
        <div className="absolute inset-0 bg-white/95 dark:bg-surface-950/95 flex flex-col items-center justify-center p-6 z-50">
          <div className="text-2xl mb-3">🔒</div>
          <h3 className="text-sm font-semibold text-surface-900 dark:text-surface-100 mb-1">Re-authentication Required</h3>
          <p className="text-[10px] text-surface-500 dark:text-surface-400 text-center mb-4">
            This entry requires your master password.
          </p>
          <form onSubmit={(e) => { e.preventDefault(); handleRepromptSubmit(); }} className="w-full max-w-[240px] space-y-2">
            <input
              type="password"
              value={repromptPassword}
              onChange={(e) => setRepromptPassword(e.target.value)}
              autoFocus
              placeholder="Master password"
              className="w-full px-3 py-2 rounded-md bg-surface-100 dark:bg-surface-800 border border-surface-300 dark:border-surface-700 text-surface-900 dark:text-surface-100 text-sm placeholder-surface-400 dark:placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
            />
            {repromptError && <p className="text-[10px] text-red-500 dark:text-red-400">{repromptError}</p>}
            <button
              type="submit"
              disabled={repromptLoading || !repromptPassword.trim()}
              className="w-full py-2 bg-accent-500 hover:bg-accent-600 text-white rounded-md text-sm font-medium disabled:opacity-50 transition-colors"
            >
              {repromptLoading ? 'Verifying…' : 'Verify'}
            </button>
            <button
              type="button"
              onClick={() => {
                setRepromptMode(false);
                setPendingRepromptAction(null);
              }}
              className="w-full py-1.5 text-sm text-surface-500 dark:text-surface-400 hover:text-surface-800 dark:hover:text-surface-200 transition-colors"
            >
              Cancel
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
