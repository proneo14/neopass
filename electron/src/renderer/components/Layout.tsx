import React, { useEffect, useRef, useCallback, useState, useMemo } from 'react';
import { Outlet, useNavigate, Link } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TitleBar } from './TitleBar';
import { ShortcutHelp } from './ShortcutHelp';
import { PasswordGenerator } from './PasswordGenerator';
import { useAuthStore } from '../store/authStore';
import { useNotificationStore } from '../store/notificationStore';
import { useSyncStore } from '../store/syncStore';
import { useVaultStore } from '../store/vaultStore';
import { performSync } from '../utils/sync';
import { useKeyboardShortcuts } from '../utils/keyboard';
import type { ShortcutDef } from '../utils/keyboard';

export function Layout() {
  const navigate = useNavigate();
  const logout = useAuthStore((s) => s.logout);
  const lock = useAuthStore((s) => s.lock);
  const timeoutAction = useAuthStore((s) => s.timeoutAction);
  const autoLockMinutes = useAuthStore((s) => s.autoLockMinutes);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastActivityRef = useRef(Date.now());

  const pending2FA = useNotificationStore((s) => s.pending2FACount);
  const pendingInvites = useNotificationStore((s) => s.pendingInviteCount);
  const dismissed = useNotificationStore((s) => s.dismissed);
  const dismiss = useNotificationStore((s) => s.dismiss);
  const totalNotifs = pending2FA + pendingInvites;

  const resetTimer = useCallback(() => {
    lastActivityRef.current = Date.now();
    if (timerRef.current) clearTimeout(timerRef.current);
    if (autoLockMinutes > 0) {
      timerRef.current = setTimeout(() => {
        if (timeoutAction === 'logout') {
          logout();
          navigate('/login');
        } else {
          lock();
          navigate('/login', { state: { locked: true } });
        }
      }, autoLockMinutes * 60_000);
    }
  }, [autoLockMinutes, timeoutAction, logout, lock, navigate]);

  useEffect(() => {
    if (autoLockMinutes <= 0) return;
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'] as const;
    events.forEach((e) => window.addEventListener(e, resetTimer, { passive: true }));
    resetTimer();
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      events.forEach((e) => window.removeEventListener(e, resetTimer));
    };
  }, [autoLockMinutes, resetTimer]);

  // ── Auto-sync timer ─────────────────────────────────────────────────
  const token = useAuthStore((s) => s.token);
  const masterKeyHex = useAuthStore((s) => s.masterKeyHex);
  const autoSyncInterval = useSyncStore((s) => s.autoSyncInterval);
  const syncStatus = useSyncStore((s) => s.status);
  const deviceId = useSyncStore((s) => s.deviceId);
  const setDeviceId = useSyncStore((s) => s.setDeviceId);

  // Initialize device ID once on mount
  useEffect(() => {
    if (!deviceId && token) {
      window.api.sync.getDeviceId().then((id: string) => setDeviceId(id));
    }
  }, [deviceId, token, setDeviceId]);

  useEffect(() => {
    if (!token || !masterKeyHex || !deviceId || autoSyncInterval <= 0) return;

    const doSync = () => {
      const currentStatus = useSyncStore.getState().status;
      if (currentStatus === 'syncing') return; // skip if already in-flight
      performSync(token, masterKeyHex, deviceId).catch(() => {});
    };

    // Run an initial sync shortly after login
    const initial = setTimeout(doSync, 3000);
    const interval = setInterval(doSync, autoSyncInterval * 1000);

    return () => {
      clearTimeout(initial);
      clearInterval(interval);
    };
  }, [token, masterKeyHex, deviceId, autoSyncInterval]);

  // Force-logout when the server revokes tokens (e.g. after emergency takeover)
  useEffect(() => {
    const cleanup = (window as any).api?.onForceLogout?.(() => {
      logout();
      navigate('/login');
    });
    return () => { cleanup?.(); };
  }, [logout, navigate]);

  // Lock vault when main process sends auto-lock signal (inactivity or extension-triggered)
  useEffect(() => {
    const cleanup = (window as any).api?.onAutoLocked?.(() => {
      logout();
      navigate('/login');
    });
    return () => { cleanup?.(); };
  }, [logout, navigate]);

  // ── Keyboard shortcuts ──────────────────────────────────────────────
  const [showShortcutHelp, setShowShortcutHelp] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const entryFields = useVaultStore((s) => s.entryFields);

  const shortcuts: ShortcutDef[] = useMemo(() => [
    {
      key: 'n', ctrl: true, description: 'New vault entry', category: 'Vault',
      action: () => {
        navigate('/vault');
        // Dispatch a custom event that the Vault page listens for
        setTimeout(() => window.dispatchEvent(new CustomEvent('lgi-new-entry')), 100);
      },
    },
    {
      key: 'f', ctrl: true, description: 'Focus search bar', category: 'Navigation',
      action: () => {
        const el = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]');
        el?.focus();
      },
    },
    {
      key: 'g', ctrl: true, description: 'Open password generator', category: 'General',
      action: () => setShowGenerator((v) => !v),
    },
    {
      key: 'l', ctrl: true, description: 'Lock vault', category: 'General',
      action: () => { logout(); navigate('/login'); },
    },
    {
      key: ',', ctrl: true, description: 'Open settings', category: 'Navigation',
      action: () => navigate('/settings'),
    },
    {
      key: 'c', ctrl: true, shift: true, description: 'Copy password', category: 'Entry',
      action: () => {
        const match = window.location.hash.match(/\/vault\/([^/]+)$/);
        if (match) {
          const fields = entryFields[match[1]];
          if (fields?.password) window.api?.clipboard?.copySecure?.(fields.password);
        }
      },
    },
    {
      key: 'u', ctrl: true, shift: true, description: 'Copy username', category: 'Entry',
      action: () => {
        const match = window.location.hash.match(/\/vault\/([^/]+)$/);
        if (match) {
          const fields = entryFields[match[1]];
          if (fields?.username) navigator.clipboard.writeText(fields.username);
        }
      },
    },
    {
      key: 'Escape', description: 'Close modal / dialog', category: 'General',
      action: () => {
        setShowShortcutHelp(false);
        setShowGenerator(false);
      },
    },
    {
      key: '/', ctrl: true, shift: true, description: 'Show keyboard shortcuts', category: 'General',
      action: () => setShowShortcutHelp((v) => !v),
    },
  ], [navigate, logout, entryFields]);

  useKeyboardShortcuts(shortcuts);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-surface-950">
      <TitleBar />
      <Sidebar />
      <main className="flex-1 overflow-auto bg-surface-950 p-6 pt-10">
        {totalNotifs > 0 && !dismissed && (
          <div className="mb-4 flex items-center gap-3 bg-accent-600/15 border border-accent-500/30 rounded-lg px-4 py-2.5">
            <span className="text-accent-400 text-sm">🔔</span>
            <span className="flex-1 text-sm text-surface-200">
              {pending2FA > 0 && `${pending2FA} shared 2FA secret${pending2FA > 1 ? 's' : ''} waiting`}
              {pending2FA > 0 && pendingInvites > 0 && ' · '}
              {pendingInvites > 0 && `${pendingInvites} org invite${pendingInvites > 1 ? 's' : ''} pending`}
            </span>
            <Link
              to="/settings"
              className="text-xs bg-accent-600 hover:bg-accent-500 text-white rounded-md px-3 py-1 transition-colors"
            >
              View
            </Link>
            <button
              onClick={dismiss}
              className="text-surface-500 hover:text-surface-300 text-lg leading-none"
              aria-label="Dismiss"
            >
              ×
            </button>
          </div>
        )}
        <Outlet />
      </main>
      {showShortcutHelp && <ShortcutHelp onClose={() => setShowShortcutHelp(false)} />}
      {showGenerator && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowGenerator(false)}>
          <div className="bg-surface-800 rounded-lg p-5 w-96 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-surface-100 mb-3">Password Generator</h3>
            <PasswordGenerator onUse={(pw) => { navigator.clipboard.writeText(pw); setShowGenerator(false); }} />
          </div>
        </div>
      )}
    </div>
  );
}
