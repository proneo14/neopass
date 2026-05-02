import React, { useEffect, useRef, useCallback } from 'react';
import { Outlet, useNavigate, Link } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TitleBar } from './TitleBar';
import { useAuthStore } from '../store/authStore';
import { useNotificationStore } from '../store/notificationStore';
import { useSyncStore } from '../store/syncStore';
import { performSync } from '../utils/sync';

export function Layout() {
  const navigate = useNavigate();
  const logout = useAuthStore((s) => s.logout);
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
        logout();
        navigate('/login');
      }, autoLockMinutes * 60_000);
    }
  }, [autoLockMinutes, logout, navigate]);

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

  return (
    <div className="flex h-screen w-screen overflow-hidden dark">
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
    </div>
  );
}
