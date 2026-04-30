import React, { useEffect, useRef, useCallback } from 'react';
import { Outlet, useNavigate, Link } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TitleBar } from './TitleBar';
import { useAuthStore } from '../store/authStore';
import { useNotificationStore } from '../store/notificationStore';

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
