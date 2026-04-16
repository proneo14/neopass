import React, { useEffect, useRef, useCallback } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TitleBar } from './TitleBar';
import { useAuthStore } from '../store/authStore';

export function Layout() {
  const navigate = useNavigate();
  const logout = useAuthStore((s) => s.logout);
  const autoLockMinutes = useAuthStore((s) => s.autoLockMinutes);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastActivityRef = useRef(Date.now());

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

  return (
    <div className="flex h-screen w-screen overflow-hidden dark">
      <TitleBar />
      <Sidebar />
      <main className="flex-1 overflow-auto bg-surface-950 p-6 pt-10">
        <Outlet />
      </main>
    </div>
  );
}
