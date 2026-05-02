import React, { lazy, Suspense, useEffect } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { AuthGuard } from './components/AuthGuard';
import { Login } from './pages/Login';
import { useThemeStore } from './store/themeStore';

// Lazy-load pages so only the active view consumes memory
const Register = lazy(() => import('./pages/Register').then(m => ({ default: m.Register })));
const Vault = lazy(() => import('./pages/Vault').then(m => ({ default: m.Vault })));
const EntryDetail = lazy(() => import('./pages/EntryDetail').then(m => ({ default: m.EntryDetail })));
const Passkeys = lazy(() => import('./pages/Passkeys').then(m => ({ default: m.Passkeys })));
const SSHKeys = lazy(() => import('./pages/SSHKeys').then(m => ({ default: m.SSHKeys })));
const Admin = lazy(() => import('./pages/Admin').then(m => ({ default: m.Admin })));
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.Settings })));
const HealthReport = lazy(() => import('./pages/HealthReport').then(m => ({ default: m.HealthReport })));
const Send = lazy(() => import('./pages/Send').then(m => ({ default: m.Send })));

function PageLoader() {
  return <div className="flex items-center justify-center h-full text-slate-400">Loading…</div>;
}

export function App() {
  const resolvedTheme = useThemeStore((s) => s.resolvedTheme);

  useEffect(() => {
    if (resolvedTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [resolvedTheme]);

  return (
    <HashRouter>
      <Suspense fallback={<PageLoader />}>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Protected routes with layout */}
        <Route
          element={
            <AuthGuard>
              <Layout />
            </AuthGuard>
          }
        >
          <Route path="/vault" element={<Vault />} />
          <Route path="/vault/favorites" element={<Vault />} />
          <Route path="/vault/archived" element={<Vault />} />
          <Route path="/vault/trash" element={<Vault />} />
          <Route path="/vault/collection/:collId" element={<Vault />} />
          <Route path="/vault/:id" element={<EntryDetail />} />
          <Route path="/passkeys" element={<Passkeys />} />
          <Route path="/ssh-keys" element={<SSHKeys />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/health" element={<HealthReport />} />
          <Route path="/send" element={<Send />} />
          <Route path="/admin" element={<Admin />} />
        </Route>

        {/* Default redirect */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
      </Suspense>
    </HashRouter>
  );
}
