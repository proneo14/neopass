import React from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { AuthGuard } from './components/AuthGuard';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Vault } from './pages/Vault';
import { EntryDetail } from './pages/EntryDetail';
import { Admin } from './pages/Admin';
import { Settings } from './pages/Settings';

export function App() {
  return (
    <HashRouter>
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
          <Route path="/vault/:id" element={<EntryDetail />} />
          <Route path="/settings" element={<Settings />} />
          <Route
            path="/admin"
            element={
              <AuthGuard requireAdmin>
                <Admin />
              </AuthGuard>
            }
          />
        </Route>

        {/* Default redirect */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </HashRouter>
  );
}
