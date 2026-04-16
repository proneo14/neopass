import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';

export function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [needs2fa, setNeeds2fa] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const [showManualLogin, setShowManualLogin] = useState(false);

  const login = useAuthStore((s) => s.login);
  const setOrg = useAuthStore((s) => s.setOrg);
  const navigate = useNavigate();

  const clearOrg = useAuthStore((s) => s.clearOrg);

  // After login, fetch org membership from backend and update store
  const loadOrgAfterLogin = async (token: string) => {
    try {
      const result = await window.api.admin.getMyOrg(token) as { member?: boolean; org_id?: string; org_name?: string; role?: string; error?: string };
      if (result.member && result.org_id) {
        setOrg(result.org_id, result.org_name ?? '', result.role ?? 'member');
      } else {
        clearOrg();
      }
    } catch { /* ignore — org loading is best-effort */ }
  };

  const handleBiometricUnlock = async () => {
    setError('');
    setBiometricLoading(true);
    try {
      const result = await window.api.biometric.unlock();
      if (result.error) {
        setError(result.error as string);
        setShowManualLogin(true);
        return;
      }
      if (result.access_token || result.token) {
        const masterKey = (result.master_key_hex ?? '') as string;
        if (!masterKey) {
          // Old biometric blob missing master key — need manual login to derive it
          setError('Please sign in with your password to update biometric enrollment.');
          setShowManualLogin(true);
          // Disable the old biometric enrollment so user re-enrolls in Settings
          await window.api.biometric.disable();
          return;
        }
        login(
          (result.access_token ?? result.token) as string,
          result.user_id as string,
          (result.email ?? '') as string,
          result.role as string | undefined,
          masterKey,
        );
        await loadOrgAfterLogin((result.access_token ?? result.token) as string);
        navigate('/vault');
      }
    } catch {
      setError('Biometric unlock failed');
      setShowManualLogin(true);
    } finally {
      setBiometricLoading(false);
    }
  };

  useEffect(() => {
    (async () => {
      const available = await window.api.biometric.isAvailable();
      if (available) {
        const configured = await window.api.biometric.isConfigured();
        setBiometricAvailable(configured);
        if (configured) {
          // Auto-trigger biometric unlock immediately
          handleBiometricUnlock();
        } else {
          setShowManualLogin(true);
        }
      } else {
        setShowManualLogin(true);
      }
    })();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = (await window.api.auth.login({ email, authHash: password })) as Record<
        string,
        unknown
      >;

      if (result.error) {
        setError(result.error as string);
        return;
      }

      if (result.requires_2fa) {
        setNeeds2fa(true);
        return;
      }

      login(
        (result.access_token ?? result.token) as string,
        result.user_id as string,
        email,
        result.role as string | undefined,
        (result.master_key_hex ?? '') as string,
      );
      await loadOrgAfterLogin((result.access_token ?? result.token) as string);
      navigate('/vault');
    } catch {
      setError('Failed to connect to server');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center h-screen w-screen bg-surface-950 dark">
      <div
        className="fixed top-0 left-0 right-0 h-9 z-50"
        style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}
      />
      <div className="w-full max-w-sm px-6">
        <div className="text-center mb-8">
          <span className="text-4xl">🔑</span>
          <h1 className="mt-3 text-xl font-semibold text-surface-100">LGI Pass</h1>
          <p className="mt-1 text-sm text-surface-400">Unlock your vault</p>
        </div>

        {error && (
          <div className="text-sm text-red-400 bg-red-400/10 px-3 py-2 rounded-md mb-4">{error}</div>
        )}

        {/* Biometric primary unlock */}
        {biometricAvailable && (
          <div className="mb-4">
            <button
              type="button"
              disabled={biometricLoading}
              onClick={handleBiometricUnlock}
              className="w-full py-3 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <span>🔓</span>
              {biometricLoading ? 'Verifying…' : 'Unlock with Biometrics'}
            </button>

            {!showManualLogin && (
              <button
                type="button"
                onClick={() => setShowManualLogin(true)}
                className="w-full mt-3 text-xs text-surface-500 hover:text-surface-300 transition-colors"
              >
                Use email &amp; password instead
              </button>
            )}
          </div>
        )}

        {/* Manual email/password login */}
        {showManualLogin && (
          <>
            {biometricAvailable && (
              <div className="relative my-4">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-surface-700" />
                </div>
                <div className="relative flex justify-center">
                  <span className="px-2 bg-surface-950 text-xs text-surface-500">or sign in manually</span>
                </div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-xs font-medium text-surface-400 mb-1">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
                  placeholder="you@example.com"
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-xs font-medium text-surface-400 mb-1">
                  Master Password
                </label>
                <input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
                  placeholder="Master password"
                />
              </div>

              {needs2fa && (
                <div>
                  <label htmlFor="totp" className="block text-xs font-medium text-surface-400 mb-1">
                    Two-Factor Code
                  </label>
                  <input
                    id="totp"
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    required
                    value={twoFactorCode}
                    onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, ''))}
                    className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
                    placeholder="123456"
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Unlocking…' : 'Unlock'}
              </button>
            </form>
          </>
        )}

        <p className="mt-6 text-center text-xs text-surface-500">
          Don&apos;t have an account?{' '}
          <Link to="/register" className="text-accent-400 hover:text-accent-300">
            Register
          </Link>
        </p>
      </div>
    </div>
  );
}
