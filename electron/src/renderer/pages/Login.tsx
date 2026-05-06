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
  const [showPassword, setShowPassword] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const [showManualLogin, setShowManualLogin] = useState(false);
  const [showSSO, setShowSSO] = useState(false);
  const [ssoOrgId, setSsoOrgId] = useState('');
  const [ssoLoading, setSsoLoading] = useState(false);

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

  const handleSSOLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ssoOrgId.trim()) return;
    setSsoLoading(true);
    setError('');
    try {
      const result = await window.api.auth.ssoLogin(ssoOrgId.trim()) as { redirect_url?: string; error?: string };
      if (result.error) {
        setError(result.error);
      } else if (result.redirect_url) {
        // Open the SSO IdP login page in the default browser
        window.open(result.redirect_url, '_blank');
      }
    } catch {
      setError('Failed to initiate SSO login');
    } finally {
      setSsoLoading(false);
    }
  };

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
    <div className="flex items-center justify-center h-screen w-screen bg-surface-950">
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
            {biometricLoading ? (
              <div className="flex flex-col items-center gap-3 py-4">
                <span className="text-3xl animate-pulse">👆</span>
                <p className="text-sm text-surface-300">Touch your fingerprint sensor or look at your camera</p>
                <button
                  type="button"
                  onClick={async () => {
                    try { await window.api.biometric.cancel(); } catch { /* ignore */ }
                    setBiometricLoading(false);
                    setShowManualLogin(true);
                  }}
                  className="mt-1 text-xs text-surface-500 hover:text-surface-300 transition-colors"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={handleBiometricUnlock}
                className="w-full py-3 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors flex items-center justify-center gap-2"
              >
                <span>🔓</span>
                Unlock with Biometrics
              </button>
            )}

            {!showManualLogin && !biometricLoading && (
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
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-3 py-2 pr-10 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
                    placeholder="Master password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-surface-400 hover:text-surface-200 transition-colors p-1"
                    tabIndex={-1}
                  >
                    {showPassword ? (
                      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
                        <path fillRule="evenodd" d="M3.28 2.22a.75.75 0 00-1.06 1.06l14.5 14.5a.75.75 0 101.06-1.06l-1.745-1.745a10.029 10.029 0 003.3-4.38 1.651 1.651 0 000-1.185A10.004 10.004 0 009.999 3a9.956 9.956 0 00-4.744 1.194L3.28 2.22zM7.752 6.69l1.092 1.092a2.5 2.5 0 013.374 3.373l1.092 1.092a4 4 0 00-5.558-5.558z" clipRule="evenodd" />
                        <path d="M10.748 13.93l2.523 2.523A9.987 9.987 0 0110 17c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 012.838-4.524l2.46 2.46a4 4 0 005.554 5.554l.44.44z" />
                      </svg>
                    ) : (
                      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
                        <path d="M10 12.5a2.5 2.5 0 100-5 2.5 2.5 0 000 5z" />
                        <path fillRule="evenodd" d="M.664 10.59a1.651 1.651 0 010-1.186A10.004 10.004 0 0110 3c4.257 0 7.893 2.66 9.336 6.41.147.381.146.804 0 1.186A10.004 10.004 0 0110 17c-4.257 0-7.893-2.66-9.336-6.41zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
                      </svg>
                    )}
                  </button>
                </div>
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

        {/* SSO Login */}
        <div className="mt-4">
          {!showSSO ? (
            <button
              type="button"
              onClick={() => setShowSSO(true)}
              className="w-full text-center text-xs text-surface-500 hover:text-surface-300 transition-colors"
            >
              Sign in with SSO
            </button>
          ) : (
            <div className="p-4 rounded-lg bg-surface-800/50 border border-surface-700">
              <p className="text-xs text-surface-400 mb-3">Enter your organization identifier to sign in with SSO.</p>
              <form onSubmit={handleSSOLogin} className="space-y-3">
                <input
                  type="text"
                  value={ssoOrgId}
                  onChange={(e) => setSsoOrgId(e.target.value)}
                  className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
                  placeholder="Organization ID"
                />
                <div className="flex gap-2">
                  <button
                    type="submit"
                    disabled={ssoLoading || !ssoOrgId.trim()}
                    className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-xs font-medium transition-colors disabled:opacity-50"
                  >
                    {ssoLoading ? 'Redirecting…' : 'Continue with SSO'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowSSO(false)}
                    className="px-3 py-2 rounded-md bg-surface-700 text-surface-300 text-xs hover:bg-surface-600 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
