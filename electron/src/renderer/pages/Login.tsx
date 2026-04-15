import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';

export function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [needs2fa, setNeeds2fa] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const login = useAuthStore((s) => s.login);
  const navigate = useNavigate();

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
        result.token as string,
        result.user_id as string,
        email,
        result.role as string | undefined,
      );
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
          <h1 className="mt-3 text-xl font-semibold text-surface-100">Quantum Password Manager</h1>
          <p className="mt-1 text-sm text-surface-400">Unlock your vault</p>
        </div>

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

          {error && (
            <div className="text-sm text-red-400 bg-red-400/10 px-3 py-2 rounded-md">{error}</div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Unlocking…' : 'Unlock'}
          </button>
        </form>

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
