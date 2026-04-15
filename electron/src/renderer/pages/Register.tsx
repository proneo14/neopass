import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';

export function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const login = useAuthStore((s) => s.login);
  const navigate = useNavigate();

  const getStrength = (pw: string): { label: string; color: string; width: string } => {
    if (pw.length === 0) return { label: '', color: 'bg-surface-700', width: 'w-0' };
    if (pw.length < 8) return { label: 'Weak', color: 'bg-red-500', width: 'w-1/4' };
    const hasUpper = /[A-Z]/.test(pw);
    const hasLower = /[a-z]/.test(pw);
    const hasDigit = /\d/.test(pw);
    const hasSymbol = /[^A-Za-z0-9]/.test(pw);
    const varieties = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
    if (pw.length >= 16 && varieties >= 3) return { label: 'Strong', color: 'bg-green-500', width: 'w-full' };
    if (pw.length >= 12 && varieties >= 2) return { label: 'Good', color: 'bg-yellow-500', width: 'w-3/4' };
    return { label: 'Fair', color: 'bg-orange-500', width: 'w-1/2' };
  };

  const strength = getStrength(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 10) {
      setError('Password must be at least 10 characters');
      return;
    }

    setLoading(true);

    try {
      const result = (await window.api.auth.register({
        email,
        authHash: password,
        salt: '',
        kdfParams: { memory: 65536, iterations: 3, parallelism: 4 },
      })) as Record<string, unknown>;

      if (result.error) {
        setError(result.error as string);
        return;
      }

      login(
        result.token as string,
        result.user_id as string,
        email,
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
          <h1 className="mt-3 text-xl font-semibold text-surface-100">Create Account</h1>
          <p className="mt-1 text-sm text-surface-400">
            Your password is processed locally with Argon2id
          </p>
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
              autoComplete="new-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
              placeholder="At least 10 characters"
            />
            {password.length > 0 && (
              <div className="mt-2">
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-1.5 bg-surface-700 rounded-full overflow-hidden">
                    <div className={`h-full ${strength.color} ${strength.width} transition-all rounded-full`} />
                  </div>
                  <span className="text-xs text-surface-400">{strength.label}</span>
                </div>
              </div>
            )}
          </div>

          <div>
            <label htmlFor="confirm" className="block text-xs font-medium text-surface-400 mb-1">
              Confirm Password
            </label>
            <input
              id="confirm"
              type="password"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
              placeholder="Confirm master password"
            />
          </div>

          {error && (
            <div className="text-sm text-red-400 bg-red-400/10 px-3 py-2 rounded-md">{error}</div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Creating account…' : 'Create Account'}
          </button>
        </form>

        <p className="mt-6 text-center text-xs text-surface-500">
          Already have an account?{' '}
          <Link to="/login" className="text-accent-400 hover:text-accent-300">
            Log in
          </Link>
        </p>
      </div>
    </div>
  );
}
