import React, { useState, useEffect } from 'react';
import { useAuthStore } from '../store/authStore';

interface RepromptDialogProps {
  /** Called when verification succeeds. */
  onVerified: () => void;
  /** Called when the user cancels. */
  onCancel: () => void;
}

/**
 * Modal that requires the user to re-authenticate via master password or
 * biometric before accessing a sensitive entry. Biometric is offered when
 * configured; master password is always available as fallback.
 */
export function RepromptDialog({ onVerified, onCancel }: RepromptDialogProps) {
  const { email, masterKeyHex } = useAuthStore();
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);

  useEffect(() => {
    // Check if biometric is configured for this device
    (async () => {
      try {
        const configured = await window.api.biometric.isConfigured();
        setBiometricAvailable(configured);
      } catch {
        setBiometricAvailable(false);
      }
    })();
  }, []);

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password.trim()) return;

    setLoading(true);
    setError('');

    try {
      const result = await window.api.vault.verifyMasterPassword(email ?? '', password, masterKeyHex ?? '');
      if (result.verified) {
        onVerified();
      } else {
        setError(result.error || 'Incorrect master password');
      }
    } catch {
      setError('Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleBiometric = async () => {
    setLoading(true);
    setError('');

    try {
      const result = await window.api.biometric.verify();
      if (result.success) {
        onVerified();
      } else {
        setError(result.error || 'Biometric verification failed');
      }
    } catch {
      setError('Biometric verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onCancel}>
      <div
        className="bg-surface-900 rounded-lg w-[380px] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-5 pt-5 pb-3 border-b border-surface-800">
          <div className="flex items-center gap-2">
            <span className="text-lg">🔒</span>
            <h3 className="text-sm font-semibold text-surface-100">Re-authentication Required</h3>
          </div>
          <p className="text-xs text-surface-400 mt-1">
            This entry requires verification before viewing sensitive fields.
          </p>
        </div>

        <div className="px-5 py-4 space-y-4">
          {/* Biometric option (shown first if available) */}
          {biometricAvailable && (
            <button
              onClick={handleBiometric}
              disabled={loading}
              className="w-full py-2.5 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <span className="animate-pulse">Verifying…</span>
              ) : (
                <>
                  <span>🔐</span>
                  Verify with Biometrics
                </>
              )}
            </button>
          )}

          {biometricAvailable && (
            <div className="flex items-center gap-3">
              <div className="flex-1 h-px bg-surface-700" />
              <span className="text-[10px] text-surface-500 uppercase tracking-wider">or</span>
              <div className="flex-1 h-px bg-surface-700" />
            </div>
          )}

          {/* Master password form */}
          <form onSubmit={handlePasswordSubmit}>
            <label className="block text-xs text-surface-400 mb-1">Master Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus={!biometricAvailable}
              placeholder="Enter master password"
              className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
            />
            {error && <p className="text-xs text-red-400 mt-1">{error}</p>}
            <button
              type="submit"
              disabled={loading || !password.trim()}
              className="w-full mt-3 py-2 rounded-md bg-surface-700 hover:bg-surface-600 text-surface-200 text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Verifying…' : 'Verify Password'}
            </button>
          </form>
        </div>

        <div className="px-5 pb-5">
          <button
            onClick={onCancel}
            className="w-full py-2 rounded-md bg-surface-800 text-surface-400 text-sm hover:bg-surface-700 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
