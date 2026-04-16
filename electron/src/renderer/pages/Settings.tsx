import React, { useState, useEffect } from 'react';
import { useAuthStore } from '../store/authStore';
import { PasswordGenerator } from '../components/PasswordGenerator';

type AutoLockOption = '1' | '5' | '15' | '30' | '60' | 'never';

const AUTO_LOCK_OPTIONS: { value: AutoLockOption; label: string }[] = [
  { value: '1', label: '1 minute' },
  { value: '5', label: '5 minutes' },
  { value: '15', label: '15 minutes' },
  { value: '30', label: '30 minutes' },
  { value: '60', label: '1 hour' },
  { value: 'never', label: 'Never' },
];

function SettingsToggle({ label, description, checked, onChange }: {
  label: string; description?: string; checked: boolean; onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center justify-between px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 transition-colors cursor-pointer">
      <div>
        <p className="text-sm text-surface-200">{label}</p>
        {description && <p className="text-xs text-surface-500 mt-0.5">{description}</p>}
      </div>
      <div
        className={`w-9 h-5 rounded-full transition-colors relative ${checked ? 'bg-accent-600' : 'bg-surface-600'}`}
        onClick={() => onChange(!checked)}
      >
        <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-transform ${checked ? 'translate-x-4' : 'translate-x-0.5'}`} />
      </div>
    </label>
  );
}

function ChangePasswordModal({ onClose }: { onClose: () => void }) {
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [error, setError] = useState('');
  const [showGenerator, setShowGenerator] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPw !== confirmPw) { setError('Passwords do not match'); return; }
    if (newPw.length < 10) { setError('Password must be at least 10 characters'); return; }
    // Will wire to backend
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface-800 rounded-lg p-5 w-96 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-surface-100 mb-4">Change Master Password</h3>
        <form onSubmit={handleSubmit} className="space-y-3">
          <input
            type="password"
            placeholder="Current master password"
            value={currentPw}
            onChange={(e) => setCurrentPw(e.target.value)}
            required
            className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
          />
          <input
            type="password"
            placeholder="New master password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            required
            className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
          />
          <input
            type="password"
            placeholder="Confirm new password"
            value={confirmPw}
            onChange={(e) => setConfirmPw(e.target.value)}
            required
            className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
          />
          <button
            type="button"
            onClick={() => setShowGenerator(!showGenerator)}
            className="text-xs text-accent-400 hover:text-accent-300"
          >
            {showGenerator ? 'Hide generator' : 'Generate password'}
          </button>
          {showGenerator && (
            <div className="p-3 bg-surface-900 rounded-lg">
              <PasswordGenerator onUse={(pw) => { setNewPw(pw); setConfirmPw(pw); setShowGenerator(false); }} />
            </div>
          )}
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex gap-2 pt-2">
            <button type="button" onClick={onClose} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
              Cancel
            </button>
            <button type="submit" className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
              Change Password
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function TwoFactorModal({ onClose }: { onClose: () => void }) {
  const [step, setStep] = useState<'intro' | 'verify'>('intro');
  const [code, setCode] = useState('');
  const demoQrUri = 'otpauth://totp/QuantumPM:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=QuantumPM';
  const demoRecoveryCodes = ['A1B2C3D4', 'E5F6G7H8', 'I9J0K1L2', 'M3N4O5P6', 'Q7R8S9T0', 'U1V2W3X4', 'Y5Z6A7B8', 'C9D0E1F2'];

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface-800 rounded-lg p-5 w-96 shadow-2xl max-h-[80vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-surface-100 mb-4">Two-Factor Authentication</h3>
        {step === 'intro' ? (
          <div className="space-y-4">
            <p className="text-xs text-surface-400">
              Scan this QR code with your authenticator app (e.g., Google Authenticator, Authy).
            </p>
            <div className="bg-white rounded-lg p-4 flex items-center justify-center">
              <div className="w-40 h-40 bg-surface-200 rounded flex items-center justify-center text-surface-600 text-xs text-center">
                QR Code<br />placeholder
              </div>
            </div>
            <div>
              <p className="text-xs text-surface-500 mb-1">Manual entry key:</p>
              <code className="text-xs text-surface-300 font-mono bg-surface-900 px-2 py-1 rounded block">
                JBSWY3DPEHPK3PXP
              </code>
            </div>
            <div>
              <p className="text-xs text-surface-500 mb-2">Recovery codes (save these):</p>
              <div className="grid grid-cols-2 gap-1">
                {demoRecoveryCodes.map((c) => (
                  <code key={c} className="text-xs text-surface-300 font-mono bg-surface-900 px-2 py-1 rounded text-center">{c}</code>
                ))}
              </div>
            </div>
            <button
              onClick={() => setStep('verify')}
              className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors"
            >
              Next: Verify Code
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-xs text-surface-400">Enter the 6-digit code from your authenticator app to verify setup.</p>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              placeholder="123456"
              className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm text-center tracking-widest placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
            />
            <div className="flex gap-2">
              <button onClick={() => setStep('intro')} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Back
              </button>
              <button onClick={onClose} className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
                Verify &amp; Enable
              </button>
            </div>
          </div>
        )}
        <button onClick={onClose} className="mt-3 w-full py-1.5 text-xs text-surface-500 hover:text-surface-300 transition-colors">
          Cancel
        </button>
      </div>
    </div>
  );
}

function BiometricEnrollModal({ onClose, onConfirm }: { onClose: () => void; onConfirm: (password: string) => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!password.trim()) {
      setError('Please enter your master password');
      return;
    }
    onConfirm(password);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface-800 rounded-lg p-5 w-96 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-surface-100 mb-2">Enable Biometric Unlock</h3>
        <p className="text-xs text-surface-400 mb-4">
          Enter your master password to securely store it for biometric unlock. Your password will be encrypted and protected by Windows Hello.
        </p>
        <form onSubmit={handleSubmit} className="space-y-3">
          <input
            type="password"
            placeholder="Master password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
            required
            className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
              Cancel
            </button>
            <button type="submit" className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
              Enable
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function Settings() {
  const { email } = useAuthStore();
  const [autoLock, setAutoLock] = useState<AutoLockOption>('15');
  const [biometricEnabled, setBiometricEnabled] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const [biometricChecking, setBiometricChecking] = useState(true);
  const [biometricError, setBiometricError] = useState('');
  const [showBiometricEnroll, setShowBiometricEnroll] = useState(false);
  const [showChangePw, setShowChangePw] = useState(false);
  const [show2fa, setShow2fa] = useState(false);

  useEffect(() => {
    (async () => {
      const available = await window.api.biometric.isAvailable();
      setBiometricAvailable(available);
      if (available) {
        const configured = await window.api.biometric.isConfigured();
        setBiometricEnabled(configured);
      }
      setBiometricChecking(false);
    })();
  }, []);

  const handleBiometricToggle = async (enabled: boolean) => {
    setBiometricError('');
    if (enabled) {
      setShowBiometricEnroll(true);
    } else {
      setBiometricLoading(true);
      try {
        const result = await window.api.biometric.disable();
        if (result.error) {
          setBiometricError(result.error);
        } else {
          setBiometricEnabled(false);
        }
      } catch {
        setBiometricError('Failed to disable biometric');
      } finally {
        setBiometricLoading(false);
      }
    }
  };

  const handleBiometricEnroll = async (password: string) => {
    setBiometricError('');
    setBiometricLoading(true);
    setShowBiometricEnroll(false);
    try {
      const result = await window.api.biometric.enableWithPassword({
        email: email ?? '',
        password,
      });
      if (result.error) {
        setBiometricError(result.error);
      } else {
        setBiometricEnabled(true);
      }
    } catch {
      setBiometricError('Biometric enrollment failed');
    } finally {
      setBiometricLoading(false);
    }
  };

  return (
    <div>
      <h1 className="text-lg font-semibold text-surface-100 mb-6">Settings</h1>

      <div className="space-y-6 max-w-lg">
        {/* Account */}
        <section>
          <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Account</h2>
          <div className="space-y-2">
            <div className="flex items-center justify-between px-4 py-3 rounded-md bg-surface-800">
              <div>
                <p className="text-sm text-surface-200">Email</p>
                <p className="text-xs text-surface-500">{email ?? 'Not signed in'}</p>
              </div>
            </div>
            <button
              onClick={async () => {
                if (biometricEnabled) {
                  const result = await window.api.biometric.verify();
                  if (!result.success) return;
                }
                setShowChangePw(true);
              }}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between"
            >
              Change Master Password
              <span className="text-surface-600">→</span>
            </button>
            <button
              onClick={() => setShow2fa(true)}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between"
            >
              Two-Factor Authentication
              <span className="text-xs text-surface-500">Not configured</span>
            </button>
          </div>
        </section>

        {/* Security */}
        <section>
          <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Security</h2>
          <div className="space-y-2">
            <SettingsToggle
              label={biometricLoading ? 'Biometric Unlock (working…)' : biometricChecking ? 'Biometric Unlock (checking…)' : 'Biometric Unlock'}
              description={
                biometricChecking
                  ? 'Checking availability…'
                  : biometricAvailable
                    ? 'Use Windows Hello or fingerprint to unlock'
                    : 'Not available on this device'
              }
              checked={biometricEnabled}
              onChange={biometricAvailable && !biometricLoading && !biometricChecking ? handleBiometricToggle : () => {}}
            />
            {biometricError && (
              <p className="text-xs text-red-400 px-4">{biometricError}</p>
            )}
            <div className="px-4 py-3 rounded-md bg-surface-800">
              <div className="flex items-center justify-between">
                <p className="text-sm text-surface-200">Auto-Lock Timeout</p>
                <select
                  value={autoLock}
                  onChange={(e) => setAutoLock(e.target.value as AutoLockOption)}
                  className="bg-surface-700 border border-surface-600 text-surface-300 text-xs rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-accent-500"
                >
                  {AUTO_LOCK_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </section>

        {/* Data */}
        <section>
          <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Data</h2>
          <div className="space-y-2">
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between">
              Sync Settings
              <span className="text-surface-600">→</span>
            </button>
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between">
              Export Vault (Encrypted Backup)
              <span className="text-surface-600">→</span>
            </button>
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-red-400 transition-colors">
              Clear Local Cache
            </button>
          </div>
        </section>

        {/* About */}
        <div className="pt-4 border-t border-surface-800">
          <p className="text-xs text-surface-600">LGI Pass v1.0.0</p>
          <p className="text-xs text-surface-700 mt-0.5">Post-quantum encryption: X-Wing KEM + AES-256-GCM</p>
        </div>
      </div>

      {showChangePw && <ChangePasswordModal onClose={() => setShowChangePw(false)} />}
      {show2fa && <TwoFactorModal onClose={() => setShow2fa(false)} />}
      {showBiometricEnroll && (
        <BiometricEnrollModal
          onClose={() => setShowBiometricEnroll(false)}
          onConfirm={handleBiometricEnroll}
        />
      )}
    </div>
  );
}
