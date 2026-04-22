import React, { useState, useEffect } from 'react';
import { useAuthStore } from '../store/authStore';
import { useVaultStore } from '../store/vaultStore';
import { PasswordGenerator } from '../components/PasswordGenerator';
import { OrgSetupWizard } from '../components/OrgSetupWizard';

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
  const [loading, setLoading] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const { token, email, login, userId } = useAuthStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPw !== confirmPw) { setError('Passwords do not match'); return; }
    if (newPw.length < 10) { setError('Password must be at least 10 characters'); return; }
    if (!token || !email || !userId) { setError('Not logged in'); return; }
    setError('');
    setLoading(true);
    try {
      const result = await window.api.auth.changePassword(token, {
        email,
        currentPassword: currentPw,
        newPassword: newPw,
      }) as Record<string, unknown>;
      if (result.error) {
        setError(String(result.error));
        return;
      }
      if (result.master_key_hex) {
        login(token, userId, email, undefined, result.master_key_hex as string);
      }
      onClose();
    } catch {
      setError('Failed to change password');
    } finally {
      setLoading(false);
    }
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
            <button type="submit" disabled={loading} className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50">
              {loading ? 'Changing...' : 'Change Password'}
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
  const _demoQrUri = 'otpauth://totp/QuantumPM:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=QuantumPM';
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
  const { email, token, masterKeyHex, autoLockMinutes, setAutoLockMinutes, orgId, orgName, setOrg, clearOrg } = useAuthStore();
  const { entries, entryFields } = useVaultStore();
  const [biometricEnabled, setBiometricEnabled] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const [biometricChecking, setBiometricChecking] = useState(true);
  const [biometricError, setBiometricError] = useState('');
  const [showBiometricEnroll, setShowBiometricEnroll] = useState(false);
  const [showChangePw, setShowChangePw] = useState(false);
  const [show2fa, setShow2fa] = useState(false);
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [pendingInvites, setPendingInvites] = useState<{ id: string; org_id: string; org_name: string; role: string; created_at: string }[]>([]);
  const [newOrgName, setNewOrgName] = useState('');
  const [orgLoading, setOrgLoading] = useState(false);
  const [orgError, setOrgError] = useState('');
  const [storageBackend, setStorageBackend] = useState<'sqlite' | 'postgres'>('sqlite');
  const [showOrgSetup, setShowOrgSetup] = useState(false);
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
    // Fetch storage backend
    window.api.storage.getBackend().then(setStorageBackend).catch(() => {});
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

  // Fetch pending invitations when user has no org
  useEffect(() => {
    if (orgId || !token) return;
    (async () => {
      try {
        const result = await window.api.admin.getMyInvitations(token) as { id: string; org_id: string; org_name: string; role: string; created_at: string }[] | { error: string };
        if (Array.isArray(result)) {
          setPendingInvites(result);
        }
      } catch { /* ignore */ }
    })();
  }, [orgId, token]);

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
                  value={autoLockMinutes === 0 ? 'never' : String(autoLockMinutes)}
                  onChange={(e) => {
                    const val = e.target.value;
                    setAutoLockMinutes(val === 'never' ? 0 : Number(val));
                  }}
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

        {/* Organization / Enterprise */}
        <section>
          <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Organization</h2>
          <div className="space-y-2">
            {/* Storage mode indicator */}
            <div className="px-4 py-3 rounded-md bg-surface-800">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-surface-200">Storage Mode</p>
                  <p className="text-xs text-surface-500">{storageBackend === 'sqlite' ? 'Local (SQLite)' : 'Server (PostgreSQL)'}</p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full ${storageBackend === 'sqlite' ? 'bg-yellow-600/20 text-yellow-400' : 'bg-green-600/20 text-green-400'}`}>
                  {storageBackend === 'sqlite' ? 'Standalone' : 'Connected'}
                </span>
              </div>
            </div>

            {storageBackend === 'sqlite' && !orgId ? (
              <>
                <p className="text-xs text-surface-500 px-1 mb-2">
                  Organization features require PostgreSQL. Upgrade to enable admin panel, member management, and escrow recovery.
                </p>
                <button
                  onClick={() => setShowOrgSetup(true)}
                  className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-accent-400 transition-colors flex items-center justify-between"
                >
                  Enable Organization Features
                  <span className="text-surface-600">→</span>
                </button>
              </>
            ) : orgId ? (
              <>
                <div className="px-4 py-3 rounded-md bg-surface-800">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-surface-200">{orgName || 'Organization'}</p>
                      <p className="text-xs text-surface-500">Role: Admin</p>
                    </div>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-accent-600/20 text-accent-400">Active</span>
                  </div>
                </div>
                <button
                  onClick={async () => {
                    if (!token || !orgId) return;
                    try {
                      const result = await window.api.admin.leaveOrg(token, orgId) as { error?: string };
                      if (result.error) { setOrgError(result.error); return; }
                      clearOrg();
                      setOrgError('');
                    } catch {
                      setOrgError('Failed to leave organization');
                    }
                  }}
                  className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-red-400 transition-colors"
                >
                  Leave Organization
                </button>
              </>
            ) : showCreateOrg ? (
              <div className="px-4 py-4 rounded-md bg-surface-800 space-y-3">
                <p className="text-sm text-surface-200">Create a new organization</p>
                <input
                  type="text"
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && newOrgName.trim() && token && masterKeyHex) {
                      setOrgLoading(true);
                      setOrgError('');
                      window.api.admin.createOrg(token, newOrgName.trim(), masterKeyHex)
                        .then((result: unknown) => {
                          const res = result as { id?: string; name?: string; error?: string };
                          if (res.error) { setOrgError(res.error); }
                          else if (res.id) { setOrg(res.id, res.name ?? newOrgName.trim(), 'admin'); setShowCreateOrg(false); setNewOrgName(''); }
                        })
                        .catch(() => setOrgError('Failed to create organization'))
                        .finally(() => setOrgLoading(false));
                    }
                  }}
                  placeholder="Organization name"
                  className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
                  autoFocus
                />
                {orgError && <p className="text-xs text-red-400">{orgError}</p>}
                <div className="flex gap-2">
                  <button
                    onClick={() => { setShowCreateOrg(false); setNewOrgName(''); setOrgError(''); }}
                    className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    disabled={orgLoading || !newOrgName.trim()}
                    onClick={() => {
                      if (!token || !masterKeyHex || !newOrgName.trim()) return;
                      setOrgLoading(true);
                      setOrgError('');
                      window.api.admin.createOrg(token, newOrgName.trim(), masterKeyHex)
                        .then((result: unknown) => {
                          const res = result as { id?: string; name?: string; error?: string };
                          if (res.error) { setOrgError(res.error); }
                          else if (res.id) { setOrg(res.id, res.name ?? newOrgName.trim(), 'admin'); setShowCreateOrg(false); setNewOrgName(''); }
                        })
                        .catch(() => setOrgError('Failed to create organization'))
                        .finally(() => setOrgLoading(false));
                    }}
                    className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm font-medium transition-colors"
                  >
                    {orgLoading ? 'Creating…' : 'Create'}
                  </button>
                </div>
              </div>
            ) : (
              <>
                <p className="text-xs text-surface-500 px-1 mb-2">
                  Create an organization to enable admin features, or accept a pending invitation.
                </p>
                <button
                  onClick={() => setShowCreateOrg(true)}
                  className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-accent-400 transition-colors flex items-center justify-between"
                >
                  Create Organization
                  <span className="text-surface-600">→</span>
                </button>
                {pendingInvites.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-xs text-surface-500 px-1 mt-3">Pending Invitations</p>
                    {pendingInvites.map((inv) => (
                      <div key={inv.id} className="px-4 py-3 rounded-md bg-surface-800 flex items-center justify-between">
                        <div>
                          <p className="text-sm text-surface-200">{inv.org_name}</p>
                          <p className="text-xs text-surface-500">
                            Role: {inv.role} · Invited {new Date(inv.created_at).toLocaleDateString()}
                          </p>
                        </div>
                        <button
                          disabled={orgLoading}
                          onClick={() => {
                            if (!token || !masterKeyHex) return;
                            setOrgLoading(true);
                            setOrgError('');
                            window.api.admin.acceptInvite(token, inv.org_id, masterKeyHex)
                              .then((result: unknown) => {
                                const res = result as { status?: string; error?: string };
                                if (res.error) { setOrgError(res.error); }
                                else { setOrg(inv.org_id, inv.org_name, inv.role); setPendingInvites([]); }
                              })
                              .catch(() => setOrgError('Failed to accept invitation'))
                              .finally(() => setOrgLoading(false));
                          }}
                          className="bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-xs rounded-lg px-3 py-1.5 transition-colors"
                        >
                          {orgLoading ? 'Joining…' : 'Accept'}
                        </button>
                      </div>
                    ))}
                    {orgError && <p className="text-xs text-red-400 px-1">{orgError}</p>}
                  </div>
                )}
              </>
            )}
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
            <button
              onClick={async () => {
                // Export decrypted vault data as JSON file
                const exportData = entries.map((entry) => ({
                  entry_type: entry.entry_type,
                  fields: entryFields[entry.id] ?? {},
                  created_at: entry.created_at,
                  updated_at: entry.updated_at,
                }));
                const json = JSON.stringify(exportData, null, 2);
                await window.api.vault.exportFile(json);
              }}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between"
            >
              Export Vault (Encrypted Backup)
              <span className="text-surface-600">→</span>
            </button>
            <button
              onClick={() => {
                useVaultStore.getState().setEntries([]);
              }}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-red-400 transition-colors"
            >
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
      {showOrgSetup && (
        <OrgSetupWizard
          onClose={() => setShowOrgSetup(false)}
          onComplete={() => setStorageBackend('postgres')}
        />
      )}
      {showBiometricEnroll && (
        <BiometricEnrollModal
          onClose={() => setShowBiometricEnroll(false)}
          onConfirm={handleBiometricEnroll}
        />
      )}
    </div>
  );
}
