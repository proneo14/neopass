import React, { useState, useEffect, useRef } from 'react';
import { useAuthStore } from '../store/authStore';
import { useVaultStore } from '../store/vaultStore';
import { useNotificationStore } from '../store/notificationStore';
import { useThemeStore } from '../store/themeStore';
import { ShortcutHelp } from '../components/ShortcutHelp';
import { PasswordGenerator } from '../components/PasswordGenerator';
import { OrgSetupWizard } from '../components/OrgSetupWizard';
import { EmergencyAccessSection } from '../components/EmergencyAccessSection';
import { ImportWizard } from '../components/ImportWizard';
import { SyncSettings } from '../components/SyncSettings';
import { ServerConfig } from '../components/ServerConfig';
import QRCode from 'qrcode';

type AutoLockOption = '1' | '5' | '15' | '30' | '60' | 'never';
type TimeoutActionOption = 'lock' | 'logout';

const AUTO_LOCK_OPTIONS: { value: AutoLockOption; label: string }[] = [
  { value: '1', label: '1 minute' },
  { value: '5', label: '5 minutes' },
  { value: '15', label: '15 minutes' },
  { value: '30', label: '30 minutes' },
  { value: '60', label: '1 hour' },
  { value: 'never', label: 'Never' },
];

const TIMEOUT_ACTION_OPTIONS: { value: TimeoutActionOption; label: string; description: string }[] = [
  { value: 'lock', label: 'Lock', description: 'Require master password or biometric to unlock' },
  { value: 'logout', label: 'Log out', description: 'Clear all data and require full login' },
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

function TwoFactorModal({ onClose, onEnabled, onDisabled, isEnabled }: { onClose: () => void; onEnabled: () => void; onDisabled: () => void; isEnabled: boolean }) {
  const { token, masterKeyHex } = useAuthStore();
  const [step, setStep] = useState<'intro' | 'setup' | 'verify' | 'confirm-disable'>('intro');
  const [code, setCode] = useState('');
  const [secret, setSecret] = useState('');
  const [qrUri, setQrUri] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const qrCanvasRef = useRef<HTMLCanvasElement>(null);

  // Render QR code when qrUri is set and step is 'setup'
  useEffect(() => {
    if (step === 'setup' && qrUri && qrCanvasRef.current) {
      QRCode.toCanvas(qrCanvasRef.current, qrUri, {
        width: 200,
        margin: 2,
        color: { dark: '#000000', light: '#ffffff' },
      }).catch(() => { /* QR render failed — user can still copy the key */ });
    }
  }, [step, qrUri]);

  const handleSetup = async () => {
    if (!token || !masterKeyHex) { setError('Not logged in'); return; }
    setLoading(true);
    setError('');
    try {
      const result = await window.api.twoFactor.setup(token, masterKeyHex) as { secret?: string; qr_uri?: string; recovery_codes?: string[]; error?: string };
      if (result.error) { setError(result.error); return; }
      setSecret(result.secret ?? '');
      setQrUri(result.qr_uri ?? '');
      setRecoveryCodes(result.recovery_codes ?? []);
      setStep('setup');
    } catch {
      setError('Failed to set up 2FA');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    if (!token || !masterKeyHex) { setError('Not logged in'); return; }
    if (code.length !== 6) { setError('Enter a 6-digit code'); return; }
    setLoading(true);
    setError('');
    try {
      const result = await window.api.twoFactor.verifySetup(token, code, masterKeyHex) as { status?: string; error?: string };
      if (result.error) { setError(result.error); return; }
      onEnabled();
      onClose();
    } catch {
      setError('Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDisable = async () => {
    if (!token) { setError('Not logged in'); return; }
    setLoading(true);
    setError('');
    try {
      const result = await window.api.twoFactor.disable(token) as { status?: string; error?: string };
      if (result.error) { setError(result.error); return; }
      onDisabled();
      onClose();
    } catch {
      setError('Failed to disable 2FA');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface-800 rounded-lg p-5 w-96 shadow-2xl max-h-[80vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-surface-100 mb-4">Two-Factor Authentication</h3>

        {step === 'intro' && !isEnabled && (
          <div className="space-y-4">
            <p className="text-xs text-surface-400">
              Protect your vault with an authenticator app. You&apos;ll need a 6-digit code from your authenticator each time you log in.
            </p>
            {error && <p className="text-xs text-red-400">{error}</p>}
            <button
              onClick={handleSetup}
              disabled={loading}
              className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
            >
              {loading ? 'Setting up…' : 'Set Up Authenticator'}
            </button>
          </div>
        )}

        {step === 'intro' && isEnabled && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 px-3 py-2 bg-green-900/30 border border-green-700/40 rounded-lg">
              <span className="text-green-400 text-sm">✓</span>
              <span className="text-xs text-green-300">Two-factor authentication is enabled</span>
            </div>
            <p className="text-xs text-surface-400">
              Disabling 2FA will remove the extra security layer from your account.
            </p>
            {error && <p className="text-xs text-red-400">{error}</p>}
            <button
              onClick={() => setStep('confirm-disable')}
              className="w-full py-2 rounded-md bg-red-600/20 hover:bg-red-600/30 text-red-400 text-sm font-medium transition-colors border border-red-600/30"
            >
              Disable Two-Factor Authentication
            </button>
          </div>
        )}

        {step === 'confirm-disable' && (
          <div className="space-y-4">
            <p className="text-xs text-red-300">
              Are you sure you want to disable two-factor authentication? This will make your account less secure.
            </p>
            {error && <p className="text-xs text-red-400">{error}</p>}
            <div className="flex gap-2">
              <button onClick={() => setStep('intro')} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Cancel
              </button>
              <button
                onClick={handleDisable}
                disabled={loading}
                className="flex-1 py-2 rounded-md bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
              >
                {loading ? 'Disabling…' : 'Confirm Disable'}
              </button>
            </div>
          </div>
        )}

        {step === 'setup' && (
          <div className="space-y-4">
            <p className="text-xs text-surface-400">
              Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.):
            </p>
            {qrUri && (
              <div className="flex justify-center py-2">
                <div className="bg-white p-2 rounded-lg">
                  <canvas ref={qrCanvasRef} />
                </div>
              </div>
            )}
            <details className="text-xs text-surface-500">
              <summary className="cursor-pointer hover:text-surface-300 transition-colors">Can&apos;t scan? Enter key manually</summary>
              <div className="relative mt-2">
                <code className="block text-xs text-surface-200 font-mono bg-surface-900 px-3 py-2.5 rounded break-all tracking-wider">
                  {secret}
                </code>
                <button
                  onClick={() => { navigator.clipboard.writeText(secret); setCopiedKey(true); setTimeout(() => setCopiedKey(false), 1500); }}
                  className="absolute top-1.5 right-1.5 text-xs text-surface-500 hover:text-accent-400 transition-colors px-1.5 py-0.5 rounded bg-surface-800"
                >
                  {copiedKey ? '✓' : 'Copy'}
                </button>
              </div>
            </details>
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-surface-500">Recovery codes (save these somewhere safe):</p>
                <button
                  onClick={() => { navigator.clipboard.writeText(recoveryCodes.join('\n')); setCopiedCodes(true); setTimeout(() => setCopiedCodes(false), 1500); }}
                  className="text-[10px] text-surface-500 hover:text-accent-400 transition-colors"
                >
                  {copiedCodes ? '✓ Copied' : 'Copy all'}
                </button>
              </div>
              <div className="grid grid-cols-2 gap-1">
                {recoveryCodes.map((c) => (
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
        )}

        {step === 'verify' && (
          <div className="space-y-4">
            <p className="text-xs text-surface-400">Enter the 6-digit code from your authenticator app to complete setup.</p>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              placeholder="123456"
              autoFocus
              className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm text-center tracking-widest placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
            />
            {error && <p className="text-xs text-red-400">{error}</p>}
            <div className="flex gap-2">
              <button onClick={() => { setStep('setup'); setError(''); setCode(''); }} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Back
              </button>
              <button
                onClick={handleVerify}
                disabled={loading || code.length !== 6}
                className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
              >
                {loading ? 'Verifying…' : 'Verify & Enable'}
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

type ExportFormat = 'encrypted_json' | 'json' | 'csv';

function ExportModal({ onClose }: { onClose: () => void }) {
  const { email, token, masterKeyHex } = useAuthStore();
  const { entries, entryFields, folders } = useVaultStore();
  const [format, setFormat] = useState<ExportFormat>('encrypted_json');
  const [step, setStep] = useState<'choose' | 'warning' | 'verify' | 'exporting'>('choose');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const isUnencrypted = format === 'json' || format === 'csv';

  const handleProceed = () => {
    if (isUnencrypted) {
      setStep('warning');
    } else {
      setStep('verify');
    }
  };

  const handleWarningAccept = () => {
    setStep('verify');
  };

  const handleVerify = async () => {
    if (!email || !masterKeyHex) return;
    setError('');
    const result = await window.api.vault.verifyMasterPassword(email, password, masterKeyHex);
    if (!result.verified) {
      setError(result.error || 'Incorrect master password');
      return;
    }
    setStep('exporting');
    await doExport();
  };

  /** Build a map of folder_id -> decrypted name */
  const buildFolderMap = async (): Promise<Record<string, string>> => {
    const map: Record<string, string> = {};
    if (!masterKeyHex) return map;
    for (const folder of folders) {
      try {
        // folder.name_encrypted is hex nonce+ciphertext
        const nonce = folder.name_encrypted.slice(0, 24);
        const cipher = folder.name_encrypted.slice(24);
        const dec = await window.api.vault.decrypt(masterKeyHex, cipher, nonce) as { plaintext?: string };
        if (dec.plaintext) map[folder.id] = dec.plaintext;
      } catch {
        map[folder.id] = 'Unknown Folder';
      }
    }
    return map;
  };

  const doExport = async () => {
    try {
      const folderMap = await buildFolderMap();

      // Fetch passkeys from server
      let passkeys: Array<Record<string, unknown>> = [];
      if (token) {
        try {
          const pkResult = await window.api.passkey.list(token);
          if (Array.isArray(pkResult)) passkeys = pkResult;
        } catch { /* passkey fetch is best-effort */ }
      }

      if (format === 'encrypted_json') {
        // Encrypted JSON — raw encrypted entries for re-import
        const exportData = entries.map((entry) => ({
          id: entry.id,
          entry_type: entry.entry_type,
          encrypted_data: entry.encrypted_data,
          nonce: entry.nonce,
          version: entry.version,
          folder_id: entry.folder_id,
          is_favorite: entry.is_favorite,
          created_at: entry.created_at,
          updated_at: entry.updated_at,
        }));
        const payload = {
          version: 1,
          format: 'lgipass_encrypted',
          exportDate: new Date().toISOString(),
          entries: exportData,
          folders: folders.map((f) => ({
            id: f.id,
            name_encrypted: f.name_encrypted,
            parent_id: f.parent_id,
          })),
          passkeys,
        };
        const json = JSON.stringify(payload, null, 2);
        await window.api.vault.exportFile(json);
      } else if (format === 'json') {
        // Unencrypted JSON — Bitwarden-compatible where possible
        const exportEntries = entries.map((entry) => {
          const fields = entryFields[entry.id] ?? {};
          const { _reprompt, _passwordHistory, _uris, ...cleanFields } = fields;
          const result: Record<string, unknown> = {
            type: entry.entry_type,
            name: fields.name || '',
            ...cleanFields,
            favorite: entry.is_favorite ?? false,
            reprompt: _reprompt === '1',
            folder: entry.folder_id ? (folderMap[entry.folder_id] ?? null) : null,
          };
          if (_passwordHistory) {
            try { result.passwordHistory = JSON.parse(_passwordHistory); } catch { /* skip */ }
          }
          if (_uris) {
            try { result.uris = JSON.parse(_uris); } catch { /* skip */ }
          }
          return result;
        });
        const payload = {
          version: 1,
          exportDate: new Date().toISOString(),
          entries: exportEntries,
          folders: await Promise.all(folders.map(async (f) => ({
            id: f.id,
            name: folderMap[f.id] ?? 'Unknown',
          }))),
          passkeys: passkeys.map((pk) => ({
            id: pk.id,
            rp_id: pk.rp_id,
            rp_name: pk.rp_name,
            username: pk.username,
            credential_id: pk.credential_id,
            public_key_alg: pk.public_key_alg,
            discoverable: pk.discoverable,
            created_at: pk.created_at,
          })),
        };
        const json = JSON.stringify(payload, null, 2);
        await window.api.vault.exportFile(json);
      } else if (format === 'csv') {
        // CSV export
        const csvEscape = (val: string): string => {
          if (!val) return '';
          if (val.includes(',') || val.includes('"') || val.includes('\n')) {
            return '"' + val.replace(/"/g, '""') + '"';
          }
          return val;
        };

        const headers = ['folder', 'type', 'name', 'username', 'password', 'uri', 'notes', 'totp', 'fields',
          'number', 'expiry', 'cvv', 'cardholder',
          'firstName', 'lastName', 'email', 'phone', 'address',
          'privateKey', 'publicKey', 'fingerprint', 'keyType', 'passphrase'];
        const rows = [headers.join(',')];

        for (const entry of entries) {
          const fields = entryFields[entry.id] ?? {};
          const folder = entry.folder_id ? (folderMap[entry.folder_id] ?? '') : '';

          // Collect "extra" custom fields not in the standard columns
          const standardKeys = new Set([
            'name', 'username', 'password', 'uri', 'notes', 'totp',
            'number', 'expiry', 'cvv', 'cardholder',
            'firstName', 'lastName', 'email', 'phone', 'address',
            'content', 'privateKey', 'publicKey', 'fingerprint', 'keyType', 'passphrase',
            '_reprompt', '_passwordHistory', '_uris',
          ]);
          const customFields: Record<string, string> = {};
          for (const [k, v] of Object.entries(fields)) {
            if (!standardKeys.has(k) && v) customFields[k] = v;
          }
          // For secure_note, put content in notes column
          const notesVal = fields.notes || (entry.entry_type === 'secure_note' ? fields.content : '') || '';

          const row = [
            csvEscape(folder),
            csvEscape(entry.entry_type),
            csvEscape(fields.name || ''),
            csvEscape(fields.username || ''),
            csvEscape(fields.password || ''),
            csvEscape(fields.uri || ''),
            csvEscape(notesVal),
            csvEscape(fields.totp || ''),
            csvEscape(Object.keys(customFields).length > 0 ? JSON.stringify(customFields) : ''),
            csvEscape(fields.number || ''),
            csvEscape(fields.expiry || ''),
            csvEscape(fields.cvv || ''),
            csvEscape(fields.cardholder || ''),
            csvEscape(fields.firstName || ''),
            csvEscape(fields.lastName || ''),
            csvEscape(fields.email || ''),
            csvEscape(fields.phone || ''),
            csvEscape(fields.address || ''),
            csvEscape(fields.privateKey || ''),
            csvEscape(fields.publicKey || ''),
            csvEscape(fields.fingerprint || ''),
            csvEscape(fields.keyType || ''),
            csvEscape(fields.passphrase || ''),
          ];
          rows.push(row.join(','));
        }

        // Add passkeys as rows with type='passkey'
        for (const pk of passkeys) {
          const row = [
            '', // folder
            csvEscape('passkey'),
            csvEscape(String(pk.rp_name || pk.rp_id || '')),
            csvEscape(String(pk.username || '')),
            '', // password
            csvEscape(String(pk.rp_id || '')), // uri = rpId
            '', // notes
            '', // totp
            csvEscape(JSON.stringify({ credential_id: pk.credential_id, public_key_alg: pk.public_key_alg, discoverable: pk.discoverable })),
            '', '', '', '', '', '', '', '', '', '', '', '', '', '',
          ];
          rows.push(row.join(','));
        }

        await window.api.vault.exportFile(rows.join('\n'), 'csv');
      }

      onClose();
    } catch {
      setError('Export failed');
      setStep('choose');
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-surface-900 rounded-lg p-6 max-w-md w-full shadow-2xl">
        <h2 className="text-lg font-semibold text-surface-100 mb-4">Export Vault</h2>

        {step === 'choose' && (
          <>
            <p className="text-sm text-surface-400 mb-4">Choose an export format:</p>
            <div className="space-y-2 mb-6">
              {([
                { value: 'encrypted_json' as const, label: 'Encrypted JSON', desc: 'Full backup — can be re-imported into LGI Pass' },
                { value: 'json' as const, label: 'Unencrypted JSON', desc: 'All entries decrypted in standard JSON format' },
                { value: 'csv' as const, label: 'Unencrypted CSV', desc: 'Flat CSV for spreadsheet / import into other managers' },
              ]).map((opt) => (
                <label
                  key={opt.value}
                  className={`flex items-start gap-3 px-4 py-3 rounded-md cursor-pointer transition-colors ${
                    format === opt.value ? 'bg-accent-600/20 border border-accent-500/40' : 'bg-surface-800 hover:bg-surface-700 border border-transparent'
                  }`}
                >
                  <input
                    type="radio"
                    name="exportFormat"
                    checked={format === opt.value}
                    onChange={() => setFormat(opt.value)}
                    className="mt-1 accent-accent-500"
                  />
                  <div>
                    <p className="text-sm text-surface-200 font-medium">{opt.label}</p>
                    <p className="text-xs text-surface-500">{opt.desc}</p>
                  </div>
                </label>
              ))}
            </div>
            <div className="flex gap-3">
              <button onClick={onClose} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Cancel
              </button>
              <button onClick={handleProceed} className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
                Continue
              </button>
            </div>
          </>
        )}

        {step === 'warning' && (
          <>
            <div className="flex items-start gap-3 px-4 py-3 rounded-lg bg-amber-500/10 border border-amber-500/30 mb-4">
              <span className="text-xl mt-0.5">⚠️</span>
              <div>
                <p className="text-sm text-amber-300 font-medium mb-1">Security Warning</p>
                <p className="text-xs text-amber-200/80">
                  Exporting unencrypted data exposes your passwords. The exported file is <strong>NOT encrypted</strong>.
                  Delete it after importing into another application.
                </p>
              </div>
            </div>
            <div className="flex gap-3">
              <button onClick={() => setStep('choose')} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Go Back
              </button>
              <button onClick={handleWarningAccept} className="flex-1 py-2 rounded-md bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium transition-colors">
                I Understand, Continue
              </button>
            </div>
          </>
        )}

        {step === 'verify' && (
          <form onSubmit={(e) => { e.preventDefault(); handleVerify(); }}>
            <p className="text-sm text-surface-400 mb-3">Re-enter your master password to export:</p>
            <input
              type="password"
              value={password}
              onChange={(e) => { setPassword(e.target.value); setError(''); }}
              placeholder="Master password"
              autoFocus
              className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 text-sm mb-3"
            />
            {error && <p className="text-xs text-red-400 mb-3">{error}</p>}
            <div className="flex gap-3">
              <button type="button" onClick={() => { setStep('choose'); setPassword(''); setError(''); }} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Cancel
              </button>
              <button type="submit" disabled={!password} className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white text-sm font-medium transition-colors">
                Export
              </button>
            </div>
          </form>
        )}

        {step === 'exporting' && (
          <div className="flex flex-col items-center py-8">
            <div className="w-8 h-8 border-2 border-accent-500 border-t-transparent rounded-full animate-spin mb-3" />
            <p className="text-sm text-surface-400">Exporting…</p>
          </div>
        )}
      </div>
    </div>
  );
}

function AppearanceSection() {
  const { theme, setTheme } = useThemeStore();
  const options: { value: 'light' | 'dark' | 'system'; label: string; icon: string }[] = [
    { value: 'light', label: 'Light', icon: '☀️' },
    { value: 'dark', label: 'Dark', icon: '🌙' },
    { value: 'system', label: 'System', icon: '💻' },
  ];

  return (
    <section>
      <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Appearance</h2>
      <div className="flex gap-2">
        {options.map((opt) => (
          <button
            key={opt.value}
            onClick={() => setTheme(opt.value)}
            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
              theme === opt.value
                ? 'bg-accent-600 text-white'
                : 'bg-surface-800 text-surface-300 hover:bg-surface-700'
            }`}
          >
            <span>{opt.icon}</span>
            <span>{opt.label}</span>
          </button>
        ))}
      </div>
    </section>
  );
}

export function Settings() {
  const { email, token, masterKeyHex, autoLockMinutes, setAutoLockMinutes, timeoutAction, setTimeoutAction, orgId, orgName, setOrg, clearOrg } = useAuthStore();
  const { entries, entryFields, folders } = useVaultStore();
  const refreshNotifications = useNotificationStore((s) => s.refresh);
  const [biometricEnabled, setBiometricEnabled] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const [biometricChecking, setBiometricChecking] = useState(true);
  const [biometricError, setBiometricError] = useState('');
  const [showBiometricEnroll, setShowBiometricEnroll] = useState(false);
  const [showChangePw, setShowChangePw] = useState(false);
  const [show2fa, setShow2fa] = useState(false);
  const [has2fa, setHas2fa] = useState(false);
  const [requireHWKey, setRequireHWKey] = useState(false);
  const [hwKeyLoading, setHwKeyLoading] = useState(false);
  const [hwKeys, setHwKeys] = useState<{ id: string; name: string; created_at: string; last_used_at: string; transports: string[] }[]>([]);
  const [hwKeyRegLoading, setHwKeyRegLoading] = useState(false);
  const [hwKeyError, setHwKeyError] = useState('');
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [pendingInvites, setPendingInvites] = useState<{ id: string; org_id: string; org_name: string; role: string; created_at: string }[]>([]);
  const [pending2FAShares, setPending2FAShares] = useState<{ id: string; from_user: string; label: string; expires_at: string; created_at: string }[]>([]);
  const [claimingShareId, setClaimingShareId] = useState('');
  const [claimResult, setClaimResult] = useState<{ secret?: string; label?: string; error?: string } | null>(null);
  const [newOrgName, setNewOrgName] = useState('');
  const [orgLoading, setOrgLoading] = useState(false);
  const [orgError, setOrgError] = useState('');
  const [storageBackend, setStorageBackend] = useState<'sqlite' | 'postgres'>('sqlite');
  const [showOrgSetup, setShowOrgSetup] = useState(false);
  const [sendDomain, setSendDomain] = useState('');
  const [sendDomainInput, setSendDomainInput] = useState('');
  const [sendDomainSaving, setSendDomainSaving] = useState(false);
  const [sendDomainMsg, setSendDomainMsg] = useState('');
  const [showImport, setShowImport] = useState(false);
  const [showSync, setShowSync] = useState(false);
  const [showServerConfig, setShowServerConfig] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [appVersion, setAppVersion] = useState('1.0.0');
  const [updateStatus, setUpdateStatus] = useState<'idle' | 'checking' | 'available' | 'not-available' | 'downloading' | 'ready' | 'error'>('idle');
  const [updateVersion, setUpdateVersion] = useState('');
  const [updateProgress, setUpdateProgress] = useState(0);
  const [updateError, setUpdateError] = useState('');
  useEffect(() => {
    window.api?.app?.getVersion?.().then((v: string) => v && setAppVersion(v));

    // Auto-update event listeners
    const unsubs = [
      window.api.onUpdateAvailable?.((info) => {
        setUpdateStatus('available');
        setUpdateVersion(info.version);
      }),
      window.api.onUpdateNotAvailable?.(() => {
        setUpdateStatus('not-available');
      }),
      window.api.onUpdateDownloadProgress?.((progress) => {
        setUpdateStatus('downloading');
        setUpdateProgress(progress.percent);
      }),
      window.api.onUpdateDownloaded?.(() => {
        setUpdateStatus('ready');
      }),
      window.api.onUpdateError?.((msg) => {
        setUpdateStatus('error');
        setUpdateError(msg);
      }),
    ];
    return () => unsubs.forEach((u) => u?.());
  }, []);
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
    // Fetch send domain
    window.api.send.getDomain().then((d) => { setSendDomain(d); setSendDomainInput(d); }).catch(() => {});
    // Fetch security settings (require HW key)
    if (token) {
      window.api.security.getSettings(token)
        .then((data) => {
          if (data.require_hw_key !== undefined) setRequireHWKey(data.require_hw_key);
          if (data.has_2fa !== undefined) setHas2fa(data.has_2fa);
        })
        .catch(() => {});
      // Fetch registered hardware keys
      window.api.passkey.listHardwareKeys(token)
        .then((data: any) => {
          if (Array.isArray(data)) setHwKeys(data);
        })
        .catch(() => {});
    }
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

  const handleHWKeyToggle = async (enabled: boolean) => {
    if (!token) return;
    setHwKeyLoading(true);
    try {
      const result = await window.api.security.setRequireHWKey(token, enabled);
      if (!result.error) {
        setRequireHWKey(enabled);
      }
    } catch {
      // ignore
    } finally {
      setHwKeyLoading(false);
    }
  };

  const handleRegisterHWKey = async () => {
    if (!token || !email) return;
    setHwKeyError('');
    setHwKeyRegLoading(true);
    try {
      // Step 1: Get challenge from server
      const opts = await window.api.hwkey.beginRegistration(token, {
        username: email,
        display_name: email,
      }) as any;

      if (opts.error) {
        setHwKeyError(opts.error);
        return;
      }

      // Step 2: Open a localhost popup window for the WebAuthn ceremony
      // (Electron's renderer is not a secure context, so we can't call navigator.credentials.create here)
      const credResult = await window.api.hwkey.webauthnCreate(JSON.stringify(opts));

      if (credResult.error) {
        if (credResult.error === 'cancelled') return;
        setHwKeyError(credResult.error);
        return;
      }

      // Step 3: Prompt user for a name
      const keyName = prompt('Give this security key a name:', 'My Security Key');
      if (!keyName) {
        setHwKeyError('Registration cancelled');
        return;
      }

      // Step 4: Send attestation to server
      const result = await window.api.hwkey.finishRegistration(token, {
        session_id: opts.session_id,
        name: keyName,
        credential_id: credResult.credential_id,
        attestation_object: credResult.attestation_object,
        client_data_json: credResult.client_data_json,
        public_key_cbor: credResult.public_key_cbor ?? '',
        transports: credResult.transports ?? ['usb'],
      }) as any;

      if (result.error) {
        setHwKeyError(result.error);
      } else {
        // Refresh the list
        const keys = await window.api.passkey.listHardwareKeys(token) as any;
        if (Array.isArray(keys)) setHwKeys(keys);
      }
    } catch (err: any) {
      setHwKeyError(err?.message ?? 'Registration failed');
    } finally {
      setHwKeyRegLoading(false);
    }
  };

  const handleDeleteHWKey = async (keyId: string) => {
    if (!token) return;
    try {
      await window.api.passkey.deleteHardwareKey(token, keyId);
      setHwKeys(prev => prev.filter(k => k.id !== keyId));
    } catch {
      // ignore
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

  // Fetch pending 2FA shares
  useEffect(() => {
    if (!token) return;
    (async () => {
      try {
        const result = await window.api.admin.listPending2FA(token) as { id: string; from_user: string; label: string; expires_at: string; created_at: string }[] | { error: string };
        if (Array.isArray(result)) {
          setPending2FAShares(result);
        }
      } catch { /* ignore */ }
    })();
  }, [token]);

  const handleClaim2FA = async (shareId: string) => {
    if (!token) { setClaimResult({ error: 'Not logged in' }); return; }
    if (!masterKeyHex) { setClaimResult({ error: 'Master key not available — please re-login' }); return; }
    setClaimingShareId(shareId);
    setClaimResult(null);
    try {
      const result = await window.api.admin.claim2FA(token, shareId, masterKeyHex) as { totp_secret?: string; label?: string; error?: string };
      if (result.error) {
        setClaimResult({ error: result.error });
      } else if (result.totp_secret) {
        setClaimResult({ secret: result.totp_secret, label: result.label });
        setPending2FAShares((prev) => prev.filter((s) => s.id !== shareId));
        refreshNotifications();
      } else {
        setClaimResult({ error: 'Unexpected response from server' });
      }
    } catch (e) {
      setClaimResult({ error: `Failed to claim 2FA secret: ${e instanceof Error ? e.message : 'unknown'}` });
    } finally {
      setClaimingShareId('');
    }
  };

  return (
    <div>
      <h1 className="text-lg font-semibold text-surface-100 mb-6">Settings</h1>

      <div className="space-y-6 max-w-lg">
        {/* Appearance */}
        <AppearanceSection />

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
              <span className={`text-xs ${has2fa ? 'text-green-400' : 'text-surface-500'}`}>{has2fa ? 'Enabled' : 'Not configured'}</span>
            </button>

            {/* Pending 2FA Shares */}
            {(pending2FAShares.length > 0 || claimResult) && (
              <div className="bg-accent-600/10 border border-accent-500/30 rounded-lg p-4 space-y-3">
                {pending2FAShares.length > 0 && (
                  <>
                    <div className="flex items-center gap-2">
                      <span className="text-accent-400 text-sm font-medium">🔑 Shared 2FA Secrets</span>
                      <span className="text-xs bg-accent-500/20 text-accent-300 px-2 py-0.5 rounded-full">{pending2FAShares.length}</span>
                    </div>
                    {pending2FAShares.map((share) => (
                      <div key={share.id} className="flex items-center justify-between bg-surface-800 rounded-lg px-3 py-2">
                        <div>
                          <p className="text-sm text-surface-200">{share.label || 'Shared 2FA'}</p>
                          <p className="text-xs text-surface-500">From {share.from_user} · Expires {new Date(share.expires_at).toLocaleString()}</p>
                        </div>
                        <button
                          onClick={() => handleClaim2FA(share.id)}
                          disabled={claimingShareId === share.id}
                          className="text-xs bg-accent-600 hover:bg-accent-500 disabled:opacity-50 text-white rounded-lg px-3 py-1.5 transition-colors"
                        >
                          {claimingShareId === share.id ? 'Claiming…' : 'Claim'}
                        </button>
                      </div>
                    ))}
                  </>
                )}
                {claimResult?.error && (
                  <p className="text-xs text-red-400">{claimResult.error}</p>
                )}
                {claimResult?.secret && (
                  <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 space-y-2">
                    <p className="text-xs text-green-400 font-medium">2FA Secret Claimed Successfully</p>
                    {claimResult.label && (
                      <p className="text-xs text-surface-200">For: <span className="font-medium">{claimResult.label}</span></p>
                    )}
                    <p className="text-xs text-surface-300 font-mono break-all select-all">{claimResult.secret}</p>
                    <p className="text-xs text-surface-500">Add this secret to your authenticator app or the matching vault entry.</p>
                  </div>
                )}
              </div>
            )}
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
            <div className="px-4 py-3 rounded-md bg-surface-800">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-surface-200">Vault Timeout Action</p>
                  <p className="text-xs text-surface-500 mt-0.5">
                    {TIMEOUT_ACTION_OPTIONS.find((o) => o.value === timeoutAction)?.description}
                  </p>
                </div>
                <select
                  value={timeoutAction}
                  onChange={(e) => setTimeoutAction(e.target.value as TimeoutActionOption)}
                  className="bg-surface-700 border border-surface-600 text-surface-300 text-xs rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-accent-500"
                >
                  {TIMEOUT_ACTION_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
            </div>
            <SettingsToggle
              label={hwKeyLoading ? 'Require Hardware Key (saving…)' : 'Require Hardware Key for Login'}
              description="When enabled, a FIDO2 security key (USB/NFC/BLE) is required after password entry"
              checked={requireHWKey}
              onChange={hwKeyLoading ? () => {} : handleHWKeyToggle}
            />
          </div>
        </section>

        {/* Hardware Security Keys — only visible when toggle is on */}
        {requireHWKey && (
        <section>
          <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Hardware Security Keys</h2>
          <div className="space-y-2">
            <p className="text-xs text-surface-500 px-1 mb-2">
              Register a FIDO2 security key (USB, NFC, or Bluetooth) for two-factor authentication when logging into your vault.
            </p>
            {hwKeys.map((key) => (
              <div key={key.id} className="flex items-center justify-between px-4 py-3 rounded-md bg-surface-800">
                <div className="flex items-center gap-3">
                  <svg className="w-5 h-5 text-accent-400 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="7" width="20" height="10" rx="2" /><circle cx="16" cy="12" r="2" /><path d="M6 12h4" /></svg>
                  <div>
                    <p className="text-sm text-surface-200">{key.name}</p>
                    <p className="text-xs text-surface-500">
                      Added {key.created_at ? new Date(key.created_at).toLocaleDateString() : '—'}
                      {key.transports?.length > 0 && ` · ${key.transports.join(', ')}`}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => handleDeleteHWKey(key.id)}
                  className="text-red-400 hover:text-red-300 transition-colors"
                  title="Remove key"
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/></svg>
                </button>
              </div>
            ))}
            {hwKeyError && (
              <p className="text-xs text-red-400 px-4">{hwKeyError}</p>
            )}
            <button
              onClick={handleRegisterHWKey}
              disabled={hwKeyRegLoading || !token}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="flex items-center gap-2">
                <span className="text-accent-400">+</span>
                {hwKeyRegLoading ? 'Insert your security key and follow the prompt…' : 'Register a Security Key'}
              </div>
              {hwKeyRegLoading && (
                <span className="text-xs text-surface-500 animate-pulse">Waiting…</span>
              )}
            </button>
          </div>
        </section>
        )}

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
                      const result = await window.api.admin.leaveOrg(token, orgId) as { status?: string; entries?: unknown[]; error?: string };
                      if (result.error) { setOrgError(result.error); return; }
                      clearOrg();
                      setOrgError('');
                      // Vault entries are saved locally by the main process;
                      // they will be auto-imported when the user logs in on SQLite mode.
                      if (result.entries && Array.isArray(result.entries) && result.entries.length > 0) {
                        // Try immediate import if still on same backend
                        window.api.vault.importExport(token).catch(() => {});
                      }
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
                                else { setOrg(inv.org_id, inv.org_name, inv.role); setPendingInvites([]); refreshNotifications(); }
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
            <button
              onClick={() => setShowImport(true)}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between"
            >
              Import from another password manager
              <span className="text-surface-600">→</span>
            </button>
            <button
              onClick={() => setShowSync(true)}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between"
            >
              Sync Settings
              <span className="text-surface-600">→</span>
            </button>
            <button
              onClick={() => setShowServerConfig(true)}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between"
            >
              Server Configuration (Local / Remote)
              <span className="text-surface-600">→</span>
            </button>
            <button
              onClick={() => setShowExport(true)}
              className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors flex items-center justify-between"
            >
              Export Vault Data
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

        {/* Emergency Access */}
        <EmergencyAccessSection />

        {/* Username & Alias */}
        <section>
          <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Username & Alias</h2>
          <div className="space-y-3 bg-surface-800 rounded-lg p-4">
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1">Catch-all Domain</label>
              <p className="text-xs text-surface-500 mb-2">
                Set a domain with catch-all email to generate random email aliases (e.g., xyz@yourdomain.com).
              </p>
              <input
                type="text"
                value={(() => { try { return localStorage.getItem('lgi-pass-catchall-domain') || ''; } catch { return ''; } })()}
                onChange={(e) => { localStorage.setItem('lgi-pass-catchall-domain', e.target.value); }}
                placeholder="mydomain.com"
                className="w-full px-3 py-2 bg-surface-900 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1">SimpleLogin API Key</label>
              <p className="text-xs text-surface-500 mb-2">
                Optional. Enables generating email aliases via SimpleLogin.
              </p>
              <input
                type="password"
                value={(() => { try { return localStorage.getItem('lgi-pass-simplelogin-key') || ''; } catch { return ''; } })()}
                onChange={(e) => { localStorage.setItem('lgi-pass-simplelogin-key', e.target.value); }}
                placeholder="sl_..."
                className="w-full px-3 py-2 bg-surface-900 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1">Addy.io API Key</label>
              <p className="text-xs text-surface-500 mb-2">
                Optional. Enables generating email aliases via Addy.io (AnonAddy).
              </p>
              <input
                type="password"
                value={(() => { try { return localStorage.getItem('lgi-pass-addyio-key') || ''; } catch { return ''; } })()}
                onChange={(e) => { localStorage.setItem('lgi-pass-addyio-key', e.target.value); }}
                placeholder="API key"
                className="w-full px-3 py-2 bg-surface-900 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
              />
            </div>
          </div>
        </section>

        {/* Secure Send */}
        <section>
          <h2 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-3">Secure Send</h2>
          <div className="space-y-3 bg-surface-800 rounded-lg p-4">
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1">Send Domain (optional)</label>
              <p className="text-xs text-surface-500 mb-2">
                Set a public domain to enable link-based sharing with server-side password protection and access tracking.
                The domain must point to your LGI Pass server.
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={sendDomainInput}
                  onChange={(e) => { setSendDomainInput(e.target.value); setSendDomainMsg(''); }}
                  placeholder="e.g. send.example.com"
                  className="flex-1 px-3 py-2 bg-surface-900 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
                />
                <button
                  disabled={sendDomainSaving}
                  onClick={async () => {
                    setSendDomainSaving(true);
                    setSendDomainMsg('');
                    try {
                      let domain = sendDomainInput.trim();
                      // Strip trailing slash and protocol
                      domain = domain.replace(/\/+$/, '');
                      if (domain && !domain.startsWith('http')) domain = 'https://' + domain;
                      const result = await window.api.send.setDomain(domain);
                      if (result.error) { setSendDomainMsg(result.error); }
                      else { setSendDomain(domain); setSendDomainInput(domain); setSendDomainMsg('Saved'); }
                    } catch { setSendDomainMsg('Failed to save'); }
                    finally { setSendDomainSaving(false); }
                  }}
                  className="px-4 py-2 bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium rounded-md transition-colors disabled:opacity-50"
                >
                  {sendDomainSaving ? 'Saving…' : 'Save'}
                </button>
              </div>
              {sendDomainMsg && (
                <p className={`text-xs mt-1 ${sendDomainMsg === 'Saved' ? 'text-green-400' : 'text-red-400'}`}>{sendDomainMsg}</p>
              )}
              {sendDomain && (
                <p className="text-xs text-green-400/70 mt-1">Link sharing enabled: {sendDomain}</p>
              )}
            </div>
          </div>
        </section>

        {/* About */}
        <div className="pt-4 border-t border-surface-800">
          <button
            onClick={() => setShowShortcuts(true)}
            className="text-xs text-accent-400 hover:text-accent-300 transition-colors mb-2"
          >
            Keyboard Shortcuts →
          </button>
          <p className="text-xs text-surface-600">LGI Pass v{appVersion}</p>
          <p className="text-xs text-surface-700 mt-0.5">Post-quantum encryption: X-Wing KEM + AES-256-GCM</p>

          {/* Update section */}
          <div className="mt-3">
            {updateStatus === 'idle' && (
              <button
                onClick={() => {
                  setUpdateStatus('checking');
                  window.api.app.checkForUpdate();
                }}
                className="text-xs text-accent-400 hover:text-accent-300 transition-colors"
              >
                Check for updates
              </button>
            )}
            {updateStatus === 'checking' && (
              <p className="text-xs text-surface-500">Checking for updates…</p>
            )}
            {updateStatus === 'not-available' && (
              <p className="text-xs text-green-400">You're on the latest version.</p>
            )}
            {updateStatus === 'available' && (
              <div className="flex items-center gap-2">
                <p className="text-xs text-amber-400">v{updateVersion} available</p>
                <button
                  onClick={() => {
                    setUpdateStatus('downloading');
                    setUpdateProgress(0);
                    window.api.app.downloadUpdate();
                  }}
                  className="text-xs px-2 py-0.5 rounded bg-accent-600 text-white hover:bg-accent-500 transition-colors"
                >
                  Download
                </button>
              </div>
            )}
            {updateStatus === 'downloading' && (
              <div>
                <p className="text-xs text-surface-400 mb-1">Downloading update… {updateProgress}%</p>
                <div className="w-full h-1.5 bg-surface-700 rounded-full overflow-hidden">
                  <div className="h-full bg-accent-500 transition-all" style={{ width: `${updateProgress}%` }} />
                </div>
              </div>
            )}
            {updateStatus === 'ready' && (
              <div className="flex items-center gap-2">
                <p className="text-xs text-green-400">Update ready</p>
                <button
                  onClick={() => window.api.app.installUpdate()}
                  className="text-xs px-2 py-0.5 rounded bg-green-600 text-white hover:bg-green-500 transition-colors"
                >
                  Restart & Install
                </button>
              </div>
            )}
            {updateStatus === 'error' && (
              <div>
                <p className="text-xs text-red-400">Update failed: {updateError || 'Unknown error'}</p>
                <button
                  onClick={() => setUpdateStatus('idle')}
                  className="text-xs text-accent-400 hover:text-accent-300 mt-1"
                >
                  Try again
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {showChangePw && <ChangePasswordModal onClose={() => setShowChangePw(false)} />}
      {show2fa && <TwoFactorModal onClose={() => setShow2fa(false)} onEnabled={() => setHas2fa(true)} onDisabled={() => setHas2fa(false)} isEnabled={has2fa} />}
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
      {showImport && <ImportWizard onClose={() => setShowImport(false)} />}
      {showSync && <SyncSettings onClose={() => setShowSync(false)} />}
      {showServerConfig && <ServerConfig onClose={() => setShowServerConfig(false)} />}
      {showExport && <ExportModal onClose={() => setShowExport(false)} />}
      {showShortcuts && <ShortcutHelp onClose={() => setShowShortcuts(false)} />}
    </div>
  );
}
