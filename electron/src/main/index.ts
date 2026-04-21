import { app, BrowserWindow, ipcMain, Menu, session, dialog, clipboard } from 'electron';
import path from 'path';
import fs from 'fs';
import nodeCrypto from 'crypto';
import { spawn, ChildProcess } from 'child_process';
import {
  isBiometricAvailable,
  isBiometricConfigured,
  enableBiometric,
  unlockWithBiometric,
  verifyBiometric,
  disableBiometric,
  warmUpBiometric,
} from './biometric';

let mainWindow: BrowserWindow | null = null;
let sidecarProcess: ChildProcess | null = null;
let sidecarPort: number | null = null;

const isDev = process.env.NODE_ENV === 'development';

// API server URL: use BACKEND_URL env or try sidecar
const backendUrl = process.env.BACKEND_URL || '';

function getApiBase(): string {
  if (backendUrl) return backendUrl;
  if (sidecarPort) return `http://127.0.0.1:${sidecarPort}`;
  return '';
}

function getSidecarPath(): string {
  const platform = process.platform;
  const ext = platform === 'win32' ? '.exe' : '';
  const binaryName = `server${ext}`;

  if (isDev) {
    return path.join(__dirname, '..', '..', '..', 'bin', binaryName);
  }
  return path.join(process.resourcesPath, 'bin', binaryName);
}

function getRandomPort(): number {
  return Math.floor(Math.random() * (65535 - 49152) + 49152);
}

async function startSidecar(): Promise<void> {
  const sidecarPath = getSidecarPath();

  if (!fs.existsSync(sidecarPath)) {
    console.log(`[sidecar] Binary not found at ${sidecarPath}, skipping`);
    return;
  }

  sidecarPort = getRandomPort();

  try {
    sidecarProcess = spawn(sidecarPath, [], {
      env: {
        ...process.env,
        PORT: String(sidecarPort),
        SIDECAR_MODE: '1',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    sidecarProcess.on('error', (err) => {
      console.error('[sidecar] Failed to start:', err.message);
      sidecarProcess = null;
    });

    sidecarProcess.stdout?.on('data', (data: Buffer) => {
      console.log(`[sidecar] ${data.toString().trim()}`);
    });

    sidecarProcess.stderr?.on('data', (data: Buffer) => {
      console.error(`[sidecar] ${data.toString().trim()}`);
    });

    sidecarProcess.on('exit', (code) => {
      console.log(`[sidecar] exited with code ${code}`);
      sidecarProcess = null;
    });

    // Wait briefly for sidecar to start
    await new Promise<void>((resolve) => setTimeout(resolve, 1000));
  } catch (err) {
    console.error('Failed to start sidecar:', err);
  }
}

function stopSidecar(): void {
  if (sidecarProcess) {
    sidecarProcess.kill();
    sidecarProcess = null;
    sidecarPort = null;
  }
  // Clean up lockfile when not using sidecar mode (BACKEND_URL mode)
  cleanupExtensionLockfile();
}

function getAppDataDir(): string {
  const appName = 'QuantumPasswordManager';
  switch (process.platform) {
    case 'win32':
      return path.join(process.env.APPDATA || path.join(process.env.USERPROFILE || '', 'AppData', 'Roaming'), appName);
    case 'darwin':
      return path.join(app.getPath('home'), 'Library', 'Application Support', appName);
    default:
      return path.join(app.getPath('home'), '.config', appName);
  }
}

/**
 * Push session state to the sidecar so the extension can fetch credentials.
 */
async function pushSessionToSidecar(token: string, masterKeyHex: string, userId: string): Promise<void> {
  const api = getApiBase();
  if (!api) return;
  try {
    await fetch(`${api}/extension/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        master_key_hex: masterKeyHex,
        user_id: userId,
      }),
    });
    console.log('[extension] session pushed to sidecar');
  } catch (err) {
    console.error('[extension] failed to push session:', err);
  }
}

/**
 * Write a lockfile for non-sidecar mode (BACKEND_URL / Docker).
 * The Go sidecar writes its own lockfile in sidecar mode.
 */
function writeExtensionLockfile(): void {
  if (!backendUrl) return; // sidecar mode — Go server writes its own lockfile
  try {
    const dir = getAppDataDir();
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    // Extract port from BACKEND_URL
    const url = new URL(backendUrl);
    const port = url.port || (url.protocol === 'https:' ? '443' : '80');
    const lockPath = path.join(dir, 'sidecar.lock');
    // No secret in BACKEND_URL mode — extension endpoints on Docker server aren't secret-protected
    fs.writeFileSync(lockPath, `${port}\n`, { mode: 0o600 });
    console.log(`[extension] wrote lockfile: ${lockPath} (port ${port})`);
  } catch (err) {
    console.error('[extension] failed to write lockfile:', err);
  }
}

function cleanupExtensionLockfile(): void {
  try {
    const lockPath = path.join(getAppDataDir(), 'sidecar.lock');
    if (fs.existsSync(lockPath)) {
      fs.unlinkSync(lockPath);
    }
  } catch { /* ignore */ }
}

function createWindow(): void {
  Menu.setApplicationMenu(null);

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: 'LGI Pass',
    backgroundColor: '#0f172a',
    autoHideMenuBar: true,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0f172a',
      symbolColor: '#94a3b8',
      height: 36,
    },
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });

  // Set Content Security Policy
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' http://localhost:*",
        ],
      },
    });
  });

  // Prevent navigation to external URLs
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const parsedUrl = new URL(url);
    if (parsedUrl.origin !== 'http://localhost:5173' && parsedUrl.protocol !== 'file:') {
      event.preventDefault();
    }
  });

  // Block new window creation
  mainWindow.webContents.setWindowOpenHandler(() => {
    return { action: 'deny' };
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  if (isDev) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// IPC Handlers
function registerIpcHandlers(): void {
  ipcMain.handle('app:getSidecarPort', () => {
    return sidecarPort;
  });

  ipcMain.handle('auth:login', async (_event, credentials: { email: string; authHash: string }) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      // Derive auth hash from password using PBKDF2 (stand-in for Argon2id until Go sidecar handles it)
      const salt = nodeCrypto.createHash('sha256').update(credentials.email).digest();
      const derived = nodeCrypto.pbkdf2Sync(credentials.authHash, salt, 100000, 64, 'sha512');
      const masterKeyHex = derived.subarray(0, 32).toString('hex');
      const authHashHex = derived.subarray(32, 64).toString('hex');

      const res = await fetch(`${api}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: credentials.email, auth_hash: authHashHex }),
      });
      const result = await res.json() as Record<string, unknown>;
      console.log('[ipc] auth:login result keys:', Object.keys(result));
      if (result.access_token || result.token) {
        result.master_key_hex = masterKeyHex;
        // Push session to sidecar for browser extension bridge
        const jwt = (result.access_token || result.token) as string;
        const userId = result.user_id as string;
        if (jwt && userId) {
          pushSessionToSidecar(jwt, masterKeyHex, userId);
        }
      }
      return result;
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('auth:logout', async () => {
    // Clear extension session on the server so browser extension mirrors lock state
    const api = getApiBase();
    if (!api) return;
    try {
      await fetch(`${api}/extension/lock`, { method: 'POST' });
      console.log('[extension] session cleared on logout');
    } catch {
      // Best effort
    }
  });

  ipcMain.handle('auth:register', async (_event, data: { email: string; password: string }) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      // Generate deterministic salt from email, derive auth hash
      const salt = nodeCrypto.createHash('sha256').update(data.email).digest();
      const derived = nodeCrypto.pbkdf2Sync(data.password, salt, 100000, 64, 'sha512');
      const masterKey = derived.subarray(0, 32);
      const authHash = derived.subarray(32, 64);

      // Generate a key pair (placeholder using X25519 until X-Wing sidecar is wired)
      const keyPair = nodeCrypto.generateKeyPairSync('x25519');
      const publicKeyBuf = keyPair.publicKey.export({ type: 'spki', format: 'der' });
      const privateKeyBuf = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });

      // Encrypt private key with master key
      const iv = nodeCrypto.randomBytes(12);
      const cipher = nodeCrypto.createCipheriv('aes-256-gcm', masterKey, iv);
      const encrypted = Buffer.concat([iv, cipher.update(privateKeyBuf), cipher.final(), cipher.getAuthTag()]);

      const body = {
        email: data.email,
        auth_hash: authHash.toString('hex'),
        salt: salt.toString('hex'),
        kdf_params: { memory: 65536, iterations: 3, parallelism: 4 },
        public_key: publicKeyBuf.toString('hex'),
        encrypted_private_key: encrypted.toString('hex'),
      };

      const res = await fetch(`${api}/api/v1/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const result = await res.json() as Record<string, unknown>;
      if (result.access_token || result.token) {
        result.master_key_hex = masterKey.toString('hex');
      }
      return result;
    } catch (err) {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('auth:changePassword', async (_event, token: string, data: { email: string; currentPassword: string; newPassword: string }) => {
    // Clear extension session on the server so browser extension mirrors lock state
    const api = getApiBase();
    if (api) {
      fetch(`${api}/extension/lock`, { method: 'POST' }).catch(() => {});
    }
    // Proceed with password change
    if (!api) return { error: 'Backend not available' };
    try {
      const salt = nodeCrypto.createHash('sha256').update(data.email).digest();

      // Derive old keys
      const oldDerived = nodeCrypto.pbkdf2Sync(data.currentPassword, salt, 100000, 64, 'sha512');
      const oldMasterKey = oldDerived.subarray(0, 32).toString('hex');

      // Derive new keys
      const newDerived = nodeCrypto.pbkdf2Sync(data.newPassword, salt, 100000, 64, 'sha512');
      const newMasterKey = newDerived.subarray(0, 32).toString('hex');
      const newAuthHash = newDerived.subarray(32, 64).toString('hex');

      const res = await fetch(`${api}/api/v1/auth/change-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          old_master_key: oldMasterKey,
          new_master_key: newMasterKey,
          new_auth_hash: newAuthHash,
          new_salt: salt.toString('hex'),
        }),
      });
      const result = await res.json() as Record<string, unknown>;
      if (result.status === 'password_changed') {
        result.master_key_hex = newMasterKey;
      }
      return result;
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:list', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:get', async (_event, token: string, entryId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:create', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:update', async (_event, token: string, entryId: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:delete', async (_event, token: string, entryId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  // --- Vault crypto IPC handlers ---

  ipcMain.handle('vault:encrypt', (_event, masterKeyHex: string, plaintext: string) => {
    try {
      const key = Buffer.from(masterKeyHex, 'hex');
      const iv = nodeCrypto.randomBytes(12);
      const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const authTag = cipher.getAuthTag();
      return {
        encrypted_data: Buffer.concat([encrypted, authTag]).toString('hex'),
        nonce: iv.toString('hex'),
      };
    } catch {
      return { error: 'Encryption failed' };
    }
  });

  ipcMain.handle('vault:decrypt', (_event, masterKeyHex: string, encryptedDataHex: string, nonceHex: string) => {
    try {
      const key = Buffer.from(masterKeyHex, 'hex');
      const iv = Buffer.from(nonceHex, 'hex');
      const data = Buffer.from(encryptedDataHex, 'hex');
      const authTag = data.subarray(data.length - 16);
      const ciphertext = data.subarray(0, data.length - 16);
      const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return { plaintext: decrypted.toString('utf8') };
    } catch {
      return { error: 'Decryption failed' };
    }
  });

  ipcMain.handle('vault:exportFile', async (_event, jsonContent: string) => {
    const win = BrowserWindow.getFocusedWindow();
    const result = await dialog.showSaveDialog(win!, {
      title: 'Export Vault',
      defaultPath: `lgipass-export-${new Date().toISOString().slice(0, 10)}.json`,
      filters: [{ name: 'JSON', extensions: ['json'] }],
    });
    if (result.canceled || !result.filePath) return { cancelled: true };
    try {
      fs.writeFileSync(result.filePath, jsonContent, 'utf8');
      return { success: true, path: result.filePath };
    } catch {
      return { error: 'Failed to write file' };
    }
  });

  // --- Secure clipboard IPC ---
  let clipboardClearTimer: ReturnType<typeof setTimeout> | null = null;
  let lastCopiedValue: string | null = null;

  ipcMain.handle('clipboard:copySecure', (_event, text: string, clearAfterMs: number = 30_000) => {
    try {
      // Clear any previous timer
      if (clipboardClearTimer) {
        clearTimeout(clipboardClearTimer);
        clipboardClearTimer = null;
      }

      // Write to clipboard with clipboard history exclusion on Windows
      if (process.platform === 'win32') {
        // Use native clipboard API via PowerShell to set the ExcludeClipboardContentFromMonitorProcessing flag.
        // This prevents Windows Clipboard History (Win+V) and cloud sync from capturing the password.
        // We pass the text via stdin (piped) to avoid shell injection.
        const cp = require('child_process') as typeof import('child_process');
        try {
          cp.execFileSync('powershell.exe', [
            '-NoProfile', '-NonInteractive', '-Command',
            `$text = [Console]::In.ReadToEnd()
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class SecureClip {
  [DllImport("user32.dll")] static extern bool OpenClipboard(IntPtr w);
  [DllImport("user32.dll")] static extern bool EmptyClipboard();
  [DllImport("user32.dll")] static extern bool CloseClipboard();
  [DllImport("user32.dll")] static extern IntPtr SetClipboardData(uint f, IntPtr h);
  [DllImport("user32.dll")] static extern uint RegisterClipboardFormatW([MarshalAs(UnmanagedType.LPWStr)] string n);
  [DllImport("kernel32.dll")] static extern IntPtr GlobalAlloc(uint f, UIntPtr sz);
  [DllImport("kernel32.dll")] static extern IntPtr GlobalLock(IntPtr h);
  [DllImport("kernel32.dll")] static extern bool GlobalUnlock(IntPtr h);
  public static void Copy(string t) {
    OpenClipboard(IntPtr.Zero);
    EmptyClipboard();
    byte[] b = System.Text.Encoding.Unicode.GetBytes(t + "\\0");
    IntPtr h = GlobalAlloc(0x0002, (UIntPtr)b.Length);
    IntPtr p = GlobalLock(h);
    Marshal.Copy(b, 0, p, b.Length);
    GlobalUnlock(h);
    SetClipboardData(13, h);
    uint ex = RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing");
    IntPtr eh = GlobalAlloc(0x0002, (UIntPtr)1);
    IntPtr ep = GlobalLock(eh);
    Marshal.WriteByte(ep, 0);
    GlobalUnlock(eh);
    SetClipboardData(ex, eh);
    CloseClipboard();
  }
}
'@
[SecureClip]::Copy($text)`
          ], { input: text, timeout: 5000, windowsHide: true });
        } catch {
          // Fallback if P/Invoke fails
          clipboard.writeText(text);
        }
      } else if (process.platform === 'darwin') {
        // On macOS, set org.nspasteboard.ConcealedType to exclude from clipboard history
        // (Spotlight clipboard history in macOS Tahoe+, and third-party clipboard managers).
        // Uses ObjC bridge via osascript; password is piped via stdin to prevent injection.
        const cp = require('child_process') as typeof import('child_process');
        try {
          cp.execFileSync('osascript', ['-l', 'ObjC', '-e', [
            'ObjC.import("AppKit");',
            'var data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;',
            'var text = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding);',
            'var pb = $.NSPasteboard.generalPasteboard;',
            'pb.clearContents;',
            'pb.setStringForType(text, $.NSPasteboardTypeString);',
            'pb.setDataForType($.NSData.alloc.init, $("org.nspasteboard.ConcealedType"));',
          ].join('\n')], { input: text, timeout: 5000 });
        } catch {
          clipboard.writeText(text);
        }
      } else {
        clipboard.writeText(text);
      }

      lastCopiedValue = text;

      // Auto-clear after timeout (default 30s)
      clipboardClearTimer = setTimeout(() => {
        try {
          const current = clipboard.readText();
          if (current === lastCopiedValue) {
            clipboard.clear();
          }
        } catch { /* ignore */ }
        lastCopiedValue = null;
        clipboardClearTimer = null;
      }, clearAfterMs);

      return { success: true };
    } catch {
      return { error: 'Failed to copy to clipboard' };
    }
  });

  // --- Biometric IPC handlers ---

  // --- Admin IPC handlers ---

  ipcMain.handle('admin:getMyOrg', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/my-org`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:getMyInvitations', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/my-invitations`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:createOrg', async (_event, token: string, name: string, masterKey: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name, master_key: masterKey }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:inviteUser', async (_event, token: string, orgId: string, email: string, role: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ email, role }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:acceptInvite', async (_event, token: string, orgId: string, masterKey: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/accept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ master_key: masterKey }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:listMembers', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/members`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:removeMember', async (_event, token: string, orgId: string, userId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:leaveOrg', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/leave`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:accessVault', async (_event, token: string, orgId: string, userId: string, masterKey: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/vault/${encodeURIComponent(userId)}?master_key=${encodeURIComponent(masterKey)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:resetPassword', async (_event, token: string, orgId: string, userId: string, data: Record<string, string>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      // Derive new auth credentials from target user's email + new password
      const targetEmail = data.target_email;
      const newPassword = data.new_password;
      const adminMasterKey = data.master_key;
      if (!targetEmail || !newPassword || !adminMasterKey) {
        return { error: 'Missing target_email, new_password, or master_key' };
      }

      const salt = nodeCrypto.createHash('sha256').update(targetEmail).digest();
      const derived = nodeCrypto.pbkdf2Sync(newPassword, salt, 100000, 64, 'sha512');
      const newMasterKeyHex = derived.subarray(0, 32).toString('hex');
      const newAuthHash = derived.subarray(32, 64).toString('hex');
      const saltHex = salt.toString('hex');

      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/vault/${encodeURIComponent(userId)}/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          master_key: adminMasterKey,
          new_master_key: newMasterKeyHex,
          new_auth_hash: newAuthHash,
          new_salt: saltHex,
        }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:setPolicy', async (_event, token: string, orgId: string, policy: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/policy`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(policy),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:getPolicy', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/policy`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:listInvitations', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/invitations`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:getAuditLog', async (_event, token: string, orgId: string, filters?: Record<string, string>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const params = new URLSearchParams();
      if (filters) {
        for (const [k, v] of Object.entries(filters)) {
          if (v) params.set(k, v);
        }
      }
      const qs = params.toString();
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/audit${qs ? `?${qs}` : ''}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('biometric:available', async () => {
    const result = await isBiometricAvailable();
    console.log('[ipc] biometric:available =', result);
    return result;
  });

  ipcMain.handle('biometric:configured', () => {
    const result = isBiometricConfigured();
    console.log('[ipc] biometric:configured =', result);
    return result;
  });

  ipcMain.handle('biometric:enable', async (_event, credentialsJson: string) => {
    try {
      if (typeof credentialsJson !== 'string' || credentialsJson.length === 0) {
        return { success: false, error: 'Invalid credentials' };
      }
      await enableBiometric(credentialsJson);
      return { success: true };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  });

  ipcMain.handle('biometric:enableWithPassword', async (_event, data: { email: string; password: string }) => {
    try {
      // Derive keys using the same KDF as the login flow
      const salt = nodeCrypto.createHash('sha256').update(data.email).digest();
      const derived = nodeCrypto.pbkdf2Sync(data.password, salt, 100000, 64, 'sha512');
      const masterKeyHex = derived.subarray(0, 32).toString('hex');
      const authHashHex = derived.subarray(32, 64).toString('hex');

      // Verify credentials against the backend first
      const api = getApiBase();
      if (api) {
        const res = await fetch(`${api}/api/v1/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: data.email, auth_hash: authHashHex }),
        });
        const result = await res.json() as Record<string, unknown>;
        if (result.error) {
          return { success: false, error: result.error as string };
        }
      }

      // Store email + authHash + masterKeyHex so biometric unlock can re-authenticate and decrypt vault
      const credentialsJson = JSON.stringify({
        email: data.email,
        authHash: authHashHex,
        masterKeyHex,
      });
      await enableBiometric(credentialsJson);

      // Zero the derived buffer
      derived.fill(0);
      console.log('[ipc] biometric:enableWithPassword success');
      return { success: true };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  });

  ipcMain.handle('biometric:unlock', async () => {
    try {
      const credentialsJson = await unlockWithBiometric();
      const creds = JSON.parse(credentialsJson) as { email: string; authHash: string; masterKeyHex?: string };

      // Authenticate with the backend using the stored credentials
      const api = getApiBase();
      if (!api) return { error: 'Backend not available' };

      const res = await fetch(`${api}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: creds.email, auth_hash: creds.authHash }),
      });
      const result = await res.json() as Record<string, unknown>;
      if (result.error) {
        return { error: result.error as string };
      }
      // Return the login result with email and master key included
      // Push session to sidecar for browser extension bridge
      const jwt = (result.access_token || result.token) as string;
      const userId = result.user_id as string;
      if (jwt && userId && creds.masterKeyHex) {
        pushSessionToSidecar(jwt, creds.masterKeyHex, userId);
      }
      return { ...result, email: creds.email, master_key_hex: creds.masterKeyHex ?? '' };
    } catch (err) {
      return { error: (err as Error).message };
    }
  });

  ipcMain.handle('biometric:verify', async () => {
    try {
      await verifyBiometric();
      return { success: true };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  });

  ipcMain.handle('biometric:disable', async () => {
    try {
      await disableBiometric();
      return { success: true };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  });
}

// App lifecycle
app.whenReady().then(async () => {
  await startSidecar();
  writeExtensionLockfile(); // For BACKEND_URL mode — sidecar writes its own in sidecar mode

  // Clear any stale extension session from a previous run
  const api = getApiBase();
  if (api) {
    fetch(`${api}/extension/lock`, { method: 'POST' }).catch(() => {});
  }

  registerIpcHandlers();
  createWindow();

  // Pre-warm the Windows Hello daemon in the background so biometric prompts are fast
  warmUpBiometric();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    stopSidecar();
    app.quit();
  }
});

app.on('before-quit', () => {
  stopSidecar();
});
