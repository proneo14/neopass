import { app, BrowserWindow, ipcMain, Menu, session, dialog, clipboard, shell } from 'electron';
import path from 'path';
import fs from 'fs';
import http from 'http';
import os from 'os';
import nodeCrypto from 'crypto';
import { spawn, execFileSync, ChildProcess } from 'child_process';
import {
  isBiometricAvailable,
  isBiometricConfigured,
  enableBiometric,
  unlockWithBiometric,
  verifyBiometric,
  disableBiometric,
  warmUpBiometric,
  promptBiometric,
  cancelBiometric,
} from './biometric';

let mainWindow: BrowserWindow | null = null;
let sidecarProcess: ChildProcess | null = null;
let sidecarPort: number | null = null;
let sidecarSecret: string | null = null;
let autoLockTimer: ReturnType<typeof setTimeout> | null = null;

// Auto-lock timeout in ms (default 15 minutes)
const AUTO_LOCK_TIMEOUT = parseInt(process.env.AUTO_LOCK_TIMEOUT || '900000', 10);

const isDev = process.env.NODE_ENV === 'development';

// API server URL: use BACKEND_URL env or try sidecar
const backendUrl = process.env.BACKEND_URL || '';

/** Read server_url from config.json (set when user opts into remote server mode). */
function getConfiguredServerUrl(): string {
  try {
    const configPath = path.join(getAppDataDir(), 'config.json');
    if (fs.existsSync(configPath)) {
      const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      if (cfg.server_url) return cfg.server_url;
    }
  } catch { /* ignore */ }
  return '';
}

/**
 * Notify the renderer to force-logout (e.g. after emergency takeover revokes tokens).
 */
function emitForceLogout(): void {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('force-logout');
    console.log('[auth] emitted force-logout to renderer');
  }
}

function getApiBase(): string {
  if (backendUrl) return backendUrl;
  const configured = getConfiguredServerUrl();
  if (configured) return configured;
  if (sidecarPort) return `http://127.0.0.1:${sidecarPort}`;
  return '';
}

/** Ensure the API is reachable; retry sidecar start once if needed. */
async function ensureApiBase(): Promise<string> {
  const base = getApiBase();
  if (base) return base;
  // Sidecar may have failed to start (e.g. firewall prompt delay) — retry once
  console.log('[sidecar] apiBase empty, retrying sidecar start…');
  await startSidecar();
  return getApiBase();
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
  // Skip sidecar if a remote server URL is configured
  const remoteUrl = getConfiguredServerUrl();
  if (remoteUrl) {
    console.log(`[sidecar] remote server configured (${remoteUrl}), skipping sidecar`);
    return;
  }

  const sidecarPath = getSidecarPath();

  if (!fs.existsSync(sidecarPath)) {
    console.log(`[sidecar] Binary not found at ${sidecarPath}, skipping`);
    return;
  }

  sidecarPort = getRandomPort();

  try {
    // Check for saved config (e.g. after SQLite→PostgreSQL migration)
    const configPath = path.join(getAppDataDir(), 'config.json');
    let savedBackend = 'sqlite';
    let savedDbUrl = '';
    if (fs.existsSync(configPath)) {
      try {
        const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        if (cfg.storage_backend === 'postgres' && cfg.database_url) {
          savedBackend = 'postgres';
          savedDbUrl = cfg.database_url;
        }
      } catch { /* ignore corrupt config */ }
    }

    const sidecarEnv: Record<string, string> = {
      ...process.env as Record<string, string>,
      PORT: String(sidecarPort),
      SIDECAR_MODE: '1',
      STORAGE_BACKEND: savedBackend,
    };
    if (savedBackend === 'sqlite') {
      sidecarEnv.SQLITE_DB_PATH = path.join(getAppDataDir(), 'vault.db');
    } else {
      sidecarEnv.DATABASE_URL = savedDbUrl;
    }

    sidecarProcess = spawn(sidecarPath, [], {
      env: sidecarEnv,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    sidecarProcess.on('error', (err) => {
      console.error('[sidecar] Failed to start:', err.message);
      sidecarProcess = null;
    });

    sidecarProcess.stdout?.on('data', (data: Buffer) => {
      const line = data.toString().trim();
      console.log(`[sidecar] ${line}`);
      // If the extension triggered a lock via the sidecar, lock the Electron app too
      if (line.includes('EXTENSION_LOCK_REQUESTED')) {
        console.log('[sidecar] extension requested vault lock');
        mainWindow?.webContents.send('vault:auto-locked');
      }
    });

    sidecarProcess.stderr?.on('data', (data: Buffer) => {
      console.error(`[sidecar] ${data.toString().trim()}`);
    });

    sidecarProcess.on('exit', (code) => {
      console.log(`[sidecar] exited with code ${code}`);
      sidecarProcess = null;
    });

    // Wait for sidecar to become ready by polling the health endpoint
    const maxAttempts = 30; // 30 x 200ms = 6 seconds max
    let ready = false;
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise<void>((resolve) => setTimeout(resolve, 200));
      if (!sidecarProcess) {
        console.error('[sidecar] process exited before becoming ready');
        break;
      }
      try {
        const res = await fetch(`http://127.0.0.1:${sidecarPort}/health`);
        if (res.ok) {
          ready = true;
          console.log(`[sidecar] ready on port ${sidecarPort}`);
          break;
        }
      } catch {
        // Not ready yet, keep polling
      }
    }
    if (!ready) {
      console.error('[sidecar] failed to become ready within timeout');
      sidecarPort = null;
    } else {
      // Read extension secret from lockfile written by the sidecar
      try {
        const lockPath = path.join(getAppDataDir(), 'sidecar.lock');
        const lockData = fs.readFileSync(lockPath, 'utf-8').trim();
        const lines = lockData.split('\n');
        if (lines.length > 1) {
          sidecarSecret = lines[1].trim();
          console.log('[sidecar] read extension secret from lockfile');
        }
      } catch {
        console.warn('[sidecar] could not read extension secret from lockfile');
      }
    }
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
async function pushSessionToSidecar(token: string, masterKeyHex: string, userId: string, email?: string): Promise<void> {
  const api = getApiBase();
  if (!api) return;
  try {
    await fetch(`${api}/extension/session`, {
      method: 'POST',
      headers: sidecarHeaders(),
      body: JSON.stringify({
        token,
        master_key_hex: masterKeyHex,
        user_id: userId,
        email: email ?? '',
      }),
    });
    console.log('[extension] session pushed to sidecar');
  } catch (err) {
    console.error('[extension] failed to push session:', err);
  }
}

/** Build headers for sidecar extension endpoints, including the shared secret. */
function sidecarHeaders(): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (sidecarSecret) {
    headers['Authorization'] = `Bearer ${sidecarSecret}`;
  }
  return headers;
}

/** Lock the extension session on the sidecar (best-effort). */
function lockExtensionSession(): void {
  const api = getApiBase();
  if (!api) return;
  fetch(`${api}/extension/lock`, { method: 'POST', headers: sidecarHeaders() }).catch(() => {});
}

/**
 * Write a lockfile for non-sidecar mode (BACKEND_URL / Docker).
 * The Go sidecar writes its own lockfile in sidecar mode.
 */
function writeExtensionLockfile(): void {
  if (!backendUrl) return; // sidecar mode — Go server writes its own lockfile
  if (sidecarPort) return; // sidecar started successfully — it wrote its own lockfile
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
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' http://localhost:* http://127.0.0.1:* https://api.pwnedpasswords.com",
        ],
      },
    });
  });

  // Prevent navigation to external URLs
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const parsedUrl = new URL(url);
    const allowedOrigins = ['http://localhost:5173', 'file://'];
    const isAllowed = allowedOrigins.some(
      (o) => parsedUrl.origin === o || parsedUrl.protocol === 'file:'
    );
    if (!isAllowed) {
      event.preventDefault();
      console.warn(`[security] blocked navigation to: ${url}`);
    }
  });

  // Block new window creation — open external URLs in the default browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://') || url.startsWith('http://')) {
      shell.openExternal(url);
    } else {
      console.warn(`[security] blocked window.open to: ${url}`);
    }
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

  // Throttle background rendering to reduce idle CPU/memory usage
  mainWindow.webContents.setBackgroundThrottling(true);

  if (isDev) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    // Disable devtools in production
    mainWindow.webContents.on('devtools-opened', () => {
      mainWindow?.webContents.closeDevTools();
    });
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

  ipcMain.handle('app:openExternal', async (_event, url: string) => {
    if (typeof url === 'string' && (url.startsWith('https://') || url.startsWith('http://'))) {
      await shell.openExternal(url);
    }
  });

  ipcMain.handle('auth:login', async (_event, credentials: { email: string; authHash: string }) => {
    const api = await ensureApiBase();
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
        // Reset auto-lock timer on successful login
        resetAutoLockTimer();
        // Push session to sidecar for browser extension bridge
        const jwt = (result.access_token || result.token) as string;
        const userId = result.user_id as string;
        if (jwt && userId) {
          pushSessionToSidecar(jwt, masterKeyHex, userId, credentials.email);
        }
        // Auto-update biometric credentials so biometric unlock uses the current master key
        try {
          const credentialsJson = JSON.stringify({
            email: credentials.email,
            authHash: authHashHex,
            masterKeyHex,
          });
          await enableBiometric(credentialsJson);
          console.log('[ipc] biometric credentials updated after manual login');
        } catch {
          // Biometric not available or not configured — ignore
        }
      }
      return result;
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('auth:logout', async () => {
    // Clear extension session on the server so browser extension mirrors lock state
    lockExtensionSession();
  });

  ipcMain.handle('auth:register', async (_event, data: { email: string; password: string }) => {
    const api = await ensureApiBase();
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
    lockExtensionSession();
    // Proceed with password change
    const api = getApiBase();
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

  ipcMain.handle('vault:list', async (_event, token: string, filter?: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      let url = `${api}/api/v1/vault/entries`;
      if (filter) url += `?${filter}`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) { emitForceLogout(); return { error: 'session_revoked' }; }
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
      if (res.status === 401) { emitForceLogout(); return { error: 'session_revoked' }; }
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

  ipcMain.handle('vault:setFavorite', async (_event, token: string, entryId: string, isFavorite: boolean) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}/favorite`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ is_favorite: isFavorite }),
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:clone', async (_event, token: string, entryId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}/clone`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:setArchived', async (_event, token: string, entryId: string, isArchived: boolean) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}/archive`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ is_archived: isArchived }),
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:restore', async (_event, token: string, entryId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}/restore`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:permanentDelete', async (_event, token: string, entryId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}/permanent`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:purgeTrash', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/trash/purge`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  // --- HIBP password breach check (runs from main process to avoid renderer CORS/CSP issues) ---

  ipcMain.handle('hibp:checkRange', async (_event, hashPrefix: string) => {
    try {
      if (!hashPrefix || hashPrefix.length !== 5) {
        return { error: 'Invalid hash prefix' };
      }
      const { net } = await import('electron');
      const resp = await net.fetch(`https://api.pwnedpasswords.com/range/${encodeURIComponent(hashPrefix)}`, {
        headers: { 'Add-Padding': 'true' },
      });
      if (!resp.ok) {
        return { error: `HIBP API returned ${resp.status}` };
      }
      const text = await resp.text();
      return { data: text };
    } catch (err: unknown) {
      return { error: err instanceof Error ? err.message : 'HIBP request failed' };
    }
  });

  // --- Vault crypto IPC handlers ---

  ipcMain.handle('vault:verifyMasterPassword', (_event, email: string, password: string, expectedMasterKeyHex: string) => {
    try {
      if (!email || !password || !expectedMasterKeyHex) {
        return { verified: false, error: 'Missing parameters' };
      }
      const salt = nodeCrypto.createHash('sha256').update(email).digest();
      const derived = nodeCrypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
      const derivedMasterKeyHex = derived.subarray(0, 32).toString('hex');
      const verified = nodeCrypto.timingSafeEqual(
        Buffer.from(derivedMasterKeyHex, 'hex'),
        Buffer.from(expectedMasterKeyHex, 'hex')
      );
      return { verified };
    } catch {
      return { verified: false, error: 'Verification failed' };
    }
  });

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

  ipcMain.handle('vault:exportFile', async (_event, content: string, format?: string) => {
    const win = BrowserWindow.getFocusedWindow();
    const isCsv = format === 'csv';
    const ext = isCsv ? 'csv' : 'json';
    const filterName = isCsv ? 'CSV' : 'JSON';
    const result = await dialog.showSaveDialog(win!, {
      title: 'Export Vault',
      defaultPath: `lgipass-export-${new Date().toISOString().slice(0, 10)}.${ext}`,
      filters: [{ name: filterName, extensions: [ext] }],
    });
    if (result.canceled || !result.filePath) return { cancelled: true };
    try {
      fs.writeFileSync(result.filePath, content, 'utf8');
      return { success: true, path: result.filePath };
    } catch {
      return { error: 'Failed to write file' };
    }
  });

  // --- SSH key generation IPC ---
  ipcMain.handle('ssh:generateKeyPair', (_event, keyType: string) => {
    try {
      let pubPem: string;
      let privPem: string;

      if (keyType === 'rsa') {
        const pair = nodeCrypto.generateKeyPairSync('rsa', {
          modulusLength: 4096,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        pubPem = pair.publicKey;
        privPem = pair.privateKey;
      } else if (keyType === 'ecdsa') {
        const pair = nodeCrypto.generateKeyPairSync('ec', {
          namedCurve: 'P-256',
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        pubPem = pair.publicKey;
        privPem = pair.privateKey;
      } else {
        // Default: Ed25519
        const pair = nodeCrypto.generateKeyPairSync('ed25519', {
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        pubPem = pair.publicKey;
        privPem = pair.privateKey;
      }

      // Compute fingerprint from DER-encoded public key
      const pubKeyObj = nodeCrypto.createPublicKey(pubPem);
      const derBytes = pubKeyObj.export({ type: 'spki', format: 'der' });
      const fp = nodeCrypto.createHash('sha256').update(derBytes).digest('base64').replace(/=+$/, '');

      // Convert to OpenSSH formats
      let sshPublic = '';
      let sshPrivate = '';
      try {
        sshPublic = (pubKeyObj.export as any)({ type: 'ssh' });
      } catch {
        // Fallback: encode DER as base64 with SSH prefix
        const b64 = derBytes.toString('base64');
        sshPublic = `${b64}`;
      }
      try {
        const privKeyObj = nodeCrypto.createPrivateKey(privPem);
        sshPrivate = (privKeyObj.export as any)({ type: 'ssh', format: 'pem' });
      } catch {
        // Fallback: strip PEM headers and wrap as OpenSSH private key
        const b64 = privPem.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '');
        sshPrivate = `${b64.match(/.{1,70}/g)?.join('\n')}`;
      }

      return {
        publicKey: sshPublic,
        privateKey: sshPrivate,
        fingerprint: `SHA256:${fp}`,
      };
    } catch (e) {
      return { error: `Key generation failed: ${e instanceof Error ? e.message : String(e)}` };
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
        try {
          execFileSync('powershell.exe', [
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
        try {
          execFileSync('osascript', ['-l', 'ObjC', '-e', [
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
      // Export passkeys before leaving
      let passkeys: unknown[] = [];
      try {
        const pkRes = await fetch(`${api}/api/v1/vault/passkeys`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (pkRes.ok) {
          const pkData = await pkRes.json();
          if (Array.isArray(pkData)) passkeys = pkData;
        }
      } catch { /* ignore passkey export failure */ }

      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/leave`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const result = await res.json() as { status?: string; entries?: unknown[]; error?: string };

      if (result.error) return result;

      // Save exported vault entries + passkeys locally for re-import after switching to SQLite
      const exportPath = path.join(app.getPath('userData'), 'vault-export.json');
      const exportData = {
        entries: result.entries || [],
        passkeys,
      };
      try {
        fs.writeFileSync(exportPath, JSON.stringify(exportData), 'utf-8');
        console.log(`[leaveOrg] Exported ${(result.entries || []).length} vault entries and ${passkeys.length} passkeys`);
      } catch (e) {
        console.error('[leaveOrg] Failed to save vault export:', e);
      }

      // Reset storage config back to SQLite
      try {
        const configPath = path.join(getAppDataDir(), 'config.json');
        if (fs.existsSync(configPath)) {
          fs.unlinkSync(configPath);
          console.log('[leaveOrg] Removed postgres config — will restart in SQLite mode');
        }
      } catch (e) {
        console.error('[leaveOrg] Failed to reset config:', e);
      }

      // Schedule app restart after returning the response so the renderer can process it
      setTimeout(() => {
        app.relaunch();
        app.exit(0);
      }, 500);

      return result;
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

  ipcMain.handle('admin:share2fa', async (_event, token: string, toUserId: string, totpSecret: string, label: string, expiresInMin: number) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/2fa/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          to_user_id: toUserId,
          totp_secret: totpSecret,
          label: label,
          expires_in_minutes: expiresInMin,
        }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('auth:listPending2FA', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/2fa/pending`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('auth:claim2FA', async (_event, token: string, shareId: string, masterKeyHex: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      // Step 1: Fetch user's encrypted private key from security settings
      const settingsRes = await fetch(`${api}/api/v1/auth/security-settings`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const settings = await settingsRes.json() as { encrypted_private_key?: string; error?: string };
      if (settings.error || !settings.encrypted_private_key) {
        return { error: 'Failed to fetch private key' };
      }

      // Step 2: Decrypt private key with master key
      const masterKey = Buffer.from(masterKeyHex, 'hex');
      const encPrivKey = Buffer.from(settings.encrypted_private_key, 'hex');
      // Format: iv(12) || ciphertext || authTag(16)
      const iv = encPrivKey.subarray(0, 12);
      const authTag = encPrivKey.subarray(encPrivKey.length - 16);
      const ciphertext = encPrivKey.subarray(12, encPrivKey.length - 16);
      const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', masterKey, iv);
      decipher.setAuthTag(authTag);
      const privateKeyDer = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

      // Step 3: Call claim endpoint with raw private key
      const res = await fetch(`${api}/api/v1/auth/2fa/claim/${encodeURIComponent(shareId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ private_key: privateKeyDer.toString('hex') }),
      });
      return await res.json();
    } catch (e) { return { error: `Claim failed: ${e instanceof Error ? e.message : 'unknown'}` }; }
  });

  ipcMain.handle('admin:propagateKeys', async (_event, token: string, orgId: string, masterKey: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/propagate-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ master_key: masterKey }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // SSO admin endpoints
  ipcMain.handle('admin:getSSOConfig', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/sso`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:setSSOConfig', async (_event, token: string, orgId: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/sso`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // SCIM admin endpoints
  ipcMain.handle('admin:getSCIMConfig', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/scim`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:setSCIMConfig', async (_event, token: string, orgId: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/scim`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:generateSCIMToken', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/scim/generate-token`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // --- Roles ---
  ipcMain.handle('admin:listRoles', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/roles`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:createRole', async (_event, token: string, orgId: string, data: { name: string; description: string; permissions: string[] }) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/roles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:updateRole', async (_event, token: string, orgId: string, roleId: string, data: { name: string; description: string; permissions: string[] }) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/roles/${encodeURIComponent(roleId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:deleteRole', async (_event, token: string, orgId: string, roleId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/roles/${encodeURIComponent(roleId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:setMemberRole', async (_event, token: string, orgId: string, userId: string, roleId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userId)}/role`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ role_id: roleId }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // --- Groups ---
  ipcMain.handle('admin:listGroups', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/groups`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:createGroup', async (_event, token: string, orgId: string, name: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/groups`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:updateGroup', async (_event, token: string, orgId: string, groupId: string, name: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/groups/${encodeURIComponent(groupId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:deleteGroup', async (_event, token: string, orgId: string, groupId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/groups/${encodeURIComponent(groupId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:listGroupMembers', async (_event, token: string, orgId: string, groupId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/groups/${encodeURIComponent(groupId)}/members`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:addGroupMember', async (_event, token: string, orgId: string, groupId: string, userId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/groups/${encodeURIComponent(groupId)}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ user_id: userId }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:removeGroupMember', async (_event, token: string, orgId: string, groupId: string, userId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // --- Collection-Group assignments ---
  ipcMain.handle('admin:listCollectionGroups', async (_event, token: string, orgId: string, collectionId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(collectionId)}/groups`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const text = await res.text();
      try { return JSON.parse(text); } catch { return { error: text || `HTTP ${res.status}` }; }
    } catch (e: unknown) { return { error: `Failed to connect to backend: ${e instanceof Error ? e.message : String(e)}` }; }
  });

  ipcMain.handle('admin:addCollectionGroup', async (_event, token: string, orgId: string, collectionId: string, groupId: string, permission: string, masterKey: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    const url = `${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(collectionId)}/groups`;
    console.log('[addCollectionGroup] POST', url, { group_id: groupId, permission });
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ group_id: groupId, permission, master_key: masterKey }),
      });
      const text = await res.text();
      console.log('[addCollectionGroup] response:', res.status, text);
      try { return JSON.parse(text); } catch { return { error: text || `HTTP ${res.status}` }; }
    } catch (e: unknown) { console.error('[addCollectionGroup] fetch error:', e); return { error: `Failed to connect to backend: ${e instanceof Error ? e.message : String(e)}` }; }
  });

  ipcMain.handle('admin:removeCollectionGroup', async (_event, token: string, orgId: string, collectionId: string, groupId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(collectionId)}/groups/${encodeURIComponent(groupId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      const text = await res.text();
      try { return JSON.parse(text); } catch { return { error: text || `HTTP ${res.status}` }; }
    } catch (e: unknown) { return { error: `Failed to connect to backend: ${e instanceof Error ? e.message : String(e)}` }; }
  });

  // --- SIEM / Webhooks ---
  ipcMain.handle('admin:exportEvents', async (_event, token: string, orgId: string, params: { format?: string; since?: string; until?: string; limit?: number }) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const qs = new URLSearchParams();
      if (params.format) qs.set('format', params.format);
      if (params.since) qs.set('since', params.since);
      if (params.until) qs.set('until', params.until);
      if (params.limit) qs.set('limit', String(params.limit));
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/events/export?${qs.toString()}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const text = await res.text();
      return { data: text, format: params.format || 'json' };
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:listWebhooks', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/webhooks`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:createWebhook', async (_event, token: string, orgId: string, data: { url: string; events: string[]; secret?: string }) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:deleteWebhook', async (_event, token: string, orgId: string, webhookId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/webhooks/${encodeURIComponent(webhookId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:toggleWebhook', async (_event, token: string, orgId: string, webhookId: string, enabled: boolean) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/webhooks/${encodeURIComponent(webhookId)}/toggle`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ enabled }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('admin:testWebhook', async (_event, token: string, orgId: string, webhookId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/webhooks/${encodeURIComponent(webhookId)}/test`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // SSO login flow
  ipcMain.handle('auth:ssoLogin', async (_event, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sso/${encodeURIComponent(orgId)}/login`);
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('auth:ssoUnlock', async (_event, orgId: string, ssoToken: string, authHash: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sso/${encodeURIComponent(orgId)}/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sso_token: ssoToken, auth_hash: authHash }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // Import vault entries and passkeys from a previous org leave export
  ipcMain.handle('vault:importExport', async (_event, token: string) => {
    const exportPath = path.join(app.getPath('userData'), 'vault-export.json');
    if (!fs.existsSync(exportPath)) return { imported: 0 };

    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };

    try {
      const raw = fs.readFileSync(exportPath, 'utf-8');
      const data = JSON.parse(raw) as {
        entries?: Array<{
          id: string;
          entry_type: string;
          encrypted_data: string;
          nonce: string;
          folder_id?: string;
        }>;
        passkeys?: Array<Record<string, unknown>>;
      };

      // Handle old format (plain array) and new format ({ entries, passkeys })
      const entries = Array.isArray(data) ? data : (data.entries || []);
      const passkeys = Array.isArray(data) ? [] : (data.passkeys || []);

      let imported = 0;
      for (const entry of entries) {
        try {
          const res = await fetch(`${api}/api/v1/vault/entries`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({
              entry_type: entry.entry_type,
              encrypted_data: entry.encrypted_data,
              nonce: entry.nonce,
              folder_id: entry.folder_id || null,
            }),
          });
          if (res.ok) imported++;
        } catch { /* skip failed entries */ }
      }

      // Import passkeys
      let passkeysImported = 0;
      for (const pk of passkeys) {
        try {
          const res = await fetch(`${api}/api/v1/vault/passkeys/register/finish`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify(pk),
          });
          if (res.ok) passkeysImported++;
        } catch { /* skip */ }
      }

      // Remove export file after import
      fs.unlinkSync(exportPath);
      console.log(`[vault:importExport] Imported ${imported}/${entries.length} entries, ${passkeysImported}/${passkeys.length} passkeys`);
      return { imported, total: entries.length, passkeysImported, passkeysTotal: passkeys.length };
    } catch (e) {
      console.error('[vault:importExport] Failed:', e);
      return { error: 'Failed to import vault entries' };
    }
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

      // Prompt fingerprint/Windows Hello before saving credentials
      await promptBiometric('set up biometric unlock');

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
        pushSessionToSidecar(jwt, creds.masterKeyHex, userId, creds.email);
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

  ipcMain.handle('biometric:cancel', async () => {
    try {
      await cancelBiometric();
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

  // --- Passkey IPC handlers ---

  ipcMain.handle('passkey:list', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/passkeys`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('passkey:delete', async (_event, token: string, passkeyId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/passkeys/${encodeURIComponent(passkeyId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('passkey:listHardwareKeys', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/hardware-keys`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('passkey:deleteHardwareKey', async (_event, token: string, keyId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/hardware-keys/${encodeURIComponent(keyId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('passkey:beginRegistration', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/passkeys/register/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('passkey:finishRegistration', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/passkeys/register/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('passkey:beginAuthentication', async (_event, token: string, rpId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/passkeys/authenticate/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ rp_id: rpId }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('passkey:finishAuthentication', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/passkeys/authenticate/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // Security settings IPC handlers
  ipcMain.handle('auth:getSecuritySettings', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/security-settings`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('auth:setRequireHWKey', async (_event, token: string, require: boolean) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/require-hardware-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ require }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // Two-factor authentication (TOTP) IPC handlers
  ipcMain.handle('auth:2fa:setup', async (_event, token: string, encryptionKey: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/2fa/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ encryption_key: encryptionKey }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('auth:2fa:verifySetup', async (_event, token: string, code: string, encryptionKey: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/2fa/verify-setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ code, encryption_key: encryptionKey }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('auth:2fa:disable', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/2fa/disable`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // Hardware key registration/authentication (vault 2FA)
  ipcMain.handle('hwkey:beginRegistration', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/hardware-keys/register/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('hwkey:finishRegistration', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/auth/hardware-keys/register/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // WebAuthn ceremony via temporary localhost window (Electron renderer is not a secure context)
  ipcMain.handle('hwkey:webauthnCreate', async (_event, optionsJSON: string) => {
    return new Promise<Record<string, unknown>>((resolve) => {
      const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Key</title>
<style>body{background:#1a1a2e;color:#e0e0e0;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column}
.msg{text-align:center;max-width:320px}.spinner{border:3px solid #333;border-top:3px solid #7c3aed;border-radius:50%;width:32px;height:32px;animation:spin 1s linear infinite;margin:16px auto}
@keyframes spin{to{transform:rotate(360deg)}}.err{color:#f87171;margin-top:12px;font-size:14px}</style></head>
<body><div class="msg"><div class="spinner"></div><p>Touch your security key…</p><p id="err" class="err"></p></div>
<script>
(async()=>{try{
const opts=${optionsJSON};
const b64=s=>{let r=s.replace(/-/g,'+').replace(/_/g,'/');while(r.length%4)r+='=';return Uint8Array.from(atob(r),c=>c.charCodeAt(0))};
const toB64=b=>{const a=new Uint8Array(b);let s='';for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'')};
const cred=await navigator.credentials.create({publicKey:{
challenge:b64(opts.challenge),
rp:opts.rp,
user:{id:b64(opts.user.id),name:opts.user.name,displayName:opts.user.displayName},
pubKeyCredParams:opts.pubKeyCredParams,
authenticatorSelection:{authenticatorAttachment:'cross-platform',residentKey:'discouraged',userVerification:'required'},
attestation:'direct',timeout:120000
}});
if(!cred){document.title='RESULT:'+JSON.stringify({error:'cancelled'});return}
const r=cred.response;
const pk=r.getPublicKey?.();
document.title='RESULT:'+JSON.stringify({
credential_id:toB64(cred.rawId),
attestation_object:toB64(r.attestationObject),
client_data_json:toB64(r.clientDataJSON),
public_key_cbor:pk?toB64(pk):'',
transports:r.getTransports?.()??['usb']
});
}catch(e){document.title='RESULT:'+JSON.stringify({error:e.message||'WebAuthn failed'})}})();
</script></body></html>`;

      const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
      });

      server.listen(0, '127.0.0.1', () => {
        const port = (server.address() as any).port;
        const win = new BrowserWindow({
          width: 420,
          height: 280,
          parent: mainWindow ?? undefined,
          modal: true,
          resizable: false,
          minimizable: false,
          maximizable: false,
          title: 'Register Security Key',
          webPreferences: { nodeIntegration: false, contextIsolation: true },
        });
        win.setMenuBarVisibility(false);

        const cleanup = () => {
          try { win.close(); } catch { /* already closed */ }
          server.close();
        };

        // Watch for title change as the result channel
        win.webContents.on('page-title-updated', (_e, title) => {
          if (title.startsWith('RESULT:')) {
            try {
              resolve(JSON.parse(title.slice(7)));
            } catch {
              resolve({ error: 'Invalid response' });
            }
            cleanup();
          }
        });

        win.on('closed', () => {
          server.close();
          resolve({ error: 'cancelled' });
        });

        const loadAndRun = async () => {
          // In dev mode, attach a virtual FIDO2 authenticator so the feature
          // can be tested without a physical security key.
          if (isDev) {
            try {
              const dbg = win.webContents.debugger;
              dbg.attach('1.3');
              await dbg.sendCommand('WebAuthn.enable');
              await dbg.sendCommand('WebAuthn.addVirtualAuthenticator', {
                options: {
                  protocol: 'ctap2',
                  transport: 'usb',
                  hasResidentKey: false,
                  hasUserVerification: true,
                  isUserVerified: true,
                },
              });
            } catch { /* best-effort */ }
          }
          win.loadURL(`http://127.0.0.1:${port}`);
        };
        loadAndRun();
      });
    });
  });

  // --- Collections IPC handlers ---

  ipcMain.handle('collections:create', async (_event, token: string, orgId: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/collections`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:listOrg', async (_event, token: string, orgId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/orgs/${encodeURIComponent(orgId)}/collections`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:listUser', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:get', async (_event, token: string, collectionId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:update', async (_event, token: string, collectionId: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:delete', async (_event, token: string, collectionId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:addMember', async (_event, token: string, collectionId: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:getMembers', async (_event, token: string, collectionId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}/members`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:removeMember', async (_event, token: string, collectionId: string, userId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}/members/${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:updatePermission', async (_event, token: string, collectionId: string, userId: string, permission: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}/members/${encodeURIComponent(userId)}/permission`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ permission }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:addEntry', async (_event, token: string, collectionId: string, entryId: string, data: { entry_type: string; encrypted_data: string; nonce: string }) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}/entries`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ entry_id: entryId, entry_type: data.entry_type, encrypted_data: data.encrypted_data, nonce: data.nonce }),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:removeEntry', async (_event, token: string, collectionId: string, entryId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}/entries/${encodeURIComponent(entryId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:listEntries', async (_event, token: string, collectionId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/collections/${encodeURIComponent(collectionId)}/entries`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('collections:getEntryCollections', async (_event, token: string, entryId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries/${encodeURIComponent(entryId)}/collections`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // --- Secure Send IPC handlers ---

  ipcMain.handle('send:create', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sends`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('send:list', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sends`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('send:delete', async (_event, token: string, sendId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sends/${encodeURIComponent(sendId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('send:disable', async (_event, token: string, sendId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sends/${encodeURIComponent(sendId)}/disable`, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('send:saveFile', async (_event, htmlContent: string, defaultFileName: string) => {
    const win = BrowserWindow.getFocusedWindow();
    const result = await dialog.showSaveDialog(win!, {
      title: 'Save Secure Send',
      defaultPath: defaultFileName || `lgipass-send-${new Date().toISOString().slice(0, 10)}.html`,
      filters: [{ name: 'HTML', extensions: ['html'] }],
    });
    if (result.canceled || !result.filePath) return { cancelled: true };
    try {
      fs.writeFileSync(result.filePath, htmlContent, 'utf8');
      return { success: true, path: result.filePath };
    } catch {
      return { error: 'Failed to write file' };
    }
  });

  // Send domain config IPC handlers
  ipcMain.handle('send:getDomain', () => {
    try {
      const configPath = path.join(getAppDataDir(), 'config.json');
      if (fs.existsSync(configPath)) {
        const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        return cfg.send_domain || '';
      }
    } catch { /* ignore */ }
    return '';
  });

  ipcMain.handle('send:setDomain', (_event, domain: string) => {
    try {
      const configPath = path.join(getAppDataDir(), 'config.json');
      let cfg: Record<string, unknown> = {};
      if (fs.existsSync(configPath)) {
        try { cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8')); } catch { /* ignore */ }
      }
      cfg.send_domain = domain;
      const configDir = path.dirname(configPath);
      if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });
      fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2), 'utf-8');
      return { success: true };
    } catch {
      return { error: 'Failed to save send domain' };
    }
  });

  // --- Emergency Access IPC handlers ---

  ipcMain.handle('emergency:invite', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:listGranted', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/granted`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:listTrusted', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/trusted`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:accept', async (_event, token: string, eaId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/accept`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:confirm', async (_event, token: string, eaId: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:initiate', async (_event, token: string, eaId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/initiate`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:approve', async (_event, token: string, eaId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/approve`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:reject', async (_event, token: string, eaId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/reject`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:getVault', async (_event, token: string, eaId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/vault`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:takeover', async (_event, token: string, eaId: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/takeover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // Full takeover: decrypt grantor's vault, re-encrypt with new password, POST takeover
  ipcMain.handle('emergency:performTakeover', async (_event, token: string, eaId: string, myMasterKeyHex: string, grantorEmail: string, newPassword: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      // 1. Decrypt grantor's vault (same as decryptVault IPC)
      const vaultRes = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/vault`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const vaultData = await vaultRes.json() as { entries?: Array<Record<string, unknown>>; encrypted_key?: string; error?: string };
      if (vaultData.error) return { error: vaultData.error };
      if (!vaultData.encrypted_key) return { error: 'Key exchange not completed — grantor must log in first' };

      // 2. Get own private key and decrypt grantor's master key
      const settingsRes = await fetch(`${api}/api/v1/auth/security-settings`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const settings = await settingsRes.json() as { encrypted_private_key?: string; error?: string };
      if (!settings.encrypted_private_key) return { error: 'Cannot access your private key' };

      const masterKey = Buffer.from(myMasterKeyHex, 'hex');
      const encPrivKey = Buffer.from(settings.encrypted_private_key, 'hex');
      const iv = encPrivKey.subarray(0, 12);
      const authTag = encPrivKey.subarray(encPrivKey.length - 16);
      const privCiphertext = encPrivKey.subarray(12, encPrivKey.length - 16);
      const privDecipher = nodeCrypto.createDecipheriv('aes-256-gcm', masterKey, iv);
      privDecipher.setAuthTag(authTag);
      const privateKeyDer = Buffer.concat([privDecipher.update(privCiphertext), privDecipher.final()]);

      // X25519 decrypt grantor's master key
      const blob = Buffer.from(vaultData.encrypted_key, 'hex');
      const ephPubRaw = blob.subarray(0, 32);
      const blobNonce = blob.subarray(32, 44);
      const blobCiphertext = blob.subarray(44);

      const privateKey = nodeCrypto.createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
      const spkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');
      const ephPubDer = Buffer.concat([spkiPrefix, ephPubRaw]);
      const ephPub = nodeCrypto.createPublicKey({ key: ephPubDer, format: 'der', type: 'spki' });

      const sharedSecret = nodeCrypto.diffieHellman({ privateKey, publicKey: ephPub });
      const decKey = nodeCrypto.createHmac('sha256', sharedSecret).update('x25519-emergency').digest();

      const blobAuthTag = blobCiphertext.subarray(blobCiphertext.length - 16);
      const blobEncData = blobCiphertext.subarray(0, blobCiphertext.length - 16);
      const blobDecipher = nodeCrypto.createDecipheriv('aes-256-gcm', decKey, blobNonce);
      blobDecipher.setAuthTag(blobAuthTag);
      const grantorMasterKey = Buffer.concat([blobDecipher.update(blobEncData), blobDecipher.final()]);

      // 3. Decrypt all vault entries with grantor's master key
      const entries = vaultData.entries || [];
      const decryptedEntries: Array<{ id: string; plaintext: Buffer; nonce: string }> = [];
      for (const entry of entries) {
        try {
          const entryData = Buffer.from(entry.encrypted_data as string, 'hex');
          const entryNonce = Buffer.from(entry.nonce as string, 'hex');
          const entryAuthTag = entryData.subarray(entryData.length - 16);
          const entryCiphertext = entryData.subarray(0, entryData.length - 16);
          const entryDecipher = nodeCrypto.createDecipheriv('aes-256-gcm', grantorMasterKey, entryNonce);
          entryDecipher.setAuthTag(entryAuthTag);
          const decrypted = Buffer.concat([entryDecipher.update(entryCiphertext), entryDecipher.final()]);
          decryptedEntries.push({ id: entry.id as string, plaintext: decrypted, nonce: entry.nonce as string });
        } catch {
          // Skip entries that can't be decrypted
        }
      }

      // 4. Derive new master key and auth hash from new password
      const newSalt = nodeCrypto.createHash('sha256').update(grantorEmail).digest();
      const newDerived = nodeCrypto.pbkdf2Sync(newPassword, newSalt, 100000, 64, 'sha512');
      const newMasterKey = newDerived.subarray(0, 32);
      const newAuthHash = newDerived.subarray(32, 64);

      // 5. Generate new X25519 key pair for grantor
      const newKeyPair = nodeCrypto.generateKeyPairSync('x25519');
      const newPublicKeyBuf = newKeyPair.publicKey.export({ type: 'spki', format: 'der' });
      const newPrivateKeyBuf = newKeyPair.privateKey.export({ type: 'pkcs8', format: 'der' });

      // Encrypt new private key with new master key
      const newIv = nodeCrypto.randomBytes(12);
      const newCipher = nodeCrypto.createCipheriv('aes-256-gcm', newMasterKey, newIv);
      const newEncPrivKey = Buffer.concat([newIv, newCipher.update(newPrivateKeyBuf), newCipher.final(), newCipher.getAuthTag()]);

      // 6. Re-encrypt all entries with new master key
      const reEncrypted: Array<{ id: string; encrypted_data: string; nonce: string }> = [];
      for (const entry of decryptedEntries) {
        const reNonce = nodeCrypto.randomBytes(12);
        const reCipher = nodeCrypto.createCipheriv('aes-256-gcm', newMasterKey, reNonce);
        const reEnc = Buffer.concat([reCipher.update(entry.plaintext), reCipher.final(), reCipher.getAuthTag()]);
        reEncrypted.push({
          id: entry.id,
          encrypted_data: reEnc.toString('hex'),
          nonce: reNonce.toString('hex'),
        });
      }

      // 7. POST takeover with new credentials and re-encrypted entries
      const takeoverRes = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/takeover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          new_auth_hash: newAuthHash.toString('hex'),
          new_salt: newSalt.toString('hex'),
          new_public_key: newPublicKeyBuf.toString('hex'),
          new_encrypted_private_key: newEncPrivKey.toString('hex'),
          new_master_key: newMasterKey.toString('hex'),
          old_master_key: grantorMasterKey.toString('hex'),
          re_encrypted_entries: reEncrypted,
        }),
      });
      return await takeoverRes.json();
    } catch (e) {
      console.error('[emergency] performTakeover error:', e);
      return { error: `Takeover failed: ${e instanceof Error ? e.message : 'unknown'}` };
    }
  });

  ipcMain.handle('emergency:delete', async (_event, token: string, eaId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('emergency:getPublicKey', async (_event, token: string, eaId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/public-key`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  // Auto-confirm: grantor encrypts their master key for the grantee using X25519
  ipcMain.handle('emergency:autoConfirm', async (_event, token: string, eaId: string, masterKeyHex: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      // 1. Get grantee's public key
      const pkRes = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/public-key`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const pkData = await pkRes.json() as { public_key?: string; error?: string };
      if (pkData.error || !pkData.public_key) return { error: pkData.error || 'Failed to get grantee public key' };

      // 2. X25519 encrypt master key with grantee's public key
      const recipientPubKeyDer = Buffer.from(pkData.public_key, 'hex');
      const recipientKey = nodeCrypto.createPublicKey({ key: recipientPubKeyDer, format: 'der', type: 'spki' });

      const ephemeral = nodeCrypto.generateKeyPairSync('x25519');
      const ephPubBuf = ephemeral.publicKey.export({ type: 'spki', format: 'der' });
      const ephPubRaw = ephPubBuf.subarray(ephPubBuf.length - 32);

      const sharedSecret = nodeCrypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientKey });
      const encKey = nodeCrypto.createHmac('sha256', sharedSecret).update('x25519-emergency').digest();

      const plaintext = Buffer.from(masterKeyHex, 'hex');
      const nonce = nodeCrypto.randomBytes(12);
      const cipher = nodeCrypto.createCipheriv('aes-256-gcm', encKey, nonce);
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();
      const ciphertext = Buffer.concat([encrypted, authTag]);
      const blob = Buffer.concat([ephPubRaw, nonce, ciphertext]);

      // 3. POST confirm with the encrypted blob
      const confirmRes = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ encrypted_key: blob.toString('hex') }),
      });
      return await confirmRes.json();
    } catch (e) { console.error('[emergency] autoConfirm error:', e); return { error: `Auto-confirm failed: ${e instanceof Error ? e.message : 'unknown'}` }; }
  });

  // Decrypt emergency vault: recovers grantor's master key and decrypts all entries
  ipcMain.handle('emergency:decryptVault', async (_event, token: string, eaId: string, masterKeyHex: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      // 1. Fetch vault data (entries + encrypted key blob)
      const vaultRes = await fetch(`${api}/api/v1/emergency-access/${encodeURIComponent(eaId)}/vault`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const vaultData = await vaultRes.json() as { entries?: Array<Record<string, unknown>>; encrypted_key?: string; error?: string };
      if (vaultData.error) return { error: vaultData.error };
      if (!vaultData.encrypted_key || vaultData.encrypted_key === '') {
        // Key exchange not done — return entries as-is (encrypted)
        return { entries: vaultData.entries || [], decrypted: false };
      }

      // 2. Get own encrypted private key from security settings
      const settingsRes = await fetch(`${api}/api/v1/auth/security-settings`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const settings = await settingsRes.json() as { encrypted_private_key?: string; error?: string };
      if (!settings.encrypted_private_key) return { entries: vaultData.entries || [], decrypted: false };

      // 3. Decrypt own private key with own master key
      const masterKey = Buffer.from(masterKeyHex, 'hex');
      const encPrivKey = Buffer.from(settings.encrypted_private_key, 'hex');
      const iv = encPrivKey.subarray(0, 12);
      const authTag = encPrivKey.subarray(encPrivKey.length - 16);
      const privCiphertext = encPrivKey.subarray(12, encPrivKey.length - 16);
      const privDecipher = nodeCrypto.createDecipheriv('aes-256-gcm', masterKey, iv);
      privDecipher.setAuthTag(authTag);
      const privateKeyDer = Buffer.concat([privDecipher.update(privCiphertext), privDecipher.final()]);

      // 4. X25519 decrypt the grantor's master key from the blob
      const blob = Buffer.from(vaultData.encrypted_key, 'hex');
      const ephPubRaw = blob.subarray(0, 32);
      const blobNonce = blob.subarray(32, 44);
      const blobCiphertext = blob.subarray(44);

      const privateKey = nodeCrypto.createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
      const spkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');
      const ephPubDer = Buffer.concat([spkiPrefix, ephPubRaw]);
      const ephPub = nodeCrypto.createPublicKey({ key: ephPubDer, format: 'der', type: 'spki' });

      const sharedSecret = nodeCrypto.diffieHellman({ privateKey, publicKey: ephPub });
      const decKey = nodeCrypto.createHmac('sha256', sharedSecret).update('x25519-emergency').digest();

      const blobAuthTag = blobCiphertext.subarray(blobCiphertext.length - 16);
      const blobEncData = blobCiphertext.subarray(0, blobCiphertext.length - 16);
      const blobDecipher = nodeCrypto.createDecipheriv('aes-256-gcm', decKey, blobNonce);
      blobDecipher.setAuthTag(blobAuthTag);
      const grantorMasterKey = Buffer.concat([blobDecipher.update(blobEncData), blobDecipher.final()]);

      // 5. Decrypt each vault entry using the recovered master key
      const entries = vaultData.entries || [];
      const decryptedEntries: Array<Record<string, unknown>> = [];
      for (const entry of entries) {
        try {
          const entryData = Buffer.from(entry.encrypted_data as string, 'hex');
          const entryNonce = Buffer.from(entry.nonce as string, 'hex');
          const entryAuthTag = entryData.subarray(entryData.length - 16);
          const entryCiphertext = entryData.subarray(0, entryData.length - 16);
          const entryDecipher = nodeCrypto.createDecipheriv('aes-256-gcm', grantorMasterKey, entryNonce);
          entryDecipher.setAuthTag(entryAuthTag);
          const decrypted = Buffer.concat([entryDecipher.update(entryCiphertext), entryDecipher.final()]);
          const data = JSON.parse(decrypted.toString('utf8'));
          decryptedEntries.push({
            id: entry.id,
            entry_type: entry.entry_type,
            data,
            version: entry.version,
            is_favorite: entry.is_favorite,
            is_archived: entry.is_archived,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
          });
        } catch {
          // Entry couldn't be decrypted — include as encrypted
          decryptedEntries.push({
            id: entry.id,
            entry_type: entry.entry_type,
            version: entry.version,
            is_favorite: entry.is_favorite,
            is_archived: entry.is_archived,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
          });
        }
      }
      return { entries: decryptedEntries, decrypted: true };
    } catch (e) { console.error('[emergency] decryptVault error:', e); return { error: `Vault decryption failed: ${e instanceof Error ? e.message : 'unknown'}` }; }
  });

  // X25519 encrypt: encrypt plaintext with recipient's X25519 public key (DER SPKI hex)
  ipcMain.handle('crypto:x25519Encrypt', (_event, plaintextHex: string, recipientPubKeyHex: string) => {
    try {
      const recipientPubKeyDer = Buffer.from(recipientPubKeyHex, 'hex');
      const recipientKey = nodeCrypto.createPublicKey({ key: recipientPubKeyDer, format: 'der', type: 'spki' });

      // Generate ephemeral X25519 key pair
      const ephemeral = nodeCrypto.generateKeyPairSync('x25519');
      const ephPubBuf = ephemeral.publicKey.export({ type: 'spki', format: 'der' });
      // Raw 32-byte public key is at the end of the SPKI DER encoding
      const ephPubRaw = ephPubBuf.subarray(ephPubBuf.length - 32);

      // ECDH shared secret
      const sharedSecret = nodeCrypto.diffieHellman({
        privateKey: ephemeral.privateKey,
        publicKey: recipientKey,
      });

      // Derive encryption key using HMAC-SHA256
      const encKey = nodeCrypto.createHmac('sha256', sharedSecret).update('x25519-emergency').digest();

      // AES-256-GCM encrypt
      const plaintext = Buffer.from(plaintextHex, 'hex');
      const nonce = nodeCrypto.randomBytes(12);
      const cipher = nodeCrypto.createCipheriv('aes-256-gcm', encKey, nonce);
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();
      const ciphertext = Buffer.concat([encrypted, authTag]);

      // blob = ephemeral pub key (32) || nonce (12) || ciphertext
      const blob = Buffer.concat([ephPubRaw, nonce, ciphertext]);
      return { encrypted: blob.toString('hex') };
    } catch (err) {
      return { error: `X25519 encryption failed: ${err}` };
    }
  });

  // X25519 decrypt: decrypt blob using own private key
  ipcMain.handle('crypto:x25519Decrypt', (_event, blobHex: string, privateKeyDerHex: string) => {
    try {
      const blob = Buffer.from(blobHex, 'hex');
      const ephPubRaw = blob.subarray(0, 32);
      const nonce = blob.subarray(32, 44);
      const ciphertext = blob.subarray(44);

      // Import own private key
      const privKeyDer = Buffer.from(privateKeyDerHex, 'hex');
      const privateKey = nodeCrypto.createPrivateKey({ key: privKeyDer, format: 'der', type: 'pkcs8' });

      // Reconstruct ephemeral public key from raw 32 bytes — X25519 SPKI DER prefix
      const spkiPrefix = Buffer.from('302a300506032b656e032100', 'hex'); // X25519 SPKI header
      const ephPubDer = Buffer.concat([spkiPrefix, ephPubRaw]);
      const ephPub = nodeCrypto.createPublicKey({ key: ephPubDer, format: 'der', type: 'spki' });

      // ECDH shared secret
      const sharedSecret = nodeCrypto.diffieHellman({
        privateKey: privateKey,
        publicKey: ephPub,
      });

      // Derive decryption key
      const decKey = nodeCrypto.createHmac('sha256', sharedSecret).update('x25519-emergency').digest();

      // AES-256-GCM decrypt
      const authTag = ciphertext.subarray(ciphertext.length - 16);
      const encData = ciphertext.subarray(0, ciphertext.length - 16);
      const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', decKey, nonce);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(encData), decipher.final()]);
      return { plaintext: decrypted.toString('hex') };
    } catch (err) {
      return { error: `X25519 decryption failed: ${err}` };
    }
  });

  // ── Sync IPC handlers ───────────────────────────────────────────────────────

  ipcMain.handle('sync:getDeviceId', () => {
    const deviceIdPath = path.join(getAppDataDir(), 'device-id');
    try {
      if (fs.existsSync(deviceIdPath)) {
        return fs.readFileSync(deviceIdPath, 'utf-8').trim();
      }
    } catch { /* regenerate */ }
    const id = `${os.hostname()}-${nodeCrypto.randomBytes(4).toString('hex')}`;
    try {
      fs.mkdirSync(path.dirname(deviceIdPath), { recursive: true });
      fs.writeFileSync(deviceIdPath, id, { mode: 0o600 });
    } catch { /* best effort */ }
    return id;
  });

  ipcMain.handle('sync:pull', async (_event, token: string, deviceId: string, lastSyncAt?: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sync/pull`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ device_id: deviceId, last_sync_at: lastSyncAt || '' }),
      });
      if (res.status === 401) { emitForceLogout(); return { error: 'session_revoked' }; }
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('sync:push', async (_event, token: string, deviceId: string, changes: unknown[]) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sync/push`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ device_id: deviceId, changes }),
      });
      if (res.status === 401) { emitForceLogout(); return { error: 'session_revoked' }; }
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('sync:resolve', async (_event, token: string, data: Record<string, unknown>) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sync/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(data),
      });
      if (res.status === 401) { emitForceLogout(); return { error: 'session_revoked' }; }
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('sync:devices', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sync/devices`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) { emitForceLogout(); return { error: 'session_revoked' }; }
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('sync:deleteDevice', async (_event, token: string, deviceId: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/sync/devices/${encodeURIComponent(deviceId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) { emitForceLogout(); return { error: 'session_revoked' }; }
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  // Storage backend IPC handlers
  ipcMain.handle('storage:getBackend', () => {
    if (backendUrl) return 'postgres';
    // Check saved config
    try {
      const configPath = path.join(getAppDataDir(), 'config.json');
      if (fs.existsSync(configPath)) {
        const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        if (cfg.storage_backend === 'postgres') return 'postgres';
      }
    } catch { /* ignore */ }
    return 'sqlite';
  });

  ipcMain.handle('storage:testPgConnection', async (_event, connectionString: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/test-pg-connection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ database_url: connectionString }),
      });
      return await res.json() as Record<string, unknown>;
    } catch { return { error: 'Failed to connect to backend' }; }
  });

  ipcMain.handle('storage:migrateToPostgres', async (_event, databaseUrl: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/admin/migrate-to-postgres`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ database_url: databaseUrl }),
      });
      const result = await res.json() as Record<string, unknown>;
      if (!result.error) {
        // Save config and restart sidecar with postgres backend
        const configDir = getAppDataDir();
        const configPath = path.join(configDir, 'config.json');
        if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });
        fs.writeFileSync(configPath, JSON.stringify({ storage_backend: 'postgres', database_url: databaseUrl }, null, 2), { mode: 0o600 });

        // Rename SQLite file as backup
        const sqlitePath = path.join(configDir, 'vault.db');
        if (fs.existsSync(sqlitePath)) {
          try { fs.renameSync(sqlitePath, sqlitePath + '.bak'); } catch { /* ignore */ }
        }

        // Restart sidecar with postgres config
        stopSidecar();
        sidecarPort = getRandomPort();
        const sidecarPath = getSidecarPath();
        if (fs.existsSync(sidecarPath)) {
          sidecarProcess = spawn(sidecarPath, [], {
            env: {
              ...process.env,
              PORT: String(sidecarPort),
              SIDECAR_MODE: '1',
              STORAGE_BACKEND: 'postgres',
              DATABASE_URL: databaseUrl,
            },
            stdio: ['pipe', 'pipe', 'pipe'],
          });
          sidecarProcess.on('error', (err) => { console.error('[sidecar] restart error:', err.message); sidecarProcess = null; });
          sidecarProcess.stdout?.on('data', (data: Buffer) => console.log(`[sidecar] ${data.toString().trim()}`));
          sidecarProcess.stderr?.on('data', (data: Buffer) => console.error(`[sidecar] ${data.toString().trim()}`));
          sidecarProcess.on('exit', (code) => { console.log(`[sidecar] exited with code ${code}`); sidecarProcess = null; });
          await new Promise<void>((resolve) => setTimeout(resolve, 1500));
        }
      }
      return result;
    } catch { return { error: 'Migration failed' }; }
  });

  // ── Server Mode IPC handlers ───────────────────────────────────────────

  /** Get current server mode: 'local' (sidecar) or 'remote' (user-provided URL). */
  ipcMain.handle('server:getConfig', () => {
    const configPath = path.join(getAppDataDir(), 'config.json');
    let serverUrl = '';
    try {
      if (fs.existsSync(configPath)) {
        const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        serverUrl = cfg.server_url || '';
      }
    } catch { /* ignore */ }
    return {
      mode: serverUrl ? 'remote' : 'local',
      serverUrl,
    };
  });

  /** Test connectivity to a remote server URL. */
  ipcMain.handle('server:testConnection', async (_event, url: string) => {
    try {
      const cleanUrl = url.replace(/\/+$/, '');
      const res = await fetch(`${cleanUrl}/health`, { signal: AbortSignal.timeout(5000) });
      if (res.ok) return { success: true };
      return { error: `Server returned status ${res.status}` };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Connection failed';
      return { error: msg };
    }
  });

  /**
   * Switch to remote server mode.
   * Stops the local sidecar and saves the server URL to config.
   * The user must then register/login on the remote server.
   * Existing local data remains in the SQLite file as a backup.
   */
  ipcMain.handle('server:setRemote', async (_event, url: string) => {
    try {
      const cleanUrl = url.replace(/\/+$/, '');
      // Verify the remote server is reachable
      const res = await fetch(`${cleanUrl}/health`, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) return { error: `Server returned status ${res.status}` };

      // Save to config
      const configDir = getAppDataDir();
      const configPath = path.join(configDir, 'config.json');
      if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });

      let cfg: Record<string, unknown> = {};
      try {
        if (fs.existsSync(configPath)) cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      } catch { /* start fresh */ }
      cfg.server_url = cleanUrl;
      fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2), { mode: 0o600 });

      // Stop local sidecar — all API calls now go to the remote URL
      stopSidecar();
      console.log(`[server] switched to remote mode: ${cleanUrl}`);
      return { success: true };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to switch';
      return { error: msg };
    }
  });

  /**
   * Switch back to local (sidecar) mode.
   * Clears the remote server_url from config and restarts the sidecar.
   */
  ipcMain.handle('server:setLocal', async () => {
    try {
      const configDir = getAppDataDir();
      const configPath = path.join(configDir, 'config.json');

      let cfg: Record<string, unknown> = {};
      try {
        if (fs.existsSync(configPath)) cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      } catch { /* start fresh */ }
      delete cfg.server_url;
      fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2), { mode: 0o600 });

      // Restart local sidecar
      await startSidecar();
      console.log('[server] switched to local mode');
      return { success: true };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to switch';
      return { error: msg };
    }
  });

  /**
   * Export all vault entries from the current server as encrypted blobs.
   * Used during local→remote migration so the user can re-import on the remote server.
   */
  ipcMain.handle('server:exportEntries', async (_event, token: string) => {
    const api = getApiBase();
    if (!api) return { error: 'Backend not available' };
    try {
      const res = await fetch(`${api}/api/v1/vault/entries`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return { error: `Server returned ${res.status}` };
      const entries = await res.json();
      return { entries };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Export failed';
      return { error: msg };
    }
  });
}

/**
 * Reset the auto-lock timer. Called on user activity (IPC calls).
 */
function resetAutoLockTimer(): void {
  if (autoLockTimer) {
    clearTimeout(autoLockTimer);
  }
  autoLockTimer = setTimeout(async () => {
    console.log('[security] auto-lock triggered after inactivity');
    // Notify the renderer to clear master key and lock the vault
    mainWindow?.webContents.send('vault:auto-locked');
    // Clear extension session
    lockExtensionSession();
  }, AUTO_LOCK_TIMEOUT);
}

/**
 * Watch the lock-signal file written by the sidecar when the extension requests a vault lock.
 * When the file changes, lock the desktop app vault.
 */
function watchExtensionLockSignal(): void {
  const signalPath = path.join(getAppDataDir(), 'lock-signal');
  // Read initial content so we only react to NEW signals
  let lastContent = '';
  try {
    lastContent = fs.readFileSync(signalPath, 'utf-8');
  } catch { /* file may not exist yet */ }

  const checkSignal = () => {
    try {
      if (!fs.existsSync(signalPath)) return;
      const content = fs.readFileSync(signalPath, 'utf-8');
      if (content && content !== lastContent) {
        lastContent = content;
        console.log('[security] extension lock signal detected, locking vault');
        mainWindow?.webContents.send('vault:auto-locked');
      }
    } catch { /* ignore read errors */ }
  };

  // Poll every 1 second (fs.watch is unreliable on some platforms)
  setInterval(checkSignal, 1000);
}

// Disable GPU acceleration in production to reduce memory (~27MB savings)
if (!isDev) {
  app.disableHardwareAcceleration();
}

// App lifecycle
app.whenReady().then(async () => {
  await startSidecar();
  writeExtensionLockfile(); // For BACKEND_URL mode — sidecar writes its own in sidecar mode

  // Clear any stale extension session from a previous run
  lockExtensionSession();

  // Certificate verification for API server connections in production
  if (!isDev && backendUrl && backendUrl.startsWith('https://')) {
    // Read pinned certificate fingerprint from environment or config
    const pinnedFingerprint = process.env.LGI_CERT_FINGERPRINT || '';

    session.defaultSession.setCertificateVerifyProc((request, callback) => {
      // If no pin is configured, accept OS-level verification
      if (!pinnedFingerprint) {
        callback(0);
        return;
      }

      // Compare the server certificate fingerprint against the pinned value
      const certFingerprint = request.certificate?.fingerprint ?? '';
      if (certFingerprint && certFingerprint === pinnedFingerprint) {
        callback(0); // Certificate matches pin
      } else {
        console.error(
          `Certificate pinning failed: expected ${pinnedFingerprint}, got ${certFingerprint}`,
        );
        callback(-2); // Reject connection
      }
    });
  }

  registerIpcHandlers();
  createWindow();

  // Start auto-lock timer
  resetAutoLockTimer();

  // Watch for extension lock signal file
  watchExtensionLockSignal();

  // Reset auto-lock on user activity
  const _activityEvents = ['mouse-move', 'keydown'] as const;
  // Use powerMonitor to detect system idle, reset on any IPC activity
  // (IPC handlers reset via the auth:login handler)

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
