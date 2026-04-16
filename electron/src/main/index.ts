import { app, BrowserWindow, ipcMain, Menu, session } from 'electron';
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
}

function createWindow(): void {
  Menu.setApplicationMenu(null);

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: 'LGI Pass',
    backgroundColor: '#020617',
    autoHideMenuBar: true,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#020617',
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
      const authHashHex = derived.subarray(32, 64).toString('hex');

      const res = await fetch(`${api}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: credentials.email, auth_hash: authHashHex }),
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
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
      return await res.json();
    } catch (err) {
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

  // --- Biometric IPC handlers ---

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

      // Store email + authHash so biometric unlock can re-authenticate
      const credentialsJson = JSON.stringify({
        email: data.email,
        authHash: authHashHex,
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
      const creds = JSON.parse(credentialsJson) as { email: string; authHash: string };

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
      // Return the login result with email included
      return { ...result, email: creds.email };
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
