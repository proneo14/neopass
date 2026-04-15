import { app, BrowserWindow, ipcMain, Menu, session } from 'electron';
import path from 'path';
import fs from 'fs';
import { spawn, ChildProcess } from 'child_process';

let mainWindow: BrowserWindow | null = null;
let sidecarProcess: ChildProcess | null = null;
let sidecarPort: number | null = null;

const isDev = process.env.NODE_ENV === 'development';

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
    title: 'Quantum Password Manager',
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
    if (!sidecarPort) return { error: 'Sidecar not running' };
    try {
      const res = await fetch(`http://127.0.0.1:${sidecarPort}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('auth:register', async (_event, data: Record<string, unknown>) => {
    if (!sidecarPort) return { error: 'Sidecar not running' };
    try {
      const res = await fetch(`http://127.0.0.1:${sidecarPort}/api/v1/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:list', async (_event, token: string) => {
    if (!sidecarPort) return { error: 'Sidecar not running' };
    try {
      const res = await fetch(`http://127.0.0.1:${sidecarPort}/api/v1/vault/entries`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:get', async (_event, token: string, entryId: string) => {
    if (!sidecarPort) return { error: 'Sidecar not running' };
    try {
      const res = await fetch(`http://127.0.0.1:${sidecarPort}/api/v1/vault/entries/${encodeURIComponent(entryId)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });

  ipcMain.handle('vault:create', async (_event, token: string, data: Record<string, unknown>) => {
    if (!sidecarPort) return { error: 'Sidecar not running' };
    try {
      const res = await fetch(`http://127.0.0.1:${sidecarPort}/api/v1/vault/entries`, {
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
    if (!sidecarPort) return { error: 'Sidecar not running' };
    try {
      const res = await fetch(`http://127.0.0.1:${sidecarPort}/api/v1/vault/entries/${encodeURIComponent(entryId)}`, {
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
    if (!sidecarPort) return { error: 'Sidecar not running' };
    try {
      const res = await fetch(`http://127.0.0.1:${sidecarPort}/api/v1/vault/entries/${encodeURIComponent(entryId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      return await res.json();
    } catch {
      return { error: 'Failed to connect to backend' };
    }
  });
}

// App lifecycle
app.whenReady().then(async () => {
  await startSidecar();
  registerIpcHandlers();
  createWindow();

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
