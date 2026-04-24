import { systemPreferences, safeStorage, BrowserWindow, app } from 'electron';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { spawn, ChildProcess } from 'child_process';

const SERVICE_NAME = 'QuantumPasswordManager';
const BLOB_FILENAME = 'biometric_vault.enc';

function getBlobPath(): string {
  const appData =
    process.platform === 'win32'
      ? process.env.APPDATA!
      : process.platform === 'darwin'
        ? path.join(process.env.HOME!, 'Library', 'Application Support')
        : path.join(process.env.HOME!, '.config');
  const dir = path.join(appData, SERVICE_NAME);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return path.join(dir, BLOB_FILENAME);
}

/**
 * Check whether the OS supports biometric / secure-credential verification.
 *
 * - Windows: checks Windows Hello (UserVerification) availability
 * - macOS: checks canPromptTouchID (Touch ID)
 * - Linux: returns true if safeStorage is available (falls back to keyring)
 */
// Cache the availability result so we don't shell out to PowerShell every time
let cachedAvailability: boolean | null = null;

export async function isBiometricAvailable(): Promise<boolean> {
  if (cachedAvailability !== null) return cachedAvailability;
  try {
    const hasPrompt = typeof systemPreferences.promptTouchID === 'function';
    const hasCan = typeof systemPreferences.canPromptTouchID === 'function';
    console.log('[biometric] platform =', process.platform);
    console.log('[biometric] promptTouchID exists =', hasPrompt);
    console.log('[biometric] canPromptTouchID exists =', hasCan);

    if (process.platform === 'win32') {
      const available = await checkWindowsHelloAvailable();
      console.log('[biometric] win32: Windows Hello available =', available);
      cachedAvailability = available;
      return available;
    }
    if (process.platform === 'darwin') {
      cachedAvailability = hasPrompt || (hasCan && systemPreferences.canPromptTouchID());
      return cachedAvailability;
    }
    cachedAvailability = false;
    return false;
  } catch (err) {
    console.error('[biometric] availability check error:', err);
    cachedAvailability = false;
    return false;
  }
}

/**
 * Check Windows Hello availability via PowerShell + UWP UserConsentVerifier.
 * Uses AsTask reflection workaround for PowerShell 5.1.
 */
function checkWindowsHelloAvailable(): Promise<boolean> {
  // Use the warm helper if it's already running
  return windowsHelloCommand('CHECK').then(
    (output) => output === 'Available',
    () => false,
  );
}

// ---------------------------------------------------------------------------
// Persistent PowerShell process for fast Windows Hello prompts
// ---------------------------------------------------------------------------
// Instead of spawning a new PowerShell process for every biometric call
// (~1.5s startup overhead each time), we keep one alive that has already
// loaded the WinRT assemblies and .NET reflection setup.  Subsequent
// commands complete in <100 ms.
// ---------------------------------------------------------------------------

let helloProcess: ChildProcess | null = null;
let helloReady = false;
let pendingCommand: {
  resolve: (output: string) => void;
  reject: (err: Error) => void;
} | null = null;
let stdoutBuffer = '';

function getHelloScriptPath(): string {
  return path.join(process.env.TEMP || process.env.TMP || '.', 'qpm_hello_daemon.ps1');
}

/**
 * Write the persistent PowerShell daemon script that:
 * 1. Loads WinRT assemblies once
 * 2. Sets up AsTask reflection once
 * 3. Reads commands from stdin line-by-line
 * 4. Responds on stdout with results
 */
function ensureHelloScript(): string {
  const scriptPath = getHelloScriptPath();
  const script = [
    '# Load WinRT + .NET runtime',
    '[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null',
    'Add-Type -AssemblyName System.Runtime.WindowsRuntime',
    '',
    '# P/Invoke for window focus management',
    'Add-Type -TypeDefinition @"',
    'using System;',
    'using System.Runtime.InteropServices;',
    'public class WinFocus {',
    '  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);',
    '  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);',
    '  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);',
    '  public static void ForceForeground(IntPtr hWnd) {',
    '    // Simulate an Alt key press/release so Windows allows SetForegroundWindow',
    '    keybd_event(0xA4, 0, 0, UIntPtr.Zero);',        // VK_LMENU down
    '    keybd_event(0xA4, 0, 2, UIntPtr.Zero);',        // VK_LMENU up
    '    ShowWindow(hWnd, 5);',                           // SW_SHOW
    '    SetForegroundWindow(hWnd);',
    '  }',
    '}',
    '"@',
    '',
    '# Cache the AsTask method once',
    '$asTaskMethods = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq "AsTask" -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq "IAsyncOperation``1" }',
    '$asTask = $asTaskMethods[0]',
    '',
    '# Signal ready',
    'Write-Output "READY"',
    '[Console]::Out.Flush()',
    '',
    '# Command loop',
    'while ($true) {',
    '  $line = [Console]::In.ReadLine()',
    '  if ($line -eq $null -or $line -eq "EXIT") { break }',
    '',
    '  if ($line -eq "CHECK") {',
    '    try {',
    '      $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()',
    '      $g = $asTask.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])',
    '      $t = $g.Invoke($null, @($op))',
    '      $t.Wait()',
    '      Write-Output $t.Result',
    '    } catch {',
    '      Write-Output "ERROR:$_"',
    '    }',
    '  }',
    '  elseif ($line.StartsWith("VERIFY:")) {',
    '    $reason = $line.Substring(7)',
    '    try {',
    '      $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($reason)',
      '      # Retry bringing the dialog to front',
      '      for ($i = 0; $i -lt 5; $i++) {',
      '        Start-Sleep -Milliseconds 200',
      '        foreach ($pname in @("CredentialUIBroker","consent","SecurityHealthSystray","UserAccountBroker","LogonUI","SystemSettings")) {',
      '          $p = Get-Process -Name $pname -ErrorAction SilentlyContinue | Select-Object -First 1',
      '          if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) { [WinFocus]::ForceForeground($p.MainWindowHandle); break }',
      '        }',
      '      }',
    '      $g = $asTask.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult])',
    '      $t = $g.Invoke($null, @($op))',
    '      $t.Wait()',
    '      if ($t.Result -eq [Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified) {',
    '        Write-Output "VERIFIED"',
    '      } else {',
    '        Write-Output "FAILED:$($t.Result)"',
    '      }',
    '    } catch {',
    '      Write-Output "ERROR:$_"',
    '    }',
    '  }',
    '  else {',
    '    Write-Output "ERROR:Unknown command"',
    '  }',
    '  [Console]::Out.Flush()',
    '}',
  ].join('\n');
  fs.writeFileSync(scriptPath, script, 'utf-8');
  return scriptPath;
}

/**
 * Start the persistent PowerShell process (if not already running).
 * Resolves when the process signals READY.
 */
function ensureHelloProcess(): Promise<void> {
  if (helloProcess && helloReady) return Promise.resolve();
  if (helloProcess) {
    // Process exists but isn't ready yet — wait for READY
    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('PowerShell startup timeout')), 10000);
      const check = setInterval(() => {
        if (helloReady) { clearInterval(check); clearTimeout(timeout); resolve(); }
      }, 50);
    });
  }

  return new Promise<void>((resolve, reject) => {
    const scriptPath = ensureHelloScript();
    const ps = spawn('powershell.exe', [
      '-NoProfile', '-NoLogo',
      '-ExecutionPolicy', 'Bypass',
      '-File', scriptPath,
    ], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: false });

    helloProcess = ps;
    stdoutBuffer = '';

    ps.stdout!.on('data', (chunk: Buffer) => {
      stdoutBuffer += chunk.toString();
      // Process complete lines
      let nlIdx: number;
      while ((nlIdx = stdoutBuffer.indexOf('\n')) !== -1) {
        const line = stdoutBuffer.slice(0, nlIdx).trim();
        stdoutBuffer = stdoutBuffer.slice(nlIdx + 1);

        if (line === 'READY') {
          helloReady = true;
          console.log('[biometric] Windows Hello daemon ready');
          resolve();
          continue;
        }

        // Deliver to pending command
        if (pendingCommand) {
          const cmd = pendingCommand;
          pendingCommand = null;
          cmd.resolve(line);
        }
      }
    });

    ps.stderr!.on('data', (chunk: Buffer) => {
      console.error('[biometric] PS stderr:', chunk.toString().trim());
    });

    ps.on('exit', (code) => {
      console.log('[biometric] Windows Hello daemon exited, code =', code);
      helloProcess = null;
      helloReady = false;
      if (pendingCommand) {
        const cmd = pendingCommand;
        pendingCommand = null;
        cmd.reject(new Error('PowerShell process exited'));
      }
    });

    ps.on('error', (err) => {
      console.error('[biometric] Windows Hello daemon error:', err.message);
      helloProcess = null;
      helloReady = false;
      reject(err);
    });

    // Kill the daemon when the app exits
    app.on('will-quit', () => {
      if (helloProcess) {
        try { helloProcess.stdin!.write('EXIT\n'); } catch { /* ignore */ }
        helloProcess.kill();
        helloProcess = null;
      }
    });
  });
}

/**
 * Send a command to the persistent PowerShell process and return the response line.
 */
async function windowsHelloCommand(command: string): Promise<string> {
  await ensureHelloProcess();
  if (!helloProcess || !helloProcess.stdin) {
    throw new Error('Windows Hello daemon not available');
  }

  return new Promise<string>((resolve, reject) => {
    pendingCommand = { resolve, reject };
    const timeout = setTimeout(() => {
      if (pendingCommand) {
        pendingCommand = null;
        reject(new Error('Windows Hello command timeout'));
      }
    }, 60000);

    const origResolve = resolve;
    pendingCommand.resolve = (output: string) => {
      clearTimeout(timeout);
      origResolve(output);
    };

    helloProcess!.stdin!.write(command + '\n');
  });
}

/**
 * Check if the user has already enrolled biometric unlock
 * (i.e. there is an encrypted master-key blob on disk).
 */
export function isBiometricConfigured(): boolean {
  return fs.existsSync(getBlobPath());
}

/**
 * Pre-warm the Windows Hello daemon so the first biometric prompt is fast.
 * Call this early in app startup.
 */
export async function warmUpBiometric(): Promise<void> {
  if (process.platform === 'win32') {
    try {
      await ensureHelloProcess();
      console.log('[biometric] daemon pre-warmed');
    } catch (err) {
      console.error('[biometric] warm-up failed:', err);
    }
  }
}

/**
 * Enable biometric unlock.
 *
 * 1. Generate a random 32-byte "biometric key".
 * 2. Encrypt the credentials payload with that biometric key (AES-256-GCM).
 * 3. Protect the biometric key with Electron safeStorage (OS credential store).
 * 4. Write the encrypted blob + the encrypted biometric key to disk.
 *
 * The payload contains the user's email and the full 64-byte derived key
 * (first 32 bytes = master key, last 32 bytes = auth hash), so that
 * biometric unlock can re-authenticate with the backend without prompting
 * for the password.
 */
export async function enableBiometric(credentialsJson: string): Promise<void> {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is not available');
  }

  const payloadBuf = Buffer.from(credentialsJson, 'utf-8');

  // 1. Generate a random biometric wrapping key
  const biometricKey = crypto.randomBytes(32);

  // 2. Encrypt the credentials with the biometric key (AES-256-GCM)
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', biometricKey, iv);
  const encrypted = Buffer.concat([cipher.update(payloadBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // 3. Protect the biometric key via OS secure storage
  const protectedBiometricKey = safeStorage.encryptString(biometricKey.toString('hex'));

  // 4. Persist to disk: [4-byte iv-len][iv][4-byte tag-len][tag][4-byte enc-len][encrypted][protectedKey]
  const blobPath = getBlobPath();
  const parts = [
    lengthPrefix(iv),
    lengthPrefix(authTag),
    lengthPrefix(encrypted),
    lengthPrefix(protectedBiometricKey),
  ];
  fs.writeFileSync(blobPath, Buffer.concat(parts), { mode: 0o600 });

  // Zero sensitive buffers
  biometricKey.fill(0);
  payloadBuf.fill(0);
}

/**
 * Unlock the vault using biometric authentication.
 *
 * 1. Read the blob from disk.
 * 2. Decrypt the biometric key via safeStorage (triggers OS biometric prompt).
 * 3. Decrypt the credentials payload with the biometric key.
 * 4. Return the credentials JSON string.
 */
export async function unlockWithBiometric(): Promise<string> {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is not available');
  }

  const blobPath = getBlobPath();
  if (!fs.existsSync(blobPath)) {
    throw new Error('Biometric unlock is not configured');
  }

  const blob = fs.readFileSync(blobPath);
  let offset = 0;

  const iv = readPrefixed(blob, offset);
  offset += 4 + iv.length;

  const authTag = readPrefixed(blob, offset);
  offset += 4 + authTag.length;

  const encrypted = readPrefixed(blob, offset);
  offset += 4 + encrypted.length;

  const protectedBiometricKey = readPrefixed(blob, offset);

  // ALWAYS require biometric verification before decrypting
  await promptBiometric('unlock your password vault');

  // Decrypt biometric key from OS secure storage
  const biometricKeyHex = safeStorage.decryptString(protectedBiometricKey);
  const biometricKey = Buffer.from(biometricKeyHex, 'hex');

  // Decrypt credentials payload
  const decipher = crypto.createDecipheriv('aes-256-gcm', biometricKey, iv);
  decipher.setAuthTag(authTag);
  const payloadBuf = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  const credentialsJson = payloadBuf.toString('utf-8');

  // Zero sensitive buffers
  biometricKey.fill(0);
  payloadBuf.fill(0);

  return credentialsJson;
}

/**
 * Disable biometric unlock by deleting the stored blob.
 */
export async function disableBiometric(): Promise<void> {
  const blobPath = getBlobPath();
  if (fs.existsSync(blobPath)) {
    // Overwrite before unlinking to avoid remnant on disk
    const size = fs.statSync(blobPath).size;
    fs.writeFileSync(blobPath, crypto.randomBytes(size));
    fs.unlinkSync(blobPath);
  }
}

/**
 * Re-verify the user's identity via biometric prompt without returning secrets.
 * Used as a gate before revealing or copying sensitive fields.
 *
 * - macOS: promptTouchID
 * - Windows: promptTouchID if available, otherwise safeStorage round-trip
 * - Linux: safeStorage decrypt round-trip (triggers keyring unlock)
 *
 * Returns true if verification succeeds, throws on failure.
 */
export async function verifyBiometric(): Promise<void> {
  if (!isBiometricConfigured()) {
    throw new Error('Biometric is not configured');
  }

  await promptBiometric('verify your identity');
}

// --- helpers ---

/**
 * Trigger the OS biometric prompt (Windows Hello / Touch ID).
 * Throws if the user cancels or the prompt is unavailable.
 */
async function promptBiometric(reason: string): Promise<void> {
  // macOS: use Electron's built-in Touch ID prompt
  if (typeof systemPreferences.promptTouchID === 'function') {
    try {
      await systemPreferences.promptTouchID(reason);
      return;
    } catch {
      throw new Error('Biometric authentication cancelled or failed');
    }
  }

  // Windows: invoke Windows Hello via UWP UserConsentVerifier
  if (process.platform === 'win32') {
    const win = BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0];
    const wasOnTop = win?.isAlwaysOnTop() ?? false;
    if (win) {
      win.setAlwaysOnTop(false);
    }
    try {
      await promptWindowsHello(reason);
    } finally {
      if (win) {
        if (wasOnTop) win.setAlwaysOnTop(true);
        win.focus();
      }
    }
    return;
  }

  throw new Error('Biometric prompt is not supported on this system');
}

/**
 * Invoke Windows Hello fingerprint/face/PIN prompt via the persistent PowerShell daemon.
 */
async function promptWindowsHello(reason: string): Promise<void> {
  const safeReason = reason.replace(/'/g, "''").replace(/\n/g, ' ');
  const output = await windowsHelloCommand(`VERIFY:${safeReason}`);
  console.log('[biometric] Windows Hello result:', output);
  if (output === 'VERIFIED') return;
  if (output.startsWith('ERROR:')) {
    throw new Error(`Windows Hello error: ${output.slice(6)}`);
  }
  throw new Error('Windows Hello verification was not approved');
}

function lengthPrefix(buf: Buffer): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt32LE(buf.length, 0);
  return Buffer.concat([header, buf]);
}

function readPrefixed(buf: Buffer, offset: number): Buffer {
  const len = buf.readUInt32LE(offset);
  return buf.subarray(offset + 4, offset + 4 + len);
}
