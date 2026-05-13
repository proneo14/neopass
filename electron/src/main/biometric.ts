import { systemPreferences, safeStorage, app } from 'electron';
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
  return path.join(process.env.TEMP || process.env.TMP || '.', 'neopass_hello_daemon.ps1');
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
  // Use Windows Biometric Framework (WinBio) instead of UserConsentVerifier
  // so that only fingerprint / face recognition is accepted — no PIN fallback.
  const script = [
    '# WinBio-based biometric daemon — fingerprint/face only, no PIN',
    'Add-Type -TypeDefinition @"',
    'using System;',
    'using System.Collections.Concurrent;',
    'using System.Runtime.InteropServices;',
    'using System.Security.Principal;',
    'using System.Threading;',
    'using System.Threading.Tasks;',
    '',
    'public class WinBio {',
    '    public const int FINGERPRINT = 0x00000008;',
    '    public const int FACIAL = 0x00000010;',
    '    public const int POOL_SYSTEM = 1;',
    '    public const int FLAG_DEFAULT = 0;',
    '    public const int SUBTYPE_ANY = 0xFF;',
    '    public const int ID_TYPE_SID = 3;',
    '    public const int S_OK = 0;',
    '',
    '    [StructLayout(LayoutKind.Sequential)]',
    '    public struct WINBIO_IDENTITY {',
    '        public int Type;',
    '        public int AccountSidSize;',
    '        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 68)]',
    '        public byte[] AccountSid;',
    '    }',
    '',
    '    [DllImport("winbio.dll")]',
    '    public static extern int WinBioEnumBiometricUnits(',
    '        int Factor, out IntPtr UnitSchemaArray, out int UnitCount);',
    '',
    '    [DllImport("winbio.dll")]',
    '    public static extern int WinBioOpenSession(',
    '        int Factor, int PoolType, int Flags,',
    '        IntPtr UnitArray, int UnitCount, IntPtr DatabaseId,',
    '        out IntPtr SessionHandle);',
    '',
    '    [DllImport("winbio.dll")]',
    '    public static extern int WinBioVerify(',
    '        IntPtr SessionHandle, ref WINBIO_IDENTITY Identity,',
    '        int SubFactor, out int UnitId,',
    '        [MarshalAs(UnmanagedType.U1)] out bool Match,',
    '        out int RejectDetail);',
    '',
    '    [DllImport("winbio.dll")]',
    '    public static extern int WinBioCloseSession(IntPtr SessionHandle);',
    '',
    '    [DllImport("winbio.dll")]',
    '    public static extern void WinBioFree(IntPtr Address);',
    '',
    '    [DllImport("winbio.dll")]',
    '    public static extern int WinBioCancel(IntPtr SessionHandle);',
    '',
    '    private static IntPtr _session = IntPtr.Zero;',
    '    private static readonly object _lock = new object();',
    '',
    '    public static int CountUnits(int factor) {',
    '        IntPtr arr; int count;',
    '        int hr = WinBioEnumBiometricUnits(factor, out arr, out count);',
    '        if (arr != IntPtr.Zero) WinBioFree(arr);',
    '        return (hr == S_OK) ? count : 0;',
    '    }',
    '',
    '    public static WINBIO_IDENTITY CurrentUser() {',
    '        var id = new WINBIO_IDENTITY();',
    '        id.Type = ID_TYPE_SID;',
    '        var sid = WindowsIdentity.GetCurrent().User;',
    '        byte[] b = new byte[sid.BinaryLength];',
    '        sid.GetBinaryForm(b, 0);',
    '        id.AccountSidSize = b.Length;',
    '        id.AccountSid = new byte[68];',
    '        Array.Copy(b, id.AccountSid, b.Length);',
    '        return id;',
    '    }',
    '',
    '    public static string Verify(int factor) {',
    '        IntPtr session;',
    '        int hr = WinBioOpenSession(factor, POOL_SYSTEM, FLAG_DEFAULT,',
    '            IntPtr.Zero, 0, IntPtr.Zero, out session);',
    '        if (hr != S_OK) return "ERROR:OpenSession:0x" + hr.ToString("X8");',
    '',
    '        lock (_lock) { _session = session; }',
    '        try {',
    '            var identity = CurrentUser();',
    '            int maxRetries = 3;',
    '            for (int attempt = 0; attempt < maxRetries; attempt++) {',
    '                int unitId; bool match; int reject;',
    '                hr = WinBioVerify(session, ref identity, SUBTYPE_ANY,',
    '                    out unitId, out match, out reject);',
    '                if (hr == S_OK && match) return "VERIFIED";',
    '                if (hr == unchecked((int)0x80098004)) return "FAILED:Canceled";',
    '                if (hr == unchecked((int)0x80098011)) return "FAILED:NotEnrolled";',
    '                if (hr == unchecked((int)0x80098005)) {',
    '                    if (attempt < maxRetries - 1) continue;',
    '                    return "FAILED:NoMatch";',
    '                }',
    '                if (hr == unchecked((int)0x80098003)) {',
    '                    if (attempt < maxRetries - 1) continue;',
    '                    return "FAILED:BadCapture";',
    '                }',
    '                return "FAILED:0x" + hr.ToString("X8");',
    '            }',
    '            return "FAILED:MaxRetries";',
    '        } finally {',
    '            lock (_lock) { _session = IntPtr.Zero; }',
    '            WinBioCloseSession(session);',
    '        }',
    '    }',
    '',
    '    public static void Cancel() {',
    '        lock (_lock) {',
    '            if (_session != IntPtr.Zero) WinBioCancel(_session);',
    '        }',
    '    }',
    '}',
    '',
    'public class BioDaemon {',
    '    private static ConcurrentQueue<string> _queue = new ConcurrentQueue<string>();',
    '',
    '    public static void Run() {',
    '        var reader = new Thread(() => {',
    '            try {',
    '                string line;',
    '                while ((line = Console.In.ReadLine()) != null)',
    '                    _queue.Enqueue(line);',
    '            } catch { }',
    '        });',
    '        reader.IsBackground = true;',
    '        reader.Start();',
    '',
    '        Console.Out.WriteLine("READY");',
    '        Console.Out.Flush();',
    '',
    '        while (true) {',
    '            string line = WaitForCommand();',
    '            if (line == null || line == "EXIT") break;',
    '            string result = ProcessCommand(line);',
    '            if (result != null) {',
    '                Console.Out.WriteLine(result);',
    '                Console.Out.Flush();',
    '            }',
    '        }',
    '    }',
    '',
    '    private static string WaitForCommand() {',
    '        string result;',
    '        while (!_queue.TryDequeue(out result))',
    '            Thread.Sleep(10);',
    '        return result;',
    '    }',
    '',
    '    private static string ProcessCommand(string line) {',
    '        if (line == "CHECK") {',
    '            try {',
    '                int fp = WinBio.CountUnits(WinBio.FINGERPRINT);',
    '                int face = WinBio.CountUnits(WinBio.FACIAL);',
    '                return (fp > 0 || face > 0) ? "Available" : "DeviceNotPresent";',
    '            } catch (Exception ex) {',
    '                return "ERROR:" + ex.Message;',
    '            }',
    '        }',
    '',
    '        if (line.StartsWith("VERIFY:")) {',
    '            try {',
    '                int fp = WinBio.CountUnits(WinBio.FINGERPRINT);',
    '                int face = WinBio.CountUnits(WinBio.FACIAL);',
    '                int factor = fp > 0 ? WinBio.FINGERPRINT',
    '                           : face > 0 ? WinBio.FACIAL : 0;',
    '                if (factor == 0) return "FAILED:NoHardware";',
    '',
    '                var task = Task.Run(() => WinBio.Verify(factor));',
    '                while (!task.IsCompleted) {',
    '                    string cmd;',
    '                    if (_queue.TryDequeue(out cmd)) {',
    '                        if (cmd == "CANCEL") WinBio.Cancel();',
    '                        else if (cmd == "EXIT") {',
    '                            WinBio.Cancel();',
    '                            return null;',
    '                        }',
    '                    }',
    '                    Thread.Sleep(50);',
    '                }',
    '                return task.Result;',
    '            } catch (Exception ex) {',
    '                return "ERROR:" + ex.Message;',
    '            }',
    '        }',
    '',
    '        if (line == "CANCEL") {',
    '            WinBio.Cancel();',
    '            return null;',
    '        }',
    '',
    '        return "ERROR:Unknown command";',
    '    }',
    '}',
    '"@',
    '',
    '[BioDaemon]::Run()',
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
 *
 * On Windows this uses the Windows Biometric Framework directly so that
 * only fingerprint / face recognition is accepted — PIN is never offered.
 */
export async function promptBiometric(reason: string): Promise<void> {
  // macOS: use Electron's built-in Touch ID prompt
  if (typeof systemPreferences.promptTouchID === 'function') {
    try {
      await systemPreferences.promptTouchID(reason);
      return;
    } catch {
      throw new Error('Biometric authentication cancelled or failed');
    }
  }

  // Windows: invoke biometric-only verification via WinBio daemon
  if (process.platform === 'win32') {
    await promptWindowsHello(reason);
    return;
  }

  throw new Error('Biometric prompt is not supported on this system');
}

/**
 * Cancel a pending biometric verification (e.g. when the user clicks Cancel
 * in the Electron UI). On Windows this sends CANCEL to the WinBio daemon
 * which calls WinBioCancel on the active session.
 */
export async function cancelBiometric(): Promise<void> {
  if (process.platform === 'win32' && helloProcess?.stdin) {
    helloProcess.stdin.write('CANCEL\n');
  }
}

/**
 * Invoke biometric verification (fingerprint / face only) via the persistent
 * PowerShell WinBio daemon.  PIN is never offered as a fallback.
 */
async function promptWindowsHello(reason: string): Promise<void> {
  const safeReason = reason.replace(/'/g, "''").replace(/\n/g, ' ');
  const output = await windowsHelloCommand(`VERIFY:${safeReason}`);
  console.log('[biometric] WinBio result:', output);
  if (output === 'VERIFIED') return;
  if (output === 'FAILED:Canceled') {
    throw new Error('Biometric authentication was cancelled');
  }
  if (output === 'FAILED:NotEnrolled') {
    throw new Error('No biometric data enrolled. Please set up fingerprint or face recognition in Windows Settings > Accounts > Sign-in options, then try again.');
  }
  if (output === 'FAILED:NoMatch') {
    throw new Error('Biometric did not match. Please try again.');
  }
  if (output === 'FAILED:BadCapture') {
    throw new Error('Could not read biometric. Please try again.');
  }
  if (output === 'FAILED:NoHardware') {
    throw new Error('No biometric hardware detected on this device.');
  }
  if (output.startsWith('ERROR:')) {
    throw new Error(`Biometric error: ${output.slice(6)}`);
  }
  throw new Error('Biometric verification was not approved');
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
