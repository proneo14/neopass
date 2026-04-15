# Quantum-Safe Password Manager — Step-by-Step Build Prompts

Use these prompts sequentially. Each prompt builds on the work from previous steps.

---

## Phase 1: Core Backend (Go API Server)

### Prompt 1 — Project Scaffolding

```
Initialize a Go project for a quantum-safe password manager.

Create the following directory structure:
- cmd/server/main.go          — API server entry point (placeholder, chi router)
- cmd/nativehost/main.go      — Native messaging host binary (placeholder)
- internal/crypto/             — All cryptographic operations
- internal/api/                — HTTP handlers
- internal/db/                 — PostgreSQL repository layer
- internal/auth/               — Authentication, sessions, 2FA
- internal/vault/              — Vault CRUD operations
- internal/admin/              — Admin operations
- internal/sync/               — Client-server vault sync
- migrations/                  — SQL migration files

Initialize go.mod with module name "github.com/<your-org>/password-manager" and add these dependencies:
- github.com/cloudflare/circl  (post-quantum crypto — X-Wing KEM, ML-DSA-65)
- github.com/jackc/pgx/v5      (PostgreSQL driver)
- github.com/go-chi/chi/v5     (HTTP router)
- golang.org/x/crypto          (Argon2id, bcrypt)
- github.com/pquerna/otp       (TOTP 2FA)
- github.com/golang-jwt/jwt/v5 (JWT tokens)
- github.com/rs/zerolog         (structured logging)

Set up cmd/server/main.go with:
- chi router with JSON middleware
- Graceful shutdown via context
- Config loaded from environment variables (DATABASE_URL, PORT, etc.)
- Health check endpoint at GET /health
```

---

### Prompt 2 — Database Schema & Migrations

```
Create the PostgreSQL migration file at migrations/001_initial.sql with these tables:

Users:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- email TEXT UNIQUE NOT NULL
- auth_hash BYTEA NOT NULL              -- bcrypt of Argon2id-derived auth token
- salt BYTEA NOT NULL                   -- salt for Argon2id KDF
- kdf_params JSONB NOT NULL DEFAULT '{"memory":65536,"iterations":3,"parallelism":4}'
- public_key BYTEA                      -- X-Wing public key for encrypted sharing
- encrypted_private_key BYTEA           -- X-Wing private key encrypted with master key
- created_at TIMESTAMPTZ DEFAULT now()
- updated_at TIMESTAMPTZ DEFAULT now()

Organizations:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- name TEXT NOT NULL
- org_public_key BYTEA NOT NULL         -- X-Wing org public key
- encrypted_org_private_key BYTEA NOT NULL  -- encrypted with admin's master key
- created_at TIMESTAMPTZ DEFAULT now()

Org Members:
- org_id UUID REFERENCES organizations(id) ON DELETE CASCADE
- user_id UUID REFERENCES users(id) ON DELETE CASCADE
- role TEXT NOT NULL CHECK (role IN ('admin', 'member'))
- escrow_blob BYTEA NOT NULL            -- user's master key encrypted with org public key
- joined_at TIMESTAMPTZ DEFAULT now()
- PRIMARY KEY (org_id, user_id)

Vault Entries:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- user_id UUID REFERENCES users(id) ON DELETE CASCADE
- org_id UUID REFERENCES organizations(id) ON DELETE SET NULL
- entry_type TEXT NOT NULL CHECK (entry_type IN ('login', 'secure_note', 'credit_card', 'identity'))
- encrypted_data BYTEA NOT NULL         -- AES-256-GCM encrypted JSON blob
- nonce BYTEA NOT NULL                  -- GCM nonce/IV (12 bytes)
- version INT NOT NULL DEFAULT 1
- folder_id UUID REFERENCES folders(id) ON DELETE SET NULL
- created_at TIMESTAMPTZ DEFAULT now()
- updated_at TIMESTAMPTZ DEFAULT now()

Folders:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- user_id UUID REFERENCES users(id) ON DELETE CASCADE
- name_encrypted BYTEA NOT NULL
- parent_id UUID REFERENCES folders(id) ON DELETE CASCADE

TOTP Secrets:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE
- encrypted_secret BYTEA NOT NULL       -- TOTP secret encrypted with user's master key
- verified BOOLEAN NOT NULL DEFAULT false
- created_at TIMESTAMPTZ DEFAULT now()

Shared 2FA:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- from_user_id UUID REFERENCES users(id) ON DELETE CASCADE
- to_user_id UUID REFERENCES users(id) ON DELETE CASCADE
- encrypted_totp_secret BYTEA NOT NULL  -- encrypted with recipient's X-Wing public key
- expires_at TIMESTAMPTZ NOT NULL
- claimed BOOLEAN NOT NULL DEFAULT false
- created_at TIMESTAMPTZ DEFAULT now()

Recovery Codes:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- user_id UUID REFERENCES users(id) ON DELETE CASCADE
- code_hash BYTEA NOT NULL              -- bcrypt hash of recovery code
- used BOOLEAN NOT NULL DEFAULT false

Sessions:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- user_id UUID REFERENCES users(id) ON DELETE CASCADE
- token_hash BYTEA NOT NULL
- device_info TEXT
- expires_at TIMESTAMPTZ NOT NULL
- created_at TIMESTAMPTZ DEFAULT now()

Audit Log:
- id UUID PRIMARY KEY DEFAULT gen_random_uuid()
- actor_id UUID REFERENCES users(id) ON DELETE SET NULL
- target_id UUID
- action TEXT NOT NULL
- details JSONB
- created_at TIMESTAMPTZ DEFAULT now()

Sync Cursors:
- user_id UUID REFERENCES users(id) ON DELETE CASCADE
- device_id TEXT NOT NULL
- last_sync_at TIMESTAMPTZ NOT NULL DEFAULT now()
- PRIMARY KEY (user_id, device_id)

Add indexes on:
- vault_entries(user_id, updated_at)
- audit_log(actor_id, created_at)
- audit_log(target_id, created_at)
- sessions(token_hash)
- sessions(expires_at)

Also create internal/db/postgres.go with:
- Connection pool setup using pgx/v5/pgxpool
- RunMigrations() function that reads and executes SQL files from migrations/
- Close() method for graceful shutdown
```

---

### Prompt 3 — Cryptographic Primitives

```
Implement the cryptographic primitives module in internal/crypto/. This is the security core of the app — every function must be carefully implemented.

internal/crypto/kdf.go:
- DeriveKeys(masterPassword string, salt []byte) -> (masterKey [32]byte, authHash [32]byte, error)
  - Uses Argon2id with 64MB memory, 3 iterations, 4 parallelism
  - Derives a 64-byte output, splits into two 32-byte keys:
    - First 32 bytes = Master Key (for vault encryption)
    - Last 32 bytes = Auth Hash (sent to server for login verification)
  - If salt is nil, generate 16 random bytes
- GenerateSalt() -> ([]byte, error) — 16 bytes from crypto/rand

internal/crypto/hybrid.go:
- GenerateKeyPair() -> (publicKey, privateKey []byte, error)
  - Uses X-Wing KEM from cloudflare/circl/kem/xwing
- Encapsulate(publicKey []byte) -> (sharedSecret [32]byte, ciphertext []byte, error)
- Decapsulate(privateKey []byte, ciphertext []byte) -> (sharedSecret [32]byte, error)
- DeriveSessionKey(sharedSecret [32]byte, context string) -> [32]byte
  - Uses SHAKE256 with domain separation: SHAKE256(sharedSecret || context)

internal/crypto/vault.go:
- Encrypt(plaintext []byte, key [32]byte) -> (ciphertext []byte, nonce []byte, error)
  - AES-256-GCM, 12-byte random nonce from crypto/rand
- Decrypt(ciphertext []byte, nonce []byte, key [32]byte) -> (plaintext []byte, error)
- ZeroBytes(b []byte) — securely zeros a byte slice

internal/crypto/orgkey.go:
- GenerateOrgKeyPair() -> (publicKey, encryptedPrivateKey []byte, adminMasterKey [32]byte, error)
  - Generates X-Wing keypair, encrypts private key with admin's master key
- EncryptEscrow(userMasterKey [32]byte, orgPublicKey []byte) -> (escrowBlob []byte, error)
  - Encrypts user's master key with org's X-Wing public key
- DecryptEscrow(escrowBlob []byte, orgPrivateKey []byte) -> (userMasterKey [32]byte, error)
  - Decrypts escrow to recover user's master key
- ReEncryptOrgPrivateKey(orgPrivateKey []byte, newAdminMasterKey [32]byte) -> ([]byte, error)

internal/crypto/signatures.go:
- GenerateSigningKeyPair() -> (publicKey, privateKey []byte, error)
  - Uses ML-DSA-65 from cloudflare/circl/sign/mldsa/mode65
- Sign(message []byte, privateKey []byte) -> (signature []byte, error)
- Verify(message []byte, signature []byte, publicKey []byte) -> (bool, error)

Write unit tests in internal/crypto/crypto_test.go that verify:
- KDF produces deterministic output for same password+salt
- KDF produces different masterKey vs authHash
- Encrypt -> Decrypt round-trip preserves plaintext
- Wrong key fails decryption
- X-Wing encapsulate/decapsulate produces matching shared secrets
- Escrow encrypt/decrypt recovers original master key
- ML-DSA sign/verify succeeds with correct key, fails with wrong key
- ZeroBytes actually zeros the buffer
```

---

### Prompt 4 — Authentication System

```
Implement the authentication system. Depends on the crypto module from Prompt 3.

internal/db/user_repo.go:
- UserRepo struct with pgxpool.Pool
- CreateUser(ctx, email, authHash, salt, kdfParams, publicKey, encryptedPrivateKey) -> (User, error)
- GetUserByEmail(ctx, email) -> (User, error)
- GetUserByID(ctx, id) -> (User, error)
- UpdateUserKeys(ctx, id, authHash, salt, publicKey, encryptedPrivateKey) -> error

internal/auth/service.go:
- AuthService struct with UserRepo, signing keys, and config
- Register(ctx, RegisterRequest) -> (RegisterResponse, error)
  - Receives: email, authHash (hex), salt (hex), kdfParams, publicKey, encryptedPrivateKey
  - Server bcrypt-hashes the authHash before storing (double-hash: client Argon2id → server bcrypt)
  - Returns: user ID, JWT access token, refresh token
- Login(ctx, LoginRequest) -> (LoginResponse, error)
  - Receives: email, authHash (hex)
  - Verifies bcrypt(storedHash, authHash)
  - If 2FA enabled: returns partial token requiring 2FA verification
  - If no 2FA: returns JWT access token + refresh token
- RefreshToken(ctx, refreshToken) -> (TokenResponse, error)
- JWT signing using ML-DSA-65 (custom signing method wrapping circl)
- JWT contains: sub (user_id), exp, iat, org_id (if applicable), role

internal/api/auth_handler.go:
- POST /api/v1/auth/register
- POST /api/v1/auth/login
- POST /api/v1/auth/refresh
- POST /api/v1/auth/logout
- Middleware: AuthMiddleware that validates JWT on protected routes, injects user context

All endpoints must:
- Return JSON responses with consistent error format { "error": "message" }
- Use parameterized queries (pgx) — no string concatenation for SQL
- Rate limit login attempts (5 per minute per IP using in-memory counter)
- Log auth events via zerolog
```

---

### Prompt 5 — 2FA System (TOTP + SMS + Sharing)

```
Implement the 2FA system. Depends on auth system from Prompt 4.

internal/auth/totp.go:
- SetupTOTP(ctx, userID) -> (secret string, qrURI string, recoveryCodes []string, error)
  - Generate TOTP secret using pquerna/otp/totp
  - Generate 8 recovery codes (random 8-char alphanumeric strings)
  - Encrypt TOTP secret with user's master key (fetched from encrypted_private_key context)
  - Store encrypted secret in totp_secrets table (verified=false)
  - Store bcrypt-hashed recovery codes in recovery_codes table
  - Return plaintext secret + QR provisioning URI + plaintext recovery codes (shown once)

- VerifyTOTPSetup(ctx, userID, code string) -> error
  - Validate TOTP code against stored (decrypted) secret
  - Mark totp_secrets.verified = true
  - If invalid, return error (don't mark verified)

- ValidateTOTP(ctx, userID, code string) -> error
  - Used during login flow
  - Check TOTP code OR check against unused recovery codes
  - If recovery code used, mark it as used

- ShareTOTP(ctx, fromUserID, toUserID, totpSecret string, expiresIn time.Duration) -> error
  - Encrypt totpSecret with recipient's X-Wing public key
  - Store in shared_2fa table with expiration
  - This allows admin to share a 2FA code with an employee they're helping

- ClaimSharedTOTP(ctx, userID, shareID) -> (secret string, error)
  - Recipient decrypts with their private key
  - Mark as claimed
  - Reject if expired or already claimed

internal/api/auth_handler.go (add endpoints):
- POST /api/v1/auth/2fa/setup         — returns QR URI + recovery codes
- POST /api/v1/auth/2fa/verify-setup  — confirms initial TOTP code
- POST /api/v1/auth/2fa/validate      — validates code during login
- POST /api/v1/auth/2fa/share         — admin shares TOTP with user (requires admin role)
- POST /api/v1/auth/2fa/claim/:id     — user claims shared TOTP

SMS fallback (optional, behind config flag ENABLE_SMS_2FA):
- SendSMS2FA(ctx, userID, phoneNumber) -> error — sends code via Twilio API
- ValidateSMS2FA(ctx, userID, code) -> error — validates SMS code (stored temporarily with 5min expiry)
```

---

### Prompt 6 — Vault CRUD Operations

```
Implement vault CRUD. Depends on crypto (Prompt 3) and auth (Prompt 4).

internal/db/vault_repo.go:
- VaultRepo struct with pgxpool.Pool
- CreateEntry(ctx, entry VaultEntry) -> (VaultEntry, error)
- GetEntry(ctx, entryID, userID) -> (VaultEntry, error)
- ListEntries(ctx, userID, filters VaultFilters) -> ([]VaultEntry, error)
  - Filters: entry_type, folder_id, search (on server-side metadata if any), updated_since
- UpdateEntry(ctx, entry VaultEntry) -> (VaultEntry, error)
  - Increments version, updates updated_at
- DeleteEntry(ctx, entryID, userID) -> error
- CreateFolder(ctx, folder Folder) -> (Folder, error)
- ListFolders(ctx, userID) -> ([]Folder, error)
- DeleteFolder(ctx, folderID, userID) -> error

internal/vault/service.go:
- VaultService struct with VaultRepo, CryptoService
- CreateEntry(ctx, userID, entryType, plaintextData []byte) -> (VaultEntry, error)
  - Encrypts plaintextData with user's master key (from session context)
  - Stores encrypted blob + nonce
- GetEntry(ctx, userID, entryID) -> (entryType string, plaintextData []byte, error)
  - Fetches encrypted entry, decrypts with master key
- UpdateEntry(ctx, userID, entryID, plaintextData []byte) -> (VaultEntry, error)
- DeleteEntry(ctx, userID, entryID) -> error
- ListEntries(ctx, userID, filters) -> ([]VaultEntrySummary, error)
  - Returns metadata only (id, type, version, timestamps) — client decrypts locally

Entry plaintext JSON structure (encrypted as a blob):
{
  "login": { "name": "", "username": "", "password": "", "uri": "", "notes": "" },
  "secure_note": { "name": "", "content": "" },
  "credit_card": { "name": "", "number": "", "expiry": "", "cvv": "", "cardholder": "" },
  "identity": { "name": "", "firstName": "", "lastName": "", "email": "", "phone": "", "address": "" }
}

internal/api/vault_handler.go:
- POST   /api/v1/vault/entries          — create entry (encrypted blob from client)
- GET    /api/v1/vault/entries           — list entries (metadata only)
- GET    /api/v1/vault/entries/:id       — get single entry (encrypted blob)
- PUT    /api/v1/vault/entries/:id       — update entry
- DELETE /api/v1/vault/entries/:id       — delete entry
- POST   /api/v1/vault/folders           — create folder
- GET    /api/v1/vault/folders           — list folders
- DELETE /api/v1/vault/folders/:id       — delete folder

All vault endpoints require authentication middleware.
Server never decrypts vault entries — it stores and serves encrypted blobs.
The exception is admin access via escrow (Prompt 7).
```

---

### Prompt 7 — Admin System

```
Implement the admin system for organization management. Depends on crypto (Prompt 3), auth (Prompt 4), and vault (Prompt 6).

internal/db/audit_repo.go:
- AuditRepo struct with pgxpool.Pool
- LogAction(ctx, actorID, targetID, action, details) -> error
- GetAuditLog(ctx, filters AuditFilters) -> ([]AuditEntry, error)
  - Filters: actor_id, target_id, action, date range, pagination

internal/admin/service.go:
- AdminService struct with repos + crypto

Organization management:
- CreateOrg(ctx, adminUserID, orgName) -> (Organization, error)
  - Generate X-Wing org keypair
  - Encrypt org private key with admin's master key
  - Create org + add admin user as admin role
  - Create escrow blob for admin user
  - Audit log: "org_created"

- InviteUser(ctx, adminUserID, orgID, email, role) -> error
  - Verify admin role
  - Create invitation record (implement invitations table if needed)
  - Audit log: "user_invited"

- AcceptInvite(ctx, userID, orgID) -> error
  - Create escrow blob: encrypt user's master key with org public key
  - Add to org_members
  - Audit log: "user_joined"

- RemoveUser(ctx, adminUserID, orgID, targetUserID) -> error
  - Verify admin role
  - Remove from org_members, delete escrow blob
  - Audit log: "user_removed"

Admin vault access (escrow-based):
- AccessUserVault(ctx, adminUserID, orgID, targetUserID) -> ([]DecryptedEntry, error)
  - Verify admin role in org
  - Decrypt org private key with admin's master key
  - Decrypt target user's escrow blob → get user's master key
  - Decrypt user's vault entries
  - Audit log: "vault_accessed" (with target user details)
  - IMPORTANT: always log this action — it's a sensitive operation

- ChangeUserPassword(ctx, adminUserID, orgID, targetUserID, newAuthHash, newSalt) -> error
  - Decrypt user's vault via escrow
  - Generate new master key from new credentials
  - Re-encrypt all vault entries with new master key
  - Update user's auth_hash, salt
  - Re-encrypt user's private key with new master key
  - Update escrow blob with new master key
  - Audit log: "password_changed_by_admin"

Policy enforcement:
- SetOrgPolicy(ctx, adminUserID, orgID, policy OrgPolicy) -> error
  - Policy struct: require_2fa bool, min_password_length int, rotation_days int
  - Store as JSONB in organizations table (add policy column)
- GetOrgPolicy(ctx, orgID) -> (OrgPolicy, error)

internal/api/admin_handler.go:
- POST   /api/v1/admin/orgs                         — create organization
- POST   /api/v1/admin/orgs/:id/invite               — invite user
- POST   /api/v1/admin/orgs/:id/accept               — accept invitation
- DELETE /api/v1/admin/orgs/:id/members/:uid          — remove user
- GET    /api/v1/admin/orgs/:id/members               — list members
- GET    /api/v1/admin/orgs/:id/vault/:uid             — access user's vault (admin only)
- POST   /api/v1/admin/orgs/:id/vault/:uid/reset-password — change user password
- PUT    /api/v1/admin/orgs/:id/policy                — set org policy
- GET    /api/v1/admin/orgs/:id/audit                 — get audit log

All admin endpoints require authentication + admin role verification.
Every admin action must be audit-logged with actor, target, timestamp, and action type.
```

---

### Prompt 8 — Sync Protocol

```
Implement the sync protocol for multi-device support. Depends on vault (Prompt 6).

internal/sync/service.go:
- SyncService struct with VaultRepo, SyncRepo

- Pull(ctx, userID, deviceID, lastSyncAt time.Time) -> (SyncResponse, error)
  - Query vault_entries WHERE user_id = userID AND updated_at > lastSyncAt
  - Include deleted entries (add a soft-delete flag: is_deleted BOOLEAN DEFAULT false to vault_entries)
  - Return list of changed entries (encrypted blobs) + new sync timestamp
  - Update sync_cursors for this device

- Push(ctx, userID, deviceID, changes []VaultEntryChange) -> ([]ConflictEntry, error)
  - For each change:
    - If server version == client's base version: apply change, increment version
    - If server version > client's base version: return as conflict
  - Return list of conflicts for client to resolve
  - Conflicts contain both server and client versions

- ResolveConflict(ctx, userID, entryID, resolution string, data []byte) -> error
  - resolution: "keep_server", "keep_client", or "merge" (client sends merged blob)

Add migration migrations/002_sync.sql:
- ALTER TABLE vault_entries ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT false;
- Add index on vault_entries(user_id, updated_at) if not exists

internal/api/sync_handler.go:
- POST /api/v1/sync/pull    — { device_id, last_sync_at } -> { entries, sync_at }
- POST /api/v1/sync/push    — { device_id, changes: [...] } -> { conflicts: [...] }
- POST /api/v1/sync/resolve — { entry_id, resolution, data }

All sync endpoints require authentication.
```

---

## Phase 2: Desktop Application (Electron + Go Sidecar)

### Prompt 9 — Electron App Scaffolding

```
Set up the Electron desktop application in the electron/ directory.

Tech stack:
- Electron (latest stable)
- Vite for build tooling
- React 18+ with TypeScript
- Tailwind CSS for styling
- electron-builder for packaging

Initialize with:
- electron/package.json with all dependencies
- electron/vite.config.ts for renderer build
- electron/electron-builder.yml for packaging config (Windows NSIS, macOS DMG, Linux AppImage)
- electron/tsconfig.json

electron/src/main/index.ts:
- Create BrowserWindow with these security settings:
  - contextIsolation: true
  - sandbox: true
  - nodeIntegration: false
  - webSecurity: true
- Content Security Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
- Spawn Go sidecar process (cmd/sidecar binary) as child process
  - Communicate via local HTTP on random high port (localhost only)
  - Sidecar handles: crypto operations, native messaging relay, local vault cache
- Handle app lifecycle: ready, window-all-closed, activate

electron/src/main/preload.ts:
- contextBridge.exposeInMainWorld('api', { ... })
- Expose IPC methods: login, register, getVault, saveEntry, etc.
- Never expose Node.js APIs directly to renderer

electron/src/renderer/main.tsx:
- React entry point
- React Router for navigation
- Global state management (Zustand or React Context)

electron/src/renderer/App.tsx:
- Route definitions:
  - /login — Login page
  - /register — Registration page
  - /vault — Vault list (protected)
  - /vault/:id — Entry detail (protected)
  - /admin — Admin dashboard (protected, admin only)
  - /settings — User settings (protected)
- Auth guard component that redirects to /login if not authenticated

Create a basic theme/layout with Tailwind:
- Dark mode by default (password manager aesthetic)
- Sidebar navigation
- Content area
```

---

### Prompt 10 — Core UI Screens

```
Build the core UI screens for the Electron app. Depends on scaffolding from Prompt 9.

electron/src/renderer/pages/Login.tsx:
- Email + master password form
- "Unlock with biometrics" button (shown if biometrics configured)
- 2FA code input (shown after initial auth if 2FA enabled)
- "Register" link
- Error handling with user-friendly messages
- Loading state during auth

electron/src/renderer/pages/Register.tsx:
- Email + master password + confirm password
- Password strength indicator (zxcvbn or custom)
- KDF parameter info ("Your password is processed locally with Argon2id")
- Generate and display recovery key
- Terms acceptance checkbox

electron/src/renderer/pages/Vault.tsx:
- Search bar with real-time filtering
- Folder tree sidebar (collapsible)
- Entry list with icons by type (login 🔑, note 📝, card 💳, identity 👤)
- Sort by: name, date modified, type
- "Add Entry" button → type selection → entry form
- Click entry → navigate to detail view
- Right-click context menu: copy username, copy password, edit, delete

electron/src/renderer/pages/EntryDetail.tsx:
- View mode: show entry fields with copy buttons
- Edit mode: inline editing with save/cancel
- Password field: hidden by default, toggle visibility, copy button
- Password history (track last N passwords for this entry)
- URI list for autofill matching
- Created/modified timestamps

electron/src/renderer/components/PasswordGenerator.tsx:
- Length slider (8-128 characters)
- Character toggles: uppercase, lowercase, digits, symbols
- Passphrase mode: word count, separator, capitalize
- Generated password display with copy button
- Strength indicator bar
- "Use this password" button (fills into entry form)

electron/src/renderer/pages/Settings.tsx:
- Account settings (change master password)
- 2FA setup/management (enable TOTP, view recovery codes)
- Biometric unlock toggle
- Auto-lock timeout (1min, 5min, 15min, 30min, 1hr, never)
- Vault sync settings
- Clear local cache
- Export vault (encrypted backup)
- About/version info
```

---

### Prompt 11 — Biometric Unlock

```
Implement biometric authentication for the Electron app. Depends on Prompts 9-10.

electron/src/main/biometric.ts:
- Detect available biometric methods:
  - Windows: Check Windows Hello availability via WinRT UserConsentVerifier
  - macOS: Check Touch ID availability via LAContext.canEvaluatePolicy
  - Linux: Check for fingerprint reader (best-effort, using polkit)

- enableBiometric(masterKey: Buffer) -> Promise<void>
  - After user successfully logs in with master password:
  - Generate a random biometric key (32 bytes)
  - Encrypt masterKey with biometric key → store encrypted blob in app data
  - Store biometric key in OS keychain using 'keytar' npm package:
    - keytar.setPassword('QuantumPasswordManager', 'biometric_key', biometricKey.toString('hex'))
  - On Windows/macOS, keytar access requires biometric/PIN verification by the OS

- unlockWithBiometric() -> Promise<Buffer> (returns masterKey)
  - Retrieve biometric key from OS keychain (triggers biometric prompt)
  - Decrypt stored master key blob with biometric key
  - Return master key

- disableBiometric() -> Promise<void>
  - Delete keychain entry
  - Delete encrypted master key blob

electron/src/main/index.ts (add IPC handlers):
- ipcMain.handle('biometric:available') -> boolean
- ipcMain.handle('biometric:enable', masterKey) -> void
- ipcMain.handle('biometric:unlock') -> masterKey
- ipcMain.handle('biometric:disable') -> void

electron/src/main/preload.ts (expose to renderer):
- window.api.biometric.isAvailable()
- window.api.biometric.enable(masterKey)
- window.api.biometric.unlock()
- window.api.biometric.disable()

Security requirements:
- Master key is NEVER stored in plain text anywhere
- Biometric key is protected by OS-level biometric verification
- Auto-clear master key from memory after lock timeout
- Log biometric unlock events locally
```

---

### Prompt 12 — Admin Dashboard UI

```
Build the admin dashboard UI. Depends on admin backend (Prompt 7) and UI framework (Prompts 9-10).

electron/src/renderer/pages/Admin.tsx:
- Tab navigation: Members | Vault Access | 2FA Sharing | Policies | Audit Log
- Only visible to users with admin role in an organization

Members tab (electron/src/renderer/components/admin/MembersPanel.tsx):
- List all org members: name, email, role, 2FA status, last active
- "Invite User" button → email input + role selector (admin/member)
- Remove user button with confirmation dialog
- Change role dropdown (admin ↔ member)
- Status indicators: active, pending invite, 2FA not configured (warning)

Vault Access tab (electron/src/renderer/components/admin/VaultAccessPanel.tsx):
- Select user → "Access Vault" button
- WARNING banner: "This action is logged and audited"
- Displays user's decrypted vault entries (via escrow)
- Admin can view, copy, or modify entries
- "Reset User Password" button:
  - New password input (or generate random)
  - Confirmation dialog explaining the impact
  - Shows progress during re-encryption

2FA Sharing tab (electron/src/renderer/components/admin/TwoFactorSharePanel.tsx):
- Select user to share with
- Input or paste TOTP secret/URI
- Set expiration (15min, 1hr, 24hr)
- "Share Securely" button → encrypts and sends
- List of pending/claimed shares with status
- Use case: admin helping employee set up an account that requires 2FA

Policies tab (electron/src/renderer/components/admin/PoliciesPanel.tsx):
- Toggle: Require 2FA for all members
- Minimum password length slider
- Password rotation period (30/60/90/180 days or disabled)
- Save button with confirmation

Audit Log tab (electron/src/renderer/components/admin/AuditLogPanel.tsx):
- Searchable, filterable table of all admin actions
- Columns: timestamp, actor, action, target, details
- Filter by: action type, actor, date range
- Export to CSV
- Color-coded severity: info (blue), warning (orange), critical (red)
```

---

## Phase 3: Browser Extensions

### Prompt 13 — Extension Scaffolding

```
Set up the browser extension in the extension/ directory with a shared codebase targeting Chrome (MV3), Firefox (MV2), and Edge (MV3).

extension/package.json:
- Dependencies: react, react-dom, typescript, webpack, web-ext, @aspect/browser-polyfill
- Scripts: build:chrome, build:firefox, build:edge, dev, test

extension/webpack.config.js:
- Multiple entry points: background, content, popup
- Output directories per browser: dist/chrome/, dist/firefox/, dist/edge/
- TypeScript loader
- Copy plugin for manifests and assets
- Environment variable for target browser

extension/src/manifest.chrome.json (Manifest V3 — also used for Edge):
{
  "manifest_version": 3,
  "name": "Quantum Password Manager",
  "version": "1.0.0",
  "description": "Quantum-safe password autofill",
  "permissions": ["storage", "nativeMessaging", "activeTab", "scripting"],
  "host_permissions": ["https://*/*", "http://*/*"],
  "background": { "service_worker": "background.js" },
  "action": { "default_popup": "popup.html", "default_icon": "icons/icon-48.png" },
  "content_scripts": [{
    "matches": ["https://*/*", "http://*/*"],
    "js": ["content.js"],
    "run_at": "document_idle"
  }],
  "icons": { "16": "icons/icon-16.png", "48": "icons/icon-48.png", "128": "icons/icon-128.png" }
}

extension/src/manifest.firefox.json (Manifest V2):
{
  "manifest_version": 2,
  "name": "Quantum Password Manager",
  "version": "1.0.0",
  "permissions": ["storage", "nativeMessaging", "activeTab", "tabs", "https://*/*", "http://*/*"],
  "background": { "scripts": ["background.js"] },
  "browser_action": { "default_popup": "popup.html", "default_icon": "icons/icon-48.png" },
  "content_scripts": [{
    "matches": ["https://*/*", "http://*/*"],
    "js": ["content.js"],
    "run_at": "document_idle"
  }],
  "browser_specific_settings": {
    "gecko": { "id": "qpm@example.com", "strict_min_version": "55.0" }
  }
}

extension/src/lib/browser-api.ts:
- Unified wrapper for chrome.* / browser.* APIs
- Methods: runtime.sendMessage, runtime.connectNative, storage.get/set, tabs.query
- Use typeof browser !== 'undefined' detection

extension/src/popup/popup.html + Popup.tsx:
- Minimal React popup shell (will be fleshed out in Prompt 16)
- Quick unlock state check
- "Open full app" link

extension/src/background/service-worker.ts:
- Native messaging port connection (placeholder)
- Message routing between popup, content script, and native host
- Badge management (credential count for current tab)
```

---

### Prompt 14 — Native Messaging Host

```
Implement the native messaging host in Go. This is a small Go binary that browser extensions communicate with via stdin/stdout.

cmd/nativehost/main.go:
- Read messages from stdin: 4-byte little-endian uint32 length prefix + JSON payload
- Write responses to stdout: same 4-byte length prefix + JSON payload
- Message types:
  - { "action": "ping" } → { "status": "ok", "version": "1.0.0" }
  - { "action": "getCredentials", "domain": "example.com" } → { "credentials": [...] }
  - { "action": "saveCredential", "domain": "...", "username": "...", "encryptedPassword": "..." } → { "status": "saved" }
  - { "action": "getStatus" } → { "locked": false, "vaultCount": 42 }
  - { "action": "lock" } → { "status": "locked" }

Communication with desktop app:
- The native host connects to the Go sidecar's local HTTP API (localhost:PORT)
- PORT is saved in a lockfile at a known location:
  - Windows: %APPDATA%/QuantumPasswordManager/sidecar.lock
  - macOS: ~/Library/Application Support/QuantumPasswordManager/sidecar.lock
  - Linux: ~/.config/QuantumPasswordManager/sidecar.lock
- If sidecar is not running, return { "error": "Desktop app not running" }

Create installer scripts for native messaging host registration:

scripts/install-native-host.ps1 (Windows):
- Copy native host binary to install directory
- Create native host manifest JSON files for Chrome, Edge, Firefox
- Register in Windows Registry:
  - HKCU\Software\Google\Chrome\NativeMessagingHosts\com.quantum.passwordmanager
  - HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.quantum.passwordmanager
  - HKCU\Software\Mozilla\NativeMessagingHosts\com.quantum.passwordmanager

scripts/install-native-host.sh (macOS/Linux):
- Copy binary to /usr/local/bin/ or ~/.local/bin/
- Create manifest JSON in:
  - Chrome: ~/Library/Application Support/Google/Chrome/NativeMessagingHosts/ (macOS)
  - Chrome: ~/.config/google-chrome/NativeMessagingHosts/ (Linux)
  - Firefox: ~/Library/Application Support/Mozilla/NativeMessagingHosts/ (macOS)
  - Firefox: ~/.mozilla/native-messaging-hosts/ (Linux)

Native host manifest template (com.quantum.passwordmanager.json):
{
  "name": "com.quantum.passwordmanager",
  "description": "Quantum Password Manager Native Host",
  "path": "/path/to/qpm-native-host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://EXTENSION_ID/"]  // or allowed_extensions for Firefox
}
```

---

### Prompt 15 — Login Form Detection & Autofill

```
Implement the content script for detecting login forms and autofilling credentials. Depends on extension scaffolding (Prompt 13) and native messaging (Prompt 14).

extension/src/content/autofill.ts:

Form Detection:
- detectLoginForms() -> FormInfo[]
  - Scan DOM for forms containing password fields
  - Heuristics:
    1. Find all <input type="password"> elements
    2. For each, find the nearest sibling/preceding input that's likely a username:
       - type="text", "email", or "tel"
       - name/id/autocomplete containing: user, email, login, username, account
    3. Check form action URL for login/signin/auth keywords
    4. Check page title/URL for login page indicators
  - Return array of { form, usernameField, passwordField, domain }

- MutationObserver: watch for dynamically added forms (SPAs)
  - Observe document.body with childList + subtree
  - Re-run detection when new forms appear
  - Debounce to avoid excessive re-scanning (300ms)

Autofill:
- autofill(usernameField, passwordField, username, password) -> void
  - Set .value on both fields
  - Dispatch events in order: focus → input → change → blur
  - Use InputEvent with inputType: 'insertText' for React/Angular compatibility
  - Handle Shadow DOM: traverse shadowRoot if fields are in web components

- showAutofillOverlay(field) -> void
  - When user focuses a detected username/password field:
  - Show a small floating dropdown below the field listing matching credentials
  - Click credential → autofill both fields
  - Dismiss on click outside or Escape key
  - Style to match OS native feel (avoid looking phishy)

Save Prompt:
- detectFormSubmission() -> void
  - Listen for form submit events and navigation events
  - If a login form was filled and submitted:
  - Capture username + password
  - Send to background script → show "Save this password?" notification
  - If user confirms → send to native host → save in vault

Communication with background:
- chrome.runtime.sendMessage for one-off requests
- Message types:
  - { type: 'formDetected', domain, fieldCount }
  - { type: 'requestCredentials', domain } → [{ username, password }]
  - { type: 'saveCredential', domain, username, password }
  - { type: 'autofillComplete', domain }

extension/src/background/service-worker.ts (update):
- Handle content script messages
- Relay credential requests to native host
- Update badge with credential count for active tab
- Handle save credential requests → forward to native host
- Tab change listener → update badge for new tab's domain
```

---

### Prompt 16 — Extension Popup UI

```
Build the extension popup UI. Depends on extension scaffolding (Prompt 13) and autofill (Prompt 15).

extension/src/popup/Popup.tsx:
- Three states: locked, unlocked, no-desktop-app

Locked state:
- "Unlock" button → triggers biometric or sends unlock request to desktop app
- Minimal branding, lock icon

No Desktop App state:
- "Desktop app not running" message
- "Download" link to project website
- Brief setup instructions

Unlocked state (main view):
- Current domain header (e.g., "github.com")
- Matching credentials list for current tab's domain:
  - Each item: favicon + username + "Fill" button
  - Click "Fill" → send autofill message to content script
  - Right-click → copy username / copy password
- "No saved logins" message if none found
- Divider
- Search bar: search all vault entries by name/username/URI
  - Results appear in list
  - Click → copy password (can't autofill on different domain)

Bottom toolbar:
- "Generate Password" button → inline password generator
  - Length slider, checkboxes (uppercase, lowercase, digits, symbols)
  - Copy button
- "Open App" button → launches/focuses desktop Electron app
- Lock icon → lock vault immediately

extension/src/popup/components/CredentialItem.tsx:
- Favicon (fetched from domain)
- Username (truncated if long)
- "Fill" button (primary action)
- "Copy" dropdown: copy username, copy password, copy TOTP code (if available)

extension/src/popup/popup.html:
- Minimal HTML: <div id="root"></div>
- Link to compiled popup.js and popup.css
- Fixed dimensions: width 350px, min-height 400px, max-height 600px

Styling:
- Match desktop app dark theme
- Smooth transitions between states
- Loading spinners for async operations
- Keyboard navigation support (tab through items, enter to fill)
```

---

## Phase 4: Hardening & Distribution

### Prompt 17 — Security Hardening

```
Apply security hardening across the entire codebase.

Go Backend:
- internal/crypto/vault.go: Add ZeroBytes() calls after every decrypt operation in defer statements
- internal/api/middleware.go:
  - Rate limiter: token bucket per IP (configurable: 100 req/min general, 5 req/min for auth)
  - CORS: configurable allowed origins, no wildcard in production
  - CSRF: Double-submit cookie pattern for browser clients
  - Security headers: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security
  - Request size limit: 1MB max body
  - Request timeout: 30 seconds
- cmd/server/main.go:
  - TLS 1.3 mandatory (Go 1.23+ enables X25519Kyber768 hybrid PQ by default)
  - Load TLS cert/key from config
  - Disable HTTP/2 push
- internal/db/: Verify ALL queries use parameterized statements (pgx handles this by default)
- Add gosec to CI/CD pipeline
- Panic recovery middleware with generic error response (don't leak stack traces)

Electron:
- electron/src/main/index.ts:
  - Content Security Policy header on all responses
  - Disable remote module, disable devtools in production
  - Certificate pinning for API server (custom session.setCertificateVerifyProc)
  - Auto-lock: clear master key from memory after inactivity timeout
  - Disable navigation to external URLs
- electron/src/main/preload.ts:
  - Validate all IPC message shapes before processing
  - Never expose fs, child_process, or other Node APIs

Browser Extension:
- extension/src/content/autofill.ts:
  - Sanitize all data before injecting into DOM
  - Never use innerHTML with user data
  - Validate domain matching strictly (prevent subdomain spoofing)
  - Clear credentials from memory after autofill completes
- extension/src/background/service-worker.ts:
  - Validate all native messaging responses
  - Timeout native host connections (5 seconds)
  - Don't log sensitive data

Add security documentation in SECURITY.md:
- Threat model overview
- Cryptographic design rationale
- Responsible disclosure policy
- Security contact email
```

---

### Prompt 18 — Docker, Installers & Distribution

```
Set up packaging and distribution for all components.

docker-compose.yml (self-hosted deployment):
- services:
  - server: Go API server image
    - Environment: DATABASE_URL, JWT_SECRET, PORT, TLS_CERT, TLS_KEY
    - Ports: 443:8443
    - Volumes: certs, config
    - Healthcheck: GET /health
    - Resource limits: 512MB RAM, 1 CPU
  - postgres: PostgreSQL 16 with data volume
    - Environment: POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
    - Volume: pgdata
    - Healthcheck: pg_isready
  - Networks: internal (server ↔ postgres)

Dockerfile (multi-stage Go build):
- Stage 1: golang:1.23-alpine, build server + nativehost binaries
- Stage 2: alpine:3.19, copy binaries + migrations, create non-root user
- ENTRYPOINT: ./server
- EXPOSE 8443

Makefile:
- build-server: go build -o bin/server cmd/server/main.go
- build-nativehost: go build -o bin/qpm-native-host cmd/nativehost/main.go
- build-electron: cd electron && npm run build
- build-extension-chrome: cd extension && npm run build:chrome
- build-extension-firefox: cd extension && npm run build:firefox
- build-extension-edge: cd extension && npm run build:edge
- build-all: all of the above
- test: go test ./... && cd electron && npm test && cd ../extension && npm test
- docker: docker-compose build
- migrate: go run cmd/migrate/main.go
- lint: golangci-lint run && cd electron && npm run lint && cd ../extension && npm run lint
- clean: rm -rf bin/ electron/dist/ extension/dist/

electron/electron-builder.yml:
- appId: com.quantum.passwordmanager
- productName: Quantum Password Manager
- Windows: nsis installer, include nativehost binary, run install-native-host.ps1 post-install
- macOS: dmg + notarization config, include nativehost binary
- Linux: AppImage + deb, include nativehost binary
- extraResources: Go sidecar binary (platform-specific)
- afterPack script: register native messaging host

Browser extension packaging:
- Chrome: zip dist/chrome/ for Chrome Web Store upload
- Firefox: web-ext sign for AMO
- Edge: zip dist/edge/ for Edge Add-ons

README.md:
- Project overview and features
- Self-hosted deployment guide (docker-compose up)
- Desktop app installation
- Browser extension installation
- Development setup guide
- Architecture diagram
```

---

### Prompt 19 — Testing Suite

```
Create a comprehensive test suite across all components.

Go Backend Tests:

internal/crypto/crypto_test.go:
- TestDeriveKeys_Deterministic: same password+salt → same output
- TestDeriveKeys_DifferentOutputs: masterKey != authHash
- TestDeriveKeys_DifferentSalts: different salt → different output
- TestEncryptDecrypt_RoundTrip: encrypt → decrypt → verify plaintext
- TestDecrypt_WrongKey: wrong key → error
- TestDecrypt_TamperedCiphertext: modified ciphertext → error
- TestXWing_KeyExchange: encapsulate → decapsulate → matching shared secrets
- TestEscrow_RoundTrip: encrypt escrow → decrypt → verify master key
- TestMLDSA_SignVerify: sign → verify succeeds
- TestMLDSA_WrongKey: verify with wrong key → fails
- TestZeroBytes: verify buffer is zeroed
- BenchmarkDeriveKeys: measure Argon2id performance
- BenchmarkEncrypt: measure AES-256-GCM throughput

internal/api/auth_handler_test.go:
- TestRegister_Success
- TestRegister_DuplicateEmail
- TestLogin_Success
- TestLogin_WrongPassword
- TestLogin_With2FA
- TestLogin_RateLimit (6th attempt within 1 minute → 429)
- TestRefreshToken_Valid
- TestRefreshToken_Expired

internal/api/vault_handler_test.go:
- TestCreateEntry_Success
- TestGetEntry_Success
- TestGetEntry_WrongUser (401/403)
- TestUpdateEntry_VersionConflict
- TestDeleteEntry_Success
- TestListEntries_WithFilters

internal/admin/service_test.go:
- TestCreateOrg_Success
- TestAccessVault_AsAdmin
- TestAccessVault_AsNonAdmin (403)
- TestChangeUserPassword_AsAdmin
- TestAuditLog_RecordsAccess

Use testcontainers-go for PostgreSQL integration tests.
Use httptest for API handler tests.

Electron Tests:

electron/tests/crypto.test.ts:
- Test IPC crypto operations via mocked sidecar

electron/tests/e2e/login.spec.ts (Playwright):
- Open app → enter credentials → verify vault loads
- Biometric unlock flow (mocked)
- 2FA flow

Browser Extension Tests:

extension/tests/autofill.test.ts:
- Mock DOM with login form → verify detection
- Mock DOM with SPA-rendered form → verify MutationObserver detection
- Autofill → verify field values and events dispatched
- Non-login form → verify no false positive

extension/tests/native-messaging.test.ts:
- Mock native host → verify message encoding (4-byte prefix)
- Verify credential request/response flow
- Verify timeout handling

CI Configuration (.github/workflows/ci.yml):
- Go: lint (golangci-lint), test (with testcontainers), build, gosec
- Electron: npm ci, lint, test, build (Linux only in CI)
- Extension: npm ci, lint, test, build for all targets
- All jobs run on push to main and PRs
```

---

## Future Phases (Reference)

### Prompt 20 — Mobile App (Phase 5, Future)

```
[FUTURE — Not part of initial build]

Build a mobile app using React Native or Flutter that shares the Go crypto library via gomobile.

Key considerations:
- Use gomobile to compile internal/crypto/ as a mobile library (.aar for Android, .framework for iOS)
- React Native wrapper around Go crypto functions
- Biometric: Android BiometricPrompt API, iOS LAContext (built-in to React Native)
- Autofill:
  - Android: Autofill Framework (AutofillService)
  - iOS: AutoFill Credential Provider Extension
- Sync: same API endpoints as desktop
- Push notification 2FA (replaces SMS)
```

### Prompt 21 — Safari Extension (Phase 5, Future)

```
[FUTURE — Not part of initial build]

Safari doesn't support native messaging. Requires a macOS App Extension approach:
- Swift-based Safari App Extension (SFSafariAppExtensionHandler)
- Shared data with desktop app via App Groups container
- UserDefaults(suiteName: "group.com.quantum.passwordmanager")
- Submit to Mac App Store alongside desktop app
```
