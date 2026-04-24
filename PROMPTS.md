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

### Prompt 18b — Standalone Build (SQLite, No Docker)

```
Add a standalone mode so LGI Pass can run as a single process with no external database or Docker dependency.
Uses modernc.org/sqlite (pure Go, no CGO) as an embedded database alternative to PostgreSQL.

Architecture:
- Standalone mode: Electron → Go sidecar (embedded SQLite) — no PostgreSQL needed
- Server mode: Go server → PostgreSQL — existing multi-user/org deployment (unchanged)
- The mode is selected via STORAGE_BACKEND env var ("sqlite" or "postgres", default "postgres")

1. Add SQLite dependency:
   - go get modernc.org/sqlite
   - go get github.com/jmoiron/sqlx (optional, for consistent query interface)

2. Create internal/db/sqlite.go:
   - NewSQLiteDB(dbPath string) → opens/creates SQLite file at dbPath
   - Default path: %APPDATA%/QuantumPasswordManager/vault.db (Windows),
     ~/Library/Application Support/QuantumPasswordManager/vault.db (macOS),
     ~/.config/QuantumPasswordManager/vault.db (Linux)
   - Run migrations on startup (embed the SQL via Go embed)
   - Enable WAL mode: PRAGMA journal_mode=WAL
   - Enable foreign keys: PRAGMA foreign_keys=ON
   - Set busy timeout: PRAGMA busy_timeout=5000
   - File permissions: 0600 (owner read/write only)

3. Create migrations/sqlite/001_initial.sql:
   - Same schema as PostgreSQL but with SQLite syntax:
     - UUID columns → TEXT with CHECK(length(id) = 36)
     - BYTEA → BLOB
     - TIMESTAMPTZ → TEXT (ISO 8601 format)
     - SERIAL → INTEGER PRIMARY KEY AUTOINCREMENT
     - JSONB → TEXT (store JSON as text, parse in Go)
     - gen_random_uuid() → generate UUIDs in Go before insert
     - No CREATE EXTENSION statements
   - Include all tables: users, organizations, org_members, folders, vault_entries,
     totp_secrets, shared_2fa, recovery_codes, sessions, audit_log, sync_cursors, invitations

4. Create internal/db/repository_interface.go:
   - Define Go interfaces for every repository:
     - UserRepo interface { CreateUser, GetUserByEmail, GetUserByID, UpdateUser, ... }
     - VaultRepo interface { CreateEntry, GetEntry, ListEntries, UpdateEntry, DeleteEntry, ... }
     - OrgRepo interface { CreateOrg, GetOrg, AddMember, GetMembers, GetEscrow, ... }
     - AuditRepo interface { LogAction, GetAuditLog, ... }
     - SyncRepo interface { GetCursor, UpdateCursor, GetChangedEntries, ... }
     - TOTPRepo interface { SaveSecret, GetSecret, ShareSecret, ClaimShared, ... }
     - SessionRepo interface { CreateSession, GetSession, DeleteSession, ... }
   - Both PostgreSQL and SQLite implementations satisfy these interfaces

5. Refactor internal/db/postgres.go:
   - Rename concrete repo structs to include "Pg" prefix (PgUserRepo, PgVaultRepo, etc.)
   - Ensure they implement the new interfaces
   - No changes to SQL queries — PostgreSQL code stays as-is

6. Create internal/db/sqlite_repos.go:
   - SQLite implementations of all repository interfaces
   - Adapt queries for SQLite syntax differences:
     - $1, $2 → ?1, ?2 (or just ?)
     - NOW() → datetime('now')
     - RETURNING → use LastInsertId() or separate SELECT
     - ILIKE → LIKE (SQLite LIKE is case-insensitive for ASCII)
     - INTERVAL → datetime('now', '-5 minutes')
   - Generate UUIDs in Go (crypto/rand) before insert

7. Update internal/config/config.go:
   - Add StorageBackend field: "sqlite" | "postgres" (env: STORAGE_BACKEND, default: "postgres")
   - Add SQLiteDBPath field (env: SQLITE_DB_PATH, default: platform-specific app data dir)
   - When StorageBackend == "sqlite", DATABASE_URL is not required

8. Update cmd/server/main.go:
   - Check config.StorageBackend
   - If "sqlite": call NewSQLiteDB(config.SQLiteDBPath), run SQLite migrations
   - If "postgres": existing PostgreSQL setup (unchanged)
   - Pass repository interfaces (not concrete types) to services and handlers

9. Update electron/src/main/index.ts (sidecar spawning):
   - When spawning the Go sidecar, set STORAGE_BACKEND=sqlite in the child process env
   - Set SQLITE_DB_PATH to the app data directory
   - No need to check for or start PostgreSQL
   - The sidecar binary is fully self-contained

10. Standalone installer (electron-builder):
    - The packaged app includes: Electron shell + Go sidecar binary + native host binary
    - No Docker, no PostgreSQL, no external dependencies
    - First launch: Go sidecar creates vault.db, runs migrations, starts serving
    - User registers → vault created locally → everything works offline

11. SQLite → PostgreSQL migration (org mode activation):
    - When user is on SQLite (standalone) and activates org mode from Settings:
      a. App shows "Organization features require a PostgreSQL database" dialog
      b. Dialog has two options:
         - "Use Docker" → shows docker run command to start PostgreSQL container:
           docker run -d --name lgipass-db -e POSTGRES_DB=password_manager
             -e POSTGRES_USER=pmuser -e POSTGRES_PASSWORD=<generated>
             -p 5432:5432 postgres:16-alpine
         - "Connect existing" → form fields: host, port, database, username, password
      c. App tests the PostgreSQL connection before proceeding
      d. Migration wizard:
         - Reads all data from SQLite (users, vault_entries, folders, sessions, etc.)
         - Runs PostgreSQL migrations (001_initial.sql, 002_admin.sql, 003_sync.sql)
         - Inserts all SQLite data into PostgreSQL tables
         - Verifies row counts match
         - Shows migration summary with entry count
      e. On success:
         - Writes DATABASE_URL to app config file (%APPDATA%/QuantumPasswordManager/config.json)
         - Updates STORAGE_BACKEND to "postgres" in config
         - Restarts the sidecar with new config
         - SQLite file is kept as backup (renamed vault.db.bak)
         - Org features (admin panel, invite, escrow) are now available
      f. On failure: rollback, keep using SQLite, show error

    - Create internal/db/migrate_sqlite_to_pg.go:
      - MigrateSQLiteToPg(sqliteDB, pgDB) → reads all tables from SQLite, bulk inserts into PG
      - Runs inside a PostgreSQL transaction — atomic (all or nothing)
      - Handles type conversions: TEXT timestamps → TIMESTAMPTZ, TEXT UUIDs → UUID, BLOB → BYTEA

    - Create electron/src/renderer/components/OrgSetupWizard.tsx:
      - Step 1: "Organization features require PostgreSQL" explanation
      - Step 2: Docker auto-setup or manual connection form
      - Step 3: Connection test (green checkmark / red error)
      - Step 4: Data migration progress bar
      - Step 5: Success — "You can now create or join an organization"

    - Add IPC handler in electron/src/main/index.ts:
      - 'test-pg-connection' → sidecar tests the DATABASE_URL
      - 'migrate-to-postgres' → triggers MigrateSQLiteToPg + sidecar restart
      - 'get-storage-backend' → returns current backend ("sqlite" or "postgres")

    - Update Settings page (electron/src/renderer/pages/Settings.tsx):
      - Show current storage mode: "Local (SQLite)" or "Server (PostgreSQL)"
      - If SQLite: show "Enable Organization Features" button → opens OrgSetupWizard
      - If PostgreSQL: show connection info (host:port/dbname), "Create Organization" button

12. Org features gating:
    - When STORAGE_BACKEND=sqlite, admin API routes return 501 Not Implemented
      with message: "Organization features require PostgreSQL. Go to Settings to upgrade."
    - The Admin nav link in the sidebar is hidden when on SQLite
    - The "Create Organization" option in Settings only appears after migration to PostgreSQL
    - All personal vault features work identically on both backends

13. Backup & portability:
    - SQLite mode: vault.db is the entire database — user can copy/backup the file
    - PostgreSQL mode: standard pg_dump for backup
    - Future: Add export-to-SQLite for users who want to go back to standalone
    - The .db file itself is NOT encrypted at rest (entries inside are AES-256-GCM encrypted)
    - For full-file encryption, optionally integrate SQLCipher in the future

14. Concurrent access:
    - SQLite WAL mode handles Electron + native host reading simultaneously
    - Single-writer limitation is fine for single-user standalone mode

15. Build targets (update Makefile):
    - build-standalone: go build -tags sqlite -o bin/server-standalone cmd/server/main.go
    - The sqlite build tag can optionally gate the SQLite code so the server-mode binary stays lean
    - build-all now includes build-standalone

Environment variables summary for standalone:
  STORAGE_BACKEND=sqlite
  SQLITE_DB_PATH=/path/to/vault.db  (optional, has platform defaults)
  PORT=0                              (random port in sidecar mode)
  SIDECAR_MODE=1
  TLS_CERT / TLS_KEY                  (optional for local-only)
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

### Prompt 22 — Passkeys, FIDO2/WebAuthn & Hardware Security Keys

```
Add passkey management, FIDO2/WebAuthn credential storage, and hardware security key support.
This makes LGI Pass a full passkey provider — users can create, store, and authenticate with
passkeys on supported websites, and use hardware keys (YubiKey, Titan, SoloKeys) for vault login.

Depends on: Prompt 3 (crypto), Prompt 4 (auth), Prompt 6 (vault), Prompt 13-16 (extension).

--- Part A: Passkey Storage & Vault Integration ---

1. Database schema — add migration migrations/004_passkeys.sql:

   Passkey Credentials:
   - id UUID PRIMARY KEY DEFAULT gen_random_uuid()
   - user_id UUID REFERENCES users(id) ON DELETE CASCADE
   - credential_id BYTEA NOT NULL UNIQUE        -- WebAuthn credential ID (from authenticator)
   - rp_id TEXT NOT NULL                         -- Relying party ID (e.g. "github.com")
   - rp_name TEXT                                -- Human-readable RP name
   - user_handle BYTEA NOT NULL                  -- RP's user handle (user.id in WebAuthn)
   - username TEXT                               -- Username at the RP
   - display_name TEXT                           -- Display name at the RP
   - public_key_cbor BYTEA NOT NULL              -- COSE public key (unencrypted — not secret)
   - encrypted_private_key BYTEA NOT NULL        -- Private key encrypted with user's master key
   - private_key_nonce BYTEA NOT NULL            -- AES-256-GCM nonce for private key
   - sign_count INT NOT NULL DEFAULT 0           -- Signature counter for clone detection
   - aaguid BYTEA                                -- Authenticator attestation GUID
   - transports TEXT[]                           -- ["internal", "usb", "ble", "nfc"]
   - discoverable BOOLEAN NOT NULL DEFAULT true  -- Resident/discoverable credential
   - backed_up BOOLEAN NOT NULL DEFAULT false    -- BS flag from authenticator data
   - algorithm INT NOT NULL DEFAULT -7           -- COSE algorithm (ES256=-7, RS256=-257, EdDSA=-8)
   - created_at TIMESTAMPTZ DEFAULT now()
   - last_used_at TIMESTAMPTZ
   - INDEX ON (rp_id, user_id)
   - INDEX ON (credential_id)

   Hardware Auth Keys (for vault login, not passkeys for websites):
   - id UUID PRIMARY KEY DEFAULT gen_random_uuid()
   - user_id UUID REFERENCES users(id) ON DELETE CASCADE
   - credential_id BYTEA NOT NULL UNIQUE
   - public_key_cbor BYTEA NOT NULL
   - sign_count INT NOT NULL DEFAULT 0
   - aaguid BYTEA
   - transports TEXT[]
   - name TEXT NOT NULL                          -- User-assigned name ("My YubiKey 5")
   - created_at TIMESTAMPTZ DEFAULT now()
   - last_used_at TIMESTAMPTZ

2. internal/db/passkey_repo.go:
   - PasskeyRepo interface:
     - CreatePasskey(ctx, passkey PasskeyCredential) -> (PasskeyCredential, error)
     - GetPasskeysByRPID(ctx, userID, rpID) -> ([]PasskeyCredential, error)
     - GetPasskeyByCredentialID(ctx, credentialID []byte) -> (PasskeyCredential, error)
     - GetAllPasskeys(ctx, userID) -> ([]PasskeyCredential, error)
     - UpdateSignCount(ctx, credentialID []byte, newCount int) -> error
     - DeletePasskey(ctx, userID, passkeyID uuid.UUID) -> error
   - HardwareKeyRepo interface:
     - RegisterHardwareKey(ctx, key HardwareAuthKey) -> (HardwareAuthKey, error)
     - GetHardwareKeys(ctx, userID) -> ([]HardwareAuthKey, error)
     - GetHardwareKeyByCredentialID(ctx, credentialID []byte) -> (HardwareAuthKey, error)
     - UpdateHardwareKeySignCount(ctx, credentialID []byte, count int) -> error
     - DeleteHardwareKey(ctx, userID, keyID uuid.UUID) -> error

3. internal/auth/webauthn.go — WebAuthn server-side logic:

   Dependencies: github.com/go-webauthn/webauthn/webauthn

   WebAuthnService struct with config (RPDisplayName, RPID, RPOrigins):
   - BeginRegistration(ctx, userID, rpID, rpName, userName, displayName) -> (options *protocol.CredentialCreation, sessionData []byte, error)
     - Generate challenge (32 random bytes)
     - Set pubKeyCredParams: ES256 (-7), RS256 (-257), EdDSA (-8)
     - Set authenticatorSelection:
       - residentKey: "preferred"
       - userVerification: "preferred"
       - authenticatorAttachment: "platform" for passkeys, "cross-platform" for hardware keys
     - Exclude existing credentials for this user+RP (prevent duplicates)
     - Store session data (challenge, user info) temporarily (5 min TTL)
     - Return PublicKeyCredentialCreationOptions JSON

   - FinishRegistration(ctx, userID, sessionData []byte, attestationResponse) -> (PasskeyCredential, error)
     - Verify challenge matches session
     - Parse attestation object (CBOR):
       - Extract authData: rpIdHash, flags (UP, UV, AT, ED, BS, BE), signCount, aaguid, credentialId, publicKey
       - Verify rpIdHash matches SHA-256(rpID)
       - Verify UP (user present) flag is set
       - Parse attestation statement (fmt: "none", "packed", "fido-u2f", "tpm", "android-key")
       - For "packed": verify self-attestation signature over authData+clientDataHash
     - Extract COSE public key from credential data
     - Generate private key locally (software authenticator) or receive from hardware
     - Encrypt private key with user's master key (AES-256-GCM)
     - Store credential in passkey_credentials table
     - Return the credential

   - BeginAuthentication(ctx, rpID, allowedCredentialIDs [][]byte) -> (options *protocol.CredentialAssertion, sessionData []byte, error)
     - Generate challenge
     - Build allowCredentials list from stored credentials
     - Set userVerification: "preferred"
     - Store session data (5 min TTL)
     - Return PublicKeyCredentialRequestOptions JSON

   - FinishAuthentication(ctx, sessionData []byte, assertionResponse) -> (credentialID []byte, error)
     - Verify challenge
     - Look up credential by ID
     - Verify signature over authenticatorData + clientDataHash using stored public key
     - Verify rpIdHash
     - Verify UP flag
     - Check signCount > stored signCount (clone detection)
     - Update signCount and last_used_at
     - Return matched credential ID

   Hardware key registration/authentication for vault login:
   - BeginHardwareKeyRegistration(ctx, userID) -> (options, sessionData, error)
     - Same as above but authenticatorAttachment: "cross-platform"
     - RPDisplayName: "LGI Pass", RPID: configured domain
   - FinishHardwareKeyRegistration(ctx, userID, sessionData, response, keyName) -> (HardwareAuthKey, error)
   - BeginHardwareKeyLogin(ctx, userID) -> (options, sessionData, error)
   - FinishHardwareKeyLogin(ctx, userID, sessionData, response) -> error
     - On success, treat as valid 2FA factor (replaces TOTP step)

4. internal/api/passkey_handler.go — REST endpoints:

   Passkey management (for website passkeys stored in vault):
   - GET    /api/v1/vault/passkeys                — list all stored passkeys
   - GET    /api/v1/vault/passkeys?rp_id=X        — list passkeys for a relying party
   - DELETE /api/v1/vault/passkeys/:id             — delete a passkey
   - POST   /api/v1/vault/passkeys/register/begin  — start passkey creation (returns options)
   - POST   /api/v1/vault/passkeys/register/finish — complete passkey creation (stores credential)
   - POST   /api/v1/vault/passkeys/authenticate/begin  — start passkey auth (returns options)
   - POST   /api/v1/vault/passkeys/authenticate/finish — complete passkey auth (returns assertion)

   Hardware key management (for vault login):
   - GET    /api/v1/auth/hardware-keys             — list registered hardware keys
   - POST   /api/v1/auth/hardware-keys/register/begin   — start hardware key registration
   - POST   /api/v1/auth/hardware-keys/register/finish   — finish registration
   - DELETE /api/v1/auth/hardware-keys/:id          — remove a hardware key
   - POST   /api/v1/auth/hardware-keys/authenticate/begin  — start hardware key login
   - POST   /api/v1/auth/hardware-keys/authenticate/finish — finish hardware key login (2FA)

   All endpoints require authentication except hardware key authenticate (which IS authentication).

5. Update internal/auth/service.go — Login flow with hardware key option:
   - After password verification, if user has hardware keys registered:
     - Return partial token with flag: requires_2fa, methods: ["totp", "hardware_key"]
     - Client can choose TOTP code OR hardware key assertion
   - ValidateHardwareKey2FA(ctx, userID, assertionResponse) -> (TokenResponse, error)
   - Hardware key counts as a second factor alongside TOTP

--- Part B: Browser Extension — Passkey Provider ---

6. extension/src/content/passkey-provider.ts — WebAuthn API interception:

   The extension acts as a virtual authenticator / passkey provider by intercepting
   the WebAuthn API on web pages.

   - Override navigator.credentials.create() and navigator.credentials.get():
     - Inject script via content script (page context, not isolated world)
     - Wrap the original functions, intercept PublicKeyCredential requests
     - Forward to background script → native host → Go sidecar for key operations

   navigator.credentials.create() interception:
   - Detect PublicKeyCredentialCreationOptions in the options argument
   - Extract: rp.id, rp.name, user.id, user.name, user.displayName, challenge,
     pubKeyCredParams, excludeCredentials, authenticatorSelection, timeout
   - Show UI prompt: "LGI Pass — Save a passkey for [rp.name]?" with user info
   - If user approves:
     a. Send to native host: { action: "passkeyCreate", rpId, rpName, userId, userName, ... }
     b. Go sidecar generates key pair (ES256 P-256 by default):
        - crypto/ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        - For EdDSA: ed25519.GenerateKey(rand.Reader)
        - For RS256: rsa.GenerateKey(rand.Reader, 2048)
     c. Build authenticatorData:
        - rpIdHash (SHA-256 of rp.id)
        - flags: UP=1, UV=1, AT=1, BE=1, BS=1 (software authenticator, backed up)
        - signCount: 0
        - attestedCredentialData: aaguid + credentialIdLength + credentialId + publicKeyCOSE
     d. Build attestation object (CBOR): { fmt: "none", attStmt: {}, authData }
     e. Build clientDataJSON: { type: "webauthn.create", challenge, origin, crossOrigin: false }
     f. Encrypt private key with master key, store in vault
     g. Return PublicKeyCredential to the page:
        - id: base64url(credentialId)
        - rawId: credentialId
        - response: { attestationObject, clientDataJSON }
        - type: "public-key"
        - authenticatorAttachment: "platform"
   - If user declines: fall through to browser's native WebAuthn handler

   navigator.credentials.get() interception:
   - Detect PublicKeyCredentialRequestOptions
   - Extract: rpId, challenge, allowCredentials, userVerification, timeout
   - Query native host for matching credentials: { action: "passkeyGet", rpId, allowCredentials }
   - If discoverable credential request (empty allowCredentials):
     - Query all credentials for this rpId
     - Show account picker: "Choose a passkey for [rpId]" with list of usernames
   - If credentials found:
     a. User selects credential (or auto-select if only one)
     b. Send to native host: { action: "passkeySign", credentialId, challenge, rpId, origin }
     c. Go sidecar:
        - Decrypt private key with master key
        - Build authenticatorData: rpIdHash + flags (UP=1, UV=1) + signCount
        - Build clientDataJSON: { type: "webauthn.get", challenge, origin }
        - Sign authenticatorData + SHA-256(clientDataJSON) with private key
        - Increment signCount
        - ZeroBytes private key after signing
     d. Return PublicKeyCredential:
        - id: base64url(credentialId)
        - rawId: credentialId
        - response: { authenticatorData, clientDataJSON, signature, userHandle }
        - type: "public-key"
   - If no credentials found: fall through to browser's native handler

   Conditional mediation (autofill-assisted passkeys):
   - Detect <input autocomplete="webauthn"> on the page
   - If found, silently query for discoverable credentials for this rpId
   - Show passkey option in autofill overlay alongside password credentials
   - User clicks passkey → trigger navigator.credentials.get() with selected credential

7. extension/src/background/service-worker.ts — add passkey message handlers:
   - Handle messages from content script:
     - { type: 'passkeyCreate', ... } → forward to native host
     - { type: 'passkeyGet', rpId, allowCredentials } → query credentials
     - { type: 'passkeySign', credentialId, clientDataHash } → sign assertion
     - { type: 'passkeyList', rpId } → list available passkeys for account picker
   - Badge: show passkey icon/indicator when passkeys available for current site

8. cmd/nativehost/main.go — add passkey actions:
   - { action: "passkeyCreate", ... } → generate keypair, encrypt, store, return attestation
   - { action: "passkeyGet", rpId, allowCredentials } → query matching credentials
   - { action: "passkeySign", credentialId, ... } → decrypt key, sign, return assertion
   - { action: "passkeyList", rpId } → return discoverable credentials for rpId
   - { action: "passkeyDelete", credentialId } → delete a passkey

--- Part C: Electron Desktop — Passkey & Hardware Key Management UI ---

9. electron/src/renderer/pages/Settings.tsx — add sections:

   Passkeys section:
   - List all stored passkeys grouped by relying party
   - Each entry shows: site name, username, created date, last used
   - Delete button per passkey (with confirmation)
   - Passkey count badge
   - Search/filter by site name

   Hardware Security Keys section:
   - List registered hardware keys: name, type (from aaguid lookup), registered date, last used
   - "Register New Key" button:
     - Opens dialog: "Insert your security key and press the button"
     - Triggers WebAuthn registration via Electron's built-in support
     - User names the key after registration
   - Delete button per key (with confirmation)
   - Toggle: "Require hardware key for login" (makes it mandatory, not just optional 2FA)

10. electron/src/renderer/components/PasskeyList.tsx:
   - Grouped list component showing passkeys by relying party
   - Site favicon from rp_id domain
   - Expandable group showing all credentials for that RP
   - Copy user handle, view public key details (algorithm, creation date)
   - Bulk delete for a relying party

11. Update login flow (electron/src/renderer/pages/Login.tsx):
   - After password entry, if 2FA required and hardware key is registered:
     - Show option: "Use security key" alongside TOTP input
     - "Use security key" → triggers navigator.credentials.get() or
       Electron IPC to sidecar → begins WebAuthn ceremony
     - Insert key + touch → completes 2FA
   - If user has ONLY hardware key (no TOTP): go straight to key prompt

--- Part D: COSE & CBOR Utilities ---

12. internal/crypto/cose.go — COSE key encoding/decoding:
   Dependencies: github.com/fxamacker/cbor/v2

   - MarshalCOSEKey(algorithm int, publicKey crypto.PublicKey) -> ([]byte, error)
     - ES256 (alg -7): kty=2, crv=1 (P-256), x, y coordinates
     - RS256 (alg -257): kty=3, n, e (modulus, exponent)
     - EdDSA (alg -8): kty=1, crv=6 (Ed25519), x
   - UnmarshalCOSEKey(coseKey []byte) -> (crypto.PublicKey, int algorithm, error)
   - MarshalAuthenticatorData(rpIdHash [32]byte, flags byte, signCount uint32, attestedCred []byte) -> []byte
   - ParseAuthenticatorData(data []byte) -> (rpIdHash, flags, signCount, attestedCred, extensions, error)
   - MarshalAttestationObject(fmt string, authData, attStmt []byte) -> ([]byte, error)

13. internal/crypto/passkey.go — passkey crypto operations:
   - GeneratePasskeyPair(algorithm int) -> (publicKey, privateKey []byte, credentialID []byte, error)
     - algorithm: -7 (ES256), -257 (RS256), -8 (EdDSA)
     - credentialID: 32 random bytes
     - Returns COSE-encoded public key, raw private key bytes
   - SignAssertion(privateKey []byte, algorithm int, authData, clientDataHash []byte) -> ([]byte, error)
     - ES256: ECDSA-SHA256, DER-encoded signature
     - RS256: RSASSA-PKCS1-v1_5-SHA256
     - EdDSA: Ed25519 signature
   - VerifyAssertion(publicKeyCOSE []byte, authData, clientDataHash, signature []byte) -> (bool, error)
   - EncryptPasskeyPrivateKey(privateKey []byte, masterKey [32]byte) -> (encrypted, nonce []byte, error)
   - DecryptPasskeyPrivateKey(encrypted, nonce []byte, masterKey [32]byte) -> ([]byte, error)

--- Part E: Security Considerations ---

14. Security requirements:
   - Private keys are NEVER sent to the server unencrypted — always encrypted with master key
   - Private keys are zeroed from memory immediately after signing (defer ZeroBytes)
   - Sign count is verified server-side to detect cloned authenticators
   - Challenge has 5-minute TTL, single-use (delete from session store after verification)
   - Origin validation: verify origin in clientDataJSON matches expected RP origin
   - rpIdHash verification: always verify rpIdHash in authenticatorData matches SHA-256(rpId)
   - User presence (UP) and user verification (UV) flags must be checked
   - Attestation: accept "none" format (privacy-preserving), optionally verify "packed"
   - Hardware key PIN/biometric is handled by the authenticator device itself
   - The extension MUST show a clear UI prompt before creating or using a passkey
     (prevent silent credential creation by malicious sites)
   - Content script injection for WebAuthn override must use page context (main world),
     not isolated content script world, to properly intercept navigator.credentials
   - On Chromium MV3: use chrome.scripting.registerContentScripts with world: "MAIN"
   - On Firefox MV2: use page script injection via script element with src=runtime.getURL()

15. AAGUID for LGI Pass software authenticator:
   - Generate a fixed AAGUID for LGI Pass: use a deterministic UUID v5 from
     namespace DNS + "lgipass.lancastergroup.com"
   - This identifies credentials created by LGI Pass vs other authenticators
   - Register with the FIDO Metadata Service (future)

16. Tests — internal/crypto/passkey_test.go:
   - TestGeneratePasskeyPair_ES256: generate → verify key format
   - TestGeneratePasskeyPair_EdDSA: generate → verify key format
   - TestSignVerifyAssertion_ES256: sign → verify round-trip
   - TestSignVerifyAssertion_EdDSA: sign → verify round-trip
   - TestEncryptDecryptPasskeyPrivateKey: encrypt → decrypt round-trip
   - TestCOSEKeyMarshalUnmarshal: marshal → unmarshal round-trip
   - TestAuthenticatorData: marshal → parse → verify fields
   - TestSignCount_CloneDetection: verify signCount enforcement
   - TestChallenge_Expiry: verify expired challenge is rejected
   - TestChallenge_Replay: verify used challenge cannot be reused
```

---

## Phase 6: Vault UX Essentials

### Prompt 23 — Favorites, Archive & Trash

```
Add favorites, archive, and trash to the vault. These are table-stakes features that
Bitwarden and 1Password both have. The goal is zero-knowledge — the server stores flags
but never decrypts entries.

Depends on: Prompt 6 (vault CRUD), Prompt 18b (SQLite).

--- Part A: Database Changes ---

1. Create migration migrations/007_vault_ux.sql (PostgreSQL):
   ALTER TABLE vault_entries ADD COLUMN is_favorite BOOLEAN NOT NULL DEFAULT false;
   ALTER TABLE vault_entries ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT false;
   ALTER TABLE vault_entries ADD COLUMN deleted_at TIMESTAMPTZ;

   -- When is_deleted=true AND deleted_at is set, entry is in trash
   -- After 30 days past deleted_at, entry should be permanently purged
   CREATE INDEX idx_vault_entries_favorite ON vault_entries(user_id, is_favorite) WHERE is_favorite = true;
   CREATE INDEX idx_vault_entries_archived ON vault_entries(user_id, is_archived) WHERE is_archived = true;
   CREATE INDEX idx_vault_entries_trash ON vault_entries(user_id, deleted_at) WHERE is_deleted = true;

2. Create matching SQLite migration migrations/sqlite/007_vault_ux.sql:
   - Same columns, no partial index support in SQLite so use regular indexes

--- Part B: Backend Changes ---

3. Update internal/db/vault_repo.go:
   - Add fields to VaultEntry struct:
     - IsFavorite bool      `json:"is_favorite"`
     - IsArchived bool      `json:"is_archived"`
     - DeletedAt  *time.Time `json:"deleted_at,omitempty"`
   - Update VaultFilters struct — add fields:
     - IsFavorite *bool   — filter for favorites only
     - IsArchived *bool   — filter for archived only
     - InTrash    *bool   — filter for trashed items (is_deleted=true AND deleted_at IS NOT NULL)
   - ListEntries: by default exclude archived and trashed entries (WHERE is_archived=false AND is_deleted=false)
     unless the filter explicitly asks for them
   - Update CreateEntry, UpdateEntry to include new fields in INSERT/UPDATE

4. Add new methods to VaultRepository interface in internal/db/repository.go:
   - SetFavorite(ctx, entryID, userID string, favorite bool) error
   - SetArchived(ctx, entryID, userID string, archived bool) error
   - RestoreEntry(ctx, entryID, userID string) error
     — sets is_deleted=false, deleted_at=NULL
   - PermanentlyDeleteEntry(ctx, entryID, userID string) error
     — actually DELETE FROM vault_entries
   - PurgeExpiredTrash(ctx, userID string) (int, error)
     — DELETE WHERE is_deleted=true AND deleted_at < now()-30 days, return count
   - ListTrash(ctx, userID string) ([]VaultEntry, error)
     — WHERE is_deleted=true AND deleted_at IS NOT NULL

5. Implement these methods in both PostgreSQL (internal/db/vault_repo.go) and
   SQLite (internal/db/sqlite_repos.go) backends.

6. Update DeleteEntry to set deleted_at=now() alongside is_deleted=true (soft delete to trash).

7. Update internal/api/vault_handler.go:
   - PUT  /api/v1/vault/entries/{id}/favorite  — body: { "is_favorite": true/false }
   - PUT  /api/v1/vault/entries/{id}/archive   — body: { "is_archived": true/false }
   - POST /api/v1/vault/entries/{id}/restore   — restore from trash
   - DELETE /api/v1/vault/entries/{id}/permanent — permanently delete (requires is_deleted=true)
   - GET  /api/v1/vault/entries?filter=favorites — list favorites only
   - GET  /api/v1/vault/entries?filter=archived  — list archived only
   - GET  /api/v1/vault/entries?filter=trash     — list trashed items
   - On server startup or on pull sync, call PurgeExpiredTrash for the requesting user

8. Update internal/api/routes.go to register the new routes.

--- Part C: Electron App Changes ---

9. Update electron/src/main/index.ts — add IPC handlers:
   - 'vault:setFavorite' → PUT /vault/entries/{id}/favorite
   - 'vault:setArchived' → PUT /vault/entries/{id}/archive
   - 'vault:restore'     → POST /vault/entries/{id}/restore
   - 'vault:permanentDelete' → DELETE /vault/entries/{id}/permanent
   - 'vault:listTrash'   → GET /vault/entries?filter=trash

10. Update electron/src/main/preload.ts — expose new APIs:
    - window.api.vault.setFavorite(id, favorite)
    - window.api.vault.setArchived(id, archived)
    - window.api.vault.restore(id)
    - window.api.vault.permanentDelete(id)
    - window.api.vault.listTrash()

11. Update electron/src/renderer/components/Sidebar.tsx:
    - Add sidebar sections below existing navigation:
      - ⭐ Favorites — filters vault to favorites only
      - 📦 Archive — shows archived entries
      - 🗑️ Trash — shows trashed entries with days remaining + restore/permanent delete
    - Show count badges next to each section
    - Active section is highlighted

12. Update electron/src/renderer/pages/Vault.tsx:
    - Add activeFilter state: 'all' | 'favorites' | 'archived' | 'trash'
    - Favorites sort first in the main 'all' view
    - Star icon toggle on each entry row (filled yellow ⭐ if favorite, outline otherwise)
    - Context menu additions:
      - "Add to Favorites" / "Remove from Favorites"
      - "Archive" (moves to archive)
      - "Move to Trash" (replaces current delete)
    - When viewing Trash:
      - Show "X days remaining" per entry (30 - days since deleted_at)
      - "Restore" button per entry
      - "Delete Forever" button per entry (with confirmation dialog)
      - "Empty Trash" button in header (permanently deletes all)
    - When viewing Archive:
      - "Unarchive" button per entry
      - No creation or editing allowed in archive view

13. Update electron/src/renderer/pages/EntryDetail.tsx:
    - Show favorite star toggle in entry header
    - If entry is archived, show "Archived" badge and "Unarchive" action
    - If entry is in trash, show read-only view with "Restore" and "Delete Forever" buttons

14. Update extension popup (extension/src/popup/Popup.tsx):
    - Show star icon next to favorited credentials
    - Sort favorites first in the credential list for the current domain

--- Part D: Sync Compatibility ---

15. Update sync protocol:
    - Include is_favorite, is_archived, deleted_at in sync pull responses
    - Include these fields in push changes
    - The sync already handles is_deleted — extend it to carry deleted_at timestamp
```

---

### Prompt 24 — Password History, Multiple URIs & Clone

```
Add password history tracking, multiple URIs per login entry, and entry cloning.
These are quality-of-life features both Bitwarden and 1Password provide.

Depends on: Prompt 6 (vault), Prompt 23 (vault UX).

--- Part A: Password History ---

Password history is stored client-side inside the encrypted vault entry JSON blob.
The server never sees plaintext — this preserves zero-knowledge.

1. Update the encrypted JSON structure for login entries:
   Current: { "name": "", "username": "", "password": "", "uri": "", "notes": "", "totp": "" }
   New:     { "name": "", "username": "", "password": "", "uris": [...], "notes": "", "totp": "",
              "passwordHistory": [{ "password": "old_pw", "changedAt": "ISO8601" }, ...] }

   - When saving a login entry and the password field changed vs the previous version:
     - Push the OLD password + current timestamp into passwordHistory array
     - Keep max 10 entries (FIFO — drop oldest when exceeding 10)

2. Electron client-side (electron/src/renderer/pages/EntryDetail.tsx):
   - Before calling vault:update, compare new password vs current decrypted password
   - If different, append { password: oldPassword, changedAt: new Date().toISOString() }
     to the passwordHistory array
   - Trim to 10 entries

3. EntryDetail.tsx — Password History display:
   - Collapsible "Password History" section below the password field
   - Only shown for login entries that have passwordHistory with entries
   - Each item shows: masked password (toggleable), "Changed on" date, copy button
   - Sorted newest first
   - "Clear History" button with confirmation

--- Part B: Multiple URIs ---

4. Update the encrypted JSON structure for login entries:
   - Replace single "uri" field with "uris" array:
     uris: [{ uri: "https://github.com/login", match: "base_domain" }, ...]
   - Match detection modes:
     - "base_domain" (default) — match on registrable domain (e.g., github.com matches *.github.com)
     - "host" — exact hostname match
     - "starts_with" — URI starts with the stored value
     - "regex" — URI matches the regex pattern
     - "exact" — exact full URI match
     - "never" — never autofill for this URI (exclusion)
   - For backward compatibility, if entry has "uri" string instead of "uris" array,
     treat it as uris: [{ uri: value, match: "base_domain" }]

5. EntryDetail.tsx — Multiple URIs UI:
   - Show list of URIs with a match mode dropdown per URI
   - "Add URI" button to append a new row
   - Remove button (X) per URI row (must keep at least one)
   - URI input + match mode selector (dropdown: Base domain, Host, Starts with, Regex, Exact, Never)
   - "Launch" icon button per URI that opens it in default browser via shell.openExternal

6. Update extension autofill domain matching (extension/src/content/autofill.ts):
   - When receiving credentials from native host, each credential now has a uris array
   - For each URI entry, apply the match detection mode:
     - base_domain: extract registrable domain from both, compare
     - host: compare hostnames exactly
     - starts_with: check if page URL starts with stored URI
     - regex: new RegExp(storedUri).test(pageUrl)
     - exact: page URL === stored URI
     - never: skip this credential for autofill
   - A credential matches if ANY of its URIs match the current page
   - Update extension popup to show the primary URI (first in array) for display

7. Update native host (cmd/nativehost/main.go) credential matching:
   - When matching credentials for a domain, check all URIs in the entry
   - Apply match detection modes as described above

--- Part C: Clone Entry ---

8. Add clone endpoint to backend:
   - POST /api/v1/vault/entries/{id}/clone
   - Reads the entry, creates a new entry with:
     - New UUID
     - Same encrypted_data, nonce, entry_type, folder_id
     - Version reset to 1
     - is_favorite, is_archived reset to false
   - Returns the new entry
   - The client then decrypts, prepends "Copy of " to the name, re-encrypts, and updates

9. Add IPC handler: 'vault:clone' → POST /vault/entries/{id}/clone
   - After cloning on server, decrypt locally, modify name, re-encrypt, update

10. Update Vault.tsx context menu:
    - Add "Clone" option
    - After clone: navigate to the new entry's detail page in edit mode

11. Update extension:
    - No extension changes needed — cloning is a desktop-only operation
```

---

### Prompt 25 — Master Password Re-prompt

```
Add per-entry master password re-prompt. When enabled on a vault entry, the user must
re-enter their master password before viewing or copying sensitive fields (password, CVV,
secure note content). Both Bitwarden and 1Password have this feature.

Depends on: Prompt 6 (vault), Prompt 23 (vault UX).

1. Add reprompt flag to the vault entry encrypted JSON blob:
   - Add "reprompt": 0 | 1 to the entry JSON (0 = no reprompt, 1 = master password)
   - This is stored inside the encrypted data, so the server never knows which entries
     require re-prompt — it's a client-side enforcement
   - Default: 0 (no reprompt)

2. Update EntryDetail.tsx:
   - Add "Master password re-prompt" toggle in edit mode (checkbox or switch)
   - When reprompt=1 and user tries to:
     - View (unmask) a password, CVV, or secure note content
     - Copy a password, CVV, or secure note content
     - Edit the entry
   - Show a modal dialog: "Enter your master password to continue"
   - Input field for master password
   - On submit: derive auth hash from entered password + stored email using same KDF
   - Compare derived masterKeyHex with stored masterKeyHex in authStore
   - If match: allow the action, cache approval for this entry for 5 minutes
   - If mismatch: show error, do not allow action
   - After 5 minutes or if vault is locked: require re-prompt again

3. Create electron/src/renderer/components/RepromptDialog.tsx:
   - Modal overlay with password input
   - "Verify" button + "Cancel" button
   - Auto-focus on password input
   - Enter key submits
   - Loading spinner during KDF derivation

4. Update Vault.tsx:
   - Context menu "Copy Password" action: if entry has reprompt=1, show re-prompt first
   - Context menu "Copy Username" action: no re-prompt needed (username is not sensitive)
   - Show a small 🔒 lock icon on entries that have reprompt enabled

5. Update extension autofill:
   - When autofilling an entry that has reprompt=1:
     - Extension popup shows a password prompt before filling
     - Password is sent to native host → sidecar for verification
     - If verified: proceed with autofill
     - If user cancels or fails: abort autofill
   - Add message type: { type: 'verifyMasterPassword', password: string } → returns { verified: boolean }

6. Add verification endpoint to sidecar extension bridge:
   - POST /extension/verify-password — body: { password: string }
   - Derives keys from password + email, compares with session's master key
   - Returns { verified: true/false }
   - Rate-limited: 5 attempts per minute

7. Update IPC: 'vault:verifyMasterPassword' → returns boolean
   - Derives keys locally in main process, compares with stored masterKeyHex
```

---

## Phase 7: Security Intelligence

### Prompt 26 — Vault Health Report & Breach Monitoring

```
Build a vault health report page (like 1Password's Watchtower or Bitwarden's Vault Health Reports)
and integrate Have I Been Pwned breach monitoring. All analysis runs client-side to maintain
zero-knowledge — the server never sees plaintext passwords or their hashes.

Depends on: Prompt 6 (vault), Prompt 10 (UI).

--- Part A: Password Health Analysis (Client-Side) ---

1. Create electron/src/renderer/utils/passwordHealth.ts:

   analyzeVault(entries: DecryptedEntry[]) → VaultHealthReport:
   - Weak Passwords:
     - Score each password: length, character variety (upper, lower, digit, symbol),
       common patterns (sequential chars, repeated chars, keyboard walks)
     - Scoring: 0-20 = Critical, 21-40 = Weak, 41-60 = Fair, 61-80 = Good, 81-100 = Strong
     - Flag entries with score < 40 as weak
   - Reused Passwords:
     - Group entries by password (hash with SHA-256 for comparison, don't store plaintext)
     - Any group with > 1 entry = reused password
     - Return groups with entry IDs and count
   - Old Passwords:
     - Entries where updated_at is older than 365 days (configurable threshold)
     - Ignore secure notes and identities
   - Missing TOTP:
     - Login entries where URI matches a known list of sites supporting 2FA
       but the entry has no totp field set
     - Include a hardcoded list of popular domains that support TOTP:
       google.com, github.com, facebook.com, amazon.com, dropbox.com,
       twitter.com, microsoft.com, apple.com, slack.com, etc. (top 50)
   - Insecure Sites:
     - Login entries where ALL URIs start with http:// (not https://)
   - Return VaultHealthReport: { weak, reused, old, missingTotp, insecure,
     totalLogins, overallScore (0-100 percentage of healthy entries) }

2. Create electron/src/renderer/utils/hibp.ts:

   checkPasswordBreach(password: string) → Promise<number>:
   - SHA-1 hash the password (using Web Crypto API)
   - Take first 5 characters (prefix)
   - GET https://api.pwnedpasswords.com/range/{prefix}
   - Parse response: each line is "SUFFIX:COUNT"
   - Check if remaining 35 characters of hash appear in response
   - Return breach count (0 = not breached)
   - This is k-anonymity: the full hash never leaves the device

   checkEmailBreach(email: string) → Promise<Breach[]>:
   - This requires HIBP API key (optional, configured in Settings)
   - GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
   - Header: hibp-api-key: {key}
   - Return array of breach info: { name, date, dataClasses }
   - If no API key configured, skip email breach checking

   batchCheckPasswords(entries: DecryptedEntry[]) → Promise<Map<string, number>>:
   - Check each login entry's password against HIBP
   - Rate limit: max 1 request per 1.5 seconds (HIBP rate limit)
   - Show progress indicator during batch check
   - Return map of entry ID → breach count
   - Cache results in memory for the session (don't re-check until next unlock)

--- Part B: Vault Health Report UI ---

3. Create electron/src/renderer/pages/HealthReport.tsx:
   - Page title: "Vault Health" or "Security Report"
   - Overall health score: large circular progress indicator (0-100%)
   - Color coded: red (<40), orange (40-70), green (>70)

   Summary cards (top row):
   - 🔴 Exposed Passwords — count of entries found in data breaches (HIBP)
   - 🟠 Weak Passwords — count of entries with weak passwords
   - 🟡 Reused Passwords — count of entries sharing passwords
   - 🔵 Old Passwords — count of entries not updated in 365+ days
   - 🟢 Missing 2FA — count of entries on TOTP-supporting sites without TOTP
   - ⚠️ Insecure Sites — count of entries with HTTP-only URIs

   Click any card → expand to show the list of affected entries:
   - Entry name, username, domain
   - Severity indicator
   - "View" button → navigates to EntryDetail
   - For reused: show group (which other entries share this password)
   - For exposed: show breach count and "Change Password" recommendation

   Bottom section:
   - "Check for Breaches" button — runs HIBP batch check with progress bar
   - "Last checked: {date}" timestamp
   - Note: "Breach checking uses k-anonymity. Your passwords never leave this device."

4. Update electron/src/renderer/components/Sidebar.tsx:
   - Add "🛡️ Health" or "📊 Reports" nav item below Vault
   - Show warning badge if there are critical findings (exposed or weak passwords)

5. Update electron/src/main/preload.ts:
   - No new IPC needed — all analysis is client-side in the renderer
   - HIBP API calls go directly from renderer (they're public HTTPS APIs, no auth needed)
   - Ensure CSP allows connecting to api.pwnedpasswords.com and haveibeenpwned.com

6. Update electron/src/main/index.ts:
   - Add api.pwnedpasswords.com and haveibeenpwned.com to CSP connect-src directive

--- Part C: Entry-Level Breach Indicators ---

7. Update electron/src/renderer/pages/Vault.tsx:
   - After vault unlock, run analyzeVault() in background
   - Show small warning icons on entries in the vault list:
     - 🔴 if password found in breach
     - 🟠 if weak password
     - 🟡 if reused password
   - These indicators are cached in vaultStore for the session

8. Update EntryDetail.tsx:
   - Show inline warning banners:
     - "This password was found in {N} data breaches. Change it immediately."
     - "This password is weak. Consider using the password generator."
     - "This password is reused across {N} entries."
   - "Generate New Password" shortcut button when weak/reused/breached
```

---

## Phase 8: Sharing & Collaboration

### Prompt 27 — Secure Send

```
Implement Secure Send — time-limited encrypted sharing of text or files via a unique link.
Recipients don't need an LGI Pass account. The decryption key is in the URL fragment
(never sent to the server). This is Bitwarden's "Send" feature equivalent.

Depends on: Prompt 3 (crypto), Prompt 4 (auth), Prompt 18 (Docker/server).

--- Part A: Database ---

1. Create migration migrations/008_sends.sql:

   CREATE TABLE sends (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     user_id UUID REFERENCES users(id) ON DELETE CASCADE,
     slug TEXT NOT NULL UNIQUE,             -- random URL-safe slug (16 chars)
     send_type TEXT NOT NULL CHECK (send_type IN ('text', 'file')),
     encrypted_data BYTEA NOT NULL,         -- AES-256-GCM encrypted payload
     nonce BYTEA NOT NULL,                  -- GCM nonce
     encrypted_name BYTEA,                  -- encrypted display name (optional)
     name_nonce BYTEA,
     password_hash BYTEA,                   -- bcrypt hash of optional access password
     max_access_count INT,                  -- NULL = unlimited
     access_count INT NOT NULL DEFAULT 0,
     file_name TEXT,                        -- original filename (for file sends, unencrypted)
     file_size INT,                         -- file size in bytes
     expires_at TIMESTAMPTZ NOT NULL,
     disabled BOOLEAN NOT NULL DEFAULT false,
     hide_email BOOLEAN NOT NULL DEFAULT false,
     created_at TIMESTAMPTZ DEFAULT now()
   );

   CREATE INDEX idx_sends_user ON sends(user_id);
   CREATE INDEX idx_sends_slug ON sends(slug);
   CREATE INDEX idx_sends_expires ON sends(expires_at);

2. Create matching SQLite migration migrations/sqlite/008_sends.sql.

--- Part B: Backend ---

3. Add SendRepository interface to internal/db/repository.go:
   - CreateSend(ctx, send Send) (Send, error)
   - GetSendBySlug(ctx, slug string) (Send, error)
   - ListSends(ctx, userID string) ([]Send, error)
   - IncrementAccessCount(ctx, sendID string) error
   - DeleteSend(ctx, sendID, userID string) error
   - DisableSend(ctx, sendID, userID string) error
   - PurgeExpiredSends(ctx) (int, error)

4. Implement in both PostgreSQL and SQLite backends.

5. Create internal/api/send_handler.go:
   Authenticated endpoints (require JWT):
   - POST   /api/v1/sends         — create a new send
     - Body: { type, encrypted_data (hex), nonce (hex), encrypted_name, name_nonce,
               password (plaintext, server bcrypt-hashes), max_access_count, expires_in_hours,
               hide_email, file_name, file_size }
     - Generate random slug (16 chars, crypto/rand, base62)
     - Validate: expires_in_hours <= 720 (30 days max), file_size <= 100MB
     - Returns: { id, slug, url: "/send/{slug}" }
   - GET    /api/v1/sends         — list user's sends
   - DELETE /api/v1/sends/{id}    — delete a send
   - PUT    /api/v1/sends/{id}/disable — disable without deleting

   Public endpoints (NO authentication):
   - GET    /api/v1/send/{slug}   — retrieve a send
     - Check: not expired, not disabled, access_count < max_access_count (if set)
     - If password_hash set: require password in query param or header
       POST /api/v1/send/{slug}/access — body: { password: "..." }
       Verify bcrypt, if wrong return 401
     - Increment access_count
     - Return: { type, encrypted_data, nonce, file_name, file_size, expires_at,
                 sender_email (unless hide_email) }
     - If max_access_count reached: return 410 Gone
     - If expired: return 410 Gone

6. Register routes in internal/api/routes.go:
   - Authenticated: /api/v1/sends (under auth middleware)
   - Public: /api/v1/send/{slug} (NO auth middleware)
   - Purge expired sends on server startup

--- Part C: Electron App ---

7. Create electron/src/renderer/pages/Send.tsx:
   - Two tabs: "Create Send" and "My Sends"

   Create Send tab:
   - Type selector: Text or File
   - Text mode: large textarea for content
   - File mode: file picker (drag & drop or browse), show filename + size
   - Options panel:
     - Name (optional descriptive name)
     - Expiration: dropdown (1 hour, 1 day, 2 days, 3 days, 7 days, 14 days, 30 days, custom)
     - Max access count: number input (0 = unlimited)
     - Password: optional password field
     - Hide my email: checkbox
   - "Create Send" button:
     a. Generate 32-byte random key locally (crypto.getRandomValues)
     b. Encrypt content with AES-256-GCM using generated key
     c. Encrypt name if provided with same key
     d. POST to /api/v1/sends with encrypted data
     e. Build share URL: https://{server}/send/{slug}#{base64url(key)}
     f. Show the URL in a copyable field with "Copy Link" button
     g. Warning: "The link contains the decryption key. Anyone with this link can access the content."

   My Sends tab:
   - List all user's sends: name (or "Unnamed"), type, created date, expires date,
     access count / max count, status (active/expired/disabled/max reached)
   - "Copy Link" button per send (re-constructs URL — key must be cached locally
     since server doesn't store it; store in local encrypted send metadata)
   - "Disable" toggle
   - "Delete" button with confirmation

8. Create a minimal public receive page:
   - This could be served by the Go server at /send/{slug}
   - Simple HTML page (server-rendered, minimal dependencies):
     a. Page loads → reads #{key} from URL fragment
     b. Fetches encrypted data from GET /api/v1/send/{slug}
     c. If password required: show password input form
     d. Decrypts data in browser using SubtleCrypto API with the key from fragment
     e. Text type: show decrypted text with copy button
     f. File type: decrypt and offer download
     g. Branding: "Sent via LGI Pass" with link to project
   - The fragment (key) is NEVER sent to the server — browsers strip fragments from HTTP requests

9. Add IPC handlers for send operations:
   - 'send:create', 'send:list', 'send:delete', 'send:disable'

10. Update Sidebar.tsx:
    - Add "📤 Send" nav item

--- Part D: Security ---

11. Security requirements:
    - Decryption key is ONLY in the URL fragment (# part) — never sent to server
    - Server stores only encrypted blobs — cannot decrypt sends
    - Rate limit public access endpoint: 10 requests per minute per IP
    - Expired sends are purged by background goroutine (run every hour)
    - File size limit: 100MB (configurable)
    - Password-protected sends: bcrypt the password server-side
    - CORS: Allow public send access from any origin (it's a public sharing feature)
```

---

### Prompt 28 — Collections (Shared Vaults)

```
Implement collections — shared vaults within an organization where multiple members can
access the same encrypted entries. Each collection has its own symmetric key, encrypted
per-member with their X-Wing public key. This is the foundation of team credential sharing
in both Bitwarden and 1Password.

Depends on: Prompt 7 (admin/org), Prompt 3 (crypto).

--- Part A: Database ---

1. Create migration migrations/009_collections.sql:

   CREATE TABLE collections (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
     name_encrypted BYTEA NOT NULL,              -- AES-256-GCM encrypted name
     name_nonce BYTEA NOT NULL,
     external_id TEXT,                            -- optional external reference ID
     created_at TIMESTAMPTZ DEFAULT now(),
     updated_at TIMESTAMPTZ DEFAULT now()
   );

   -- Per-member access to a collection with their encrypted copy of the collection key
   CREATE TABLE collection_members (
     collection_id UUID REFERENCES collections(id) ON DELETE CASCADE,
     user_id UUID REFERENCES users(id) ON DELETE CASCADE,
     encrypted_key BYTEA NOT NULL,               -- collection symmetric key encrypted with user's public key
     permission TEXT NOT NULL CHECK (permission IN ('read', 'write', 'manage')),
     PRIMARY KEY (collection_id, user_id)
   );

   -- Junction table: entries can belong to multiple collections
   CREATE TABLE collection_entries (
     collection_id UUID REFERENCES collections(id) ON DELETE CASCADE,
     entry_id UUID REFERENCES vault_entries(id) ON DELETE CASCADE,
     PRIMARY KEY (collection_id, entry_id)
   );

   CREATE INDEX idx_collections_org ON collections(org_id);
   CREATE INDEX idx_collection_members_user ON collection_members(user_id);
   CREATE INDEX idx_collection_entries_entry ON collection_entries(entry_id);

2. Create matching SQLite migration (but collections require PostgreSQL/org mode,
   so SQLite version just creates the tables for schema consistency).

--- Part B: Crypto ---

3. Add to internal/crypto/vault.go or new file internal/crypto/collection.go:
   - GenerateCollectionKey() → (key [32]byte, error)
     — 32 random bytes for AES-256-GCM collection key
   - EncryptCollectionKey(collectionKey [32]byte, userPublicKey []byte) → ([]byte, error)
     — Encrypt collection key with user's X-Wing public key (KEM encapsulate + AES-GCM)
   - DecryptCollectionKey(encryptedKey []byte, userPrivateKey []byte) → ([32]byte, error)
     — Decrypt collection key with user's X-Wing private key

--- Part C: Backend ---

4. Add CollectionRepository interface to internal/db/repository.go:
   - CreateCollection(ctx, collection Collection) (Collection, error)
   - GetCollection(ctx, collectionID string) (Collection, error)
   - ListCollections(ctx, orgID string) ([]Collection, error)
   - ListUserCollections(ctx, userID string) ([]CollectionWithPermission, error)
   - UpdateCollection(ctx, collection Collection) error
   - DeleteCollection(ctx, collectionID string) error
   - AddCollectionMember(ctx, collectionID, userID string, encryptedKey []byte, permission string) error
   - RemoveCollectionMember(ctx, collectionID, userID string) error
   - GetCollectionMembers(ctx, collectionID string) ([]CollectionMember, error)
   - GetCollectionKey(ctx, collectionID, userID string) ([]byte, error)
   - AddEntryToCollection(ctx, collectionID, entryID string) error
   - RemoveEntryFromCollection(ctx, collectionID, entryID string) error
   - GetCollectionEntries(ctx, collectionID, userID string) ([]VaultEntry, error)
   - GetEntryCollections(ctx, entryID string) ([]Collection, error)

5. Implement in PostgreSQL backend. SQLite returns 501 Not Implemented (org feature).

6. Create internal/api/collection_handler.go:
   - POST   /api/v1/orgs/{orgId}/collections                    — create collection
     - Admin or manager creates collection
     - Generate collection key, encrypt for creator, store
   - GET    /api/v1/orgs/{orgId}/collections                    — list org collections
   - GET    /api/v1/collections/{id}                             — get collection details
   - PUT    /api/v1/collections/{id}                             — update collection name
   - DELETE /api/v1/collections/{id}                             — delete collection (manage only)
   - POST   /api/v1/collections/{id}/members                    — add member
     - Body: { user_id, permission }
     - Encrypt collection key with new member's public key
   - DELETE /api/v1/collections/{id}/members/{uid}              — remove member
   - PUT    /api/v1/collections/{id}/members/{uid}/permission   — change permission
   - POST   /api/v1/collections/{id}/entries                    — add entry to collection
     - Entry must be re-encrypted with collection key (client sends the re-encrypted blob)
   - DELETE /api/v1/collections/{id}/entries/{entryId}          — remove entry from collection
   - GET    /api/v1/collections/{id}/entries                    — list entries in collection

   Permission enforcement:
   - "read": can list and read entries, cannot modify
   - "write": can read, add, edit entries
   - "manage": can read, write, add/remove members, delete collection

--- Part D: Electron App ---

7. Update Admin.tsx — add "Collections" tab:
   - List all org collections with member count and entry count
   - Create collection form: name + initial members
   - Edit collection: rename, add/remove members, change permissions
   - Delete collection with confirmation

8. Update Vault.tsx sidebar:
   - Show collections alongside folders (separate section: "Collections")
   - Click collection → filter vault to show collection entries
   - Collection entries show a "shared" indicator icon

9. Update EntryDetail.tsx:
   - "Assign to Collection" action in edit mode
   - Shows which collections the entry belongs to
   - Permission indicator: read-only entries are not editable

10. Add IPC handlers for all collection operations.
11. Add preload API: window.api.collections.{create, list, get, update, delete, addMember, ...}
```

---

### Prompt 29 — Emergency Access

```
Implement emergency access — users can designate trusted contacts who can request
access to their vault after a configurable waiting period. The vault owner can approve
or reject during the wait. Both Bitwarden and 1Password offer this.

Depends on: Prompt 3 (crypto), Prompt 4 (auth), Prompt 6 (vault).

--- Part A: Database ---

1. Create migration migrations/010_emergency_access.sql:

   CREATE TABLE emergency_access (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     grantor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     grantee_id UUID REFERENCES users(id) ON DELETE SET NULL,
     grantee_email TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN
       ('invited', 'accepted', 'recovery_initiated', 'recovery_approved', 'recovery_rejected', 'expired')),
     access_type TEXT NOT NULL CHECK (access_type IN ('view', 'takeover')),
     wait_time_days INT NOT NULL DEFAULT 7,
     encrypted_key BYTEA,                          -- grantor's master key encrypted with grantee's public key
     key_nonce BYTEA,
     recovery_initiated_at TIMESTAMPTZ,
     created_at TIMESTAMPTZ DEFAULT now(),
     updated_at TIMESTAMPTZ DEFAULT now()
   );

   CREATE INDEX idx_emergency_grantor ON emergency_access(grantor_id);
   CREATE INDEX idx_emergency_grantee ON emergency_access(grantee_id);

2. Create matching SQLite migration.

--- Part B: Backend ---

3. Add EmergencyAccessRepository interface:
   - CreateEmergencyAccess(ctx, ea EmergencyAccess) (EmergencyAccess, error)
   - GetEmergencyAccess(ctx, id string) (EmergencyAccess, error)
   - ListGrantedAccess(ctx, grantorID string) ([]EmergencyAccess, error)
   - ListTrustedBy(ctx, granteeID string) ([]EmergencyAccess, error)
   - UpdateStatus(ctx, id, status string) error
   - SetEncryptedKey(ctx, id string, encryptedKey, nonce []byte) error
   - InitiateRecovery(ctx, id string) error  — sets status + recovery_initiated_at
   - DeleteEmergencyAccess(ctx, id string) error
   - GetAutoApproveEligible(ctx) ([]EmergencyAccess, error) — where recovery_initiated_at + wait_time_days <= now

4. Create internal/api/emergency_handler.go:
   - POST   /api/v1/emergency-access/invite    — grantor invites grantee by email
     - Body: { email, access_type ("view"|"takeover"), wait_time_days (1-30) }
     - Creates record with status "invited"
   - GET    /api/v1/emergency-access/granted    — list people I've granted access to
   - GET    /api/v1/emergency-access/trusted    — list people who've trusted me
   - POST   /api/v1/emergency-access/{id}/accept — grantee accepts invitation
     - Status: invited → accepted
     - Grantor should encrypt their master key with grantee's public key at this point
       (grantor is notified to approve the key exchange)
   - POST   /api/v1/emergency-access/{id}/confirm — grantor confirms and sends encrypted key
     - Body: { encrypted_key (hex), key_nonce (hex) }
     - Grantor encrypts their master key with grantee's public key
   - POST   /api/v1/emergency-access/{id}/initiate — grantee initiates recovery
     - Status: accepted → recovery_initiated
     - Sets recovery_initiated_at = now
     - Grantor should be notified (audit log entry)
   - POST   /api/v1/emergency-access/{id}/approve  — grantor approves recovery early
     - Status: recovery_initiated → recovery_approved
   - POST   /api/v1/emergency-access/{id}/reject   — grantor rejects recovery
     - Status: recovery_initiated → recovery_rejected
   - GET    /api/v1/emergency-access/{id}/vault     — grantee reads vault (after approval)
     - Check: status == recovery_approved OR (status == recovery_initiated
       AND recovery_initiated_at + wait_time_days <= now)
     - Return encrypted vault entries + encrypted master key
     - Grantee decrypts master key with their private key, then decrypts entries
   - POST   /api/v1/emergency-access/{id}/takeover  — grantee takes over account
     - Only if access_type == takeover AND access is approved/auto-approved
     - Reset grantor's password, re-encrypt vault with new master key
   - DELETE /api/v1/emergency-access/{id}            — revoke/cancel

5. Background job (on server startup or periodic):
   - Check for emergency access records where:
     status == recovery_initiated AND recovery_initiated_at + wait_time_days <= now()
   - Auto-approve: set status = recovery_approved
   - Run every hour

--- Part C: Electron App ---

6. Add "Emergency Access" section to Settings.tsx:
   Two sub-sections:

   "Trusted Contacts" (people who can access MY vault):
   - List of grantees: email, access type (view/takeover), wait time, status
   - "Add Trusted Contact" button → form: email, access type, wait time slider (1-30 days)
   - Status indicators: invited, accepted (ready), recovery initiated (⚠️ with countdown),
     approved, rejected
   - "Reject" button when status is recovery_initiated
   - "Revoke" button to remove access entirely
   - When grantee accepts: prompt to encrypt master key for them → call /confirm

   "People Who Trust Me" (vaults I can access):
   - List of grantors: email, access type, wait time, status
   - "Accept" button for pending invitations
   - "Request Access" button when status is accepted → initiates recovery
   - "View Vault" button when access is approved → shows read-only vault view
   - Countdown timer when recovery is initiated: "Access in X days Y hours"

7. Add IPC handlers for all emergency access operations.
8. Add preload API: window.api.emergencyAccess.{invite, accept, confirm, initiate, approve, reject, getVault, ...}
9. Audit log: all emergency access actions are logged.
```

---

## Phase 9: Import/Export & Interoperability

### Prompt 30 — Import from Other Password Managers

```
Implement a vault import feature supporting CSV/JSON exports from major password managers.
All parsing happens client-side in the Electron renderer — no plaintext data is sent to the server.
Users can import when switching from another password manager.

Depends on: Prompt 6 (vault), Prompt 10 (Electron UI).

--- Part A: Import Parsers ---

1. Create electron/src/renderer/utils/importers/ directory with a parser per format:

   electron/src/renderer/utils/importers/types.ts:
   - ImportedEntry: { type, name, username, password, uri, uris, notes, totp,
     fields (custom), cardNumber, cardExpiry, cardCvv, cardHolder,
     firstName, lastName, email, phone, address, folder }
   - ImportResult: { entries: ImportedEntry[], folders: string[], errors: string[], warnings: string[] }

   electron/src/renderer/utils/importers/bitwarden.ts:
   - parseBitwardenCSV(csv: string) → ImportResult
     - Columns: folder, favorite, type, name, notes, fields, reprompt, login_uri, login_username,
       login_password, login_totp
     - Type mapping: 1=login, 2=secure_note, 3=card, 4=identity
   - parseBitwardenJSON(json: string) → ImportResult
     - Standard Bitwarden JSON export format with encrypted/unencrypted variants

   electron/src/renderer/utils/importers/onepassword.ts:
   - parse1PasswordCSV(csv: string) → ImportResult
     - 1PUX format columns: Title, Url, Username, Password, Notes, Type
   - parse1Password1PUX(data: ArrayBuffer) → ImportResult
     - 1PUX is a zip containing JSON, parse the export.data file

   electron/src/renderer/utils/importers/lastpass.ts:
   - parseLastPassCSV(csv: string) → ImportResult
     - Columns: url, username, password, totp, extra, name, grouping, fav

   electron/src/renderer/utils/importers/chrome.ts:
   - parseChromeCSV(csv: string) → ImportResult
     - Columns: name, url, username, password, note

   electron/src/renderer/utils/importers/firefox.ts:
   - parseFirefoxCSV(csv: string) → ImportResult
     - Columns: url, username, password, httpRealm, formActionOrigin, guid, timeCreated,
       timeLastUsed, timePasswordChanged

   electron/src/renderer/utils/importers/keepass.ts:
   - parseKeePassCSV(csv: string) → ImportResult
     - Columns: Group, Title, Username, Password, URL, Notes

   electron/src/renderer/utils/importers/dashlane.ts:
   - parseDashlaneCSV(csv: string) → ImportResult
     - Columns: username, username2, username3, title, password, note, url, category, otpSecret

   electron/src/renderer/utils/importers/index.ts:
   - ImportFormat enum: Bitwarden_CSV, Bitwarden_JSON, OnePassword_CSV, OnePassword_1PUX,
     LastPass_CSV, Chrome_CSV, Firefox_CSV, KeePass_CSV, Dashlane_CSV
   - parseImport(format: ImportFormat, data: string | ArrayBuffer) → ImportResult

   Each parser:
   - Handle UTF-8 BOM
   - Skip empty rows
   - Map fields to ImportedEntry structure
   - Collect parsing errors per row (don't fail entire import)
   - Handle missing/optional columns gracefully

--- Part B: Import Wizard UI ---

2. Create electron/src/renderer/components/ImportWizard.tsx:
   Step 1 — Source Selection:
   - Grid of import source buttons with logos:
     Bitwarden, 1Password, LastPass, Chrome, Firefox, KeePass, Dashlane
   - Each shows "CSV" or "JSON" format badge
   - Brief instruction per source: "Export from Bitwarden: Settings → Export Vault → CSV"

   Step 2 — File Upload:
   - Drag & drop zone or file browse button
   - Accept: .csv, .json, .1pux
   - Show file name and size after selection
   - "Parse" button

   Step 3 — Preview & Configure:
   - Table showing parsed entries: type icon, name, username, URI, folder
   - Entry count summary: "Found X logins, Y notes, Z cards, W identities"
   - Errors/warnings section (collapsible) if any rows failed to parse
   - Duplicate detection: check against existing vault entries by (username + URI)
     - Highlight duplicates with "Already exists" badge
     - Checkbox: "Skip duplicates" (default: checked)
   - Folder mapping: show detected folders, option to create in LGI Pass or skip
   - Select/deselect individual entries with checkboxes

   Step 4 — Import:
   - "Import X entries" button with confirmation
   - Progress bar (entry by entry):
     a. For each entry: create encrypted JSON blob, encrypt with master key
     b. POST to /api/v1/vault/entries
     c. Create folders as needed
   - Success summary: "Imported X entries into Y folders. Z skipped (duplicates)."
   - "View Vault" button to go to vault page

3. Add import to Settings.tsx:
   - "Import Data" section with "Import from another password manager" button → opens ImportWizard
   - Also accessible from empty vault state (shown when vault has 0 entries)

4. Add IPC handlers if needed (all parsing is client-side, but vault creation uses existing IPC).
```

---

### Prompt 31 — Enhanced Export & SSH Keys

```
Add enhanced export options and SSH key storage as a new vault entry type.

Depends on: Prompt 6 (vault), Prompt 10 (Electron UI).

--- Part A: Enhanced Export ---

1. Update electron/src/renderer/pages/Settings.tsx — "Export Data" section:
   - Three export format options:
     a. Encrypted JSON (existing) — full backup, importable back into LGI Pass
     b. Unencrypted JSON — all entries decrypted, standard format
     c. Unencrypted CSV — flat CSV for spreadsheet/import into other managers

   - Before any export:
     - Master password re-prompt (always, regardless of reprompt setting)
     - Warning dialog: "Exporting unencrypted data exposes your passwords. The exported file
       is NOT encrypted. Delete it after importing into another application."

   - CSV format:
     - Columns: folder, type, name, username, password, uri, notes, totp, fields
     - One row per entry
     - Fields column: JSON string of custom fields
     - Credit card entries: name, number, expiry, cvv, cardholder in their own columns
     - Identity entries: firstName, lastName, email, phone, address in their own columns

   - JSON format (unencrypted):
     - { version: 1, exportDate: ISO8601, entries: [...], folders: [...] }
     - Each entry: { type, name, fields..., folder, favorite, reprompt }
     - Compatible with Bitwarden JSON import format where possible

   - File save dialog: Electron dialog.showSaveDialog with appropriate extension
   - After export: log to audit (if org mode): "vault_exported"

--- Part B: SSH Key Entry Type ---

2. Update database: add 'ssh_key' to entry_type CHECK constraint.
   Create migration migrations/011_ssh_keys.sql:
   - PostgreSQL: ALTER TABLE vault_entries DROP CONSTRAINT vault_entries_entry_type_check;
     ALTER TABLE vault_entries ADD CONSTRAINT vault_entries_entry_type_check
     CHECK (entry_type IN ('login', 'secure_note', 'credit_card', 'identity', 'ssh_key'));
   - SQLite: no ALTER CHECK support, but SQLite doesn't enforce CHECK by default anyway

3. SSH key encrypted JSON structure:
   {
     "name": "GitHub Deploy Key",
     "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
     "publicKey": "ssh-ed25519 AAAA... user@host",
     "fingerprint": "SHA256:...",
     "keyType": "ed25519",        -- ed25519, rsa, ecdsa
     "passphrase": "",            -- optional key passphrase
     "notes": ""
   }

4. Update EntryDetail.tsx for SSH key display:
   - Public key: monospace text field with copy button
   - Private key: hidden by default, toggle to show (monospace), copy button
   - Fingerprint: read-only display
   - Key type badge: Ed25519, RSA-4096, ECDSA
   - "Copy Public Key" prominent button
   - When creating: option to paste existing key OR generate new key pair

5. Update Vault.tsx:
   - Add SSH key type (🔑 icon, differentiate from login with different color or 🗝️)
   - Include in "Add Entry" type selector

6. SSH key generation (optional, client-side):
   - Generate Ed25519 or RSA-4096 key pair using Web Crypto or Node.js crypto
   - Convert to OpenSSH format
   - Calculate fingerprint (SHA-256 of public key)
   - No server involvement — all client-side

7. Update extension: no changes needed — SSH keys are desktop-only entries.
```

---

## Phase 10: UX Polish

### Prompt 32 — Theme Toggle, Tags & Keyboard Shortcuts

```
Add light/dark theme toggle, a tag system for vault entries, and keyboard shortcuts.
These are quality-of-life features that improve daily usability.

Depends on: Prompt 9-10 (Electron UI).

--- Part A: Dark/Light Theme ---

1. Update electron/tailwind.config.mjs:
   - Set darkMode: 'class' (manual toggle via class on <html>)

2. Create electron/src/renderer/store/themeStore.ts (Zustand):
   - theme: 'dark' | 'light' | 'system'
   - resolvedTheme: 'dark' | 'light' (actual applied theme)
   - setTheme(theme) — persists to localStorage
   - On init: read from localStorage, default 'dark'
   - If 'system': listen to window.matchMedia('(prefers-color-scheme: dark)')

3. Update electron/src/renderer/App.tsx:
   - Apply 'dark' class to <html> element based on resolvedTheme
   - Wrap app in theme provider

4. Audit all components for hard-coded dark colors:
   - Replace bg-slate-900 with bg-white dark:bg-slate-900
   - Replace text-white with text-slate-900 dark:text-white
   - Replace bg-slate-800 with bg-slate-100 dark:bg-slate-800
   - Replace border-slate-700 with border-slate-200 dark:border-slate-700
   - Focus on: Sidebar, Vault, EntryDetail, Settings, Admin, Login, Register
   - Extension popup: keep dark theme only (popup is small, dark works better)

5. Add theme toggle to Settings.tsx:
   - "Appearance" section
   - Three options: Light, Dark, System (with radio buttons or segmented control)
   - Live preview when toggling

--- Part B: Tags System ---

6. Add tags to vault entry encrypted JSON:
   - Inside the encrypted blob, add: "tags": ["work", "social", "banking", ...]
   - Tags are encrypted (zero-knowledge), so server can't filter by tag
   - All tag filtering happens client-side after decryption

7. Update EntryDetail.tsx:
   - Tag input field in edit mode:
     - Type tag name, press Enter or comma to add
     - Click X on tag to remove
     - Auto-suggest from existing tags across all entries
     - Max 10 tags per entry
   - Display mode: show tags as colored pills below entry name

8. Update Vault.tsx:
   - "Tags" section in sidebar (below folders):
     - List all unique tags across all decrypted entries
     - Click tag → filter vault to entries with that tag
     - Show entry count per tag
   - Tag filter can combine with folder filter and type filter
   - Tags appear as small pills in the entry list view

9. Update vaultStore.ts:
   - Add selectedTags: string[] filter
   - Derive allTags from decrypted entries

--- Part C: Keyboard Shortcuts ---

10. Create electron/src/renderer/utils/keyboard.ts:
    - Global keyboard shortcut handler using document.addEventListener('keydown')
    - Shortcut definitions:
      Global (work from any page):
      - Ctrl+N — new vault entry (open create dialog)
      - Ctrl+F — focus search bar
      - Ctrl+G — open password generator
      - Ctrl+L — lock vault
      - Ctrl+, — open settings
      - Ctrl+Shift+C — copy current entry's password (if on entry detail)
      - Ctrl+Shift+U — copy current entry's username (if on entry detail)
      - Escape — close any open modal/dialog

      Vault list:
      - ↑/↓ — navigate entries
      - Enter — open selected entry
      - Delete — move selected entry to trash (with confirmation)

    - Don't trigger shortcuts when focused on input/textarea (except Escape)
    - Use event.preventDefault() to avoid browser defaults

11. Create electron/src/renderer/components/ShortcutHelp.tsx:
    - Modal showing all available shortcuts in a two-column grid
    - Triggered by Ctrl+? or from Settings page
    - Group by category: Navigation, Vault, Entry, General

12. Add "Keyboard Shortcuts" link in Settings.tsx → opens ShortcutHelp modal.
```

---

### Prompt 33 — Vault Timeout Actions, Username Generator & Misc UX

```
Add vault timeout action options, email alias / username generator, and other UX improvements.

Depends on: Prompt 10-11 (Electron UI, biometric).

--- Part A: Vault Timeout Actions ---

1. Update electron/src/renderer/store/authStore.ts:
   - Add timeoutAction: 'lock' | 'logout' (default: 'lock')
   - 'lock': clear master key, keep session token, user re-enters password or biometric to unlock
   - 'logout': clear everything (token, master key, cached entries), redirect to login page,
     require full email + password re-entry

2. Update electron/src/main/index.ts auto-lock handler:
   - Read timeoutAction from auth store (via IPC)
   - If 'lock': existing behavior (clear master key, show unlock)
   - If 'logout': clear all session data, close sidecar session, redirect to /login
   - Extension bridge: if logout, also clear extension session

3. Update Settings.tsx:
   - "Vault Timeout Action" dropdown alongside the existing auto-lock timeout:
     - Lock (default) — "Require master password or biometric to unlock"
     - Log out — "Clear all data and require full login"

--- Part B: Username / Email Alias Generator ---

4. Create electron/src/renderer/components/UsernameGenerator.tsx:
   Four generation modes:

   a. Random Word + Number:
      - Format: {word}{number} (e.g., "thunder4729")
      - Use a built-in word list (100-200 common English words, no offensive words)
      - Number: 2-6 digits (configurable)
      - Options: capitalize first letter, add separator

   b. Random Characters:
      - Format: random alphanumeric string (e.g., "x8k2m9p4")
      - Length: 8-20 characters (slider)

   c. UUID-based:
      - Format: UUID v4 (e.g., "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
      - Useful for unique usernames where format doesn't matter

   d. Email Alias (catch-all):
      - User configures their domain in Settings (e.g., "mydomain.com")
      - Generates: random+@mydomain.com (e.g., "x8k2m9@mydomain.com")
      - Requires a catch-all email setup on the domain

   e. Email Alias Service (optional, API integration):
      - Support SimpleLogin API:
        - POST https://app.simplelogin.io/api/alias/random/new
        - Header: Authentication: {api_key}
      - Support AnonAddy (addy.io) API:
        - POST https://app.addy.io/api/v1/aliases
        - Header: Authorization: Bearer {api_key}
      - API keys configured in Settings
      - Generate button → creates alias → returns the alias email

5. Update Settings.tsx — "Username & Alias" section:
   - Default username format: dropdown (Word+Number, Random, UUID, Catch-all, Service)
   - Catch-all domain: text input
   - SimpleLogin API key: password input (optional)
   - AnonAddy API key: password input (optional)

6. Integrate username generator into EntryDetail.tsx:
   - Small "⟳ Generate" button next to username field when creating a new login entry
   - Opens inline popover with generator options and "Use" button

7. Update PasswordGenerator.tsx:
   - Add a tab or toggle: "Password" | "Username"
   - Username tab shows the UsernameGenerator component
   - This way both generators are accessible from the same component

--- Part C: Entry Sorting & Search Improvements ---

8. Update Vault.tsx search:
   - Search across all decrypted fields (name, username, notes, URIs, tags)
   - Highlight matching text in search results
   - Show which field matched (small label: "matched in username", "matched in notes")

9. Update entry sorting options:
   - Current: name, updated_at, entry_type
   - Add: created_at, recently used (last_copied_at — track in local store)
   - Add: favorites first toggle (independent of sort order)

10. Empty states:
    - Empty vault: show onboarding prompt with "Import passwords" and "Create first entry" CTAs
    - Empty trash: show "Trash is empty" with trash icon
    - Empty archive: show "No archived items"
    - No search results: show "No entries match your search" with suggestion to clear filters
```

---

## Phase 11: Enterprise Features

### Prompt 34 — SSO & SCIM Integration

```
Add Single Sign-On (SAML/OIDC) and SCIM directory provisioning for enterprise deployments.
SSO authenticates the user but does NOT unlock the vault — the master password is still
required for decryption (same model as Bitwarden and 1Password).

Depends on: Prompt 4 (auth), Prompt 7 (admin/org).

IMPORTANT: This is a PostgreSQL-only feature (enterprise/org mode).

--- Part A: SSO Authentication ---

1. Create migration migrations/012_sso.sql:

   ALTER TABLE organizations ADD COLUMN sso_enabled BOOLEAN NOT NULL DEFAULT false;
   ALTER TABLE organizations ADD COLUMN sso_config JSONB;
   -- sso_config: {
   --   provider: "saml" | "oidc",
   --   saml: { entity_id, sso_url, certificate, name_id_format },
   --   oidc: { issuer, client_id, client_secret_encrypted, redirect_uri, scopes },
   --   auto_enroll: true  -- auto-add authenticated users to org
   -- }

   ALTER TABLE users ADD COLUMN sso_external_id TEXT;
   CREATE UNIQUE INDEX idx_users_sso_external ON users(sso_external_id) WHERE sso_external_id IS NOT NULL;

2. Create internal/auth/sso.go:
   Dependencies: github.com/crewjam/saml, github.com/coreos/go-oidc/v3

   SSOService struct:
   - InitiateSAMLLogin(orgID string) → (redirectURL string, requestID string, error)
     - Build SAML AuthnRequest, redirect to IdP SSO URL
   - HandleSAMLCallback(orgID string, samlResponse string) → (email, externalID string, error)
     - Parse and validate SAML Response
     - Verify signature against stored IdP certificate
     - Extract NameID (email) and attributes
   - InitiateOIDCLogin(orgID string) → (redirectURL, state string, error)
     - Build OIDC authorization URL with PKCE
   - HandleOIDCCallback(orgID, code, state string) → (email, externalID string, error)
     - Exchange code for tokens, verify ID token, extract claims

3. SSO Login Flow:
   a. User selects "Login with SSO" on login page
   b. Enter organization identifier (org slug or domain)
   c. Redirect to IdP login page
   d. IdP authenticates, redirects back with assertion/token
   e. Server validates assertion, finds/creates user by email
   f. If user exists: return JWT with partial auth (SSO authenticated, vault still locked)
   g. User enters master password to decrypt vault (SSO doesn't replace master password)
   h. If auto_enroll and user not in org: add to org as member

4. Create internal/api/sso_handler.go:
   - GET  /api/v1/sso/{orgId}/login       — initiate SSO login (redirect to IdP)
   - POST /api/v1/sso/{orgId}/callback     — handle SSO callback (SAML POST or OIDC redirect)
   - POST /api/v1/sso/{orgId}/unlock       — after SSO, user sends master password to unlock vault

5. Admin SSO configuration UI:
   - Add "SSO" tab to Admin.tsx
   - Provider selector: SAML 2.0 or OpenID Connect
   - SAML config: Entity ID, SSO URL, IdP certificate (textarea)
   - OIDC config: Issuer URL, Client ID, Client Secret
   - Test connection button
   - Enable/disable toggle
   - Save configuration → encrypted and stored in sso_config

6. Update Login.tsx:
   - Add "Login with SSO" option below the password form
   - SSO login prompts for organization identifier first
   - After SSO redirect, show master password input (vault unlock step)

--- Part B: SCIM Directory Provisioning ---

7. Create migration: add SCIM token column to organizations:
   ALTER TABLE organizations ADD COLUMN scim_token_hash BYTEA;
   ALTER TABLE organizations ADD COLUMN scim_enabled BOOLEAN NOT NULL DEFAULT false;

8. Create internal/api/scim_handler.go:
   SCIM 2.0 endpoints (authenticated via bearer token from scim_token_hash):

   Users:
   - GET    /api/v1/scim/v2/Users          — list provisioned users (paginated, filtered)
   - GET    /api/v1/scim/v2/Users/{id}     — get user by ID
   - POST   /api/v1/scim/v2/Users          — create/provision user
     - Creates user record + sends invitation email
     - Schema: { userName (email), name.givenName, name.familyName, active, externalId }
   - PUT    /api/v1/scim/v2/Users/{id}     — replace user attributes
   - PATCH  /api/v1/scim/v2/Users/{id}     — partial update (e.g., deactivate)
     - Deactivating a user: remove from org, revoke sessions
   - DELETE /api/v1/scim/v2/Users/{id}     — deprovision user

   Groups (optional, future):
   - Map to collections
   - GET/POST/PATCH/DELETE /api/v1/scim/v2/Groups

   Standard SCIM responses:
   - ListResponse: { schemas, totalResults, startIndex, itemsPerPage, Resources }
   - SCIM error: { schemas, status, detail }
   - Support filter parameter: filter=userName eq "user@example.com"

9. SCIM auth middleware:
   - Bearer token in Authorization header
   - bcrypt compare against scim_token_hash in organizations table
   - Only allow SCIM requests from the org that owns the token

10. Admin SCIM configuration:
    - "Directory Sync" tab in Admin.tsx
    - Generate SCIM token (show once, store bcrypt hash)
    - Show SCIM endpoint URL
    - Enable/disable toggle
    - Show provisioned user list with sync status
```

---

### Prompt 35 — Custom Roles, Groups & SIEM Integration

```
Add custom roles with granular permissions, user groups for collection assignment,
and SIEM integration for enterprise audit log export.

Depends on: Prompt 7 (admin), Prompt 28 (collections), Prompt 34 (SSO/SCIM).

IMPORTANT: PostgreSQL-only (enterprise features).

--- Part A: Custom Roles ---

1. Create migration migrations/013_roles_groups.sql:

   CREATE TABLE roles (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
     name TEXT NOT NULL,
     description TEXT,
     permissions JSONB NOT NULL DEFAULT '[]',
     is_builtin BOOLEAN NOT NULL DEFAULT false,
     created_at TIMESTAMPTZ DEFAULT now()
   );

   -- Built-in roles (seeded on org creation):
   -- { name: "Admin", permissions: ["*"], is_builtin: true }
   -- { name: "Member", permissions: ["vault.read","vault.write","collection.read"], is_builtin: true }

   CREATE TABLE groups (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
     name TEXT NOT NULL,
     external_id TEXT,               -- for SCIM directory sync
     created_at TIMESTAMPTZ DEFAULT now()
   );

   CREATE TABLE group_members (
     group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
     user_id UUID REFERENCES users(id) ON DELETE CASCADE,
     PRIMARY KEY (group_id, user_id)
   );

   -- Groups can be assigned to collections
   CREATE TABLE collection_groups (
     collection_id UUID REFERENCES collections(id) ON DELETE CASCADE,
     group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
     permission TEXT NOT NULL CHECK (permission IN ('read', 'write', 'manage')),
     encrypted_key BYTEA NOT NULL,
     PRIMARY KEY (collection_id, group_id)
   );

   -- Replace simple role TEXT in org_members with role_id
   ALTER TABLE org_members ADD COLUMN role_id UUID REFERENCES roles(id);

   CREATE UNIQUE INDEX idx_roles_org_name ON roles(org_id, name);
   CREATE INDEX idx_groups_org ON groups(org_id);

2. Permission definitions (JSONB array of permission strings):
   - "vault.read" — read own vault entries
   - "vault.write" — create/edit/delete own vault entries
   - "vault.export" — export vault data
   - "collection.read" — read collection entries
   - "collection.write" — edit collection entries
   - "collection.manage" — manage collection members
   - "org.invite" — invite users to org
   - "org.remove" — remove users from org
   - "org.policy" — manage org policies
   - "org.audit" — view audit logs
   - "org.vault_access" — access other users' vaults (escrow)
   - "org.sso" — manage SSO configuration
   - "org.scim" — manage SCIM provisioning
   - "*" — superadmin, all permissions

3. Update internal/api/middleware.go:
   - RequirePermission(permission string) middleware
   - Checks user's role → role.permissions → contains permission or "*"
   - Replace hardcoded role == "admin" checks with permission checks

4. Create admin API endpoints:
   - CRUD for roles: /api/v1/orgs/{id}/roles
   - CRUD for groups: /api/v1/orgs/{id}/groups
   - Manage group members: /api/v1/orgs/{id}/groups/{gid}/members
   - Assign group to collection: /api/v1/collections/{id}/groups

5. Admin UI:
   - "Roles" tab in Admin.tsx: list roles, create custom role with permission checkboxes,
     edit permissions, delete (cannot delete built-in roles)
   - "Groups" tab in Admin.tsx: list groups, add/remove members, assign to collections
   - When inviting user: select role from dropdown (not just admin/member)

--- Part B: SIEM Integration ---

6. Create internal/api/siem_handler.go:

   Event log streaming:
   - GET /api/v1/admin/orgs/{id}/events/export — export audit logs in structured format
     - Query params: format (json, cef, syslog), since, until, limit
     - JSON format: NDJSON (newline-delimited JSON), one event per line
     - CEF format: CEF:0|LGI|Pass|1.0|{action}|{description}|{severity}|...
     - Syslog format: RFC 5424 structured data

   Webhook delivery:
   - POST /api/v1/admin/orgs/{id}/webhooks — create webhook
     - Body: { url, events (array of action types or "*"), secret }
     - Secret used for HMAC-SHA256 signature verification
   - GET    /api/v1/admin/orgs/{id}/webhooks — list webhooks
   - DELETE /api/v1/admin/orgs/{id}/webhooks/{id} — delete webhook
   - POST   /api/v1/admin/orgs/{id}/webhooks/{id}/test — send test event

7. Webhook delivery system:
   - When an audit log entry is created, check for matching webhooks
   - POST to webhook URL with JSON body: { event, timestamp, actor, target, details }
   - Header: X-LGIPass-Signature: HMAC-SHA256(body, secret)
   - Retry: 3 attempts with exponential backoff (1s, 5s, 30s)
   - Store delivery status in webhook_deliveries table

8. Create migration for webhooks:
   CREATE TABLE webhooks (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
     url TEXT NOT NULL,
     events TEXT[] NOT NULL DEFAULT '{*}',
     secret_hash BYTEA NOT NULL,
     enabled BOOLEAN NOT NULL DEFAULT true,
     created_at TIMESTAMPTZ DEFAULT now()
   );

   CREATE TABLE webhook_deliveries (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
     event_id UUID REFERENCES audit_log(id) ON DELETE CASCADE,
     status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
     response_code INT,
     attempts INT NOT NULL DEFAULT 0,
     last_attempt_at TIMESTAMPTZ,
     created_at TIMESTAMPTZ DEFAULT now()
   );

9. Admin UI:
   - "Integrations" tab in Admin.tsx:
     - Event Log Export section: format selector + date range + "Export" button
     - Webhooks section: list webhooks, add new, test, enable/disable, delete
     - Show recent delivery status (last 10) with response codes
```

---

### Prompt 36 — Comprehensive Test Suite for New Features

```
Create tests for all features added in Prompts 23-35. Follow the existing test patterns
in the testing/ directory.

Depends on: All previous prompts in this phase.

--- Part A: Go Backend Tests ---

testing/vault_ux_test.go:
- TestFavorite_SetAndUnset: set favorite → list with filter → verify
- TestArchive_SetAndUnset: archive → verify excluded from default list → unarchive
- TestTrash_DeleteAndRestore: delete → verify in trash → restore → verify in default list
- TestTrash_PermanentDelete: delete → permanent delete → verify gone
- TestTrash_AutoPurge: delete → set deleted_at to 31 days ago → purge → verify removed
- TestClone_Entry: clone entry → verify new ID, same data, version=1
- TestListEntries_Filters: test favorites, archived, trash filter combinations

testing/send_handler_test.go:
- TestCreateSend_Text: create text send → verify slug + encrypted data stored
- TestAccessSend_Success: create → access via slug → verify access_count incremented
- TestAccessSend_Expired: create with 1hr expiry → set expires_at to past → access → verify 410
- TestAccessSend_MaxAccess: create with max_access_count=1 → access twice → verify 410
- TestAccessSend_Password: create with password → access without password → 401
- TestAccessSend_WithPassword: access with correct password → 200
- TestPurgeSends: create expired sends → purge → verify deleted

testing/collection_handler_test.go:
- TestCreateCollection: create collection → verify stored
- TestAddMember: add member with read permission → verify access
- TestCollectionPermission_ReadOnly: read member cannot modify entries
- TestCollectionPermission_Write: write member can add/edit entries
- TestCollectionPermission_Manage: manage member can add/remove other members
- TestDeleteCollection: delete → verify cascade deletes members and entry assignments

testing/emergency_access_test.go:
- TestEmergencyAccess_InviteAndAccept: invite → accept → verify status
- TestEmergencyAccess_InitiateRecovery: initiate → verify wait period
- TestEmergencyAccess_ApproveRecovery: approve → verify vault accessible
- TestEmergencyAccess_RejectRecovery: reject → verify vault NOT accessible
- TestEmergencyAccess_AutoApprove: initiate → advance time past wait_time → verify auto-approved
- TestEmergencyAccess_Takeover: takeover → verify password reset + vault re-encrypted

--- Part B: Electron Tests ---

testing/electron/import.test.ts:
- TestParseBitwardenCSV: parse sample CSV → verify entry count and fields
- TestParse1PasswordCSV: parse sample CSV → verify mapping
- TestParseLastPassCSV: parse sample CSV → verify grouping to folders
- TestParseChromeCSV: parse simple format → verify all fields
- TestParseFirefoxCSV: parse Firefox export → verify timestamps handled
- TestDuplicateDetection: import entries → re-import same → verify duplicates detected

testing/electron/password-health.test.ts:
- TestWeakPasswordDetection: score common passwords → verify flagged as weak
- TestStrongPasswordDetection: score complex passwords → verify flagged as strong
- TestReusedPasswordDetection: multiple entries same password → verify grouped
- TestOldPasswordDetection: entry with old updated_at → verify flagged
- TestInsecureURI: http:// URI → verify flagged
- TestHIBP_KAnonymity: verify only 5-char prefix sent (mock fetch)

testing/electron/send.test.ts:
- TestCreateSend: encrypt content → verify key in fragment only
- TestDecryptSend: encrypt → build URL → extract key from fragment → decrypt → verify

--- Part C: Extension Tests ---

testing/extension/uri-matching.test.ts:
- TestBaseDomainMatch: "github.com" matches "https://github.com/login"
- TestHostMatch: exact hostname matching
- TestStartsWithMatch: prefix URI matching
- TestRegexMatch: regex pattern matching
- TestExactMatch: full URL exact match
- TestNeverMatch: "never" mode skips credential
- TestMultipleURIs: credential with multiple URIs, verify any-match logic
```
