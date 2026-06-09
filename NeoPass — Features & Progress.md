# NeoPass — Features & Progress

**Stack**: Go 1.25, PostgreSQL 16 / SQLite, Electron 41, React 18, TypeScript, Vite, Webpack, Docker, TLS 1.3

---

## Quantum-Safe Cryptography ✅
- **X-Wing** hybrid KEM (X25519 + ML-KEM-768) for key encapsulation — post-quantum resistant key exchange
- **ML-DSA-65** (CRYSTALS-Dilithium) for digital signatures — used for JWT signing/verification
- **AES-256-GCM** for vault entry encryption with 12-byte random nonces
- **Argon2id** key derivation (64 MB memory, 3 iterations, 4 parallelism) — produces 32-byte master key + 32-byte auth hash from password + salt
- **bcrypt** server-side hashing of client-derived auth hash (double-hash: password never transmitted)
- **SHAKE-256** domain-separated session key derivation from KEM shared secrets (e.g., `"escrow-encryption"`, `"emergency-access"`, `"shared-2fa"`)
- Zero-knowledge architecture — server never decrypts vault data
- `ZeroBytes()` deferred on all decrypted buffers to prevent memory residue
- Cloudflare `circl` library for post-quantum primitives

---

## Authentication ✅
- Email/password registration with client-side Argon2id key derivation
- Login returns JWT (ML-DSA-65 signed) or 2FA challenge if enabled
- Access tokens: 15-minute duration, refresh tokens: 7-day duration with rotation
- Token revocation via `tokens_revoked_at` timestamp — invalidates all tokens issued before that time
- Password change re-encrypts all vault entries with new master key
- Hardware key enforcement — per-user flag requiring WebAuthn on every login
- Security settings endpoint returns `has_2fa`, `require_hw_key`, and method availability
- Rate limited: 5 requests/minute per IP on all auth endpoints

---

## Two-Factor Authentication ✅
- **TOTP**: Generate secret + QR URI, encrypt with user's master key before storage, verify code with time window
- **Recovery codes**: 8 codes (8 chars each), bcrypt-hashed on server, single-use
- **SMS 2FA**: Telnyx integration for SMS OTP delivery and validation
- **TOTP sharing**: Share encrypted TOTP secrets between users via X-Wing KEM with label and expiration
- Pending shared TOTPs listed and claimed per user
- Partial JWT token (`is_2fa=true`) blocks access to protected routes until 2FA validated

---

## Hardware Keys & Passkeys (WebAuthn) ✅
- **Hardware keys**: Register/authenticate FIDO2 security keys (YubiKey, etc.) with WebAuthn
- **Passkeys**: Full FIDO2 passkey lifecycle — register, authenticate, list, delete per relying party
- 32-byte cryptographic challenge with 5-minute session TTL
- Sign count tracking and COSE public key storage
- Transport types: Bluetooth, BLE, hybrid, internal, NFC, USB
- FIDO metadata endpoint (public, no auth required)
- Extension bridge support — passkey operations proxied through native host

---

## Vault Management ✅
- Entry types: `login`, `secure_note`, `credit_card`, `identity`, `ssh_key`
- Full CRUD with client-side AES-256-GCM encryption — server stores only ciphertext + nonce
- Version tracking (incremented on each update) for conflict detection
- Folder hierarchy with encrypted folder names and `parent_id` self-join
- Favorites toggle and archive/unarchive
- Soft delete (trash) with restore and permanent purge
- Bulk trash purge with configurable age threshold
- Entry cloning with optional target folder
- Filter by entry type, folder, update timestamp, favorite status, archived, or trashed
- Per-entry collection membership query

---

## Multi-Device Sync ✅
- Pull-based sync: client provides `device_id` + `last_sync_at`, server returns all entries modified since
- Push-based sync: client sends local changes with `base_version` for conflict detection
- Version conflict detection — server compares `base_version` vs current `server_version`
- Conflict resolution strategies: `keep_server` (discard client), `keep_client` (force update), `merge` (client provides merged ciphertext)
- Sync cursor tracking per device with `last_sync_at` timestamp
- Device management: list all synced devices, delete stale devices
- Soft-deleted entries included in sync response with `deleted_at` timestamp for client-side cleanup

---

## Organizations & Admin ✅
- Organization creation with X-Wing keypair — org private key encrypted with admin's master key
- One organization per user constraint
- Member management: invite by email, accept/decline, role assignment, removal (self-deletion prevention)
- **Escrow system**: Each member's vault key encrypted with org public key, stored as `escrow_blob`
- **Admin vault access**: Admin decrypts org private key → decapsulates user's escrow → recovers master key → decrypts vault entries (fully audit logged)
- **Admin password reset**: Re-encrypts user's vault entries via escrow recovery
- Org key propagation to new members via `encrypted_org_key` per member
- Invitation system with pending/accepted states
- Organization security policy: `require_2fa`, `min_password_length`, `rotation_days`
- PostgreSQL connection test and SQLite → PostgreSQL migration endpoints

---

## Granular Roles & Permissions ✅
- Custom role CRUD with JSON permission arrays (e.g., `org.admin`, `org.member`, `org.audit`)
- Built-in roles with `is_builtin` flag
- `RequirePermission` middleware checks role permissions with wildcard (`*`) superuser support
- Legacy `admin`/`member` role fallback when RoleRepository unavailable
- Per-member `role_id` assignment within organization

---

## Groups ✅
- Group CRUD within organization with `external_id` for SCIM directory sync
- Group membership management (add/remove users)
- Groups assignable to collections — all group members inherit collection access
- Encrypted collection key distributed per group

---

## Collections (Shared Vaults) ✅
- Encrypted collection name with per-collection AES key
- Members receive encrypted copy of collection key (encrypted with their master key)
- Permission hierarchy: `read` (view), `write` (add/update entries), `manage` (member management)
- Collection entries via junction table — entries can belong to multiple collections
- Separate `collection_entry_data` table with entry data encrypted using collection key (decryptable without master key)
- Group-based collection access with per-group encrypted key and permission level
- Organization-scoped and personal collection support

---

## Secure Send ✅
- Time-limited encrypted sharing (1–720 hours) with random base62 slug (16 chars)
- Send types: `text` and `file` (up to 100 MB)
- Optional bcrypt password protection — server verifies before returning encrypted data
- Optional max access count — auto-expires after N accesses
- Hide sender email option
- Public receive page (HTML) with client-side Web Crypto API decryption
- Decryption key passed in URL fragment (`#key`) — never sent to server
- Disable send early (owner action)
- Hourly background job purges expired sends

---

## Emergency Access ✅
- Invite trusted contact by email with access type (`view` or `takeover`) and wait period (1–30 days)
- Grantee accepts, grantor encrypts vault key using grantee's X-Wing public key via KEM
- After wait period: grantee initiates recovery → grantor approves or denies
- On approval: grantee decapsulates shared secret → derives session key → decrypts vault key → accesses vault
- Full status lifecycle: `invited` → `accepted` → `recovery_initiated` → `recovery_approved`/`recovery_rejected`/`expired`
- Background goroutine auto-approves after wait period elapses
- All emergency access operations audit logged

---

## SSO (Single Sign-On) ✅
- SAML and OIDC identity provider integration (PostgreSQL-only)
- Flow: SSO login redirect → IdP authentication → callback with partial JWT (`is_2fa=true`) → unlock with `auth_hash` → full tokens
- SSO state tracking with nonce and CSRF validation via `sso_states` table
- Per-org SSO configuration (enabled flag + `sso_config_json`)
- `sso_external_id` linking on user record
- Rate limited: 10 requests/minute per IP on SSO endpoints

---

## SCIM 2.0 Provisioning ✅
- Full SCIM 2.0 user lifecycle: list, create, get, replace (PUT), patch, delete (PostgreSQL-only)
- Filter and pagination support (`startIndex`, `count`)
- Bearer token authentication — bcrypt-verified against org's `scim_token_hash`
- Admin endpoint to generate SCIM API tokens
- Per-org SCIM enable/disable configuration

---

## SIEM & Webhooks ✅
- Audit log export in JSON, CEF, and Syslog formats with date range and limit filters (PostgreSQL-only)
- Webhook CRUD: URL, event subscriptions, bcrypt-hashed secret
- Supported events: `org_member_added`, `org_member_removed`, `vault_accessed`, `password_reset`, `user_deleted`, etc.
- Webhook enable/disable toggle and test delivery endpoint
- Delivery tracking with status (`pending`/`delivered`/`failed`), response code, and retry attempts

---

## Electron Desktop App ✅
- Electron 41 with React 18 + Vite + TypeScript + Zustand state management
- **Sidecar architecture**: Spawns Go server binary on `127.0.0.1` with random port, writes port to lockfile for native host discovery
- Context isolation + sandbox + `nodeIntegration=false` — renderer has no direct Node.js access
- Preload script IPC bridge validates all messages
- CSP: `default-src 'self'`
- DevTools disabled in production builds
- **Biometric unlock**: Windows Hello / macOS Keychain — encrypted master key stored in OS keychain
- **Auto-lock**: Clears master key from memory after 15 minutes of inactivity
- **Clipboard**: Auto-clears after 30 seconds with OS-level exclusion flags (Windows `ExcludeClipboardContentFromMonitorProcessing`, macOS `org.nspasteboard.ConcealedType`)
- Client-side Argon2id (WASM) — all vault decryption happens in renderer
- Routes: `/login`, `/vault`, `/settings`, `/browser` (extension integration)
- QR code generation for 2FA setup and passkey registration
- Auto-update mechanism via `electron-updater`
- Platform builds: Windows `.exe` (NSIS installer), macOS `.dmg` (with entitlements), Linux AppImage

---

## Browser Extension ✅
- Chrome (Manifest V3) and Firefox (Manifest V2) support with `webextension-polyfill` for cross-browser compatibility
- **Content script**: Detects login forms, injects NeoPass autofill button via Shadow DOM (prevents page JS access)
- **Popup UI**: React-based quick search, credential list, copy-to-clipboard with 30-second auto-clear
- **Background service worker**: Routes messages between content script, popup, and native host
- **Native messaging**: Stdio-based protocol (4-byte length-prefixed JSON, 1 MB max) via `com.neopass.nativehost`
- Actions: `checkStatus`, `searchCredentials`, `saveCredential`, `updateCredential`, `secureCopy`, `verifyPassword`, passkey operations
- `escapeHtml` on all user data — no raw `innerHTML`
- Strict domain matching for credential autofill
- Permissions: `storage`, `webRequest`, `activeTab`, `scripting`

---

## Native Messaging Host ✅
- Standalone Go binary bridging browser extension ↔ Electron sidecar
- Reads sidecar port from lockfile (`~/.config/QuantumPasswordManager/.sidecar.lock`)
- Shared secret authentication (Bearer token) on all sidecar HTTP requests
- Structured logging (zerolog) to `nativehost.log` in app data directory
- Cross-platform clipboard support (Windows `clip.exe` / Unix `xclip`/`pbcopy`) with auto-clear timer
- Install scripts for Windows (PowerShell) and Unix (shell)

---

## Security Hardening ✅
- **TLS 1.3** minimum when `TLS_CERT` + `TLS_KEY` configured
- **Security headers**: HSTS (max-age=31536000, includeSubDomains), X-Content-Type-Options nosniff, X-Frame-Options DENY, Referrer-Policy no-referrer, Permissions-Policy (disabled features)
- **CORS**: Configurable allowed origins (no wildcard), preflight handling
- **CSRF**: Double-submit cookie pattern with constant-time comparison (skipped in sidecar mode)
- **Rate limiting**: 100/min general, 5/min auth, 10/min SSO — skipped in sidecar mode
- **Request size limit**: 1 MB body
- **Request timeout**: 30 seconds
- **Panic recovery**: Catches panics, returns generic HTTP 500 (no stack trace leakage)
- **Parameterized SQL**: pgx/sqlite with prepared statements — no SQL injection
- **Session management**: JWT with short-lived access + rotating refresh tokens
- **Audit logging**: All sensitive admin operations recorded with actor, target, action, details, timestamp

---

## Database ✅
- **PostgreSQL 16** for multi-user/enterprise deployments — pgx connection pool with parameterized queries
- **SQLite** for standalone single-user mode — `modernc.org/sqlite` (pure Go, no CGO)
- Repository interface pattern — all data access abstracted behind interfaces with PostgreSQL and SQLite implementations
- 16 sequential migrations covering: initial schema, admin/orgs, sync, passkeys, hardware keys, org key distribution, shared 2FA labels, vault UX (favorites/archive/trash), secure sends, collections, collection entry data, emergency access, token revocation, SSH keys, SSO, roles/groups/SIEM
- SQLite-specific migration set in `migrations/sqlite/`
- Auto-migration on server startup

---

## Testing ✅
- Go unit tests with mock repositories (`MockUserRepo`, `MockVaultRepo`, `MockOrgRepo`, `MockAuditRepo`)
- Test coverage: auth handler (register, login, duplicates, invalid credentials), vault handler (CRUD, soft delete, restore, favorites, archive), collections (permissions hierarchy), emergency access (full invite → recovery flow), secure send (creation, expiry, password protection, access count), crypto (KDF, encryption/decryption, passkeys), vault UX (folders, filtering, trash/purge)
- Electron UI tests (Vitest)
- Extension tests (content script injection, native messaging protocol)
- `make test` runs all suites, `make test-go` / `make test-electron` / `make test-extension` for targeted runs

---

## Infrastructure ✅
- **Docker**: Multi-stage build (Go 1.24-alpine builder → Alpine 3.20 runtime), non-root `appuser` (UID 1000), stripped binary (`-trimpath -s -w`), CGO disabled (static binary)
- **Docker Compose**: PostgreSQL 16-alpine + server on internal bridge network, persistent volume (`password-manager-pgdata`), DB health check (`pg_isready` every 3s), server health check (`/health` every 10s), memory limit 512M, CPU limit 1.0
- **Makefile targets**: `build-server`, `build-standalone`, `build-nativehost`, `build-electron`, `build-extension-{chrome,firefox,edge}`, `package-extensions`, `dist-electron{,-win,-mac,-linux}`, `test`, `lint`, `docker`, `docker-up`, `docker-down`, `migrate`, `clean`
- **Background goroutines**: Purge expired Secure Sends (hourly), auto-approve emergency access after wait period
- **Graceful shutdown**: SIGINT/SIGTERM handler with context cancellation
- **Logging**: zerolog structured JSON logging with configurable level (`LOG_LEVEL`)
- **Health endpoint**: `GET /health` for container orchestration
