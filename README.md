# LGI Pass — Quantum-Safe Password Manager

A post-quantum password manager featuring end-to-end encryption with hybrid classical/post-quantum cryptography, multi-device sync, browser extension autofill, and organization-level administration with escrow recovery.

## Architecture Overview

| Component | Technology | Description |
|-----------|-----------|-------------|
| **Backend** | Go 1.25 / chi router | REST API server with TLS, rate limiting, JWT auth |
| **Database** | PostgreSQL 16 | Vault storage, user accounts, audit log |
| **Desktop App** | Electron 41 / React 18 / Vite | Cross-platform desktop client with biometric unlock |
| **Browser Extension** | WebExtension (Chrome/Firefox/Edge) | Autofill, native messaging bridge |
| **Native Host** | Go binary (stdio) | Bridge between browser extension and sidecar/server |

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Electron    │────▶│  Go Server   │────▶│  PostgreSQL  │
│  Desktop App │     │  (API v1)    │     │              │
└──────────────┘     └──────┬───────┘     └──────────────┘
                            │
┌──────────────┐     ┌──────┴───────┐
│  Browser     │────▶│  Native Host │
│  Extension   │     │  (stdio)     │
└──────────────┘     └──────────────┘
```

## Cryptography

### Post-Quantum Algorithms

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Key Encapsulation (KEM) | **X-Wing** (X25519 + ML-KEM-768) | `github.com/cloudflare/circl/kem/xwing` |
| Digital Signatures | **ML-DSA-65** (FIPS 204) | `github.com/cloudflare/circl/sign/mldsa/mldsa65` |
| JWT Signing | **ML-DSA-65** (custom `jwt.SigningMethod`) | Custom adapter over circl |
| Symmetric Encryption | **AES-256-GCM** | Go stdlib `crypto/aes` + `crypto/cipher` |
| Key Derivation | **Argon2id** | `golang.org/x/crypto/argon2` |
| Key Stretching (KDF) | **SHAKE-256** (domain-separated) | `golang.org/x/crypto/sha3` |
| Password Verification | **bcrypt** (server-side double hash) | `golang.org/x/crypto/bcrypt` |

### Key Derivation (Argon2id)

Parameters (OWASP recommended):

| Parameter | Value |
|-----------|-------|
| Memory | 64 MB (`64 * 1024` KiB) |
| Iterations | 3 |
| Parallelism | 4 |
| Output Length | 64 bytes (32-byte master key + 32-byte auth hash) |
| Salt Size | 16 bytes (random) |

The master password is derived into two halves:
- **First 32 bytes** → Master Key (vault encryption, never leaves the client)
- **Last 32 bytes** → Auth Hash (sent to server, bcrypt-hashed server-side for storage)

### Hybrid KEM (X-Wing)

X-Wing combines X25519 (classical) and ML-KEM-768 (post-quantum) into a single KEM. Used for:
- User keypairs (public key stored on server, private key encrypted with master key)
- Organization keypairs (org private key encrypted with admin's master key)
- Escrow encryption (user master key encrypted with org public key via KEM)
- TOTP secret sharing between users

Session keys are derived from KEM shared secrets using SHAKE-256 with domain-separation strings (e.g., `"escrow-encryption"`, `"shared-2fa"`).

### JWT Authentication

- **Algorithm**: ML-DSA-65 (post-quantum digital signatures)
- **Access Token Duration**: 15 minutes (default)
- **Refresh Token Duration**: 7 days (default)
- **Signing Keypair**: Generated at server startup (ML-DSA-65 keypair)
- **2FA Partial Tokens**: `is_2fa` claim set to `true` — rejected by `AuthMiddleware` on protected routes

## API Endpoints

Base path: `/api/v1`

### Authentication (`/auth`)

Rate limited: **5 requests/minute per IP**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/register` | No | Register new user |
| `POST` | `/auth/login` | No | Login (returns JWT or 2FA challenge) |
| `POST` | `/auth/refresh` | No | Refresh access token |
| `POST` | `/auth/logout` | No | Logout / invalidate session |
| `POST` | `/auth/change-password` | Yes | Change password (self-service) |

### Two-Factor Authentication (`/auth/2fa`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/2fa/validate` | Temp | Validate TOTP/recovery code during login |
| `POST` | `/auth/2fa/sms/send` | Temp | Send SMS verification code |
| `POST` | `/auth/2fa/sms/validate` | Temp | Validate SMS code during login |
| `POST` | `/auth/2fa/setup` | Yes | Generate TOTP secret + recovery codes |
| `POST` | `/auth/2fa/verify-setup` | Yes | Confirm initial TOTP code |
| `POST` | `/auth/2fa/disable` | Yes | Disable 2FA |
| `POST` | `/auth/2fa/share` | Yes | Share TOTP secret with another user |
| `POST` | `/auth/2fa/claim/{id}` | Yes | Claim a shared TOTP secret |

### Vault (`/vault`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/vault/entries` | Yes | Create vault entry |
| `GET` | `/vault/entries` | Yes | List all vault entries |
| `GET` | `/vault/entries/{id}` | Yes | Get single vault entry |
| `PUT` | `/vault/entries/{id}` | Yes | Update vault entry |
| `DELETE` | `/vault/entries/{id}` | Yes | Delete vault entry |
| `POST` | `/vault/folders` | Yes | Create folder |
| `GET` | `/vault/folders` | Yes | List folders |
| `DELETE` | `/vault/folders/{id}` | Yes | Delete folder |

### Admin / Organizations (`/admin`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/my-org` | Yes | Get user's current organization |
| `GET` | `/admin/my-invitations` | Yes | Get pending invitations for user |
| `POST` | `/admin/orgs` | Yes | Create a new organization |
| `POST` | `/admin/orgs/{id}/leave` | Yes | Leave organization |
| `POST` | `/admin/orgs/{id}/invite` | Yes | Invite user to org (admin only) |
| `POST` | `/admin/orgs/{id}/accept` | Yes | Accept org invitation |
| `GET` | `/admin/orgs/{id}/members` | Yes | List org members (admin only) |
| `DELETE` | `/admin/orgs/{id}/members/{uid}` | Yes | Remove member (admin only) |
| `GET` | `/admin/orgs/{id}/vault/{uid}` | Yes | Access user vault via escrow (admin only) |
| `POST` | `/admin/orgs/{id}/vault/{uid}/reset-password` | Yes | Reset user password via escrow (admin only) |
| `GET` | `/admin/orgs/{id}/policy` | Yes | Get org security policy |
| `PUT` | `/admin/orgs/{id}/policy` | Yes | Update org security policy |
| `GET` | `/admin/orgs/{id}/invitations` | Yes | List org invitations |
| `GET` | `/admin/orgs/{id}/audit` | Yes | Get audit log |

### Sync (`/sync`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/sync/pull` | Yes | Pull changes since last sync |
| `POST` | `/sync/push` | Yes | Push local changes (returns conflicts) |
| `POST` | `/sync/resolve` | Yes | Resolve sync conflict (`keep_server`, `keep_client`, `merge`) |

### Extension Bridge (`/extension`)

Localhost-only, protected by shared secret (not under `/api/v1`):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/extension/session` | Push auth session from desktop app |
| `GET` | `/extension/status` | Get bridge status |
| `GET` | `/extension/credentials` | Get credentials for autofill |
| `POST` | `/extension/credentials` | Save new credential |
| `PUT` | `/extension/credentials/{id}` | Update credential |
| `POST` | `/extension/lock` | Lock the vault / clear session |

### Other

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/` | API version (`{"version":"1.0.0"}`) |

## Security Middleware

- **JWT Auth Middleware**: Validates Bearer tokens, rejects partial 2FA tokens on protected routes
- **Rate Limiter**: Per-IP sliding window rate limiting (configurable limit and window)
- **Request Timeout**: 30-second request timeout
- **CORS/CSP**: Content Security Policy enforced in Electron (desktop app)
- **Content-Type**: All responses set to `application/json`

## Database Schema

### Tables

| Table | Description |
|-------|-------------|
| `users` | User accounts with email, bcrypt auth hash, salt, KDF params, X-Wing keypair |
| `organizations` | Org name, X-Wing keypair (private key encrypted with admin master key), policy |
| `org_members` | Org membership with role (`admin`/`member`) and escrow blob |
| `folders` | Encrypted folder names, hierarchical via `parent_id` |
| `vault_entries` | Encrypted vault entries (AES-256-GCM), typed (`login`, `secure_note`, `credit_card`, `identity`), versioned, soft-delete |
| `totp_secrets` | Encrypted TOTP secrets per user |
| `shared_2fa` | Time-limited TOTP sharing between users (KEM-encrypted) |
| `recovery_codes` | bcrypt-hashed recovery codes (8 codes per user) |
| `sessions` | Session tracking with hashed tokens and device info |
| `audit_log` | Actor/target/action audit trail with JSONB details |
| `sync_cursors` | Per-user per-device sync timestamps |
| `invitations` | Org invitations with role and acceptance status |

### Migrations

- `001_initial.sql` — Core schema: users, orgs, vault entries, folders, TOTP, sessions, audit log, sync cursors
- `002_admin.sql` — Policy column on organizations, invitations table
- `003_sync.sql` — Soft-delete flag (`is_deleted`) on vault entries

## Device Switching & Biometric Unlock

### Switching Devices

Users will **not** lose access when switching devices. The master key is **never stored permanently** — it is **re-derived** from the master password every time you log in:

```
Master Password → Argon2id KDF → 64 bytes
    ├─ First 32 bytes = Master Key (encrypts/decrypts vault)
    └─ Last 32 bytes = Auth Hash (sent to server for login)
```

Since the encrypted vault lives in the **database on the server**, all a user needs is their **email + master password** on any new device. The KDF produces the same master key deterministically, and the vault data is fetched from the server and decrypted locally. Nothing device-specific is required.

### Biometric Unlock (Windows Hello / Touch ID)

Biometrics are a **convenience shortcut**, not the source of truth. When biometric unlock is enabled:

1. The user's email + derived 64-byte key are encrypted with a random AES-256-GCM "biometric key"
2. That biometric key is protected by **Electron safeStorage** (Windows DPAPI / macOS Keychain)
3. The encrypted blob is written to disk (`biometric_vault.enc` in the app data directory)

When you biometric-unlock, the OS verifies your fingerprint/face → Electron decrypts the biometric key → that decrypts your cached credentials → logs you in automatically.

**This is device-local only.** If you switch devices:
- You log in with email + master password (works everywhere)
- You optionally re-enable biometric unlock on the new device
- The old device's biometric blob is irrelevant

### What the Database Stores for Auth

| Field | Contents |
|-------|----------|
| `email` | Login identifier |
| `auth_hash` | **bcrypt hash** of the Argon2id auth hash (double-hashed — server never sees the master key half) |
| `salt` | Random 16-byte Argon2id salt |
| `encrypted_data` + `nonce` | Vault entries encrypted with the user's master key (AES-256-GCM) |
| `public_key` | X-Wing public key (for KEM-based sharing and escrow) |
| `encrypted_private_key` | X-Wing private key encrypted with the master key |

The database does **not** store biometrics, device passwords, or fingerprint data. Biometrics are handled entirely by the OS (Windows Hello / Touch ID) on each device — the server never knows about them.

## Two-Factor Authentication

### TOTP
- **Issuer**: `QuantumPasswordManager`
- **Library**: `github.com/pquerna/otp`
- **Storage**: TOTP secret encrypted with user's master key (AES-256-GCM)
- **Recovery**: 8 recovery codes (8 chars each), bcrypt-hashed server-side
- **Sharing**: TOTP secrets can be shared between users via X-Wing KEM encryption with time-limited expiry

### SMS (Telnyx)
- **Provider**: Telnyx API (`https://api.telnyx.com/v2/messages`)
- **Code**: 6-digit numeric code
- **Expiry**: 5 minutes
- **Cleanup**: Background goroutine cleans expired codes every minute
- **Toggle**: Enabled via `ENABLE_SMS_2FA=true` environment variable

## Sync Protocol

The sync system uses **optimistic concurrency control** with version-based conflict detection:

1. **Pull**: Fetch all entries changed since the client's last sync timestamp; update server-side sync cursor
2. **Push**: Submit local changes with `base_version`; server checks for version mismatches
3. **Conflicts**: When `server_version != base_version`, the entry is returned as a conflict with both server and client data
4. **Resolution**: Client resolves via `keep_server`, `keep_client`, or `merge` (with new encrypted data)

Wire format uses hex-encoded encrypted data and nonces. Soft-deleted entries are synced with `is_deleted: true`.

## Organization & Admin Features

- **Create Organization**: Generates an X-Wing keypair for the org; admin's master key encrypts the org private key
- **Escrow System**: Each member's master key is encrypted with the org public key (KEM) and stored as an escrow blob
- **Admin Vault Access**: Admin decrypts org private key → decrypts member's escrow → gets member's master key → decrypts vault entries. **Always audit-logged**.
- **Password Reset**: Admin can re-encrypt all of a user's vault entries with a new master key via escrow
- **Org Policy**: JSON policy with `require_2fa`, `min_password_length`, `rotation_days`
- **Invitation System**: Email-based invitations with role assignment
- **Audit Log**: All admin actions logged with actor, target, action, and details

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8443` | Server listen port |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `MIGRATIONS_DIR` | `"migrations"` | Path to SQL migration files |
| `TLS_CERT` | — | TLS certificate file path |
| `TLS_KEY` | — | TLS private key file path |
| `LOG_LEVEL` | `"info"` | Log level (`debug`, `info`, `warn`, `error`) |
| `SIDECAR_MODE` | — | Set to `"1"` to enable sidecar mode (Electron-managed server) |
| `EXTENSION_SECRET` | — | Shared secret for extension bridge auth (auto-generated in sidecar mode) |
| `ENABLE_SMS_2FA` | `"false"` | Set to `"true"` to enable SMS 2FA via Telnyx |
| `TELNYX_API_KEY` | — | Telnyx API key for SMS 2FA |
| `TELNYX_FROM_NUMBER` | — | Telnyx sender phone number or messaging profile ID |

## Getting Started

### Prerequisites

- **Go** 1.25+
- **Node.js** 18+ and npm
- **PostgreSQL** 16+ (or Docker)
- **Docker & Docker Compose** (optional, for containerized deployment)

### Quick Start (Docker)

```bash
# Start PostgreSQL + API server
docker compose up --build

# Server available at http://localhost:8444
# Internally runs on port 8443
```

### Manual Backend Setup

```bash
# Start PostgreSQL (or use an existing instance)
export DATABASE_URL="postgres://pmuser:pmpass_dev_only@localhost:5432/password_manager?sslmode=disable"
export PORT=8443
export MIGRATIONS_DIR=migrations
export LOG_LEVEL=debug

# Run the server
go run ./cmd/server/main.go
```

### Desktop App (Electron)

```bash
cd electron
npm install

# Development (with hot-reload)
npm run dev

# Production build
npm run build

# Start with backend URL
cross-env BACKEND_URL=http://localhost:8444 npm start

# Package for distribution
npm run dist           # Current platform
npm run dist:win       # Windows (NSIS installer)
npm run dist:mac       # macOS (DMG)
npm run dist:linux     # Linux (AppImage)
```

### Browser Extension

```bash
cd extension
npm install

# Development (Chrome, with watch)
npm run dev

# Production builds
npm run build:chrome
npm run build:firefox
npm run build:edge
```

### Native Messaging Host

Install the native messaging host so the browser extension can communicate with the desktop app:

**Linux / macOS:**
```bash
./scripts/install-native-host.sh [binary_path] [chrome_extension_id]
```

**Windows (PowerShell):**
```powershell
.\scripts\install-native-host.ps1 [-BinaryPath path] [-ExtensionID id]
```

The installer:
- Copies the binary to the platform-specific app data directory
- Generates Chrome/Chromium/Edge and Firefox native messaging manifests
- On Windows, registers manifests in `HKCU` registry keys for Chrome, Edge, and Firefox
- Native host name: `com.quantum.passwordmanager`

## Docker

### Dockerfile

Multi-stage build:
1. **Builder**: `golang:1.24-alpine` — downloads dependencies, compiles Go binary with `CGO_ENABLED=0`
2. **Runtime**: `alpine:3.20` — minimal image with `ca-certificates` and `tzdata`, runs as non-root `appuser` (UID 1000)

### docker-compose.yml

| Service | Image | Ports | Notes |
|---------|-------|-------|-------|
| `postgres` | `postgres:16-alpine` | internal only | Health-checked, persistent volume `pgdata` |
| `server` | custom (Dockerfile) | `8444:8443` | Auto-runs migrations, depends on healthy postgres |

## Desktop App Features

- **Window**: 1200×800 (min 800×600), frameless title bar, dark theme (`#020617`)
- **Sidecar Mode**: Electron can spawn the Go server binary as a child process on a random high port
- **Biometric Unlock**: Windows Hello, macOS Touch ID support via `electron.systemPreferences`
- **Extension Bridge**: Pushes auth session to sidecar so browser extension can fetch credentials
- **Lockfile**: Writes `sidecar.lock` to app data dir for extension discovery
- **Security**: Context isolation, sandbox enabled, CSP headers, no `nodeIntegration`

### App Routes

| Route | Page | Auth Required |
|-------|------|--------------|
| `/login` | Login | No |
| `/register` | Register | No |
| `/vault` | Vault list | Yes |
| `/vault/:id` | Entry detail | Yes |
| `/settings` | Settings | Yes |
| `/admin` | Admin panel | Yes (admin role) |

### Key Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `react` | 18.3 | UI framework |
| `react-router-dom` | 6.23 | Client-side routing |
| `zustand` | 4.5 | State management |
| `tailwindcss` | 3.4 | Utility-first CSS |
| `vite` | 5.3 | Build tool / dev server |
| `electron` | 41.2 | Desktop shell |
| `electron-builder` | 26.8 | Packaging / distribution |

## Browser Extension

- **Targets**: Chrome, Firefox, Edge (separate manifests per browser)
- **Stack**: React 18, TypeScript, Webpack 5, Tailwind CSS
- **Polyfill**: `webextension-polyfill` for cross-browser compatibility
- **Components**: Background service worker, content script (autofill), popup UI
- **Native Messaging**: Communicates with native host binary (`com.quantum.passwordmanager`) via stdio

## Project Structure

```
├── cmd/
│   ├── server/main.go           # API server entry point
│   └── nativehost/main.go       # Browser extension native messaging host
├── internal/
│   ├── admin/                   # Organization & admin service
│   ├── api/                     # HTTP handlers, routes, middleware
│   ├── auth/                    # JWT (ML-DSA-65), TOTP, SMS 2FA
│   ├── config/                  # Environment-based configuration
│   ├── crypto/                  # X-Wing KEM, ML-DSA-65, AES-256-GCM, Argon2id
│   ├── db/                      # PostgreSQL repositories (pgx)
│   ├── sync/                    # Multi-device sync with conflict resolution
│   └── vault/                   # Vault CRUD service
├── migrations/                  # PostgreSQL migration SQL files
├── electron/                    # Desktop app (Electron + React + Vite)
│   └── src/
│       ├── main/                # Electron main process, biometric, preload
│       └── renderer/            # React UI (pages, components, stores)
├── extension/                   # Browser extension (Chrome/Firefox/Edge)
│   └── src/
│       ├── background/          # Service worker
│       ├── content/             # Content script + autofill
│       ├── popup/               # Extension popup UI
│       └── lib/                 # Shared browser API + messaging
├── bin/                         # Pre-built native host binaries
├── scripts/                     # Native host installers (bash + PowerShell)
├── Dockerfile                   # Multi-stage Go build
├── docker-compose.yml           # PostgreSQL + server
└── go.mod                       # Go module definition
```

## License

Copyright © 2026
