# LGI Pass — Quantum-Safe Password Manager

A post-quantum password manager featuring end-to-end encryption with hybrid classical/post-quantum cryptography, multi-device sync, browser extension autofill, and organization-level administration with escrow recovery.

## Architecture Overview

| Component | Technology | Description |
|-----------|-----------|-------------|
| **Backend** | Go 1.25 / chi router | REST API server with TLS, rate limiting, JWT auth |
| **Database** | PostgreSQL 16 / SQLite | Vault storage, user accounts, audit log (SQLite for standalone/dev) |
| **Desktop App** | Electron 41 / React 18 / Vite | Cross-platform desktop client with biometric unlock |
| **Browser Extension** | WebExtension (Chrome/Firefox/Edge) | Autofill, native messaging bridge |
| **Native Host** | Go binary (stdio) | Bridge between browser extension and sidecar/server |

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Electron    │────▶│  Go Server   │────▶│  PostgreSQL  │
│  Desktop App │     │  (API v1)    │     │  or SQLite   │
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
| `POST` | `/auth/require-hardware-key` | Yes | Set hardware key enforcement |
| `GET` | `/auth/security-settings` | Yes | Get security settings |

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
| `DELETE` | `/vault/entries/{id}` | Yes | Delete vault entry (soft-delete to trash) |
| `PUT` | `/vault/entries/{id}/favorite` | Yes | Toggle favorite |
| `PUT` | `/vault/entries/{id}/archive` | Yes | Toggle archive |
| `POST` | `/vault/entries/{id}/restore` | Yes | Restore from trash |
| `DELETE` | `/vault/entries/{id}/permanent` | Yes | Permanently delete (purge) |
| `POST` | `/vault/entries/{id}/clone` | Yes | Clone vault entry |
| `GET` | `/vault/entries/{id}/collections` | Yes | Get entry's collections |
| `POST` | `/vault/trash/purge` | Yes | Purge all trash |
| `POST` | `/vault/folders` | Yes | Create folder |
| `GET` | `/vault/folders` | Yes | List folders |
| `DELETE` | `/vault/folders/{id}` | Yes | Delete folder |

Supported entry types: `login`, `secure_note`, `credit_card`, `identity`, `ssh_key`

### Passkeys & Hardware Keys (`/vault/passkeys`, `/auth/hardware-keys`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/vault/passkeys` | Yes | List website passkeys for RP |
| `DELETE` | `/vault/passkeys/{id}` | Yes | Delete passkey |
| `POST` | `/vault/passkeys/register/begin` | Yes | Begin WebAuthn passkey registration |
| `POST` | `/vault/passkeys/register/finish` | Yes | Finish passkey registration |
| `POST` | `/vault/passkeys/authenticate/begin` | Yes | Begin passkey authentication |
| `POST` | `/vault/passkeys/authenticate/finish` | Yes | Finish passkey authentication |
| `GET` | `/auth/hardware-keys` | Yes | List hardware auth keys |
| `DELETE` | `/auth/hardware-keys/{id}` | Yes | Delete hardware key |
| `POST` | `/auth/hardware-keys/register/begin` | Yes | Begin hardware key registration |
| `POST` | `/auth/hardware-keys/register/finish` | Yes | Finish hardware key registration |
| `POST` | `/auth/hardware-keys/authenticate/begin` | Yes | Begin hardware key authentication |
| `POST` | `/auth/hardware-keys/authenticate/finish` | Yes | Finish hardware key authentication |
| `GET` | `/fido/metadata` | No | Public FIDO metadata |

### Admin / Organizations (`/admin`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/admin/test-pg-connection` | Yes | Test PostgreSQL connection (for migration) |
| `POST` | `/admin/migrate-to-postgres` | Yes | Migrate data from SQLite to PostgreSQL |
| `GET` | `/admin/my-org` | Yes | Get user's current organization |
| `GET` | `/admin/my-invitations` | Yes | Get pending invitations for user |
| `POST` | `/admin/orgs` | Yes | Create a new organization |
| `POST` | `/admin/orgs/{id}/leave` | Yes | Leave organization |
| `POST` | `/admin/orgs/{id}/invite` | Yes | Invite user to org (admin only) |
| `POST` | `/admin/orgs/{id}/accept` | Yes | Accept org invitation |
| `GET` | `/admin/orgs/{id}/members` | Yes | List org members (admin only) |
| `DELETE` | `/admin/orgs/{id}/members/{uid}` | Yes | Remove member (admin only) |
| `PUT` | `/admin/orgs/{id}/members/{uid}/role` | Yes | Set member's role (admin only) |
| `GET` | `/admin/orgs/{id}/vault/{uid}` | Yes | Access user vault via escrow (admin only) |
| `POST` | `/admin/orgs/{id}/vault/{uid}/reset-password` | Yes | Reset user password via escrow (admin only) |
| `GET` | `/admin/orgs/{id}/policy` | Yes | Get org security policy |
| `PUT` | `/admin/orgs/{id}/policy` | Yes | Update org security policy |
| `GET` | `/admin/orgs/{id}/invitations` | Yes | List org invitations |
| `GET` | `/admin/orgs/{id}/audit` | Yes | Get audit log |

### Roles (`/admin/orgs/{id}/roles`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/orgs/{id}/roles` | Yes | List roles |
| `POST` | `/admin/orgs/{id}/roles` | Yes | Create custom role |
| `PUT` | `/admin/orgs/{id}/roles/{roleId}` | Yes | Update role |
| `DELETE` | `/admin/orgs/{id}/roles/{roleId}` | Yes | Delete role |

### Groups (`/admin/orgs/{id}/groups`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/orgs/{id}/groups` | Yes | List groups |
| `POST` | `/admin/orgs/{id}/groups` | Yes | Create group |
| `PUT` | `/admin/orgs/{id}/groups/{gid}` | Yes | Update group |
| `DELETE` | `/admin/orgs/{id}/groups/{gid}` | Yes | Delete group |
| `GET` | `/admin/orgs/{id}/groups/{gid}/members` | Yes | List group members |
| `POST` | `/admin/orgs/{id}/groups/{gid}/members` | Yes | Add member to group |
| `DELETE` | `/admin/orgs/{id}/groups/{gid}/members/{uid}` | Yes | Remove member from group |

### Sync (`/sync`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/sync/pull` | Yes | Pull changes since last sync |
| `POST` | `/sync/push` | Yes | Push local changes (returns conflicts) |
| `POST` | `/sync/resolve` | Yes | Resolve sync conflict (`keep_server`, `keep_client`, `merge`) |

### Secure Send (`/sends`)

Time-limited encrypted sharing via unique links. Supports text and file (up to 100 MB) with optional password protection and max access count.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/sends` | Yes | Create secure send |
| `GET` | `/sends` | Yes | List user's sends |
| `DELETE` | `/sends/{id}` | Yes | Delete send |
| `PUT` | `/sends/{id}/disable` | Yes | Disable send (revoke access) |
| `GET` | `/send/{slug}` | No | Access send (public page) |
| `POST` | `/send/{slug}/access` | No | Access send with password |

### Collections (`/collections`)

Shared vaults within an organization with per-member permissions (`read`, `write`, `manage`).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/collections` | Yes | List user's collections |
| `POST` | `/collections` | Yes | Create collection |
| `GET` | `/collections/{id}` | Yes | Get collection |
| `PUT` | `/collections/{id}` | Yes | Update collection |
| `DELETE` | `/collections/{id}` | Yes | Delete collection |
| `POST` | `/collections/{id}/members` | Yes | Add member to collection |
| `GET` | `/collections/{id}/members` | Yes | List collection members |
| `DELETE` | `/collections/{id}/members/{uid}` | Yes | Remove member |
| `PUT` | `/collections/{id}/members/{uid}/permission` | Yes | Update member permission |
| `POST` | `/collections/{id}/entries` | Yes | Add entry to collection |
| `GET` | `/collections/{id}/entries` | Yes | List collection entries |
| `DELETE` | `/collections/{id}/entries/{entryId}` | Yes | Remove entry from collection |
| `POST` | `/orgs/{orgId}/collections` | Yes | Create org collection |
| `GET` | `/orgs/{orgId}/collections` | Yes | List org collections |
| `GET` | `/orgs/{orgId}/collections/{collId}/groups` | Yes | List collection groups |
| `POST` | `/orgs/{orgId}/collections/{collId}/groups` | Yes | Add group to collection |
| `DELETE` | `/orgs/{orgId}/collections/{collId}/groups/{gid}` | Yes | Remove group from collection |

### Emergency Access (`/emergency-access`)

Trusted contacts can request vault access after a configurable waiting period.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/emergency-access/invite` | Yes | Invite trusted contact |
| `GET` | `/emergency-access/granted` | Yes | List access I granted to others |
| `GET` | `/emergency-access/trusted` | Yes | List contacts who trust me |
| `POST` | `/emergency-access/{id}/accept` | Yes | Accept invitation |
| `GET` | `/emergency-access/{id}/public-key` | Yes | Get grantee's public key |
| `POST` | `/emergency-access/{id}/confirm` | Yes | Confirm emergency contact (encrypt key) |
| `POST` | `/emergency-access/{id}/initiate` | Yes | Initiate recovery (start wait period) |
| `POST` | `/emergency-access/{id}/approve` | Yes | Approve recovery request |
| `POST` | `/emergency-access/{id}/reject` | Yes | Reject recovery request |
| `GET` | `/emergency-access/{id}/vault` | Yes | Get vault after recovery approved |
| `POST` | `/emergency-access/{id}/takeover` | Yes | Takeover account (full access) |
| `DELETE` | `/emergency-access/{id}` | Yes | Delete emergency access |

### SSO (`/sso`) — PostgreSQL only

Single Sign-On via SAML or OIDC identity providers.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/sso/{orgId}/login` | No | Initiate SSO login (redirects to IdP) |
| `POST` | `/sso/{orgId}/callback` | No | Handle IdP callback (SAML/OIDC) |
| `POST` | `/sso/{orgId}/unlock` | No | Account unlock via SSO |
| `GET` | `/admin/orgs/{id}/sso` | Yes | Get SSO config (admin only) |
| `PUT` | `/admin/orgs/{id}/sso` | Yes | Set SSO config (admin only) |

### SCIM 2.0 (`/scim`) — PostgreSQL only

Automated user provisioning via SCIM 2.0 protocol, authenticated with bearer token.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/scim/v2/{orgId}/Users` | Bearer | List users |
| `POST` | `/scim/v2/{orgId}/Users` | Bearer | Create user |
| `GET` | `/scim/v2/{orgId}/Users/{id}` | Bearer | Get user |
| `PUT` | `/scim/v2/{orgId}/Users/{id}` | Bearer | Update user |
| `PATCH` | `/scim/v2/{orgId}/Users/{id}` | Bearer | Patch user |
| `DELETE` | `/scim/v2/{orgId}/Users/{id}` | Bearer | Delete user |
| `POST` | `/admin/orgs/{id}/scim/generate-token` | Yes | Generate SCIM API token |
| `GET` | `/admin/orgs/{id}/scim` | Yes | Get SCIM config |
| `PUT` | `/admin/orgs/{id}/scim` | Yes | Set SCIM config |

### SIEM & Webhooks (`/admin/orgs/{id}`) — PostgreSQL only

Event export and real-time webhook delivery for security monitoring.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/orgs/{id}/events/export` | Yes | Export audit events (JSON/CEF/Syslog) |
| `GET` | `/admin/orgs/{id}/webhooks` | Yes | List webhooks |
| `POST` | `/admin/orgs/{id}/webhooks` | Yes | Create webhook |
| `DELETE` | `/admin/orgs/{id}/webhooks/{webhookId}` | Yes | Delete webhook |
| `PUT` | `/admin/orgs/{id}/webhooks/{webhookId}/toggle` | Yes | Enable/disable webhook |
| `POST` | `/admin/orgs/{id}/webhooks/{webhookId}/test` | Yes | Test webhook delivery |

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
| `users` | User accounts with email, bcrypt auth hash, salt, KDF params, X-Wing keypair, hardware key enforcement, SSO external ID, token revocation timestamp |
| `organizations` | Org name, X-Wing keypair, policy, SSO config (SAML/OIDC), SCIM config |
| `org_members` | Org membership with role (`admin`/`member`), escrow blob, per-admin encrypted org key, role assignment |
| `folders` | Encrypted folder names, hierarchical via `parent_id` |
| `vault_entries` | Encrypted vault entries (AES-256-GCM), typed (`login`, `secure_note`, `credit_card`, `identity`, `ssh_key`), versioned, favorites, archive, soft-delete with trash expiry |
| `totp_secrets` | Encrypted TOTP secrets per user |
| `shared_2fa` | Time-limited TOTP sharing between users (KEM-encrypted) with service label |
| `recovery_codes` | bcrypt-hashed recovery codes (8 codes per user) |
| `sessions` | Session tracking with hashed tokens and device info |
| `audit_log` | Actor/target/action audit trail with JSONB details |
| `sync_cursors` | Per-user per-device sync timestamps |
| `invitations` | Org invitations with role and acceptance status |
| `passkey_credentials` | WebAuthn passkeys stored in vault for website authentication |
| `hardware_auth_keys` | Hardware security keys for vault login 2FA |
| `sends` | Secure Send shares — time-limited encrypted data via unique slugs, optional password, max access count |
| `collections` | Shared vaults within an organization with encrypted names |
| `collection_members` | Per-member collection access with encrypted key and permission (`read`/`write`/`manage`) |
| `collection_entries` | Junction table linking entries to collections with per-collection encrypted data |
| `emergency_access` | Trusted contact emergency access with configurable wait period and access type (`view`/`takeover`) |
| `roles` | Custom organization roles with granular JSONB permissions |
| `groups` | User groups for bulk collection assignment |
| `group_members` | Group membership |
| `collection_groups` | Groups assigned to collections with permission level |
| `webhooks` | SIEM integration webhooks with event filtering |
| `webhook_deliveries` | Webhook delivery tracking with retry status |

### Migrations

**PostgreSQL** (`migrations/`):
- `001_initial.sql` — Core schema: users, orgs, vault entries, folders, TOTP, sessions, audit log, sync cursors
- `002_admin.sql` — Policy column on organizations, invitations table
- `003_sync.sql` — Soft-delete flag (`is_deleted`) on vault entries
- `004_passkeys.sql` — WebAuthn passkey credentials and hardware auth keys tables
- `005_hw_key_enforcement.sql` — `require_hw_key` flag on users
- `006_admin_org_key.sql` — Per-admin `encrypted_org_key` on org members
- `007_shared_2fa_label.sql` — Service label on shared 2FA entries
- `008_vault_ux.sql` — Favorites, archive, and trash (with `deleted_at` timestamp) on vault entries
- `009_secure_send.sql` — Sends table for time-limited encrypted sharing
- `010_collections.sql` — Collections, collection members, and collection entries tables
- `011_collection_entry_data.sql` — Per-collection encrypted data on collection entries
- `012_emergency_access.sql` — Emergency access table with wait period and access types
- `013_token_revocation.sql` — `tokens_revoked_at` column on users for JWT invalidation
- `014_ssh_keys.sql` — `ssh_key` entry type added to vault entries
- `015_sso.sql` — SSO config (SAML/OIDC) and SCIM support on organizations, SSO external ID on users
- `016_roles_groups_siem.sql` — Custom roles, groups, group members, collection groups, webhooks, and webhook deliveries

**SQLite** (`migrations/sqlite/`):
- `001_initial.sql` — Combined schema (all tables in one migration, SQLite-compatible syntax)

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
- **Multi-Admin Support**: Per-admin encrypted org key so any admin can decrypt the org private key for vault access
- **Admin Vault Access**: Admin decrypts org private key → decrypts member's escrow → gets member's master key → decrypts vault entries. **Always audit-logged**.
- **Password Reset**: Admin can re-encrypt all of a user's vault entries with a new master key via escrow
- **Org Policy**: JSON policy with `require_2fa`, `min_password_length`, `rotation_days`
- **Invitation System**: Email-based invitations with role assignment
- **Custom Roles**: Granular JSONB permissions for fine-grained access control beyond admin/member
- **Groups**: User groups for bulk collection assignment and management
- **Audit Log**: All admin actions logged with actor, target, action, and details
- **Token Revocation**: `tokens_revoked_at` timestamp invalidates all JWTs issued before that time

## Collections (Shared Vaults)

- **Per-Org Collections**: Encrypted shared vaults within an organization
- **Permissions**: Per-member access levels — `read`, `write`, or `manage`
- **Group Assignment**: Assign entire groups to collections with permission levels
- **Per-Collection Encryption**: Entries re-encrypted with collection-specific keys for secure sharing
- **Multi-Collection Entries**: A single vault entry can belong to multiple collections

## Secure Send

- **Time-Limited Sharing**: Share encrypted text or files via unique links with configurable expiry (max 720 hours)
- **Password Protection**: Optional bcrypt-hashed password for additional access control
- **Max Access Count**: Configurable maximum number of accesses before the link is disabled
- **File Support**: Up to 100 MB file attachments
- **Hide Email**: Option to hide sender's email from recipients
- **Disable/Revoke**: Senders can disable active sends at any time

## Emergency Access

- **Trusted Contacts**: Designate trusted contacts who can request vault access in emergencies
- **Configurable Wait Period**: Set a waiting period (in days) before recovery is granted
- **Access Types**: `view` (read-only vault access) or `takeover` (full account takeover)
- **Approval Flow**: Grantor can approve or reject recovery requests during the wait period
- **Auto-Approve**: If the grantor does not respond within the wait period, access is automatically granted
- **KEM-Encrypted Keys**: Emergency keys encrypted with the grantee's X-Wing public key

## SSO & SCIM (Enterprise)

- **SSO Providers**: SAML and OIDC identity provider integration per organization
- **Auto-Enrollment**: Optionally auto-enroll new SSO users into the organization
- **SCIM 2.0**: Automated user provisioning and deprovisioning via SCIM protocol
- **SCIM Authentication**: Bearer token authentication (bcrypt-hashed token stored server-side)

## SIEM & Webhooks

- **Event Export**: Export audit events in JSON, CEF, or Syslog format
- **Webhooks**: Real-time event delivery to external security monitoring systems
- **Event Filtering**: Configure which events trigger each webhook (default: all)
- **Delivery Tracking**: Track webhook delivery status, response codes, and retry attempts

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8443` | Server listen port |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `MIGRATIONS_DIR` | `"migrations"` | Path to SQL migration files |
| `TLS_CERT` | — | TLS certificate file path |
| `TLS_KEY` | — | TLS private key file path |
| `LOG_LEVEL` | `"info"` | Log level (`debug`, `info`, `warn`, `error`) |
| `CORS_ORIGINS` | — | Comma-separated allowed CORS origins (no wildcard in production) |
| `SIDECAR_MODE` | — | Set to `"1"` to enable sidecar mode (Electron-managed server) |
| `EXTENSION_SECRET` | — | Shared secret for extension bridge auth (auto-generated in sidecar mode) |
| `STORAGE_BACKEND` | `"postgres"` | Storage backend: `"postgres"` or `"sqlite"` |
| `SQLITE_DB_PATH` | Platform app data dir | Path to SQLite database file (used when `STORAGE_BACKEND=sqlite`) |
| `ENABLE_SMS_2FA` | `"false"` | Set to `"true"` to enable SMS 2FA via Telnyx |
| `TELNYX_API_KEY` | — | Telnyx API key for SMS 2FA |
| `TELNYX_FROM_NUMBER` | — | Telnyx sender phone number or messaging profile ID |

## Getting Started

### Prerequisites

- **Go** 1.25+
- **Node.js** 18+ and npm
- **PostgreSQL** 16+ (or Docker) — not required when using SQLite backend
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

### Standalone Setup (SQLite)

No PostgreSQL required — uses a local SQLite database:

```bash
export STORAGE_BACKEND=sqlite
export SQLITE_DB_PATH="$HOME/.config/QuantumPasswordManager/vault.db"
export PORT=8443
export LOG_LEVEL=debug

go run ./cmd/server/main.go
```

On Windows (PowerShell):
```powershell
$env:STORAGE_BACKEND = "sqlite"
$env:SQLITE_DB_PATH = "$env:APPDATA\QuantumPasswordManager\vault.db"
$env:PORT = "8443"
go run ./cmd/server/main.go
```

> **Note:** Organization/admin features return `501 Not Implemented` on the SQLite backend. Use the Settings page to migrate to PostgreSQL when ready.

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

## Testing

All tests are centralized in the `testing/` directory. The suite covers Go backend, Electron desktop app, and browser extension.

### Run All Tests

```bash
# Go backend tests (crypto, auth, vault, admin, collections, emergency access, sends, vault UX — 83 tests)
go test -v ./testing/...

# Electron tests (IPC crypto, login flow, biometric — 18 tests)
cd electron && npm test

# Extension tests (autofill, native messaging — 27 tests)
cd extension && npx jest --config ../testing/extension/jest.config.js --rootDir ../testing/extension
```

### Go Backend Tests (`testing/`)

Run with race detector and coverage:
```bash
go test -race -coverprofile=coverage.out ./testing/...
```

| File | Tests | Description |
|------|-------|-------------|
| `crypto_test.go` | 20 + 2 benchmarks | KDF determinism, AES-256-GCM round-trip/tamper, X-Wing KEM exchange, ML-DSA-65 sign/verify, escrow, re-encrypt org key, ZeroBytes |
| `auth_handler_test.go` | 8 | Register success/duplicate, login success/wrong password/2FA, rate limiting (429 on 6th attempt), refresh valid/expired |
| `vault_handler_test.go` | 9 | Create/get/update/delete entries, list with filters, unauthorized access, invalid type, folder CRUD |
| `admin_service_test.go` | 7 | Create org, access vault as admin/non-admin, change password, audit log, invite+accept, leave org |
| `vault_ux_test.go` | 7 | Favorite set/unset, archive set/unset, trash delete/restore, permanent delete, auto-purge, clone entry, list filters |
| `collection_handler_test.go` | 8 | Create collection, add member, read/write/manage permissions, delete collection, list empty/with membership |
| `emergency_access_test.go` | 12 | Invite/accept flow, initiate/approve/reject recovery, auto-approve, takeover, delete, list granted/trusted, handler tests |
| `send_handler_test.go` | 11 | Create text send, access success/expired/max-count, password protection (with/without/wrong), list, delete, disable, purge |

Tests use in-memory mock repositories (`mocks.go`) — no database required. Benchmarks:
```bash
go test -bench=. -benchmem ./testing/...
```

### Electron Tests (`testing/electron/`)

Included in the electron vitest config and run via `npm test` from the `electron/` directory:

| File | Tests | Description |
|------|-------|-------------|
| `crypto.test.ts` | 8 | IPC encrypt/decrypt round-trip, auth login, vault list, biometric availability, clipboard |
| `login.spec.ts` | 10 | Login with valid/invalid credentials, 2FA flow, vault loading + decryption, biometric unlock/not-configured |

### Extension Tests (`testing/extension/`)

Run from the `extension/` directory:
```bash
cd extension
npx jest --config ../testing/extension/jest.config.js --rootDir ../testing/extension
```

| File | Tests | Description |
|------|-------|-------------|
| `autofill.test.ts` | 10 | Standard login form detection, SPA forms without `<form>` tag, MutationObserver dynamic form insertion, field value setting with native setter + event dispatch, no false positives on search forms |
| `native-messaging.test.ts` | 17 | JSON message serialization, 4-byte length-prefix encoding, credential request/response flow, ping/status/lock/save actions, timeout handling, domain matching (exact, subdomain, spoofing prevention) |

### CI

All tests run automatically on push to `main` and pull requests via GitHub Actions (`.github/workflows/ci.yml`):

| Job | Runner | Description |
|-----|--------|-------------|
| `go-lint` | ubuntu | golangci-lint |
| `go-security` | ubuntu | gosec security scanning |
| `go-test` | ubuntu | `go test -race` with coverage upload |
| `go-build` | ubuntu | Cross-compile (linux, darwin, darwin-arm64, windows) |
| `docker` | ubuntu | Docker build + health endpoint verification |
| `electron-lint` | ubuntu | ESLint |
| `electron-test` | ubuntu | Vitest (includes `testing/electron/`) |
| `electron-build` | ubuntu | Vite production build |
| `release-windows` | windows | NSIS installer (`.exe`) |
| `release-mac` | macos | DMG installer |
| `release-linux` | ubuntu | AppImage + `.deb` |
| `extension-lint` | ubuntu | ESLint |
| `extension-test` | ubuntu | Jest + integration tests from `testing/extension/` |
| `extension-build` | ubuntu | Build + zip for Chrome, Firefox, Edge |

## Docker

### Dockerfile

Multi-stage build:
1. **Builder**: `golang:1.24-alpine` (with `GOTOOLCHAIN=auto` to satisfy `go 1.25` in go.mod) — downloads dependencies, compiles server + native host binaries with `CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`
2. **Runtime**: `alpine:3.20` — minimal image with `ca-certificates` and `tzdata`, runs as non-root `appuser` (UID 1000)

### docker-compose.yml

| Service | Image | Ports | Notes |
|---------|-------|-------|-------|
| `postgres` | `postgres:16-alpine` | internal only | Health-checked, persistent volume `pgdata`, internal network |
| `server` | custom (Dockerfile) | `8444:8443` | Auto-runs migrations, depends on healthy postgres, 512MB/1CPU limit, health-checked |

Networks: `internal` bridge network isolates server ↔ postgres communication.

### Self-Hosted Deployment

```bash
# Quick start
docker compose up --build -d

# With TLS (mount cert files)
# 1. Place cert.pem and key.pem in a certs/ directory
# 2. Update docker-compose.yml:
#    volumes: - ./certs:/app/certs:ro
#    environment:
#      TLS_CERT: /app/certs/cert.pem
#      TLS_KEY: /app/certs/key.pem

# With custom CORS origins
# environment:
#   CORS_ORIGINS: "https://myapp.example.com,https://admin.example.com"

# View logs
docker compose logs -f server

# Stop
docker compose down

# Reset database
docker compose down -v
```

## Makefile

| Target | Description |
|--------|-------------|
| `build-server` | Build Go API server binary |
| `build-standalone` | Build standalone server binary |
| `build-nativehost` | Build native messaging host binary |
| `build-electron` | Build Electron desktop app |
| `build-extension-chrome` | Build Chrome extension |
| `build-extension-firefox` | Build Firefox extension |
| `build-extension-edge` | Build Edge extension |
| `build-extensions` | Build all browser extensions |
| `build-all` | Build everything |
| `test` | Run all tests (Go + Electron + Extension) |
| `test-go` | Run Go tests only |
| `test-electron` | Run Electron tests only |
| `test-extension` | Run extension tests only |
| `docker` | Build Docker images |
| `docker-up` | Start containers (`docker compose up --build -d`) |
| `docker-down` | Stop containers |
| `lint` | Run all linters (golangci-lint + eslint) |
| `lint-go` | Run Go linter only |
| `package-extension-chrome` | Build and zip Chrome extension |
| `package-extension-firefox` | Build and zip Firefox extension |
| `package-extension-edge` | Build and zip Edge extension |
| `package-extensions` | Zip all extensions for store submission |
| `dist-electron` | Package Electron app for current platform |
| `dist-electron-win` | Package Electron app for Windows (NSIS) |
| `dist-electron-mac` | Package Electron app for macOS (DMG) |
| `dist-electron-linux` | Package Electron app for Linux (AppImage + deb) |
| `migrate` | Run database migrations |
| `clean` | Remove all build artifacts |

## Distribution

### Desktop App (Electron)

Packaged with [electron-builder](https://www.electron.build/):

| Platform | Format | Notes |
|----------|--------|-------|
| Windows | NSIS installer | Auto-registers native messaging host via PowerShell post-install |
| macOS | DMG | Hardened runtime, code signing ready, notarization config included |
| Linux | AppImage + .deb | Desktop integration, icon set |

The installer bundles:
- Electron shell + React renderer
- Go sidecar binary (platform-specific, in `resources/bin/`)
- Native messaging host binary (in `resources/bin/`)
- Native host installer scripts (in `resources/scripts/`)

### Browser Extensions

| Target | Store | Package |
|--------|-------|---------|
| Chrome | Chrome Web Store | `lgi-pass-chrome.zip` |
| Firefox | AMO (addons.mozilla.org) | `lgi-pass-firefox.zip` |
| Edge | Edge Add-ons | `lgi-pass-edge.zip` |

Build and package:
```bash
cd extension
npm run package         # All three
npm run package:chrome  # Chrome only
npm run package:firefox # Firefox only
npm run package:edge    # Edge only
```

## Desktop App Features

- **Window**: 1200×800 (min 800×600), frameless title bar, dark theme (`#020617`)
- **Sidecar Mode**: Electron can spawn the Go server binary as a child process on a random high port
- **Biometric Unlock**: Windows Hello, macOS Touch ID support via `electron.systemPreferences`
- **Extension Bridge**: Pushes auth session to sidecar so browser extension can fetch credentials
- **Lockfile**: Writes `sidecar.lock` to app data dir for extension discovery
- **Security**: Context isolation, sandbox enabled, CSP headers, no `nodeIntegration`
- **Vault UX**: Favorites, archive, trash with auto-purge, entry cloning
- **Passkey Management**: Store and manage WebAuthn passkeys for websites
- **SSH Key Storage**: Store SSH keys as vault entries
- **Secure Send**: Create and manage time-limited encrypted shares

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
│   ├── api/                     # HTTP handlers, routes, middleware (auth, vault, admin, passkeys, sends, collections, emergency, SSO, SCIM, SIEM)
│   ├── auth/                    # JWT (ML-DSA-65), TOTP, SMS 2FA
│   ├── config/                  # Environment-based configuration
│   ├── crypto/                  # X-Wing KEM, ML-DSA-65, AES-256-GCM, Argon2id
│   ├── db/                      # PostgreSQL repositories (pgx)
│   ├── sync/                    # Multi-device sync with conflict resolution
│   └── vault/                   # Vault CRUD service
├── testing/                     # Centralized test suite (Go, Electron, Extension)
├── migrations/                  # SQL migration files (001-016, PostgreSQL + SQLite)
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
├── testing/                     # Centralized test suite
│   ├── crypto_test.go           # Crypto tests (KDF, AES-GCM, X-Wing, ML-DSA-65)
│   ├── mocks.go                 # Mock repositories (User, Vault, Org, Audit, Send, Collection, Emergency)
│   ├── auth_handler_test.go     # Auth handler tests (register, login, 2FA, rate limit)
│   ├── vault_handler_test.go    # Vault handler tests (CRUD, auth, filters)
│   ├── admin_service_test.go    # Admin service tests (orgs, escrow, audit)
│   ├── vault_ux_test.go         # Vault UX tests (favorites, archive, trash, clone)
│   ├── collection_handler_test.go # Collection tests (CRUD, permissions, members)
│   ├── emergency_access_test.go # Emergency access tests (invite, recovery, takeover)
│   ├── send_handler_test.go     # Secure Send tests (create, access, password, expiry)
│   ├── electron/                # Electron IPC + flow tests (vitest)
│   │   ├── crypto.test.ts
│   │   └── login.spec.ts
│   └── extension/               # Extension autofill + native messaging tests (jest)
│       ├── jest.config.js
│       ├── autofill.test.ts
│       └── native-messaging.test.ts
├── bin/                         # Pre-built native host binaries
├── scripts/                     # Native host installers (bash + PowerShell)
├── Dockerfile                   # Multi-stage Go build
├── docker-compose.yml           # PostgreSQL + server
├── .github/workflows/ci.yml     # CI/CD pipeline (lint, test, build, release)
├── Makefile                     # Build, test, lint, package targets
├── SECURITY.md                  # Security policy and threat model
└── go.mod                       # Go module definition
```

## License

Copyright © 2026
