# Security Policy

## Threat Model

NeoPass is designed to protect user credentials against both current and future threats, including quantum computing attacks.

### Trust Boundaries

1. **Client ↔ Server**: All communication over TLS 1.3 (with X25519Kyber768 hybrid PQ key exchange on Go 1.23+). The server never sees plaintext vault data — all encryption/decryption happens client-side.
2. **Browser Extension ↔ Native Host**: Communication via native messaging (stdin/stdout) on localhost only, authenticated with a shared secret.
3. **Electron ↔ Go Sidecar**: HTTP on localhost with random high port, protected by extension secret.

### Assets Protected

- **Master Password**: Never transmitted or stored. Argon2id derives two keys: a master key (for vault encryption) and an auth hash (for server authentication). The server stores a bcrypt hash of the auth hash (double-hash).
- **Vault Entries**: AES-256-GCM encrypted with the master key. The server stores only encrypted blobs and nonces.
- **Private Keys**: X-Wing (ML-KEM-768 + X25519) keypairs for key exchange; ML-DSA-65 for JWT signing. Private keys are encrypted with the master key before storage.
- **TOTP Secrets**: Encrypted with the user's master key before storage.

### Threat Categories

| Threat | Mitigation |
|--------|------------|
| Server compromise | Zero-knowledge architecture — server has no access to plaintext |
| Quantum key recovery | X-Wing KEM (ML-KEM-768 + X25519 hybrid) for all key exchanges |
| Quantum signature forgery | ML-DSA-65 for JWT signing |
| Brute-force login | Argon2id (64 MB, 3 iterations) + bcrypt on server + rate limiting (5/min) |
| Session hijacking | Short-lived JWTs, refresh token rotation, TLS 1.3 only |
| XSS in Electron | Context isolation, sandbox, CSP, no `nodeIntegration` |
| Extension injection | Shadow DOM isolation, `escapeHtml` for all user data, no raw `innerHTML` |
| Subdomain spoofing | Strict domain matching with `.` prefix check |
| Memory disclosure | `ZeroBytes()` on all decrypted buffers, auto-lock with memory clearing |
| Admin abuse | All admin vault access is audit-logged with actor, target, and timestamp |

## Cryptographic Design

### Key Derivation

```
Master Password + Salt → Argon2id(64 MB, 3 iter, 4 parallel) → 64 bytes
  ├── bytes [0:32]  → Master Key (vault encryption, never leaves client)
  └── bytes [32:64] → Auth Hash → bcrypt on server → stored
```

### Vault Encryption

- **Algorithm**: AES-256-GCM
- **Nonce**: 12 bytes from `crypto/rand` (unique per encryption)
- **Key**: Master Key (32 bytes from KDF)
- **Data**: JSON blob containing entry fields

### Key Exchange (Sharing & Escrow)

- **Algorithm**: X-Wing KEM (ML-KEM-768 + X25519 hybrid)
- **Library**: cloudflare/circl
- **Use cases**: Organization escrow, admin password recovery, 2FA sharing
- **Session key derivation**: SHAKE256 with domain separation

### Digital Signatures

- **Algorithm**: ML-DSA-65 (CRYSTALS-Dilithium)
- **Library**: cloudflare/circl
- **Use case**: JWT token signing and verification

### Transport Security

- **Protocol**: TLS 1.3 minimum (enforced server-side)
- **Key Exchange**: X25519Kyber768 (Go 1.23+ default for post-quantum protection in transit)
- **Certificate**: Configurable via TLS_CERT / TLS_KEY environment variables

## Security Hardening Measures

### Go Backend

- Parameterized SQL queries (pgx) — no string concatenation
- Rate limiting: 100 req/min general, 5 req/min for auth endpoints
- Request body size limit: 1 MB
- Request timeout: 30 seconds
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`
- CORS: configurable allowed origins, no wildcard
- CSRF: double-submit cookie pattern for browser clients
- Panic recovery middleware with generic error responses (no stack trace leaks)
- `ZeroBytes()` called on all decrypted plaintext via `defer` statements

### Electron Desktop App

- Context isolation enabled, sandbox enabled, `nodeIntegration` disabled
- Content Security Policy: `default-src 'self'`
- DevTools disabled in production builds
- Navigation to external URLs blocked
- Auto-lock after inactivity (configurable, default 15 minutes)
- IPC message shape validation in preload script
- Biometric keys stored in OS keychain (Windows Hello / macOS Keychain)
- Clipboard auto-clear after 30 seconds
- Windows: `ExcludeClipboardContentFromMonitorProcessing` flag set
- macOS: `org.nspasteboard.ConcealedType` flag set

### Browser Extension

- Shadow DOM isolation for all injected UI elements
- `escapeHtml()` applied to all user data before DOM insertion
- No raw `innerHTML` with unsanitized data
- Strict domain matching (prevents subdomain spoofing)
- Native host connection timeout: 5 seconds
- Native host response validation
- Sensitive data never logged in service worker

## Responsible Disclosure

If you discover a security vulnerability, please report it responsibly:

1. **Email**: security@neopass.example.com
2. **Do NOT** open a public GitHub issue for security vulnerabilities
3. Include a detailed description and reproduction steps
4. We will acknowledge receipt within 48 hours
5. We aim to provide a fix within 90 days

## Security Contact

- **Email**: security@neopass.example.com
- **PGP Key**: Available upon request
