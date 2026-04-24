/**
 * TOTP (Time-based One-Time Password) generator — RFC 6238.
 * Uses the Web Crypto API for HMAC-SHA1 computation.
 */

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decode a base32-encoded string into raw bytes. */
function base32Decode(input: string): Uint8Array {
  const clean = input.replace(/[\s=\-]/g, '').toUpperCase();
  const bits: number[] = [];
  for (const ch of clean) {
    const val = BASE32_CHARS.indexOf(ch);
    if (val === -1) continue;
    for (let i = 4; i >= 0; i--) {
      bits.push((val >> i) & 1);
    }
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | bits[i * 8 + j];
    }
    bytes[i] = byte;
  }
  return bytes;
}

/** Compute HMAC-SHA1 using the Web Crypto API. */
async function hmacSha1(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, message);
  return new Uint8Array(sig);
}

/**
 * Generate a TOTP code from a base32-encoded secret.
 * @param secret  Base32-encoded secret (or otpauth:// URI)
 * @param period  Time step in seconds (default 30)
 * @param digits  Number of digits (default 6)
 */
export async function generateTOTP(
  secret: string,
  period = 30,
  digits = 6,
): Promise<string> {
  // Extract secret from otpauth:// URI if needed
  let rawSecret = secret;
  if (secret.startsWith('otpauth://')) {
    const parsed = parseOtpauthUri(secret);
    if (parsed) rawSecret = parsed.secret;
  }

  const key = base32Decode(rawSecret);
  const time = Math.floor(Date.now() / 1000 / period);

  // 8-byte big-endian counter
  const timeBytes = new Uint8Array(8);
  let t = time;
  for (let i = 7; i >= 0; i--) {
    timeBytes[i] = t & 0xff;
    t = Math.floor(t / 256);
  }

  const hmac = await hmacSha1(key, timeBytes);

  // Dynamic truncation (RFC 4226 §5.4)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)) %
    Math.pow(10, digits);

  return code.toString().padStart(digits, '0');
}

/** Seconds remaining in the current TOTP period. */
export function getTimeRemaining(period = 30): number {
  return period - (Math.floor(Date.now() / 1000) % period);
}

/** Parse an otpauth:// URI into its components. */
export function parseOtpauthUri(
  uri: string,
): { secret: string; issuer?: string; account?: string; period?: number; digits?: number } | null {
  try {
    const url = new URL(uri);
    if (url.protocol !== 'otpauth:') return null;
    const secret = url.searchParams.get('secret');
    if (!secret) return null;
    return {
      secret,
      issuer: url.searchParams.get('issuer') ?? undefined,
      account: decodeURIComponent(url.pathname).split(':').pop() ?? undefined,
      period: url.searchParams.get('period') ? parseInt(url.searchParams.get('period')!) : undefined,
      digits: url.searchParams.get('digits') ? parseInt(url.searchParams.get('digits')!) : undefined,
    };
  } catch {
    return null;
  }
}
