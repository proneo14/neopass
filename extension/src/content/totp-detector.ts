/**
 * TOTP secret detection for 2FA setup pages.
 *
 * Scans the page for:
 * 1. QR code images → decode with jsQR to extract otpauth:// URIs
 * 2. otpauth:// URIs in links, text, data attributes, input values
 * 3. Base32-encoded secrets displayed as "setup key" / "manual entry" text
 *
 * When a secret is found, shows a banner offering to save it to LGI Pass.
 */

import { browserAPI, extractDomain } from '../lib/browser-api';

const TOTP_BANNER_ID = 'lgipass-totp-banner';

/**
 * Valid base32 (RFC 4648): only A-Z and 2-7, at least 16 chars.
 * Must NOT be a common English word / placeholder.
 */
const BASE32_RE = /^[A-Z2-7]{16,}$/;

/** otpauth:// URI pattern. */
const OTPAUTH_RE = /otpauth:\/\/totp\/[^\s"'<>]+/i;

/**
 * Strings that look base32 but are English words or common placeholders.
 * We reject these to avoid false positives.
 */
const FALSE_POSITIVE_WORDS = new Set([
  'YOURTWOFACTORSECRET',
  'YOURSECRETKEY',
  'EXAMPLESECRETKEY',
  'ENTERSECRETHERE',
  'BASETHIRTYTWOKEY',
  'REPLACEWITHYOURKEY',
  'PLACEHOLDERSECRET',
]);

let bannerShown = false;
let lastDetectedSecret = '';

/**
 * Extract the secret from an otpauth:// URI.
 */
function secretFromOtpauth(uri: string): string | null {
  try {
    const url = new URL(uri);
    return url.searchParams.get('secret') || null;
  } catch {
    return null;
  }
}

/**
 * Check if a string looks like a real TOTP secret (not a word).
 * Real base32 secrets tend to have scattered digits (2-7) and lack
 * vowel patterns that form readable words.
 */
function isLikelyRealSecret(s: string): boolean {
  if (FALSE_POSITIVE_WORDS.has(s)) return false;

  // Reject if it forms readable English-like words (has lots of vowels in sequence)
  const vowelRuns = s.match(/[AEIOU]{3,}/g);
  if (vowelRuns && vowelRuns.length >= 2) return false;

  // Real secrets usually contain at least some digits (2-7 in base32)
  const digitCount = (s.match(/[2-7]/g) || []).length;
  // Accept if has digits OR is very long (long random strings may skip digits)
  if (digitCount > 0 || s.length >= 32) return true;

  // Short all-alpha strings are likely words, not secrets
  if (s.length < 32 && digitCount === 0) return false;

  return true;
}

/**
 * Ask the background service worker to capture + scan the visible tab for QR codes.
 * This bypasses CORS since captureVisibleTab() screenshots the rendered page.
 */
async function scanQRCodes(): Promise<{ secret: string; otpauthUri: string } | null> {
  try {
    const response = await browserAPI.runtime.sendMessage({ type: 'scanQR' }) as
      { secret?: string; otpauthUri?: string; error?: string } | undefined;
    if (response?.secret && response?.otpauthUri) {
      return { secret: response.secret, otpauthUri: response.otpauthUri };
    }
  } catch {
    console.debug('[QPM] QR scan request failed');
  }
  return null;
}

/**
 * Scan the page DOM for TOTP secrets via text/attribute inspection.
 */
function scanForTOTPSecretInText(): { secret: string; otpauthUri?: string } | null {
  // 1. Check for otpauth:// URIs in links
  const links = document.querySelectorAll<HTMLAnchorElement>('a[href*="otpauth://"]');
  for (const link of links) {
    const match = link.href.match(OTPAUTH_RE);
    if (match) {
      const secret = secretFromOtpauth(match[0]);
      if (secret) return { secret, otpauthUri: match[0] };
    }
  }

  // 2. Check data attributes for otpauth URIs
  const qrElements = document.querySelectorAll<HTMLElement>(
    '[data-uri*="otpauth://"], [data-value*="otpauth://"], [data-qr*="otpauth://"], ' +
    'img[src*="otpauth://"], [data-otpauth-uri]'
  );
  for (const el of qrElements) {
    for (const attr of ['data-uri', 'data-value', 'data-qr', 'src', 'data-otpauth-uri']) {
      const val = el.getAttribute(attr);
      if (val) {
        const match = val.match(OTPAUTH_RE);
        if (match) {
          const secret = secretFromOtpauth(match[0]);
          if (secret) return { secret, otpauthUri: match[0] };
        }
      }
    }
  }

  // 3. Check all text content for otpauth:// URIs
  const bodyText = document.body?.innerText ?? '';
  const otpauthMatch = bodyText.match(OTPAUTH_RE);
  if (otpauthMatch) {
    const secret = secretFromOtpauth(otpauthMatch[0]);
    if (secret) return { secret, otpauthUri: otpauthMatch[0] };
  }

  // 4. Check input/textarea values for otpauth URIs
  const inputs = document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
    'input[value*="otpauth://"], textarea'
  );
  for (const input of inputs) {
    const val = input.value || input.getAttribute('value') || '';
    const match = val.match(OTPAUTH_RE);
    if (match) {
      const secret = secretFromOtpauth(match[0]);
      if (secret) return { secret, otpauthUri: match[0] };
    }
  }

  // 5. Look for displayed base32 secrets — but be very strict.
  // Only check elements that are specifically used to display secrets:
  // <code>, <kbd>, <pre>, monospace-styled elements, and read-only inputs
  const strictCandidates = document.querySelectorAll<HTMLElement>(
    'code, kbd, pre, ' +
    'input[readonly], input[disabled], ' +
    '[class*="totp" i], [class*="otp-secret" i], [class*="secret-key" i], ' +
    '[class*="setup-key" i], [class*="manual-key" i], [data-secret]'
  );

  for (const el of strictCandidates) {
    let text = '';
    if (el instanceof HTMLInputElement) {
      text = el.value;
    } else {
      text = el.textContent?.trim() ?? '';
    }

    if (!text || text.length > 100 || text.length < 16) continue;

    const cleaned = text.replace(/[\s-]/g, '').toUpperCase();
    if (BASE32_RE.test(cleaned) && isLikelyRealSecret(cleaned)) {
      return { secret: cleaned };
    }
  }

  return null;
}

/**
 * Show a banner at the top of the page offering to save the TOTP secret.
 */
function showTOTPBanner(secret: string) {
  // Remove existing banner
  document.getElementById(TOTP_BANNER_ID)?.remove();

  const banner = document.createElement('div');
  banner.id = TOTP_BANNER_ID;
  const shadow = banner.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = `
    :host {
      all: initial;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .totp-banner {
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483647;
      background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
      border: 1px solid #4338ca;
      border-radius: 12px;
      padding: 16px 20px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      max-width: 380px;
      color: #e0e7ff;
      display: flex;
      flex-direction: column;
      gap: 12px;
      animation: slideIn 0.3s ease-out;
    }
    @keyframes slideIn {
      from { opacity: 0; transform: translateY(-20px) scale(0.95); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    .totp-header {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
      font-weight: 600;
      color: #c7d2fe;
    }
    .totp-header svg {
      width: 20px;
      height: 20px;
      flex-shrink: 0;
    }
    .totp-secret {
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 12px;
      color: #a5b4fc;
      background: rgba(0,0,0,0.3);
      padding: 6px 10px;
      border-radius: 6px;
      word-break: break-all;
      max-height: 40px;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .totp-actions {
      display: flex;
      gap: 8px;
      justify-content: flex-end;
    }
    .totp-btn {
      border: none;
      border-radius: 6px;
      padding: 8px 16px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s;
    }
    .totp-btn-save {
      background: #6366f1;
      color: white;
    }
    .totp-btn-save:hover {
      background: #818cf8;
    }
    .totp-btn-dismiss {
      background: transparent;
      color: #94a3b8;
      border: 1px solid #475569;
    }
    .totp-btn-dismiss:hover {
      background: rgba(255,255,255,0.05);
      color: #cbd5e1;
    }
  `;

  const wrapper = document.createElement('div');
  wrapper.className = 'totp-banner';

  const header = document.createElement('div');
  header.className = 'totp-header';
  header.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
    Save TOTP to LGI Pass?
  `;

  const secretDisplay = document.createElement('div');
  secretDisplay.className = 'totp-secret';
  // Show masked secret for security
  secretDisplay.textContent = secret.substring(0, 4) + '••••' + secret.substring(secret.length - 4);

  const actions = document.createElement('div');
  actions.className = 'totp-actions';

  const dismissBtn = document.createElement('button');
  dismissBtn.className = 'totp-btn totp-btn-dismiss';
  dismissBtn.textContent = 'Dismiss';
  dismissBtn.onclick = () => {
    banner.remove();
    bannerShown = false;
  };

  const saveBtn = document.createElement('button');
  saveBtn.className = 'totp-btn totp-btn-save';
  saveBtn.textContent = 'Save TOTP';
  saveBtn.onclick = async () => {
    saveBtn.textContent = 'Saving...';
    saveBtn.style.opacity = '0.7';
    saveBtn.style.pointerEvents = 'none';

    try {
      const domain = extractDomain(window.location.href) ?? '';
      const response = await browserAPI.runtime.sendMessage({
        type: 'saveTOTP',
        domain,
        secret,
      });

      const resp = response as { status?: string; error?: string };
      if (resp?.status === 'saved') {
        saveBtn.textContent = '✓ Saved!';
        saveBtn.style.background = '#22c55e';
        setTimeout(() => {
          banner.remove();
          bannerShown = false;
        }, 1500);
      } else {
        saveBtn.textContent = resp?.error ?? 'Failed';
        saveBtn.style.background = '#ef4444';
        saveBtn.style.pointerEvents = 'auto';
        setTimeout(() => {
          saveBtn.textContent = 'Retry';
          saveBtn.style.background = '#6366f1';
          saveBtn.style.opacity = '1';
        }, 2000);
      }
    } catch {
      saveBtn.textContent = 'Error';
      saveBtn.style.background = '#ef4444';
    }
  };

  actions.appendChild(dismissBtn);
  actions.appendChild(saveBtn);

  wrapper.appendChild(header);
  wrapper.appendChild(secretDisplay);
  wrapper.appendChild(actions);

  shadow.appendChild(style);
  shadow.appendChild(wrapper);

  banner.style.cssText = 'position:fixed;top:0;right:0;z-index:2147483647;pointer-events:auto;';
  document.body.appendChild(banner);
}

/**
 * Scan page for TOTP secrets and show banner if found.
 * Tries QR code scanning first, then falls back to text detection.
 */
export async function detectAndPromptTOTP() {
  if (bannerShown) return;

  // Try QR code scanning (most reliable)
  const qrResult = await scanQRCodes();
  if (qrResult) {
    if (qrResult.secret !== lastDetectedSecret) {
      lastDetectedSecret = qrResult.secret;
      bannerShown = true;
      showTOTPBanner(qrResult.secret);
      console.debug('[QPM] TOTP secret found via QR code');
      return;
    }
  }

  // Fall back to text-based detection
  const result = scanForTOTPSecretInText();
  if (!result) return;

  if (result.secret === lastDetectedSecret) return;
  lastDetectedSecret = result.secret;

  bannerShown = true;
  showTOTPBanner(result.secret);
  console.debug('[QPM] TOTP secret detected via text scan');
}

/**
 * Check if the current page looks like a 2FA setup page.
 */
export function isLikely2FASetupPage(): boolean {
  const text = document.body?.innerText?.toLowerCase() ?? '';
  const title = document.title.toLowerCase();
  const url = window.location.href.toLowerCase();

  const indicators = [
    'two-factor', 'two factor', '2fa', '2-fa',
    'authenticator', 'totp', 'verification app',
    'google authenticator', 'microsoft authenticator', 'authy',
    'scan the qr', 'scan this qr', 'scan the code', 'scan a qr',
    'setup key', 'secret key', 'manual entry',
    'time-based', 'one-time password',
    'set up authenticator', 'authenticator app',
    'two-step verification', 'two step verification',
    'qr code',
  ];

  const combined = title + ' ' + url;
  const hasUrlHint = indicators.some((ind) => combined.includes(ind));

  if (hasUrlHint) return true;

  // Check page text — require at least 2 indicators to reduce false positives
  let count = 0;
  for (const ind of indicators) {
    if (text.includes(ind)) {
      count++;
      if (count >= 2) return true;
    }
  }

  return false;
}
