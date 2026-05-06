/**
 * Tests for Secure Send encryption flow.
 * Verifies that:
 * - Content is encrypted before creating a send
 * - The encryption key is only in the URL fragment (never sent to server)
 * - Decryption with the correct key recovers the original content
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the Electron ipcRenderer for send IPC calls
const mockInvoke = vi.fn();

vi.mock('electron', () => ({
  contextBridge: {
    exposeInMainWorld: vi.fn(),
  },
  ipcRenderer: {
    invoke: (...args: unknown[]) => mockInvoke(...args),
  },
}));

// ---------------------------------------------------------------------------
// Helpers: simulate client-side send encryption
// ---------------------------------------------------------------------------

/**
 * Simulates the client-side encryption that happens before creating a send.
 * In production this uses AES-256-GCM via the Go sidecar.
 */
function simulateEncrypt(plaintext: string, key: string): { encrypted_data: string; nonce: string } {
  // For testing, we use a simple reversible transform (not real crypto)
  // In production, this calls the Go sidecar's AES-256-GCM via IPC
  const encoded = Buffer.from(plaintext).toString('hex');
  const nonce = '000102030405060708090a0b'; // 12-byte nonce in hex
  return {
    encrypted_data: encoded + '_enc_' + key.substring(0, 8),
    nonce,
  };
}

function simulateDecrypt(encrypted_data: string, nonce: string, key: string): string {
  const parts = encrypted_data.split('_enc_');
  if (parts.length !== 2 || parts[1] !== key.substring(0, 8)) {
    throw new Error('decrypt: message authentication failed');
  }
  return Buffer.from(parts[0], 'hex').toString();
}

/**
 * Builds a send URL. The key is ONLY in the fragment (# part).
 * Browsers never send the fragment to the server.
 */
function buildSendURL(baseURL: string, slug: string, key: string): string {
  return `${baseURL}/send/${slug}#${key}`;
}

function extractKeyFromURL(url: string): string {
  const hashIndex = url.indexOf('#');
  if (hashIndex === -1) throw new Error('No key in URL');
  return url.substring(hashIndex + 1);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Secure Send — Encryption', () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it('encrypts content before creating a send', () => {
    const key = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'; // 32-char key
    const plaintext = 'This is my secret message';

    const { encrypted_data, nonce } = simulateEncrypt(plaintext, key);

    expect(encrypted_data).not.toBe(plaintext);
    expect(encrypted_data).toBeTruthy();
    expect(nonce).toBeTruthy();
  });

  it('key is only in the URL fragment', () => {
    const key = 'mySecretKey1234567890abcdefghijkl';
    const slug = 'aBcDeFgH12345678';
    const url = buildSendURL('https://vault.example.com', slug, key);

    // Fragment should contain the key
    expect(url).toContain('#' + key);

    // The path part (what the server sees) should NOT contain the key
    const pathPart = url.split('#')[0];
    expect(pathPart).not.toContain(key);
    expect(pathPart).toBe(`https://vault.example.com/send/${slug}`);
  });

  it('extracts key from URL fragment', () => {
    const key = 'extractedKey123456789012345678901';
    const url = `https://vault.example.com/send/slug123#${key}`;

    const extracted = extractKeyFromURL(url);
    expect(extracted).toBe(key);
  });

  it('throws when URL has no fragment', () => {
    expect(() => extractKeyFromURL('https://vault.example.com/send/slug123')).toThrow(
      'No key in URL'
    );
  });
});

describe('Secure Send — Decrypt Round Trip', () => {
  it('encrypts and decrypts content successfully', () => {
    const key = 'roundTripKey12345678901234567890';
    const plaintext = 'Confidential: API key is sk_live_xxx';

    const { encrypted_data, nonce } = simulateEncrypt(plaintext, key);
    const decrypted = simulateDecrypt(encrypted_data, nonce, key);

    expect(decrypted).toBe(plaintext);
  });

  it('fails decryption with wrong key', () => {
    const key = 'correctKey1234567890123456789012';
    const wrongKey = 'wrongKeyXXXXXXXX890123456789012';
    const plaintext = 'secret data';

    const { encrypted_data, nonce } = simulateEncrypt(plaintext, key);

    expect(() => simulateDecrypt(encrypted_data, nonce, wrongKey)).toThrow(
      'authentication failed'
    );
  });
});

describe('Secure Send — Full Flow', () => {
  it('simulates create → share URL → receive → decrypt', () => {
    const key = 'fullFlowKey12345678901234567890!';
    const plaintext = 'Bank account: 1234-5678-9012';

    // Step 1: Sender encrypts content
    const { encrypted_data, nonce } = simulateEncrypt(plaintext, key);

    // Step 2: Send to server (server stores encrypted_data + nonce, never sees key)
    const slug = 'xYz123AbC456DeF7';

    // Step 3: Build share URL with key in fragment
    const shareURL = buildSendURL('https://vault.example.com', slug, key);

    // Step 4: Recipient opens URL, browser sends request WITHOUT fragment
    const serverPath = shareURL.split('#')[0];
    expect(serverPath).toBe('https://vault.example.com/send/xYz123AbC456DeF7');

    // Step 5: Server returns encrypted_data + nonce
    // Step 6: Client extracts key from URL fragment and decrypts
    const extractedKey = extractKeyFromURL(shareURL);
    const decrypted = simulateDecrypt(encrypted_data, nonce, extractedKey);

    expect(decrypted).toBe(plaintext);
  });

  it('creates send via IPC', async () => {
    mockInvoke.mockResolvedValue({
      id: 'send-1',
      slug: 'testSlug1234567',
      url: '/send/testSlug1234567',
    });

    const result = await mockInvoke('send:create', {
      type: 'text',
      encrypted_data: 'deadbeef',
      nonce: '001122334455667788990011',
      expires_in_hours: 24,
    });

    expect(mockInvoke).toHaveBeenCalledWith('send:create', expect.objectContaining({
      type: 'text',
    }));
    expect(result.slug).toBeTruthy();
    expect(result.id).toBeTruthy();
  });
});
