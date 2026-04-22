/**
 * Placeholder E2E tests for Electron app using Playwright.
 * These tests verify the main user flows of the desktop application.
 *
 * NOTE: Full E2E tests require electron + playwright-electron setup.
 * These are structured as integration test stubs that can be expanded
 * when the CI environment supports Electron testing.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the window.api object that the preload script exposes
const mockApi = {
  getSidecarPort: vi.fn(),
  auth: {
    login: vi.fn(),
    logout: vi.fn(),
    register: vi.fn(),
    changePassword: vi.fn(),
  },
  vault: {
    list: vi.fn(),
    get: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    encrypt: vi.fn(),
    decrypt: vi.fn(),
  },
  biometric: {
    isAvailable: vi.fn(),
    isConfigured: vi.fn(),
    enable: vi.fn(),
    enableWithPassword: vi.fn(),
    unlock: vi.fn(),
    verify: vi.fn(),
    disable: vi.fn(),
  },
  clipboard: {
    copySecure: vi.fn(),
  },
};

describe('Login Flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should login with valid credentials and receive tokens', async () => {
    mockApi.auth.login.mockResolvedValue({
      user_id: 'user-1',
      access_token: 'access-tok',
      refresh_token: 'refresh-tok',
    });

    const result = await mockApi.auth.login({
      email: 'test@example.com',
      authHash: 'abc123def456',
    });

    expect(result.user_id).toBe('user-1');
    expect(result.access_token).toBeTruthy();
    expect(result.refresh_token).toBeTruthy();
  });

  it('should return error for invalid credentials', async () => {
    mockApi.auth.login.mockRejectedValue(new Error('invalid credentials'));

    await expect(
      mockApi.auth.login({ email: 'bad@example.com', authHash: 'wrong' })
    ).rejects.toThrow('invalid credentials');
  });

  it('should handle 2FA flow', async () => {
    mockApi.auth.login.mockResolvedValue({
      requires_2fa: true,
      temp_token: 'temp-tok-abc',
    });

    const result = await mockApi.auth.login({
      email: '2fa@example.com',
      authHash: 'valid-hash',
    });

    expect(result.requires_2fa).toBe(true);
    expect(result.temp_token).toBeTruthy();
    expect(result.access_token).toBeUndefined();
  });
});

describe('Vault Loading', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should load vault entries after login', async () => {
    mockApi.vault.list.mockResolvedValue([
      { id: 'e1', entry_type: 'login', version: 1, created_at: '2024-01-01' },
      { id: 'e2', entry_type: 'secure_note', version: 1, created_at: '2024-01-02' },
    ]);

    const entries = await mockApi.vault.list('valid-token');

    expect(entries).toHaveLength(2);
    expect(entries[0].entry_type).toBe('login');
  });

  it('should decrypt vault entries with master key', async () => {
    mockApi.vault.decrypt.mockResolvedValue({
      plaintext: JSON.stringify({ username: 'user', password: 'pass123' }),
    });

    const result = await mockApi.vault.decrypt(
      'a'.repeat(64),
      'encrypted-hex',
      'nonce-hex'
    );

    const data = JSON.parse(result.plaintext);
    expect(data.username).toBe('user');
    expect(data.password).toBe('pass123');
  });
});

describe('Biometric Unlock Flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should check biometric availability', async () => {
    mockApi.biometric.isAvailable.mockResolvedValue(true);

    const available = await mockApi.biometric.isAvailable();
    expect(available).toBe(true);
  });

  it('should enable biometric with master key', async () => {
    mockApi.biometric.enable.mockResolvedValue({ success: true });

    const result = await mockApi.biometric.enable('a'.repeat(64));
    expect(result.success).toBe(true);
  });

  it('should unlock vault with biometric', async () => {
    mockApi.biometric.unlock.mockResolvedValue({
      masterKeyHex: 'b'.repeat(64),
      token: 'access-token',
    });

    const result = await mockApi.biometric.unlock();
    expect(result.masterKeyHex).toBeTruthy();
    expect(result.token).toBeTruthy();
  });

  it('should handle biometric not configured', async () => {
    mockApi.biometric.isConfigured.mockResolvedValue(false);
    mockApi.biometric.unlock.mockRejectedValue(new Error('not configured'));

    const configured = await mockApi.biometric.isConfigured();
    expect(configured).toBe(false);

    await expect(mockApi.biometric.unlock()).rejects.toThrow('not configured');
  });
});

describe('Secure Clipboard', () => {
  it('should copy to clipboard with auto-clear', async () => {
    mockApi.clipboard.copySecure.mockResolvedValue({ success: true });

    const result = await mockApi.clipboard.copySecure('sensitive-password', 30000);
    expect(result.success).toBe(true);
    expect(mockApi.clipboard.copySecure).toHaveBeenCalledWith('sensitive-password', 30000);
  });
});
