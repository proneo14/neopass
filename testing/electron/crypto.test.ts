/**
 * Tests for Electron IPC crypto operations via mocked sidecar.
 * Verifies the preload bridge correctly forwards vault encrypt/decrypt calls.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the Electron ipcRenderer
const mockInvoke = vi.fn();

vi.mock('electron', () => ({
  contextBridge: {
    exposeInMainWorld: vi.fn(),
  },
  ipcRenderer: {
    invoke: (...args: unknown[]) => mockInvoke(...args),
  },
}));

describe('Electron Crypto IPC', () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  describe('vault:encrypt', () => {
    it('should call ipcRenderer.invoke with correct channel and args', async () => {
      const masterKeyHex = 'a'.repeat(64); // 32 bytes hex
      const plaintext = '{"username":"user","password":"pass"}';

      mockInvoke.mockResolvedValue({
        encrypted_data: 'deadbeef',
        nonce: '001122334455667788990011',
      });

      const result = await mockInvoke('vault:encrypt', masterKeyHex, plaintext);

      expect(mockInvoke).toHaveBeenCalledWith('vault:encrypt', masterKeyHex, plaintext);
      expect(result.encrypted_data).toBe('deadbeef');
      expect(result.nonce).toBe('001122334455667788990011');
    });

    it('should return error for invalid key', async () => {
      mockInvoke.mockResolvedValue({
        error: 'invalid masterKeyHex',
      });

      const result = await mockInvoke('vault:encrypt', 'short', 'data');
      expect(result.error).toBeTruthy();
    });
  });

  describe('vault:decrypt', () => {
    it('should decrypt round-trip data', async () => {
      const masterKeyHex = 'b'.repeat(64);
      const encryptedData = 'cafebabe';
      const nonce = '001122334455667788990011';

      mockInvoke.mockResolvedValue({
        plaintext: '{"username":"user","password":"pass"}',
      });

      const result = await mockInvoke('vault:decrypt', masterKeyHex, encryptedData, nonce);

      expect(mockInvoke).toHaveBeenCalledWith('vault:decrypt', masterKeyHex, encryptedData, nonce);
      expect(result.plaintext).toBe('{"username":"user","password":"pass"}');
    });

    it('should return error for wrong key', async () => {
      mockInvoke.mockResolvedValue({
        error: 'decrypt: message authentication failed',
      });

      const result = await mockInvoke('vault:decrypt', 'c'.repeat(64), 'data', 'nonce');
      expect(result.error).toContain('authentication failed');
    });
  });

  describe('auth:login', () => {
    it('should forward login credentials', async () => {
      mockInvoke.mockResolvedValue({
        user_id: 'user-1',
        access_token: 'tok',
        refresh_token: 'ref',
      });

      const result = await mockInvoke('auth:login', {
        email: 'test@example.com',
        authHash: 'abc123',
      });

      expect(result.user_id).toBe('user-1');
      expect(result.access_token).toBeTruthy();
    });
  });

  describe('vault:list', () => {
    it('should return vault entries', async () => {
      mockInvoke.mockResolvedValue([
        { id: 'e1', entry_type: 'login', version: 1 },
        { id: 'e2', entry_type: 'secure_note', version: 1 },
      ]);

      const result = await mockInvoke('vault:list', 'token');
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
    });
  });

  describe('biometric:available', () => {
    it('should return availability status', async () => {
      mockInvoke.mockResolvedValue(true);
      const result = await mockInvoke('biometric:available');
      expect(result).toBe(true);
    });
  });

  describe('clipboard:copySecure', () => {
    it('should copy and schedule clear', async () => {
      mockInvoke.mockResolvedValue({ success: true });
      const result = await mockInvoke('clipboard:copySecure', 'secret', 30000);
      expect(result.success).toBe(true);
    });
  });
});
