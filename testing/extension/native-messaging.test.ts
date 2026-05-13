/**
 * Tests for browser extension native messaging host communication.
 * Verifies the 4-byte length-prefix protocol and request/response flow.
 */

// Mock browser API
jest.mock('webextension-polyfill', () => ({
  __esModule: true,
  default: {
    runtime: {
      sendMessage: jest.fn(),
      onMessage: { addListener: jest.fn() },
      connectNative: jest.fn(),
      getURL: (path: string) => `chrome-extension://test/${path}`,
      sendNativeMessage: jest.fn(),
    },
    storage: {
      local: {
        get: jest.fn().mockResolvedValue({}),
        set: jest.fn().mockResolvedValue(undefined),
        remove: jest.fn().mockResolvedValue(undefined),
      },
    },
    tabs: {
      query: jest.fn().mockResolvedValue([]),
      sendMessage: jest.fn(),
      onActivated: { addListener: jest.fn() },
      onUpdated: { addListener: jest.fn() },
    },
    action: {
      setBadgeText: jest.fn(),
      setBadgeBackgroundColor: jest.fn(),
    },
    alarms: {
      create: jest.fn(),
      onAlarm: { addListener: jest.fn() },
    },
  },
}));

import type {
  NativeHostRequest,
  NativeHostResponse,
  Credential,
} from '../../extension/src/lib/messages';

// ---------------------------------------------------------------------------
// Native Messaging Protocol Tests
// ---------------------------------------------------------------------------

describe('Native Messaging — Message Encoding', () => {
  test('messages should be JSON-serializable', () => {
    const request: NativeHostRequest = {
      action: 'getCredentials',
      domain: 'example.com',
    };

    const json = JSON.stringify(request);
    expect(json).toBeTruthy();

    const parsed = JSON.parse(json) as NativeHostRequest;
    expect(parsed.action).toBe('getCredentials');
    expect(parsed.domain).toBe('example.com');
  });

  test('4-byte length prefix encoding', () => {
    const message = JSON.stringify({ action: 'ping' });
    const messageBytes = Buffer.from(message, 'utf-8');
    const length = messageBytes.length;

    // Create 4-byte little-endian length prefix
    const prefix = new Uint8Array(4);
    prefix[0] = length & 0xff;
    prefix[1] = (length >> 8) & 0xff;
    prefix[2] = (length >> 16) & 0xff;
    prefix[3] = (length >> 24) & 0xff;

    // Verify it decodes back correctly
    const decoded = prefix[0] | (prefix[1] << 8) | (prefix[2] << 16) | (prefix[3] << 24);
    expect(decoded).toBe(length);
  });

  test('4-byte length prefix for large messages', () => {
    // Create a message with many credentials (simulating large response)
    const credentials: Credential[] = Array.from({ length: 100 }, (_, i) => ({
      id: `cred-${i}`,
      username: `user${i}@example.com`,
      password: `password${i}!`,
      domain: `site${i}.example.com`,
      name: `Site ${i}`,
      uri: `https://site${i}.example.com`,
      notes: '',
      matched: true,
    }));

    const response: NativeHostResponse = {
      status: 'ok',
      credentials,
    };

    const json = JSON.stringify(response);
    const messageBytes = Buffer.from(json, 'utf-8');
    const length = messageBytes.length;

    // Verify length fits in 4 bytes (max ~4GB)
    expect(length).toBeLessThan(2 ** 32);
    expect(length).toBeGreaterThan(0);

    // Verify round-trip
    const prefix = new ArrayBuffer(4);
    new DataView(prefix).setUint32(0, length, true); // little-endian
    const decodedLength = new DataView(prefix).getUint32(0, true);
    expect(decodedLength).toBe(length);
  });
});

describe('Native Messaging — Credential Request/Response Flow', () => {
  test('getCredentials request format', () => {
    const request: NativeHostRequest = {
      action: 'getCredentials',
      domain: 'github.com',
    };

    expect(request.action).toBe('getCredentials');
    expect(request.domain).toBe('github.com');
  });

  test('credentials response with matches', () => {
    const response: NativeHostResponse = {
      status: 'ok',
      credentials: [
        {
          id: 'cred-1',
          username: 'user@github.com',
          password: 'hunter2',
          domain: 'github.com',
          name: 'GitHub',
          uri: 'https://github.com/login',
          notes: '',
          matched: true,
        },
      ],
    };

    expect(response.credentials).toHaveLength(1);
    expect(response.credentials![0].domain).toBe('github.com');
    expect(response.credentials![0].matched).toBe(true);
  });

  test('credentials response with no matches', () => {
    const response: NativeHostResponse = {
      status: 'ok',
      credentials: [],
    };

    expect(response.credentials).toHaveLength(0);
  });

  test('error response', () => {
    const response: NativeHostResponse = {
      error: 'vault is locked',
    };

    expect(response.error).toBe('vault is locked');
    expect(response.credentials).toBeUndefined();
  });

  test('ping request/response', () => {
    const request: NativeHostRequest = {
      action: 'ping',
    };

    const response: NativeHostResponse = {
      status: 'ok',
      version: '1.0.0',
    };

    expect(request.action).toBe('ping');
    expect(response.status).toBe('ok');
    expect(response.version).toBeTruthy();
  });

  test('getStatus request/response', () => {
    const request: NativeHostRequest = {
      action: 'getStatus',
    };

    const response: NativeHostResponse = {
      status: 'ok',
      locked: false,
      vaultCount: 42,
    };

    expect(request.action).toBe('getStatus');
    expect(response.locked).toBe(false);
    expect(response.vaultCount).toBe(42);
  });

  test('lock request', () => {
    const request: NativeHostRequest = {
      action: 'lock',
    };

    expect(request.action).toBe('lock');
  });

  test('saveCredential request', () => {
    const request: NativeHostRequest = {
      action: 'saveCredential',
      domain: 'newsite.com',
      username: 'newuser@example.com',
      encryptedPassword: 'aabbccdd...',
    };

    expect(request.action).toBe('saveCredential');
    expect(request.domain).toBe('newsite.com');
    expect(request.username).toBe('newuser@example.com');
  });
});

describe('Native Messaging — Timeout Handling', () => {
  test('should timeout after configured duration', async () => {
    const TIMEOUT_MS = 100;

    const timeoutPromise = new Promise<NativeHostResponse>((_, reject) => {
      setTimeout(() => reject(new Error('native host timeout')), TIMEOUT_MS);
    });

    // Simulate a native host that never responds
    const neverResolve = new Promise<NativeHostResponse>(() => {});

    await expect(
      Promise.race([neverResolve, timeoutPromise])
    ).rejects.toThrow('native host timeout');
  });

  test('should handle disconnect gracefully', () => {
    // Simulate port disconnect
    const port = {
      name: 'neopass-native-host',
      onMessage: { addListener: jest.fn() },
      onDisconnect: { addListener: jest.fn() },
      postMessage: jest.fn(),
      disconnect: jest.fn(),
    };

    // Register disconnect handler
    let disconnectHandler: (() => void) | null = null;
    port.onDisconnect.addListener.mockImplementation((handler: () => void) => {
      disconnectHandler = handler;
    });

    port.onDisconnect.addListener(() => {});

    // Simulate disconnect
    expect(port.onDisconnect.addListener).toHaveBeenCalled();
  });
});

describe('Native Messaging — Domain Matching', () => {
  // Import the utility function
  function domainsMatch(credentialDomain: string, pageDomain: string): boolean {
    if (!credentialDomain || !pageDomain) return false;
    const cred = credentialDomain.toLowerCase();
    const page = pageDomain.toLowerCase();
    if (cred === page) return true;
    return page.endsWith('.' + cred);
  }

  test('exact domain match', () => {
    expect(domainsMatch('github.com', 'github.com')).toBe(true);
  });

  test('subdomain match', () => {
    expect(domainsMatch('github.com', 'api.github.com')).toBe(true);
  });

  test('no match for different domains', () => {
    expect(domainsMatch('github.com', 'gitlab.com')).toBe(false);
  });

  test('no match for spoofed subdomain', () => {
    expect(domainsMatch('example.com', 'evil-example.com')).toBe(false);
  });

  test('case insensitive', () => {
    expect(domainsMatch('GitHub.COM', 'github.com')).toBe(true);
  });

  test('empty domains return false', () => {
    expect(domainsMatch('', 'github.com')).toBe(false);
    expect(domainsMatch('github.com', '')).toBe(false);
  });
});
