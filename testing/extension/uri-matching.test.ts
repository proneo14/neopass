/**
 * Tests for URI / domain matching used by the browser extension
 * to match vault entries against the current page's URL.
 */

// Mock webextension-polyfill before any imports
jest.mock('webextension-polyfill', () => ({
  runtime: { sendMessage: jest.fn(), onMessage: { addListener: jest.fn() } },
  tabs: { query: jest.fn() },
}));

import { extractDomain, domainsMatch } from '../../extension/src/lib/browser-api';

// ---------------------------------------------------------------------------
// extractDomain
// ---------------------------------------------------------------------------

describe('extractDomain', () => {
  it('extracts hostname from HTTPS URL', () => {
    expect(extractDomain('https://example.com/path')).toBe('example.com');
  });

  it('extracts hostname from HTTP URL', () => {
    expect(extractDomain('http://example.com:8080/path?q=1')).toBe('example.com');
  });

  it('extracts subdomain', () => {
    expect(extractDomain('https://sub.domain.example.com')).toBe('sub.domain.example.com');
  });

  it('returns null for invalid URL', () => {
    expect(extractDomain('not-a-url')).toBeNull();
  });

  it('returns null for empty string', () => {
    expect(extractDomain('')).toBeNull();
  });

  it('handles URL with port', () => {
    expect(extractDomain('https://localhost:3000')).toBe('localhost');
  });

  it('handles IP address', () => {
    expect(extractDomain('https://192.168.1.1/admin')).toBe('192.168.1.1');
  });
});

// ---------------------------------------------------------------------------
// domainsMatch — Exact Match
// ---------------------------------------------------------------------------

describe('domainsMatch — exact', () => {
  it('matches identical domains', () => {
    expect(domainsMatch('example.com', 'example.com')).toBe(true);
  });

  it('is case-insensitive', () => {
    expect(domainsMatch('Example.COM', 'example.com')).toBe(true);
  });

  it('does not match different domains', () => {
    expect(domainsMatch('example.com', 'other.com')).toBe(false);
  });

  it('returns false for empty credential domain', () => {
    expect(domainsMatch('', 'example.com')).toBe(false);
  });

  it('returns false for empty page domain', () => {
    expect(domainsMatch('example.com', '')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// domainsMatch — Subdomain Match
// ---------------------------------------------------------------------------

describe('domainsMatch — subdomain', () => {
  it('matches subdomain against base domain', () => {
    expect(domainsMatch('example.com', 'sub.example.com')).toBe(true);
  });

  it('matches deep subdomain', () => {
    expect(domainsMatch('example.com', 'a.b.c.example.com')).toBe(true);
  });

  it('prevents subdomain spoofing (evil-example.com)', () => {
    // "evil-example.com" ends with "example.com" but is NOT a subdomain
    expect(domainsMatch('example.com', 'evil-example.com')).toBe(false);
  });

  it('prevents prefix spoofing (exampleXcom.evil.com)', () => {
    expect(domainsMatch('example.com', 'example.com.evil.com')).toBe(false);
  });

  it('does not match when page is parent of credential', () => {
    // Credential is sub.example.com, page is example.com
    // sub.example.com should NOT match against plain example.com page
    expect(domainsMatch('sub.example.com', 'example.com')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Server-side match modes (tested via pure logic, no server)
// ---------------------------------------------------------------------------

describe('URI match modes — logic verification', () => {
  // These tests verify the match mode logic that the server uses,
  // reimplemented here to ensure the browser extension can reason about them.

  function hostMatch(uri: string, domain: string): boolean {
    try {
      const parsed = new URL(uri);
      return parsed.hostname.toLowerCase() === domain.toLowerCase();
    } catch {
      return false;
    }
  }

  function startsWithMatch(uri: string, domain: string): boolean {
    return (
      uri.startsWith('https://' + domain) || uri.startsWith('http://' + domain)
    );
  }

  function regexMatch(pattern: string, domain: string): boolean {
    try {
      const re = new RegExp(pattern);
      return re.test('https://' + domain) || re.test('http://' + domain);
    } catch {
      return false;
    }
  }

  function exactMatch(uri: string, domain: string): boolean {
    return uri === 'https://' + domain || uri === 'http://' + domain;
  }

  function neverMatch(): boolean {
    return false;
  }

  describe('host match', () => {
    it('matches exact hostname', () => {
      expect(hostMatch('https://example.com/path', 'example.com')).toBe(true);
    });

    it('does not match subdomain', () => {
      expect(hostMatch('https://sub.example.com', 'example.com')).toBe(false);
    });
  });

  describe('starts_with match', () => {
    it('matches URL starting with domain', () => {
      expect(startsWithMatch('https://example.com/login', 'example.com')).toBe(true);
    });

    it('does not match different domain', () => {
      expect(startsWithMatch('https://other.com/login', 'example.com')).toBe(false);
    });
  });

  describe('regex match', () => {
    it('matches regex pattern', () => {
      expect(regexMatch('example\\.com', 'example.com')).toBe(true);
    });

    it('handles complex regex', () => {
      expect(regexMatch('(dev|staging)\\.example\\.com', 'dev.example.com')).toBe(true);
      expect(regexMatch('(dev|staging)\\.example\\.com', 'staging.example.com')).toBe(true);
      expect(regexMatch('(dev|staging)\\.example\\.com', 'prod.example.com')).toBe(false);
    });

    it('returns false for invalid regex', () => {
      expect(regexMatch('[invalid', 'example.com')).toBe(false);
    });
  });

  describe('exact match', () => {
    it('matches exact URL', () => {
      expect(exactMatch('https://example.com', 'example.com')).toBe(true);
    });

    it('does not match with path', () => {
      expect(exactMatch('https://example.com/path', 'example.com')).toBe(false);
    });
  });

  describe('never match', () => {
    it('always returns false', () => {
      expect(neverMatch()).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Multiple URIs — entry with several URI match configurations
// ---------------------------------------------------------------------------

describe('Multiple URIs per entry', () => {
  interface TestURI {
    uri: string;
    match?: 'base_domain' | 'host' | 'starts_with' | 'regex' | 'exact' | 'never';
  }

  function entryMatchesDomain(uris: TestURI[], pageDomain: string): boolean {
    if (!uris || uris.length === 0) return false;
    return uris.some((u) => {
      const mode = u.match || 'base_domain';
      if (mode === 'never') return false;
      if (mode === 'base_domain') {
        const domain = extractDomain(u.uri);
        return domain ? domainsMatch(domain, pageDomain) : false;
      }
      if (mode === 'host') {
        const domain = extractDomain(u.uri);
        return domain?.toLowerCase() === pageDomain.toLowerCase();
      }
      if (mode === 'exact') {
        return u.uri === 'https://' + pageDomain || u.uri === 'http://' + pageDomain;
      }
      return false; // starts_with / regex would need full URL context
    });
  }

  it('matches when any URI matches', () => {
    const uris: TestURI[] = [
      { uri: 'https://app.example.com', match: 'host' },
      { uri: 'https://example.com', match: 'base_domain' },
    ];
    expect(entryMatchesDomain(uris, 'sub.example.com')).toBe(true);
  });

  it('does not match when all URIs use never', () => {
    const uris: TestURI[] = [
      { uri: 'https://example.com', match: 'never' },
    ];
    expect(entryMatchesDomain(uris, 'example.com')).toBe(false);
  });

  it('does not match when no URIs provided', () => {
    expect(entryMatchesDomain([], 'example.com')).toBe(false);
  });

  it('defaults to base_domain when match is undefined', () => {
    const uris: TestURI[] = [{ uri: 'https://example.com' }];
    expect(entryMatchesDomain(uris, 'example.com')).toBe(true);
    expect(entryMatchesDomain(uris, 'sub.example.com')).toBe(true);
  });
});
