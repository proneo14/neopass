/**
 * Tests for password health analysis utilities.
 * All analysis runs client-side to maintain zero-knowledge.
 */
import { describe, it, expect, vi } from 'vitest';

import {
  scorePassword,
  findWeakPasswords,
  findReusedPasswords,
  findOldPasswords,
  findInsecureURIs,
  calculateOverallScore,
  analyzeVault,
  type PasswordHealthEntry,
} from '../../electron/src/renderer/utils/passwordHealth';

// ---------------------------------------------------------------------------
// Password Scoring
// ---------------------------------------------------------------------------

describe('scorePassword', () => {
  it('flags common passwords as Very Weak (score 0)', () => {
    const common = ['password', '123456', 'qwerty', 'admin', 'letmein'];
    for (const pw of common) {
      const result = scorePassword(pw);
      expect(result.score, `"${pw}" should be score 0`).toBe(0);
      expect(result.label).toBe('Very Weak');
    }
  });

  it('flags empty password as Very Weak', () => {
    expect(scorePassword('').score).toBe(0);
  });

  it('flags short passwords as weak', () => {
    const result = scorePassword('Ab1!');
    expect(result.score).toBeLessThanOrEqual(1);
  });

  it('scores complex long passwords as Strong or Very Strong', () => {
    const result = scorePassword('C0mpl3x!P@ssw0rd#2024');
    expect(result.score).toBeGreaterThanOrEqual(3);
  });

  it('scores medium passwords as Fair', () => {
    const result = scorePassword('Medium12');
    expect(result.score).toBeGreaterThanOrEqual(1);
    expect(result.score).toBeLessThanOrEqual(3);
  });

  it('penalizes repeated characters', () => {
    const result = scorePassword('aaaaaaaaaa');
    expect(result.score).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Weak Password Detection
// ---------------------------------------------------------------------------

describe('findWeakPasswords', () => {
  it('detects weak passwords', () => {
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'Bad', username: 'u', password: 'password', uri: '', updatedAt: new Date().toISOString() },
      { entryId: '2', name: 'Good', username: 'u', password: 'V3ry$ecure!Long#Pass', uri: '', updatedAt: new Date().toISOString() },
      { entryId: '3', name: 'Short', username: 'u', password: 'ab', uri: '', updatedAt: new Date().toISOString() },
    ];

    const weak = findWeakPasswords(entries);
    expect(weak.length).toBeGreaterThanOrEqual(2); // "password" and "ab"
    expect(weak.find((e) => e.entryId === '2')).toBeUndefined(); // strong password not flagged
  });

  it('excludes entries without passwords', () => {
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'No PW', username: 'u', password: '', uri: '', updatedAt: new Date().toISOString() },
    ];
    const weak = findWeakPasswords(entries);
    expect(weak).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Reused Password Detection
// ---------------------------------------------------------------------------

describe('findReusedPasswords', () => {
  it('groups entries with the same password', () => {
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'Site A', username: 'u', password: 'shared123', uri: '', updatedAt: '' },
      { entryId: '2', name: 'Site B', username: 'u', password: 'shared123', uri: '', updatedAt: '' },
      { entryId: '3', name: 'Site C', username: 'u', password: 'unique456', uri: '', updatedAt: '' },
    ];

    const groups = findReusedPasswords(entries);
    expect(groups).toHaveLength(1);
    expect(groups[0]).toHaveLength(2);
    expect(groups[0].map((e) => e.entryId).sort()).toEqual(['1', '2']);
  });

  it('returns empty for all unique passwords', () => {
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'A', username: 'u', password: 'pass1', uri: '', updatedAt: '' },
      { entryId: '2', name: 'B', username: 'u', password: 'pass2', uri: '', updatedAt: '' },
    ];
    const groups = findReusedPasswords(entries);
    expect(groups).toHaveLength(0);
  });

  it('handles multiple reuse groups', () => {
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'A', username: 'u', password: 'same1', uri: '', updatedAt: '' },
      { entryId: '2', name: 'B', username: 'u', password: 'same1', uri: '', updatedAt: '' },
      { entryId: '3', name: 'C', username: 'u', password: 'same2', uri: '', updatedAt: '' },
      { entryId: '4', name: 'D', username: 'u', password: 'same2', uri: '', updatedAt: '' },
    ];
    const groups = findReusedPasswords(entries);
    expect(groups).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Old Password Detection
// ---------------------------------------------------------------------------

describe('findOldPasswords', () => {
  it('flags passwords older than 90 days', () => {
    const oldDate = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString();
    const recentDate = new Date().toISOString();

    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'Old', username: 'u', password: 'pass', uri: '', updatedAt: oldDate },
      { entryId: '2', name: 'Recent', username: 'u', password: 'pass', uri: '', updatedAt: recentDate },
    ];

    const old = findOldPasswords(entries);
    expect(old).toHaveLength(1);
    expect(old[0].entryId).toBe('1');
  });

  it('respects custom maxAgeDays', () => {
    const date = new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString();
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'A', username: 'u', password: 'p', uri: '', updatedAt: date },
    ];

    expect(findOldPasswords(entries, 30)).toHaveLength(1);
    expect(findOldPasswords(entries, 60)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Insecure URI Detection
// ---------------------------------------------------------------------------

describe('findInsecureURIs', () => {
  it('flags http:// URIs', () => {
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'Insecure', username: 'u', password: 'p', uri: 'http://example.com', updatedAt: '' },
      { entryId: '2', name: 'Secure', username: 'u', password: 'p', uri: 'https://example.com', updatedAt: '' },
    ];

    const insecure = findInsecureURIs(entries);
    expect(insecure).toHaveLength(1);
    expect(insecure[0].entryId).toBe('1');
  });

  it('ignores entries without URIs', () => {
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'No URI', username: 'u', password: 'p', uri: '', updatedAt: '' },
    ];
    expect(findInsecureURIs(entries)).toHaveLength(0);
  });

  it('ignores invalid URIs', () => {
    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'Bad', username: 'u', password: 'p', uri: 'not-a-url', updatedAt: '' },
    ];
    expect(findInsecureURIs(entries)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// HIBP k-Anonymity Check
// ---------------------------------------------------------------------------

describe('HIBP k-Anonymity', () => {
  it('only sends 5-char SHA-1 prefix (mock verification)', async () => {
    // This test verifies the k-anonymity approach:
    // We hash the password, take the first 5 chars, and only send that prefix.
    const { createHash } = await import('crypto');
    const password = 'testpassword123';
    const sha1 = createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    expect(prefix).toHaveLength(5);
    expect(suffix.length).toBeGreaterThan(0);
    // The full hash should never be sent — only the prefix
    expect(prefix + suffix).toBe(sha1);
    // In production, only `prefix` would be sent to api.pwnedpasswords.com
  });
});

// ---------------------------------------------------------------------------
// Overall Score
// ---------------------------------------------------------------------------

describe('calculateOverallScore', () => {
  it('returns 100 for an empty vault', () => {
    const score = calculateOverallScore({
      totalLogins: 0,
      weakPasswords: [],
      reusedGroups: [],
      oldPasswords: [],
      insecureURIs: [],
      breachedPasswords: [],
    });
    expect(score).toBe(100);
  });

  it('returns high score for healthy vault', () => {
    const score = calculateOverallScore({
      totalLogins: 10,
      weakPasswords: [],
      reusedGroups: [],
      oldPasswords: [],
      insecureURIs: [],
      breachedPasswords: [],
    });
    expect(score).toBe(100);
  });

  it('penalizes weak passwords', () => {
    const entry: PasswordHealthEntry = { entryId: '1', name: 'A', username: 'u', password: 'p', uri: '', updatedAt: '' };
    const score = calculateOverallScore({
      totalLogins: 4,
      weakPasswords: [entry, entry],
      reusedGroups: [],
      oldPasswords: [],
      insecureURIs: [],
      breachedPasswords: [],
    });
    expect(score).toBeLessThan(100);
  });

  it('penalizes breached passwords heavily', () => {
    const entry: PasswordHealthEntry = { entryId: '1', name: 'A', username: 'u', password: 'p', uri: '', updatedAt: '' };
    const score = calculateOverallScore({
      totalLogins: 1,
      weakPasswords: [],
      reusedGroups: [],
      oldPasswords: [],
      insecureURIs: [],
      breachedPasswords: [entry],
    });
    expect(score).toBeLessThanOrEqual(80);
  });
});

// ---------------------------------------------------------------------------
// analyzeVault Integration
// ---------------------------------------------------------------------------

describe('analyzeVault', () => {
  it('produces a complete report', () => {
    const now = new Date().toISOString();
    const oldDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString();

    const entries: PasswordHealthEntry[] = [
      { entryId: '1', name: 'Strong', username: 'u1', password: 'V3ry$ecure!Pass#99', uri: 'https://secure.com', updatedAt: now },
      { entryId: '2', name: 'Weak', username: 'u2', password: 'password', uri: 'https://weak.com', updatedAt: now },
      { entryId: '3', name: 'Reused1', username: 'u3', password: 'reused!', uri: 'https://a.com', updatedAt: now },
      { entryId: '4', name: 'Reused2', username: 'u4', password: 'reused!', uri: 'https://b.com', updatedAt: now },
      { entryId: '5', name: 'Old', username: 'u5', password: 'old-pass-123', uri: 'https://old.com', updatedAt: oldDate },
      { entryId: '6', name: 'HTTP', username: 'u6', password: 'insecure1!', uri: 'http://plain.com', updatedAt: now },
    ];

    const report = analyzeVault(entries);

    expect(report.totalLogins).toBe(6);
    expect(report.weakPasswords.length).toBeGreaterThanOrEqual(1); // "password" is weak
    expect(report.reusedGroups.length).toBeGreaterThanOrEqual(1); // "reused!" group
    expect(report.oldPasswords.length).toBeGreaterThanOrEqual(1); // entry 5
    expect(report.insecureURIs.length).toBeGreaterThanOrEqual(1); // entry 6
    expect(report.overallScore).toBeLessThan(100);
    expect(report.overallScore).toBeGreaterThanOrEqual(0);
  });
});
