/**
 * Tests for vault import parsers.
 * Verifies that CSV/JSON exports from major password managers are correctly
 * parsed into the normalized ImportedEntry format.
 */
import { describe, it, expect } from 'vitest';

// Import parsers directly
import { parseBitwardenCSV, parseBitwardenJSON } from '../../electron/src/renderer/utils/importers/bitwarden';
import { parse1PasswordCSV } from '../../electron/src/renderer/utils/importers/onepassword';
import { parseLastPassCSV } from '../../electron/src/renderer/utils/importers/lastpass';
import { parseChromeCSV } from '../../electron/src/renderer/utils/importers/chrome';
import { parseFirefoxCSV } from '../../electron/src/renderer/utils/importers/firefox';

// ---------------------------------------------------------------------------
// Bitwarden CSV
// ---------------------------------------------------------------------------

describe('Bitwarden CSV Import', () => {
  const sampleCSV = `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Social,1,login,Twitter,,,,https://twitter.com,alice,p@ssw0rd,
,0,note,My Note,Some secret content,,,,,
Work,,login,GitHub,,,,https://github.com,bob,gh-token123,JBSWY3DPEHPK3PXP`;

  it('parses login entries correctly', () => {
    const result = parseBitwardenCSV(sampleCSV);
    expect(result.errors).toHaveLength(0);
    expect(result.entries).toHaveLength(3);

    const twitter = result.entries[0];
    expect(twitter.type).toBe('login');
    expect(twitter.name).toBe('Twitter');
    expect(twitter.fields.username).toBe('alice');
    expect(twitter.fields.password).toBe('p@ssw0rd');
    expect(twitter.fields.uri).toBe('https://twitter.com');
    expect(twitter.folder).toBe('Social');
    expect(twitter.favorite).toBe(true);
  });

  it('parses secure notes', () => {
    const result = parseBitwardenCSV(sampleCSV);
    const note = result.entries[1];
    expect(note.type).toBe('secure_note');
    expect(note.name).toBe('My Note');
    expect(note.fields.content).toBe('Some secret content');
  });

  it('parses TOTP fields', () => {
    const result = parseBitwardenCSV(sampleCSV);
    const github = result.entries[2];
    expect(github.fields.totp).toBe('JBSWY3DPEHPK3PXP');
  });

  it('handles empty CSV', () => {
    const result = parseBitwardenCSV(`folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`);
    expect(result.entries).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });
});

describe('Bitwarden JSON Import', () => {
  it('parses JSON export with items and folders', () => {
    const json = JSON.stringify({
      encrypted: false,
      folders: [{ id: 'f1', name: 'Work' }],
      items: [
        {
          type: 1,
          name: 'GitHub',
          folderId: 'f1',
          login: {
            username: 'bob',
            password: 'secret',
            uris: [{ uri: 'https://github.com' }],
            totp: 'TOTP123',
          },
          notes: 'dev account',
        },
        {
          type: 2,
          name: 'Private Note',
          notes: 'very secret',
        },
      ],
    });

    const result = parseBitwardenJSON(json);
    expect(result.errors).toHaveLength(0);
    expect(result.entries).toHaveLength(2);

    const github = result.entries[0];
    expect(github.type).toBe('login');
    expect(github.fields.username).toBe('bob');
    expect(github.fields.totp).toBe('TOTP123');

    const note = result.entries[1];
    expect(note.type).toBe('secure_note');
  });

  it('handles invalid JSON', () => {
    const result = parseBitwardenJSON('not json');
    expect(result.entries).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// 1Password CSV
// ---------------------------------------------------------------------------

describe('1Password CSV Import', () => {
  const sampleCSV = `Title,Username,Password,URL,Notes,Type
Gmail,user@gmail.com,mypassword,https://mail.google.com,personal email,login
Secret Note,,,,,Secure Note`;

  it('parses login entries', () => {
    const result = parse1PasswordCSV(sampleCSV);
    expect(result.errors).toHaveLength(0);
    expect(result.entries.length).toBeGreaterThanOrEqual(1);

    const gmail = result.entries[0];
    expect(gmail.type).toBe('login');
    expect(gmail.name).toBe('Gmail');
    expect(gmail.fields.username).toBe('user@gmail.com');
    expect(gmail.fields.password).toBe('mypassword');
    expect(gmail.fields.uri).toBe('https://mail.google.com');
  });

  it('maps secure note type', () => {
    const result = parse1PasswordCSV(sampleCSV);
    // Second entry should be a secure note based on Type column
    const noteEntries = result.entries.filter((e) => e.type === 'secure_note');
    expect(noteEntries.length).toBeGreaterThanOrEqual(1);
  });

  it('handles credit card type', () => {
    const csv = `Title,Username,Password,URL,Notes,Type,Card Number,Expiry Date,CVV,Cardholder Name
My Card,,,,billing,Credit Card,4111111111111111,12/25,123,John Doe`;

    const result = parse1PasswordCSV(csv);
    const card = result.entries.find((e) => e.type === 'credit_card');
    expect(card).toBeDefined();
    expect(card!.fields.number).toBe('4111111111111111');
    expect(card!.fields.cvv).toBe('123');
  });
});

// ---------------------------------------------------------------------------
// LastPass CSV
// ---------------------------------------------------------------------------

describe('LastPass CSV Import', () => {
  const sampleCSV = `url,username,password,totp,extra,name,grouping,fav
https://twitter.com,alice,twitterpw,,some notes,Twitter,Social,1
http://sn,,,,This is a secure note,My Secret Note,,0
https://github.com,bob,ghpass,TOTP123,,GitHub,Work,0`;

  it('parses login entries', () => {
    const result = parseLastPassCSV(sampleCSV);
    expect(result.errors).toHaveLength(0);

    const twitter = result.entries.find((e) => e.name === 'Twitter');
    expect(twitter).toBeDefined();
    expect(twitter!.type).toBe('login');
    expect(twitter!.fields.username).toBe('alice');
    expect(twitter!.folder).toBe('Social');
    expect(twitter!.favorite).toBe(true);
  });

  it('detects secure notes from http://sn URL', () => {
    const result = parseLastPassCSV(sampleCSV);
    const note = result.entries.find((e) => e.type === 'secure_note');
    expect(note).toBeDefined();
    expect(note!.name).toBe('My Secret Note');
  });

  it('maps folder from grouping column', () => {
    const result = parseLastPassCSV(sampleCSV);
    const github = result.entries.find((e) => e.name === 'GitHub');
    expect(github!.folder).toBe('Work');
  });

  it('preserves TOTP', () => {
    const result = parseLastPassCSV(sampleCSV);
    const github = result.entries.find((e) => e.name === 'GitHub');
    expect(github!.fields.totp).toBe('TOTP123');
  });
});

// ---------------------------------------------------------------------------
// Chrome CSV
// ---------------------------------------------------------------------------

describe('Chrome CSV Import', () => {
  const sampleCSV = `name,url,username,password,note
example.com,https://example.com,admin,pass123,
GitHub,https://github.com,dev,devpass,work account`;

  it('parses all entries as login type', () => {
    const result = parseChromeCSV(sampleCSV);
    expect(result.errors).toHaveLength(0);
    expect(result.entries).toHaveLength(2);

    for (const entry of result.entries) {
      expect(entry.type).toBe('login');
    }
  });

  it('maps all fields correctly', () => {
    const result = parseChromeCSV(sampleCSV);
    const github = result.entries[1];
    expect(github.name).toBe('GitHub');
    expect(github.fields.username).toBe('dev');
    expect(github.fields.password).toBe('devpass');
    expect(github.fields.uri).toBe('https://github.com');
    expect(github.fields.notes).toBe('work account');
  });

  it('handles empty fields', () => {
    const csv = `name,url,username,password,note
Blank,,,,`;
    const result = parseChromeCSV(csv);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].fields.username).toBe('');
  });
});

// ---------------------------------------------------------------------------
// Firefox CSV
// ---------------------------------------------------------------------------

describe('Firefox CSV Import', () => {
  const sampleCSV = `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
https://example.com,user1,pass1,,,abc-123,1620000000000,1625000000000,1622000000000
https://github.com/login,dev,devpass,,,def-456,1620000000000,1625000000000,1623000000000`;

  it('parses entries and derives name from URL', () => {
    const result = parseFirefoxCSV(sampleCSV);
    expect(result.errors).toHaveLength(0);
    expect(result.entries).toHaveLength(2);

    expect(result.entries[0].name).toBe('example.com');
    expect(result.entries[1].name).toBe('github.com');
  });

  it('maps username, password, and URI', () => {
    const result = parseFirefoxCSV(sampleCSV);
    const entry = result.entries[0];
    expect(entry.fields.username).toBe('user1');
    expect(entry.fields.password).toBe('pass1');
    expect(entry.fields.uri).toBe('https://example.com');
  });

  it('handles missing URL gracefully', () => {
    const csv = `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
,user1,pass1,,,,,`;
    const result = parseFirefoxCSV(csv);
    expect(result.entries).toHaveLength(1);
    // Name should fall back
    expect(result.entries[0].name).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Duplicate Detection
// ---------------------------------------------------------------------------

describe('Duplicate Detection', () => {
  it('identifies entries with same name, username, and URI', () => {
    const entries = [
      { type: 'login' as const, name: 'GitHub', fields: { name: 'GitHub', username: 'dev', password: 'p1', uri: 'https://github.com' } },
      { type: 'login' as const, name: 'GitHub', fields: { name: 'GitHub', username: 'dev', password: 'p2', uri: 'https://github.com' } },
      { type: 'login' as const, name: 'Twitter', fields: { name: 'Twitter', username: 'alice', password: 'p3', uri: 'https://twitter.com' } },
    ];

    // Simple duplicate detection: same name + username + uri
    const seen = new Set<string>();
    const duplicates: typeof entries = [];
    for (const entry of entries) {
      const key = `${entry.name}|${entry.fields.username}|${entry.fields.uri}`;
      if (seen.has(key)) {
        duplicates.push(entry);
      } else {
        seen.add(key);
      }
    }

    expect(duplicates).toHaveLength(1);
    expect(duplicates[0].name).toBe('GitHub');
  });
});
