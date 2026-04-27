import type { PasswordHealthEntry } from './passwordHealth';

/**
 * Check a password against the Have I Been Pwned Passwords API using
 * k-anonymity. Only the first 5 characters of the SHA-1 hash are sent
 * to the API — the full hash never leaves the device.
 *
 * The actual HTTP request is made from the main process via IPC to
 * avoid renderer CSP/CORS restrictions.
 */
export async function checkPasswordBreach(password: string): Promise<number> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  const result = await window.api.hibp.checkRange(prefix);

  if (result.error) {
    throw new Error(result.error);
  }

  const lines = (result.data ?? '').split('\n');
  for (const line of lines) {
    const [hashSuffix, count] = line.trim().split(':');
    if (hashSuffix === suffix) {
      return parseInt(count, 10);
    }
  }

  return 0;
}

export interface BreachResult {
  entryId: string;
  count: number;
}

/**
 * Check multiple entries against HIBP. Returns only entries that appear
 * in breaches. Rate-limits requests with a small delay to be polite
 * to the HIBP API.
 */
export async function checkBreaches(
  entries: PasswordHealthEntry[],
  onProgress?: (checked: number, total: number) => void,
): Promise<BreachResult[]> {
  const results: BreachResult[] = [];
  const seen = new Map<string, number>(); // password -> breach count cache

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (!entry.password) {
      onProgress?.(i + 1, entries.length);
      continue;
    }

    let count: number;
    const cached = seen.get(entry.password);
    if (cached !== undefined) {
      count = cached;
    } else {
      try {
        count = await checkPasswordBreach(entry.password);
        seen.set(entry.password, count);
      } catch {
        // Skip on error, don't block the whole check
        onProgress?.(i + 1, entries.length);
        continue;
      }
      // Small delay between API calls to avoid hammering HIBP
      if (i < entries.length - 1) {
        await new Promise((r) => setTimeout(r, 150));
      }
    }

    if (count > 0) {
      results.push({ entryId: entry.entryId, count });
    }

    onProgress?.(i + 1, entries.length);
  }

  return results;
}
