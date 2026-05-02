import { csvToObjects } from './csv';
import type { ImportResult, ImportedEntry } from './types';

/**
 * Parse Firefox CSV export.
 * Columns: url, username, password, httpRealm, formActionOrigin, guid, timeCreated,
 *          timeLastUsed, timePasswordChanged
 */
export function parseFirefoxCSV(text: string): ImportResult {
  const entries: ImportedEntry[] = [];
  const errors: string[] = [];
  const rows = csvToObjects(text);

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    try {
      const url = row.url || row.URL || '';
      // Firefox doesn't export a name field — derive from URL
      let name = 'Untitled';
      try {
        const parsed = new URL(url);
        name = parsed.hostname || url;
      } catch {
        name = url || 'Untitled';
      }

      const fields: Record<string, string> = {
        name,
        username: row.username || '',
        password: row.password || '',
        uri: url,
        notes: '',
      };

      entries.push({
        type: 'login',
        name,
        fields,
      });
    } catch (e) {
      errors.push(`Row ${i + 2}: ${e instanceof Error ? e.message : 'Parse error'}`);
    }
  }

  return { entries, errors };
}
