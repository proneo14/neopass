import { csvToObjects } from './csv';
import type { ImportResult, ImportedEntry } from './types';

/**
 * Parse Chrome/Chromium CSV export.
 * Columns: name, url, username, password, note
 */
export function parseChromeCSV(text: string): ImportResult {
  const entries: ImportedEntry[] = [];
  const errors: string[] = [];
  const rows = csvToObjects(text);

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    try {
      const name = row.name || row.Name || row.url || 'Untitled';
      const fields: Record<string, string> = {
        name,
        username: row.username || row.Username || '',
        password: row.password || row.Password || '',
        uri: row.url || row.URL || '',
        notes: row.note || row.Note || row.notes || '',
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
