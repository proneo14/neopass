import { csvToObjects } from './csv';
import type { ImportResult, ImportedEntry } from './types';

/**
 * Parse LastPass CSV export.
 * Columns: url, username, password, totp, extra, name, grouping, fav
 */
export function parseLastPassCSV(text: string): ImportResult {
  const entries: ImportedEntry[] = [];
  const errors: string[] = [];
  const rows = csvToObjects(text);

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    try {
      const name = row.name || row.Name || 'Untitled';
      const url = row.url || row.URL || '';
      const username = row.username || row.Username || '';
      const password = row.password || row.Password || '';
      const notes = row.extra || row.Extra || row.notes || '';
      const totp = row.totp || '';
      const folder = row.grouping || row.Grouping || row.group || '';

      // LastPass uses url "http://sn" for secure notes
      const isNote = url === 'http://sn' || url === 'http://sn/';
      const type: ImportedEntry['type'] = isNote ? 'secure_note' : 'login';

      const fields: Record<string, string> = { name };

      if (type === 'login') {
        fields.username = username;
        fields.password = password;
        fields.uri = url;
        fields.notes = notes;
        if (totp) fields.totp = totp;
      } else {
        fields.content = notes;
      }

      entries.push({
        type,
        name,
        fields,
        folder: folder || undefined,
        favorite: row.fav === '1',
      });
    } catch (e) {
      errors.push(`Row ${i + 2}: ${e instanceof Error ? e.message : 'Parse error'}`);
    }
  }

  return { entries, errors };
}
