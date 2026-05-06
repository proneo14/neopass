import { csvToObjects } from './csv';
import type { ImportResult, ImportedEntry } from './types';

/**
 * Parse Dashlane CSV export.
 * Columns: title, url, username, password, note, category
 */
export function parseDashlaneCSV(text: string): ImportResult {
  const entries: ImportedEntry[] = [];
  const errors: string[] = [];
  const rows = csvToObjects(text);

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    try {
      const name = row.title || row.Title || row.url || 'Untitled';
      const fields: Record<string, string> = {
        name,
        username: row.username || row.Username || row.login || row.Login || '',
        password: row.password || row.Password || '',
        uri: row.url || row.URL || '',
        notes: row.note || row.Note || row.notes || '',
      };

      // Dashlane exports secure notes with type "note"
      const isSecureNote =
        (row.type === 'note' || row.Type === 'note') ||
        (!fields.username && !fields.password && !fields.uri && fields.notes);

      entries.push({
        type: isSecureNote ? 'secure_note' : 'login',
        name,
        fields,
      });
    } catch (e) {
      errors.push(`Row ${i + 2}: ${e instanceof Error ? e.message : 'Parse error'}`);
    }
  }

  return { entries, errors };
}
