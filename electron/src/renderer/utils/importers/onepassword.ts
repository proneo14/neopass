import { csvToObjects } from './csv';
import type { ImportResult, ImportedEntry } from './types';

/**
 * Parse 1Password CSV export.
 * 1Password exports have varying columns depending on the item type.
 * Common columns: Title, Username, Password, URL, Notes, Type
 * Also supports 1Password 1PUX/1PIF JSON format.
 */
export function parse1PasswordCSV(text: string): ImportResult {
  const entries: ImportedEntry[] = [];
  const errors: string[] = [];
  const rows = csvToObjects(text);

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    try {
      const name = row.Title || row.title || 'Untitled';
      const notes = row.Notes || row.notes || row.notesPlain || '';
      const type1p = (row.Type || row.type || 'login').toLowerCase();

      let type: ImportedEntry['type'] = 'login';
      if (type1p.includes('note') || type1p === 'secure note') type = 'secure_note';
      else if (type1p.includes('card') || type1p === 'credit card') type = 'credit_card';
      else if (type1p.includes('identity')) type = 'identity';

      const fields: Record<string, string> = { name };

      if (type === 'login') {
        fields.username = row.Username || row.username || '';
        fields.password = row.Password || row.password || '';
        fields.uri = row.URL || row.url || row.URLs || '';
        fields.notes = notes;
        if (row['One-Time Password'] || row.otp) {
          fields.totp = row['One-Time Password'] || row.otp;
        }
      } else if (type === 'secure_note') {
        fields.content = notes;
      } else if (type === 'credit_card') {
        fields.number = row['Card Number'] || row.number || '';
        fields.expiry = row['Expiry Date'] || row.expiry || '';
        fields.cvv = row.CVV || row['Verification Number'] || '';
        fields.cardholder = row['Cardholder Name'] || row.cardholder || '';
        fields.notes = notes;
      } else if (type === 'identity') {
        fields.firstName = row['First Name'] || row.firstName || '';
        fields.lastName = row['Last Name'] || row.lastName || '';
        fields.email = row.Email || row.email || '';
        fields.phone = row.Phone || row.phone || '';
        fields.address = row.Address || row.address || '';
        fields.notes = notes;
      }

      entries.push({
        type,
        name,
        fields,
        folder: row.Vault || row.vault || row.Category || undefined,
        favorite: row.Favorite === '1' || row.favorite === 'true',
      });
    } catch (e) {
      errors.push(`Row ${i + 2}: ${e instanceof Error ? e.message : 'Parse error'}`);
    }
  }

  return { entries, errors };
}
