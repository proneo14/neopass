import { csvToObjects } from './csv';
import type { ImportResult, ImportedEntry } from './types';

/**
 * Parse Bitwarden CSV export.
 * Columns: folder, favorite, type, name, notes, fields, reprompt, login_uri, login_username,
 *          login_password, login_totp
 */
export function parseBitwardenCSV(text: string): ImportResult {
  const entries: ImportedEntry[] = [];
  const errors: string[] = [];
  const rows = csvToObjects(text);

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    try {
      const bwType = (row.type ?? '').toLowerCase();
      let type: ImportedEntry['type'] = 'login';
      if (bwType === 'note' || bwType === 'securenote') type = 'secure_note';
      else if (bwType === 'card') type = 'credit_card';
      else if (bwType === 'identity') type = 'identity';

      const name = row.name || 'Untitled';
      const fields: Record<string, string> = { name };

      if (type === 'login') {
        fields.username = row.login_username ?? '';
        fields.password = row.login_password ?? '';
        fields.uri = row.login_uri ?? '';
        fields.notes = row.notes ?? '';
        if (row.login_totp) fields.totp = row.login_totp;
      } else if (type === 'secure_note') {
        fields.content = row.notes ?? '';
      } else if (type === 'credit_card') {
        fields.number = row.fields ?? '';
        fields.notes = row.notes ?? '';
      } else if (type === 'identity') {
        fields.notes = row.notes ?? '';
      }

      entries.push({
        type,
        name,
        fields,
        folder: row.folder || undefined,
        favorite: row.favorite === '1',
      });
    } catch (e) {
      errors.push(`Row ${i + 2}: ${e instanceof Error ? e.message : 'Parse error'}`);
    }
  }

  return { entries, errors };
}

/**
 * Parse Bitwarden JSON export.
 */
export function parseBitwardenJSON(text: string): ImportResult {
  const entries: ImportedEntry[] = [];
  const errors: string[] = [];

  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    return { entries: [], errors: ['Invalid JSON file'] };
  }

  // Bitwarden JSON has { encrypted: false, folders: [...], items: [...] }
  const items = data.items ?? data;
  if (!Array.isArray(items)) {
    return { entries: [], errors: ['No items found in JSON'] };
  }

  const folderMap: Record<string, string> = {};
  if (Array.isArray(data.folders)) {
    for (const f of data.folders) {
      if (f.id && f.name) folderMap[f.id] = f.name;
    }
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    try {
      // type: 1=login, 2=secure_note, 3=card, 4=identity
      let type: ImportedEntry['type'] = 'login';
      if (item.type === 2) type = 'secure_note';
      else if (item.type === 3) type = 'credit_card';
      else if (item.type === 4) type = 'identity';

      const name = item.name || 'Untitled';
      const fields: Record<string, string> = { name };

      if (type === 'login' && item.login) {
        fields.username = item.login.username ?? '';
        fields.password = item.login.password ?? '';
        fields.uri = item.login.uris?.[0]?.uri ?? '';
        fields.notes = item.notes ?? '';
        if (item.login.totp) fields.totp = item.login.totp;
      } else if (type === 'secure_note') {
        fields.content = item.notes ?? '';
      } else if (type === 'credit_card' && item.card) {
        fields.number = item.card.number ?? '';
        fields.expiry = `${item.card.expMonth ?? ''}/${item.card.expYear ?? ''}`;
        fields.cvv = item.card.code ?? '';
        fields.cardholder = item.card.cardholderName ?? '';
        fields.notes = item.notes ?? '';
      } else if (type === 'identity' && item.identity) {
        fields.firstName = item.identity.firstName ?? '';
        fields.lastName = item.identity.lastName ?? '';
        fields.email = item.identity.email ?? '';
        fields.phone = item.identity.phone ?? '';
        fields.address = [
          item.identity.address1,
          item.identity.address2,
          item.identity.city,
          item.identity.state,
          item.identity.postalCode,
          item.identity.country,
        ].filter(Boolean).join(', ');
        fields.notes = item.notes ?? '';
      }

      entries.push({
        type,
        name,
        fields,
        folder: item.folderId ? folderMap[item.folderId] : undefined,
        favorite: item.favorite === true,
      });
    } catch (e) {
      errors.push(`Item ${i + 1}: ${e instanceof Error ? e.message : 'Parse error'}`);
    }
  }

  return { entries, errors };
}
