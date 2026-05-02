export type { ImportedEntry, ImportResult } from './types';
export { parseBitwardenCSV, parseBitwardenJSON } from './bitwarden';
export { parse1PasswordCSV } from './onepassword';
export { parseLastPassCSV } from './lastpass';
export { parseChromeCSV } from './chrome';
export { parseFirefoxCSV } from './firefox';
export { parseKeePassXML } from './keepass';

import { parseBitwardenCSV, parseBitwardenJSON } from './bitwarden';
import { parse1PasswordCSV } from './onepassword';
import { parseLastPassCSV } from './lastpass';
import { parseChromeCSV } from './chrome';
import { parseFirefoxCSV } from './firefox';
import { parseKeePassXML } from './keepass';
import type { ImportResult } from './types';

export interface ImportSource {
  id: string;
  name: string;
  icon: string;
  formats: string; // description of accepted formats
  accept: string; // file input accept attribute
}

export const IMPORT_SOURCES: ImportSource[] = [
  { id: 'bitwarden', name: 'Bitwarden', icon: '🔐', formats: 'CSV or JSON export', accept: '.csv,.json' },
  { id: '1password', name: '1Password', icon: '🔑', formats: 'CSV export', accept: '.csv' },
  { id: 'lastpass', name: 'LastPass', icon: '🔒', formats: 'CSV export', accept: '.csv' },
  { id: 'chrome', name: 'Chrome / Edge', icon: '🌐', formats: 'CSV export', accept: '.csv' },
  { id: 'firefox', name: 'Firefox', icon: '🦊', formats: 'CSV export', accept: '.csv' },
  { id: 'keepass', name: 'KeePass', icon: '🗝️', formats: 'XML export (KDBX)', accept: '.xml' },
];

/**
 * Route file content to the appropriate parser based on source ID and file name.
 */
export function parseImportFile(sourceId: string, fileContent: string, fileName: string): ImportResult {
  switch (sourceId) {
    case 'bitwarden':
      if (fileName.endsWith('.json')) return parseBitwardenJSON(fileContent);
      return parseBitwardenCSV(fileContent);
    case '1password':
      return parse1PasswordCSV(fileContent);
    case 'lastpass':
      return parseLastPassCSV(fileContent);
    case 'chrome':
      return parseChromeCSV(fileContent);
    case 'firefox':
      return parseFirefoxCSV(fileContent);
    case 'keepass':
      return parseKeePassXML(fileContent);
    default:
      return { entries: [], errors: [`Unknown source: ${sourceId}`] };
  }
}
