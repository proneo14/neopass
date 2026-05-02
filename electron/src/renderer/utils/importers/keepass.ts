import type { ImportResult, ImportedEntry } from './types';

/**
 * Parse KeePass XML export (KDBX XML format).
 * Structure: <KeePassFile><Root><Group><Entry>...
 */
export function parseKeePassXML(text: string): ImportResult {
  const entries: ImportedEntry[] = [];
  const errors: string[] = [];

  const parser = new DOMParser();
  const doc = parser.parseFromString(text, 'text/xml');

  const parseError = doc.querySelector('parsererror');
  if (parseError) {
    return { entries: [], errors: ['Invalid XML file: ' + parseError.textContent?.slice(0, 100)] };
  }

  function processGroup(groupEl: Element, folderPath: string) {
    // Get group name
    const nameEl = groupEl.querySelector(':scope > Name');
    const groupName = nameEl?.textContent || '';
    const currentPath = folderPath ? `${folderPath}/${groupName}` : groupName;

    // Process entries in this group
    const entryEls = groupEl.querySelectorAll(':scope > Entry');
    for (let i = 0; i < entryEls.length; i++) {
      try {
        const entry = entryEls[i];
        const strings = entry.querySelectorAll(':scope > String');
        const fieldMap: Record<string, string> = {};

        for (const str of strings) {
          const key = str.querySelector('Key')?.textContent ?? '';
          const value = str.querySelector('Value')?.textContent ?? '';
          fieldMap[key] = value;
        }

        const name = fieldMap.Title || 'Untitled';
        const fields: Record<string, string> = {
          name,
          username: fieldMap.UserName || '',
          password: fieldMap.Password || '',
          uri: fieldMap.URL || '',
          notes: fieldMap.Notes || '',
        };

        entries.push({
          type: 'login',
          name,
          fields,
          folder: currentPath || undefined,
        });
      } catch (e) {
        errors.push(`Entry in "${currentPath}": ${e instanceof Error ? e.message : 'Parse error'}`);
      }
    }

    // Recursively process subgroups
    const subGroups = groupEl.querySelectorAll(':scope > Group');
    for (const sub of subGroups) {
      processGroup(sub, currentPath);
    }
  }

  // Find root group(s)
  const rootGroups = doc.querySelectorAll('KeePassFile > Root > Group');
  if (rootGroups.length === 0) {
    // Try alternate structure
    const altGroups = doc.querySelectorAll('Root > Group');
    if (altGroups.length === 0) {
      errors.push('No groups found in KeePass XML');
    } else {
      for (const g of altGroups) processGroup(g, '');
    }
  } else {
    for (const g of rootGroups) processGroup(g, '');
  }

  return { entries, errors };
}
