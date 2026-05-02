/** Normalized entry structure produced by all import parsers. */
export interface ImportedEntry {
  type: 'login' | 'secure_note' | 'credit_card' | 'identity';
  name: string;
  fields: Record<string, string>;
  folder?: string;
  favorite?: boolean;
}

/** Result from an import parser. */
export interface ImportResult {
  entries: ImportedEntry[];
  errors: string[];
}
