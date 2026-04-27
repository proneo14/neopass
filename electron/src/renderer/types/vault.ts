export interface VaultEntry {
  id: string;
  entry_type: 'login' | 'secure_note' | 'credit_card' | 'identity';
  encrypted_data: string;
  nonce: string;
  version: number;
  folder_id: string | null;
  is_favorite: boolean;
  is_archived: boolean;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Folder {
  id: string;
  name_encrypted: string;
  parent_id: string | null;
}

export interface LoginURI {
  uri: string;
  match?: 'base_domain' | 'host' | 'starts_with' | 'regex' | 'exact' | 'never';
}

export interface PasswordHistoryEntry {
  password: string;
  date: string; // ISO 8601
}

export interface LoginData {
  name: string;
  username: string;
  password: string;
  uri: string;
  uris?: LoginURI[];
  notes: string;
  passwordHistory?: PasswordHistoryEntry[];
}

export interface SecureNoteData {
  name: string;
  content: string;
}

export interface CreditCardData {
  name: string;
  number: string;
  expiry: string;
  cvv: string;
  cardholder: string;
}

export interface IdentityData {
  name: string;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
}

export type EntryData = LoginData | SecureNoteData | CreditCardData | IdentityData;

export const ENTRY_TYPE_ICONS: Record<string, string> = {
  login: '🔑',
  secure_note: '📝',
  credit_card: '💳',
  identity: '👤',
};

export const ENTRY_TYPE_LABELS: Record<string, string> = {
  login: 'Login',
  secure_note: 'Secure Note',
  credit_card: 'Credit Card',
  identity: 'Identity',
};
