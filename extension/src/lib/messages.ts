/**
 * Message types for communication between popup, content script,
 * background service worker, and native messaging host.
 */
export interface FormDetectedMessage {
  type: 'formDetected';
  domain: string;
  fieldCount: number;
}

export interface RequestCredentialsMessage {
  type: 'requestCredentials';
  domain: string;
}

export interface CredentialsResponseMessage {
  type: 'credentialsResponse';
  credentials: Credential[];
}

export interface SaveCredentialMessage {
  type: 'saveCredential';
  domain: string;
  username: string;
  password: string;
}

export interface AutofillMessage {
  type: 'autofill';
  username: string;
  password: string;
}

export interface AutofillCompleteMessage {
  type: 'autofillComplete';
  domain: string;
}

export interface GetStatusMessage {
  type: 'getStatus';
}

export interface StatusResponseMessage {
  type: 'statusResponse';
  status: 'locked' | 'unlocked' | 'no-desktop-app';
  vaultCount?: number;
}

export interface LockMessage {
  type: 'lock';
}

export interface UnlockMessage {
  type: 'unlock';
}

export interface OpenAppMessage {
  type: 'openApp';
}

export interface SecureCopyMessage {
  type: 'secureCopy';
  text: string;
}

export interface FillCredentialMessage {
  type: 'fillCredential';
  username: string;
  password: string;
}

export interface SavePromptMessage {
  type: 'savePrompt';
  domain: string;
  username: string;
  password: string;
}

export interface ShowSavePromptMessage {
  type: 'showSavePrompt';
  domain: string;
  username: string;
  password: string;
}

export interface VaultLockedMessage {
  type: 'vaultLocked';
}

export type ExtensionMessage =
  | FormDetectedMessage
  | RequestCredentialsMessage
  | CredentialsResponseMessage
  | SaveCredentialMessage
  | AutofillMessage
  | AutofillCompleteMessage
  | GetStatusMessage
  | StatusResponseMessage
  | LockMessage
  | UnlockMessage
  | OpenAppMessage
  | SecureCopyMessage
  | FillCredentialMessage
  | SavePromptMessage
  | ShowSavePromptMessage
  | VaultLockedMessage;

export interface Credential {
  id: string;
  username: string;
  password: string;
  domain: string;
  name: string;
  uri: string;
  notes: string;
  matched: boolean;
}

/**
 * Native messaging host message types.
 */
export interface NativeHostRequest {
  action: 'ping' | 'getCredentials' | 'saveCredential' | 'getStatus' | 'lock';
  domain?: string;
  username?: string;
  encryptedPassword?: string;
}

export interface NativeHostResponse {
  status?: string;
  version?: string;
  credentials?: Credential[];
  locked?: boolean;
  vaultCount?: number;
  error?: string;
}
