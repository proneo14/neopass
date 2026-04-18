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
  | OpenAppMessage;

export interface Credential {
  id: string;
  username: string;
  password: string;
  domain: string;
  name: string;
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
