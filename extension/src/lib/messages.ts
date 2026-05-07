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
  theme?: 'dark' | 'light';
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

export interface SaveTOTPMessage {
  type: 'saveTOTP';
  domain: string;
  secret: string;
  credentialId?: string;
}

export interface ScanQRMessage {
  type: 'scanQR';
}

export interface VerifyMasterPasswordMessage {
  type: 'verifyMasterPassword';
  email: string;
  password: string;
}

export interface VerifyMasterPasswordResponseMessage {
  type: 'verifyMasterPasswordResponse';
  verified: boolean;
  error?: string;
}

export interface PasskeyCreateMessage {
  type: 'passkeyCreate';
  rpId: string;
  rpName: string;
  userName: string;
  displayName: string;
  challenge?: string;
  origin?: string;
  userId?: string;
  algorithm?: number;
}

export interface PasskeyGetMessage {
  type: 'passkeyGet';
  rpId: string;
  allowCredentials?: string[];
}

export interface PasskeySignMessage {
  type: 'passkeySign';
  credentialId: string;
  rpId: string;
  origin: string;
  challenge: string;
}

export interface PasskeyListMessage {
  type: 'passkeyList';
  rpId: string;
}

export interface PasskeyResponseMessage {
  type: 'passkeyResponse';
  action: string;
  passkeys?: PasskeyInfo[];
  assertion?: Record<string, string>;
  options?: Record<string, unknown>;
  error?: string;
}

export interface PasskeyInfo {
  credentialId: string;
  rpId: string;
  rpName: string;
  username: string;
  displayName: string;
  createdAt: string;
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
  | VaultLockedMessage
  | SaveTOTPMessage
  | ScanQRMessage
  | VerifyMasterPasswordMessage
  | VerifyMasterPasswordResponseMessage
  | PasskeyCreateMessage
  | PasskeyGetMessage
  | PasskeySignMessage
  | PasskeyListMessage
  | PasskeyResponseMessage;

export interface CredentialURI {
  uri: string;
  match?: 'base_domain' | 'host' | 'starts_with' | 'regex' | 'exact' | 'never';
}

export interface Credential {
  id: string;
  username: string;
  password: string;
  domain: string;
  name: string;
  uri: string;
  uris?: CredentialURI[];
  notes: string;
  matched: boolean;
  is_favorite: boolean;
  reprompt: number;
}

/**
 * Native messaging host message types.
 */
export interface NativeHostRequest {
  action: 'ping' | 'getCredentials' | 'saveCredential' | 'getStatus' | 'lock'
    | 'passkeyCreate' | 'passkeyGet' | 'passkeySign' | 'passkeyList' | 'passkeyDelete'
    | 'updateCredential' | 'verifyPassword';
  domain?: string;
  username?: string;
  encryptedPassword?: string;
  email?: string;
  password?: string;
  rpId?: string;
  rpName?: string;
  userName?: string;
  displayName?: string;
  credentialId?: string;
  challenge?: string;
  origin?: string;
  algorithm?: number;
  allowCredentials?: string[];
  id?: string;
  name?: string;
  uri?: string;
  notes?: string;
  totp?: string;
}

export interface NativeHostResponse {
  status?: string;
  version?: string;
  credentials?: Credential[];
  locked?: boolean;
  vaultCount?: number;
  theme?: string;
  error?: string;
  verified?: boolean;
  passkeys?: PasskeyInfo[];
  assertion?: Record<string, string>;
  options?: Record<string, unknown>;
}
