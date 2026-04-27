import { contextBridge, ipcRenderer } from 'electron';

/**
 * Validate that a value is a non-empty string to prevent injection.
 */
function validateString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Invalid ${name}: expected non-empty string`);
  }
  return value;
}

/**
 * Validate that a value is a plain object (not null, not array).
 */
function validateObject(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`Invalid ${name}: expected object`);
  }
  return value as Record<string, unknown>;
}

const api = {
  getSidecarPort: (): Promise<number | null> => ipcRenderer.invoke('app:getSidecarPort'),

  auth: {
    login: (credentials: { email: string; authHash: string }): Promise<unknown> => {
      validateObject(credentials, 'credentials');
      validateString(credentials.email, 'email');
      validateString(credentials.authHash, 'authHash');
      return ipcRenderer.invoke('auth:login', credentials);
    },
    logout: (): Promise<void> =>
      ipcRenderer.invoke('auth:logout'),
    register: (data: { email: string; password: string }): Promise<unknown> => {
      validateObject(data, 'data');
      validateString(data.email, 'email');
      validateString(data.password, 'password');
      return ipcRenderer.invoke('auth:register', data);
    },
    changePassword: (token: string, data: { email: string; currentPassword: string; newPassword: string }): Promise<unknown> => {
      validateString(token, 'token');
      validateObject(data, 'data');
      validateString(data.email, 'email');
      validateString(data.currentPassword, 'currentPassword');
      validateString(data.newPassword, 'newPassword');
      return ipcRenderer.invoke('auth:changePassword', token, data);
    },
  },

  vault: {
    list: (token: string, filter?: string): Promise<unknown> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('vault:list', token, filter);
    },
    get: (token: string, entryId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(entryId, 'entryId');
      return ipcRenderer.invoke('vault:get', token, entryId);
    },
    create: (token: string, data: Record<string, unknown>): Promise<unknown> => {
      validateString(token, 'token');
      validateObject(data, 'data');
      return ipcRenderer.invoke('vault:create', token, data);
    },
    update: (token: string, entryId: string, data: Record<string, unknown>): Promise<unknown> => {
      validateString(token, 'token');
      validateString(entryId, 'entryId');
      validateObject(data, 'data');
      return ipcRenderer.invoke('vault:update', token, entryId, data);
    },
    delete: (token: string, entryId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(entryId, 'entryId');
      return ipcRenderer.invoke('vault:delete', token, entryId);
    },
    setFavorite: (token: string, entryId: string, isFavorite: boolean): Promise<unknown> => {
      validateString(token, 'token');
      validateString(entryId, 'entryId');
      return ipcRenderer.invoke('vault:setFavorite', token, entryId, isFavorite);
    },
    setArchived: (token: string, entryId: string, isArchived: boolean): Promise<unknown> => {
      validateString(token, 'token');
      validateString(entryId, 'entryId');
      return ipcRenderer.invoke('vault:setArchived', token, entryId, isArchived);
    },
    restore: (token: string, entryId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(entryId, 'entryId');
      return ipcRenderer.invoke('vault:restore', token, entryId);
    },
    permanentDelete: (token: string, entryId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(entryId, 'entryId');
      return ipcRenderer.invoke('vault:permanentDelete', token, entryId);
    },
    purgeTrash: (token: string): Promise<unknown> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('vault:purgeTrash', token);
    },
    clone: (token: string, entryId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(entryId, 'entryId');
      return ipcRenderer.invoke('vault:clone', token, entryId);
    },
    encrypt: (masterKeyHex: string, plaintext: string): Promise<{ encrypted_data: string; nonce: string; error?: string }> => {
      validateString(masterKeyHex, 'masterKeyHex');
      validateString(plaintext, 'plaintext');
      return ipcRenderer.invoke('vault:encrypt', masterKeyHex, plaintext);
    },
    decrypt: (masterKeyHex: string, encryptedData: string, nonce: string): Promise<{ plaintext: string; error?: string }> => {
      validateString(masterKeyHex, 'masterKeyHex');
      validateString(encryptedData, 'encryptedData');
      validateString(nonce, 'nonce');
      return ipcRenderer.invoke('vault:decrypt', masterKeyHex, encryptedData, nonce);
    },
    exportFile: (jsonContent: string): Promise<{ success?: boolean; cancelled?: boolean; path?: string; error?: string }> =>
      ipcRenderer.invoke('vault:exportFile', jsonContent),
    importExport: (token: string): Promise<{ imported?: number; total?: number; error?: string }> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('vault:importExport', token);
    },
  },

  biometric: {
    isAvailable: (): Promise<boolean> => ipcRenderer.invoke('biometric:available'),
    isConfigured: (): Promise<boolean> => ipcRenderer.invoke('biometric:configured'),
    enable: (masterKeyHex: string): Promise<{ success: boolean; error?: string }> =>
      ipcRenderer.invoke('biometric:enable', masterKeyHex),
    enableWithPassword: (data: { email: string; password: string }): Promise<{ success: boolean; error?: string }> =>
      ipcRenderer.invoke('biometric:enableWithPassword', data),
    unlock: (): Promise<Record<string, unknown>> =>
      ipcRenderer.invoke('biometric:unlock'),
    verify: (): Promise<{ success: boolean; error?: string }> =>
      ipcRenderer.invoke('biometric:verify'),
    disable: (): Promise<{ success: boolean; error?: string }> =>
      ipcRenderer.invoke('biometric:disable'),
  },

  clipboard: {
    copySecure: (text: string, clearAfterMs?: number): Promise<{ success?: boolean; error?: string }> =>
      ipcRenderer.invoke('clipboard:copySecure', text, clearAfterMs ?? 30_000),
  },

  passkey: {
    list: (token: string): Promise<unknown> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('passkey:list', token);
    },
    delete: (token: string, passkeyId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(passkeyId, 'passkeyId');
      return ipcRenderer.invoke('passkey:delete', token, passkeyId);
    },
    listHardwareKeys: (token: string): Promise<unknown> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('passkey:listHardwareKeys', token);
    },
    deleteHardwareKey: (token: string, keyId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(keyId, 'keyId');
      return ipcRenderer.invoke('passkey:deleteHardwareKey', token, keyId);
    },
    beginRegistration: (token: string, data: Record<string, unknown>): Promise<unknown> => {
      validateString(token, 'token');
      validateObject(data, 'data');
      return ipcRenderer.invoke('passkey:beginRegistration', token, data);
    },
    finishRegistration: (token: string, data: Record<string, unknown>): Promise<unknown> => {
      validateString(token, 'token');
      validateObject(data, 'data');
      return ipcRenderer.invoke('passkey:finishRegistration', token, data);
    },
    beginAuthentication: (token: string, rpId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(rpId, 'rpId');
      return ipcRenderer.invoke('passkey:beginAuthentication', token, rpId);
    },
    finishAuthentication: (token: string, data: Record<string, unknown>): Promise<unknown> => {
      validateString(token, 'token');
      validateObject(data, 'data');
      return ipcRenderer.invoke('passkey:finishAuthentication', token, data);
    },
  },

  security: {
    getSettings: (token: string): Promise<{ require_hw_key?: boolean; has_2fa?: boolean; error?: string }> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('auth:getSecuritySettings', token);
    },
    setRequireHWKey: (token: string, require: boolean): Promise<{ status?: string; error?: string }> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('auth:setRequireHWKey', token, require);
    },
  },

  twoFactor: {
    setup: (token: string, encryptionKey: string): Promise<{ secret?: string; qr_uri?: string; recovery_codes?: string[]; error?: string }> => {
      validateString(token, 'token');
      validateString(encryptionKey, 'encryptionKey');
      return ipcRenderer.invoke('auth:2fa:setup', token, encryptionKey);
    },
    verifySetup: (token: string, code: string, encryptionKey: string): Promise<{ status?: string; error?: string }> => {
      validateString(token, 'token');
      validateString(code, 'code');
      validateString(encryptionKey, 'encryptionKey');
      return ipcRenderer.invoke('auth:2fa:verifySetup', token, code, encryptionKey);
    },
    disable: (token: string): Promise<{ status?: string; error?: string }> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('auth:2fa:disable', token);
    },
  },

  hwkey: {
    beginRegistration: (token: string, data: Record<string, unknown>): Promise<unknown> => {
      validateString(token, 'token');
      validateObject(data, 'data');
      return ipcRenderer.invoke('hwkey:beginRegistration', token, data);
    },
    finishRegistration: (token: string, data: Record<string, unknown>): Promise<unknown> => {
      validateString(token, 'token');
      validateObject(data, 'data');
      return ipcRenderer.invoke('hwkey:finishRegistration', token, data);
    },
    webauthnCreate: (optionsJSON: string): Promise<{ credential_id?: string; attestation_object?: string; client_data_json?: string; public_key_cbor?: string; transports?: string[]; error?: string }> => {
      validateString(optionsJSON, 'optionsJSON');
      return ipcRenderer.invoke('hwkey:webauthnCreate', optionsJSON);
    },
  },

  admin: {
    getMyOrg: (token: string): Promise<unknown> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('admin:getMyOrg', token);
    },
    getMyInvitations: (token: string): Promise<unknown> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('admin:getMyInvitations', token);
    },
    createOrg: (token: string, name: string, masterKey: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(name, 'name');
      validateString(masterKey, 'masterKey');
      return ipcRenderer.invoke('admin:createOrg', token, name, masterKey);
    },
    inviteUser: (token: string, orgId: string, email: string, role: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      validateString(email, 'email');
      validateString(role, 'role');
      return ipcRenderer.invoke('admin:inviteUser', token, orgId, email, role);
    },
    acceptInvite: (token: string, orgId: string, masterKey: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      validateString(masterKey, 'masterKey');
      return ipcRenderer.invoke('admin:acceptInvite', token, orgId, masterKey);
    },
    listMembers: (token: string, orgId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      return ipcRenderer.invoke('admin:listMembers', token, orgId);
    },
    removeMember: (token: string, orgId: string, userId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      validateString(userId, 'userId');
      return ipcRenderer.invoke('admin:removeMember', token, orgId, userId);
    },
    leaveOrg: (token: string, orgId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      return ipcRenderer.invoke('admin:leaveOrg', token, orgId);
    },
    accessVault: (token: string, orgId: string, userId: string, masterKey: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      validateString(userId, 'userId');
      validateString(masterKey, 'masterKey');
      return ipcRenderer.invoke('admin:accessVault', token, orgId, userId, masterKey);
    },
    resetPassword: (token: string, orgId: string, userId: string, data: { master_key: string; target_email: string; new_password: string }): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      validateString(userId, 'userId');
      validateObject(data, 'data');
      return ipcRenderer.invoke('admin:resetPassword', token, orgId, userId, data);
    },
    setPolicy: (token: string, orgId: string, policy: Record<string, unknown>): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      validateObject(policy, 'policy');
      return ipcRenderer.invoke('admin:setPolicy', token, orgId, policy);
    },
    getPolicy: (token: string, orgId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      return ipcRenderer.invoke('admin:getPolicy', token, orgId);
    },
    listInvitations: (token: string, orgId: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      return ipcRenderer.invoke('admin:listInvitations', token, orgId);
    },
    getAuditLog: (token: string, orgId: string, filters?: Record<string, string>): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      return ipcRenderer.invoke('admin:getAuditLog', token, orgId, filters);
    },
    share2fa: (token: string, toUserId: string, totpSecret: string, label: string, expiresInMin: number): Promise<unknown> => {
      validateString(token, 'token');
      validateString(toUserId, 'toUserId');
      validateString(totpSecret, 'totpSecret');
      return ipcRenderer.invoke('admin:share2fa', token, toUserId, totpSecret, label, expiresInMin);
    },
    propagateKeys: (token: string, orgId: string, masterKey: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(orgId, 'orgId');
      validateString(masterKey, 'masterKey');
      return ipcRenderer.invoke('admin:propagateKeys', token, orgId, masterKey);
    },
    listPending2FA: (token: string): Promise<unknown> => {
      validateString(token, 'token');
      return ipcRenderer.invoke('auth:listPending2FA', token);
    },
    claim2FA: (token: string, shareId: string, masterKeyHex: string): Promise<unknown> => {
      validateString(token, 'token');
      validateString(shareId, 'shareId');
      validateString(masterKeyHex, 'masterKeyHex');
      return ipcRenderer.invoke('auth:claim2FA', token, shareId, masterKeyHex);
    },
  },

  storage: {
    getBackend: (): Promise<'sqlite' | 'postgres'> =>
      ipcRenderer.invoke('storage:getBackend'),
    testPgConnection: (connectionString: string): Promise<{ success?: boolean; error?: string }> => {
      validateString(connectionString, 'connectionString');
      return ipcRenderer.invoke('storage:testPgConnection', connectionString);
    },
    migrateToPostgres: (databaseUrl: string): Promise<{ error?: string; users?: number; vault_entries?: number }> => {
      validateString(databaseUrl, 'databaseUrl');
      return ipcRenderer.invoke('storage:migrateToPostgres', databaseUrl);
    },
  },

  openExternal: (url: string): Promise<void> => {
    validateString(url, 'url');
    return ipcRenderer.invoke('app:openExternal', url);
  },
} as const;

contextBridge.exposeInMainWorld('api', api);

export type ElectronAPI = typeof api;
