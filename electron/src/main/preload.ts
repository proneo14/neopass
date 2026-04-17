import { contextBridge, ipcRenderer } from 'electron';

const api = {
  getSidecarPort: (): Promise<number | null> => ipcRenderer.invoke('app:getSidecarPort'),

  auth: {
    login: (credentials: { email: string; authHash: string }): Promise<unknown> =>
      ipcRenderer.invoke('auth:login', credentials),
    register: (data: { email: string; password: string }): Promise<unknown> =>
      ipcRenderer.invoke('auth:register', data),
    changePassword: (token: string, data: { email: string; currentPassword: string; newPassword: string }): Promise<unknown> =>
      ipcRenderer.invoke('auth:changePassword', token, data),
  },

  vault: {
    list: (token: string): Promise<unknown> =>
      ipcRenderer.invoke('vault:list', token),
    get: (token: string, entryId: string): Promise<unknown> =>
      ipcRenderer.invoke('vault:get', token, entryId),
    create: (token: string, data: Record<string, unknown>): Promise<unknown> =>
      ipcRenderer.invoke('vault:create', token, data),
    update: (token: string, entryId: string, data: Record<string, unknown>): Promise<unknown> =>
      ipcRenderer.invoke('vault:update', token, entryId, data),
    delete: (token: string, entryId: string): Promise<unknown> =>
      ipcRenderer.invoke('vault:delete', token, entryId),
    encrypt: (masterKeyHex: string, plaintext: string): Promise<{ encrypted_data: string; nonce: string; error?: string }> =>
      ipcRenderer.invoke('vault:encrypt', masterKeyHex, plaintext),
    decrypt: (masterKeyHex: string, encryptedData: string, nonce: string): Promise<{ plaintext: string; error?: string }> =>
      ipcRenderer.invoke('vault:decrypt', masterKeyHex, encryptedData, nonce),
    exportFile: (jsonContent: string): Promise<{ success?: boolean; cancelled?: boolean; path?: string; error?: string }> =>
      ipcRenderer.invoke('vault:exportFile', jsonContent),
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

  admin: {
    getMyOrg: (token: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:getMyOrg', token),
    getMyInvitations: (token: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:getMyInvitations', token),
    createOrg: (token: string, name: string, masterKey: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:createOrg', token, name, masterKey),
    inviteUser: (token: string, orgId: string, email: string, role: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:inviteUser', token, orgId, email, role),
    acceptInvite: (token: string, orgId: string, masterKey: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:acceptInvite', token, orgId, masterKey),
    listMembers: (token: string, orgId: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:listMembers', token, orgId),
    removeMember: (token: string, orgId: string, userId: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:removeMember', token, orgId, userId),
    leaveOrg: (token: string, orgId: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:leaveOrg', token, orgId),
    accessVault: (token: string, orgId: string, userId: string, masterKey: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:accessVault', token, orgId, userId, masterKey),
    resetPassword: (token: string, orgId: string, userId: string, data: { master_key: string; target_email: string; new_password: string }): Promise<unknown> =>
      ipcRenderer.invoke('admin:resetPassword', token, orgId, userId, data),
    setPolicy: (token: string, orgId: string, policy: Record<string, unknown>): Promise<unknown> =>
      ipcRenderer.invoke('admin:setPolicy', token, orgId, policy),
    getPolicy: (token: string, orgId: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:getPolicy', token, orgId),
    listInvitations: (token: string, orgId: string): Promise<unknown> =>
      ipcRenderer.invoke('admin:listInvitations', token, orgId),
    getAuditLog: (token: string, orgId: string, filters?: Record<string, string>): Promise<unknown> =>
      ipcRenderer.invoke('admin:getAuditLog', token, orgId, filters),
  },
} as const;

contextBridge.exposeInMainWorld('api', api);

export type ElectronAPI = typeof api;
