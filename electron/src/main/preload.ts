import { contextBridge, ipcRenderer } from 'electron';

const api = {
  getSidecarPort: (): Promise<number | null> => ipcRenderer.invoke('app:getSidecarPort'),

  auth: {
    login: (credentials: { email: string; authHash: string }): Promise<unknown> =>
      ipcRenderer.invoke('auth:login', credentials),
    register: (data: { email: string; password: string }): Promise<unknown> =>
      ipcRenderer.invoke('auth:register', data),
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
} as const;

contextBridge.exposeInMainWorld('api', api);

export type ElectronAPI = typeof api;
