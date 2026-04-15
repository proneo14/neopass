import { contextBridge, ipcRenderer } from 'electron';

const api = {
  getSidecarPort: (): Promise<number | null> => ipcRenderer.invoke('app:getSidecarPort'),

  auth: {
    login: (credentials: { email: string; authHash: string }): Promise<unknown> =>
      ipcRenderer.invoke('auth:login', credentials),
    register: (data: Record<string, unknown>): Promise<unknown> =>
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
} as const;

contextBridge.exposeInMainWorld('api', api);

export type ElectronAPI = typeof api;
