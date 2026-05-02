import { create } from 'zustand';

export type SyncStatus = 'idle' | 'syncing' | 'success' | 'error';

interface SyncState {
  deviceId: string;
  lastSyncAt: string | null;
  status: SyncStatus;
  statusMessage: string;
  /** Auto-sync interval in seconds (0 = disabled). */
  autoSyncInterval: number;

  setDeviceId: (id: string) => void;
  setLastSyncAt: (ts: string | null) => void;
  setStatus: (status: SyncStatus, message?: string) => void;
  setAutoSyncInterval: (seconds: number) => void;
}

const SYNC_STORAGE_KEY = 'lgi-pass-sync';

function loadPersistedSync(): { lastSyncAt: string | null; autoSyncInterval: number } {
  try {
    const raw = localStorage.getItem(SYNC_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        lastSyncAt: parsed.lastSyncAt ?? null,
        autoSyncInterval: parsed.autoSyncInterval ?? 30,
      };
    }
  } catch { /* ignore */ }
  return { lastSyncAt: null, autoSyncInterval: 30 };
}

function persistSync(state: { lastSyncAt: string | null; autoSyncInterval: number }) {
  try {
    localStorage.setItem(SYNC_STORAGE_KEY, JSON.stringify(state));
  } catch { /* ignore */ }
}

const initial = loadPersistedSync();

export const useSyncStore = create<SyncState>((set, get) => ({
  deviceId: '',
  lastSyncAt: initial.lastSyncAt,
  status: 'idle',
  statusMessage: '',
  autoSyncInterval: initial.autoSyncInterval,

  setDeviceId: (id) => set({ deviceId: id }),

  setLastSyncAt: (ts) => {
    set({ lastSyncAt: ts });
    persistSync({ lastSyncAt: ts, autoSyncInterval: get().autoSyncInterval });
  },

  setStatus: (status, message) => set({ status, statusMessage: message ?? '' }),

  setAutoSyncInterval: (seconds) => {
    set({ autoSyncInterval: seconds });
    persistSync({ lastSyncAt: get().lastSyncAt, autoSyncInterval: seconds });
  },
}));
