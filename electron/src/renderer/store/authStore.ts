import { create } from 'zustand';

interface AuthState {
  token: string | null;
  userId: string | null;
  email: string | null;
  role: string | null;
  masterKeyHex: string | null;
  autoLockMinutes: number; // 0 = never
  isAuthenticated: boolean;
  login: (token: string, userId: string, email: string, role?: string, masterKeyHex?: string) => void;
  logout: () => void;
  setAutoLockMinutes: (minutes: number) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: null,
  userId: null,
  email: null,
  role: null,
  masterKeyHex: null,
  autoLockMinutes: 15,
  isAuthenticated: false,
  login: (token, userId, email, role, masterKeyHex) =>
    set({ token, userId, email, role: role ?? null, masterKeyHex: masterKeyHex ?? null, isAuthenticated: true }),
  logout: () =>
    set({ token: null, userId: null, email: null, role: null, masterKeyHex: null, isAuthenticated: false }),
  setAutoLockMinutes: (autoLockMinutes) => set({ autoLockMinutes }),
}));
