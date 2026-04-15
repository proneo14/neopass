import { create } from 'zustand';

interface AuthState {
  token: string | null;
  userId: string | null;
  email: string | null;
  role: string | null;
  isAuthenticated: boolean;
  login: (token: string, userId: string, email: string, role?: string) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: null,
  userId: null,
  email: null,
  role: null,
  isAuthenticated: false,
  login: (token, userId, email, role) =>
    set({ token, userId, email, role: role ?? null, isAuthenticated: true }),
  logout: () =>
    set({ token: null, userId: null, email: null, role: null, isAuthenticated: false }),
}));
