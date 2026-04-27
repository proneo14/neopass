import { create } from 'zustand';
import { useVaultStore } from './vaultStore';

// Persist org info to localStorage, scoped per userId
const ORG_STORAGE_PREFIX = 'lgi-pass-org-';

function orgKey(userId: string): string {
  return `${ORG_STORAGE_PREFIX}${userId}`;
}

function loadOrgFromStorage(userId: string | null): { orgId: string | null; orgName: string | null; role: string | null } {
  if (!userId) return { orgId: null, orgName: null, role: null };
  try {
    const raw = localStorage.getItem(orgKey(userId));
    if (raw) {
      const data = JSON.parse(raw);
      return { orgId: data.orgId ?? null, orgName: data.orgName ?? null, role: data.role ?? null };
    }
  } catch { /* ignore */ }
  return { orgId: null, orgName: null, role: null };
}

function saveOrgToStorage(userId: string | null, orgId: string | null, orgName: string | null, role: string | null) {
  if (!userId) return;
  if (orgId) {
    localStorage.setItem(orgKey(userId), JSON.stringify({ orgId, orgName, role }));
  } else {
    localStorage.removeItem(orgKey(userId));
  }
}

interface AuthState {
  token: string | null;
  userId: string | null;
  email: string | null;
  role: string | null;
  masterKeyHex: string | null;
  orgId: string | null;
  orgName: string | null;
  autoLockMinutes: number; // 0 = never
  isAuthenticated: boolean;
  login: (token: string, userId: string, email: string, role?: string, masterKeyHex?: string) => void;
  logout: () => void;
  setAutoLockMinutes: (minutes: number) => void;
  setOrg: (orgId: string, orgName: string, role: string) => void;
  clearOrg: () => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: null,
  userId: null,
  email: null,
  role: null,
  masterKeyHex: null,
  orgId: null,
  orgName: null,
  autoLockMinutes: 15,
  isAuthenticated: false,
  login: (token, userId, email, role, masterKeyHex) => {
    const org = loadOrgFromStorage(userId);
    set({
      token, userId, email,
      role: org.role ?? role ?? null,
      masterKeyHex: masterKeyHex ?? null,
      orgId: org.orgId,
      orgName: org.orgName,
      isAuthenticated: true,
    });
  },
  logout: () => {
    const { userId } = get();
    saveOrgToStorage(userId, null, null, null);
    // Clear reprompt approvals so protected entries require re-auth after login
    useVaultStore.getState().clearRepromptApprovals();
    // Notify server to clear extension session
    window.api?.auth?.logout?.().catch(() => {});
    set({ token: null, userId: null, email: null, role: null, masterKeyHex: null, orgId: null, orgName: null, isAuthenticated: false });
  },
  setAutoLockMinutes: (autoLockMinutes) => set({ autoLockMinutes }),
  setOrg: (orgId, orgName, role) => {
    const { userId } = get();
    saveOrgToStorage(userId, orgId, orgName, role);
    set({ orgId, orgName, role });
  },
  clearOrg: () => {
    const { userId } = get();
    saveOrgToStorage(userId, null, null, null);
    set({ orgId: null, orgName: null, role: null });
  },
}));
