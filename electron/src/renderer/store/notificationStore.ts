import { create } from 'zustand';
import { useAuthStore } from './authStore';

interface NotificationState {
  pending2FACount: number;
  pendingInviteCount: number;
  dismissed: boolean;
  totalCount: () => number;
  dismiss: () => void;
  refresh: () => Promise<void>;
}

export const useNotificationStore = create<NotificationState>((set, get) => ({
  pending2FACount: 0,
  pendingInviteCount: 0,
  dismissed: false,

  totalCount: () => get().pending2FACount + get().pendingInviteCount,

  dismiss: () => set({ dismissed: true }),

  refresh: async () => {
    const { token, orgId } = useAuthStore.getState();
    if (!token) return;

    let twoFACount = 0;
    let inviteCount = 0;

    try {
      const shares = await window.api.admin.listPending2FA(token) as { id: string }[] | { error: string };
      if (Array.isArray(shares)) twoFACount = shares.length;
    } catch { /* ignore */ }

    if (!orgId) {
      try {
        const invites = await window.api.admin.getMyInvitations(token) as { id: string }[] | { error: string };
        if (Array.isArray(invites)) inviteCount = invites.length;
      } catch { /* ignore */ }
    }

    const prev = get();
    const newTotal = twoFACount + inviteCount;
    const oldTotal = prev.pending2FACount + prev.pendingInviteCount;

    set({
      pending2FACount: twoFACount,
      pendingInviteCount: inviteCount,
      // Reset dismissed if new notifications arrive
      dismissed: newTotal > oldTotal ? false : prev.dismissed,
    });
  },
}));
