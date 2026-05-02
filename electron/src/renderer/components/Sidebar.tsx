import React, { useEffect, useState } from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';
import { useNotificationStore } from '../store/notificationStore';
import { useVaultStore } from '../store/vaultStore';

const navItems = [
  { to: '/vault', label: 'Vault', icon: '🔐' },
  { to: '/passkeys', label: 'Passkeys', icon: '🪪' },
  { to: '/ssh-keys', label: 'SSH Keys', icon: '🗝️' },
  { to: '/health', label: 'Health', icon: '🛡️' },
  { to: '/send', label: 'Send', icon: '📤' },
];

const adminItems = [
  { to: '/admin', label: 'Admin', icon: '🛡️' },
];

export function Sidebar() {
  const { email, role, orgId, token, logout, setOrg } = useAuthStore();
  const navigate = useNavigate();
  const notifCount = useNotificationStore((s) => s.totalCount());
  const refreshNotifications = useNotificationStore((s) => s.refresh);
  const healthFlags = useVaultStore((s) => s.healthFlags);
  const healthIssueCount = Object.values(healthFlags).filter(
    (f) => f.weak || f.breached || f.reused
  ).length;

  // Fetch notification counts on mount and every 30s
  useEffect(() => {
    if (!token) return;
    refreshNotifications();
    const interval = setInterval(refreshNotifications, 30_000);
    return () => clearInterval(interval);
  }, [token, refreshNotifications]);

  // Ensure org info is loaded — covers race conditions where
  // login() finishes before loadOrgAfterLogin resolves.
  useEffect(() => {
    if (!token || (orgId && role)) return;
    (async () => {
      try {
        const result = await window.api.admin.getMyOrg(token) as { member?: boolean; org_id?: string; org_name?: string; role?: string };
        if (result.member && result.org_id) {
          setOrg(result.org_id, result.org_name ?? '', result.role ?? 'member');
        }
      } catch { /* ignore */ }
    })();
  }, [token, orgId, role]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className="flex flex-col w-60 bg-surface-900 border-r border-surface-700 h-full">
      {/* Brand */}
      <div className="flex items-center gap-2 px-4 pt-10 pb-4 border-b border-surface-700 shrink-0">
        <span className="text-xl">🔑</span>
        <span className="text-sm font-semibold text-surface-100 tracking-tight">
          LGI Pass
        </span>
      </div>

      {/* Scrollable navigation */}
      <nav className="flex-1 px-2 py-3 space-y-1 overflow-y-auto min-h-0">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/vault'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive
                  ? 'bg-accent-600/20 text-accent-400'
                  : 'text-surface-300 hover:bg-surface-800 hover:text-surface-100'
              }`
            }
          >
            <span>{item.icon}</span>
            <span className="flex-1">{item.label}</span>
            {item.to === '/health' && healthIssueCount > 0 && (
              <span className="flex items-center justify-center min-w-[18px] h-[18px] rounded-full bg-orange-500 text-white text-[10px] font-bold px-1">
                {healthIssueCount}
              </span>
            )}
          </NavLink>
        ))}

        {/* Vault filters */}
        <div className="mx-3 mt-4 mb-2">
          <span className="text-[10px] font-semibold text-surface-500 uppercase tracking-widest">Filters</span>
        </div>
        {[
          { to: '/vault/favorites', label: 'Favorites', icon: '★' },
          { to: '/vault/archived', label: 'Archive', icon: '📦' },
          { to: '/vault/trash', label: 'Trash', icon: '🗑️' },
        ].map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive
                  ? 'bg-accent-600/20 text-accent-400'
                  : 'text-surface-300 hover:bg-surface-800 hover:text-surface-100'
              }`
            }
          >
            <span>{item.icon}</span>
            <span>{item.label}</span>
          </NavLink>
        ))}

        {orgId && <CollectionsSidebarSection />}

        {role === 'admin' && orgId && (
          <>
            <div className="mx-3 mt-4 mb-2">
              <span className="text-[10px] font-semibold text-surface-500 uppercase tracking-widest">Organization</span>
            </div>
            {adminItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                    isActive
                      ? 'bg-accent-600/20 text-accent-400'
                      : 'text-surface-300 hover:bg-surface-800 hover:text-surface-100'
                  }`
                }
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </NavLink>
            ))}
          </>
        )}
      </nav>

      {/* Pinned bottom: Settings + User + Logout */}
      <div className="shrink-0 border-t border-surface-700">
        <div className="px-2 py-1">
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive
                  ? 'bg-accent-600/20 text-accent-400'
                  : 'text-surface-300 hover:bg-surface-800 hover:text-surface-100'
              }`
            }
          >
            <span>⚙️</span>
            <span className="flex-1">Settings</span>
            {notifCount > 0 && (
              <span className="flex items-center justify-center min-w-[18px] h-[18px] rounded-full bg-red-500 text-white text-[10px] font-bold px-1 animate-pulse">
                {notifCount}
              </span>
            )}
          </NavLink>
        </div>
        <div className="px-3 py-3">
          <div className="flex items-center gap-2 px-2 mb-2">
            <div className="w-7 h-7 rounded-full bg-accent-600 flex items-center justify-center text-xs font-medium text-white">
              {email?.charAt(0).toUpperCase() ?? '?'}
            </div>
            <span className="text-xs text-surface-400 truncate">{email}</span>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm text-surface-400 hover:bg-surface-800 hover:text-surface-200 transition-colors"
          >
            <span>🚪</span>
            <span>Logout</span>
          </button>
        </div>
      </div>
    </aside>
  );
}

// Collections sidebar section — shows the user's collections when in an org
function CollectionsSidebarSection() {
  const { token, masterKeyHex } = useAuthStore();
  const collectionsVersion = useVaultStore((s) => s.collectionsVersion);
  const navigate = useNavigate();
  const location = useLocation();

  const [collections, setCollections] = useState<{ id: string; name: string }[]>([]);

  useEffect(() => {
    if (!token || !masterKeyHex) return;
    let cancelled = false;
    const load = async () => {
      try {
        const result = await window.api.collections.listUser(token) as Array<{
          id: string;
          name_encrypted: string;
          name_nonce: string;
          encrypted_key: string;
        }> | { error: string };
        if (cancelled || 'error' in result) return;
        const items: { id: string; name: string }[] = [];
        for (const c of result) {
          try {
            // Decrypt collection key with master key, then decrypt name with collection key
            const ekNonce = c.encrypted_key.slice(0, 24);
            const ekCipher = c.encrypted_key.slice(24);
            const collKeyDec = await window.api.vault.decrypt(masterKeyHex, ekCipher, ekNonce) as { plaintext: string };
            const dec = await window.api.vault.decrypt(collKeyDec.plaintext, c.name_encrypted, c.name_nonce) as { plaintext: string };
            items.push({ id: c.id, name: dec.plaintext });
          } catch {
            items.push({ id: c.id, name: '(encrypted)' });
          }
        }
        if (!cancelled) {
          setCollections(items);
          // If viewing a deleted collection, redirect to vault
          const collMatch = location.pathname.match(/\/vault\/collection\/(.+)/);
          if (collMatch && items.length > 0 && !items.some(c => c.id === collMatch[1])) {
            navigate('/vault');
          }
        }
      } catch { /* ignore */ }
    };
    load();
    const interval = setInterval(load, 15000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [token, masterKeyHex, collectionsVersion]);

  return (
    <>
      <div className="mx-3 mt-4 mb-2">
        <span className="text-[10px] font-semibold text-surface-500 uppercase tracking-widest">
          Collections
        </span>
      </div>
      {collections.length === 0 ? (
        <div className="px-3 py-1 text-xs text-surface-600 italic">No collections yet</div>
      ) : (
        collections.map((coll) => (
          <NavLink
            key={coll.id}
            to={`/vault/collection/${coll.id}`}
            className={({ isActive }) =>
              `w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive
                  ? 'bg-accent-600/20 text-accent-400'
                  : 'text-surface-300 hover:bg-surface-800 hover:text-surface-100'
              }`
            }
          >
            <span>📁</span>
            <span className="truncate">{coll.name}</span>
          </NavLink>
        ))
      )}
    </>
  );
}
