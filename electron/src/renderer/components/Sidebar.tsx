import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';

const navItems = [
  { to: '/vault', label: 'Vault', icon: '🔐' },
  { to: '/passkeys', label: 'Passkeys', icon: '🪪' },
];

const adminItems = [
  { to: '/admin', label: 'Admin', icon: '🛡️' },
];

export function Sidebar() {
  const { email, role, logout } = useAuthStore();
  const navigate = useNavigate();
  const [storageBackend, setStorageBackend] = useState<'sqlite' | 'postgres'>('sqlite');

  useEffect(() => {
    window.api.storage.getBackend().then(setStorageBackend).catch(() => {});
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className="flex flex-col w-60 bg-surface-900 border-r border-surface-700 h-full">
      {/* Brand */}
      <div className="flex items-center gap-2 px-4 pt-10 pb-4 border-b border-surface-700">
        <span className="text-xl">🔑</span>
        <span className="text-sm font-semibold text-surface-100 tracking-tight">
          LGI Pass
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3 space-y-1">
        {navItems.map((item) => (
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

        {role === 'admin' && storageBackend === 'postgres' && (
          <>
            <div className="mx-3 mb-2" style={{ marginTop: 75 }}>
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

      {/* User section */}
      <div className="px-2 pb-1">
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
          <span>Settings</span>
        </NavLink>
      </div>
      <div className="px-3 py-3 border-t border-surface-700">
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
    </aside>
  );
}
