import React, { useState, useEffect } from 'react';
import { useAuthStore } from '../store/authStore';
import { MembersPanel } from '../components/admin/MembersPanel';
import { VaultAccessPanel } from '../components/admin/VaultAccessPanel';
import { TwoFactorSharePanel } from '../components/admin/TwoFactorSharePanel';
import { PoliciesPanel } from '../components/admin/PoliciesPanel';
import { AuditLogPanel } from '../components/admin/AuditLogPanel';

const TABS = [
  { id: 'members', label: 'Members', icon: '👥' },
  { id: 'vault', label: 'Vault Access', icon: '🔓' },
  { id: '2fa', label: '2FA Sharing', icon: '🔑' },
  { id: 'policies', label: 'Policies', icon: '📋' },
  { id: 'audit', label: 'Audit Log', icon: '📜' },
] as const;

type TabId = (typeof TABS)[number]['id'];

export function Admin() {
  const [activeTab, setActiveTab] = useState<TabId>('members');
  const { orgId, orgName, token, role, masterKeyHex, setOrg, clearOrg } = useAuthStore();

  // Refresh org info from backend on mount and propagate org keys to all admins
  useEffect(() => {
    if (!token) return;
    (async () => {
      try {
        const result = await window.api.admin.getMyOrg(token) as { member?: boolean; org_id?: string; org_name?: string; role?: string };
        if (result.member && result.org_id) {
          setOrg(result.org_id, result.org_name ?? '', result.role ?? 'member');
          // Auto-propagate org keys so all admins can access vault
          if (result.role === 'admin' && masterKeyHex) {
            window.api.admin.propagateKeys(token, result.org_id, masterKeyHex).catch(() => {});
          }
        } else {
          clearOrg();
        }
      } catch { /* ignore */ }
    })();
  }, [token]);

  if (!orgId) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <span className="text-4xl">🛡️</span>
        <h1 className="text-xl font-semibold text-surface-100">Admin Dashboard</h1>
        <p className="text-sm text-surface-400 text-center max-w-sm">
          No organization configured. Go to <span className="text-accent-400">Settings → Organization</span> to create one.
        </p>
      </div>
    );
  }

  if (role !== 'admin') {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <span className="text-4xl">🔒</span>
        <h1 className="text-xl font-semibold text-surface-100">Access Restricted</h1>
        <p className="text-sm text-surface-400 text-center max-w-sm">
          Only organization administrators can access this dashboard.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-surface-800">
        <div>
          <h1 className="text-lg font-semibold text-surface-100">Admin Dashboard</h1>
          <p className="text-xs text-surface-400 mt-0.5">{orgName || orgId}</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-surface-800 px-6">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab.id
                ? 'text-accent-400 border-accent-500'
                : 'text-surface-400 border-transparent hover:text-surface-200 hover:border-surface-600'
            }`}
          >
            <span className="mr-1.5">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto p-6">
        {activeTab === 'members' && <MembersPanel orgId={orgId} />}
        {activeTab === 'vault' && <VaultAccessPanel orgId={orgId} />}
        {activeTab === '2fa' && <TwoFactorSharePanel orgId={orgId} />}
        {activeTab === 'policies' && <PoliciesPanel orgId={orgId} />}
        {activeTab === 'audit' && <AuditLogPanel orgId={orgId} />}
      </div>
    </div>
  );
}
