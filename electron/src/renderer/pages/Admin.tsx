import React, { useState, useEffect } from 'react';
import { useAuthStore } from '../store/authStore';
import { MembersPanel } from '../components/admin/MembersPanel';
import { VaultAccessPanel } from '../components/admin/VaultAccessPanel';
import { TwoFactorSharePanel } from '../components/admin/TwoFactorSharePanel';
import { PoliciesPanel } from '../components/admin/PoliciesPanel';
import { AuditLogPanel } from '../components/admin/AuditLogPanel';
import { CollectionsPanel } from '../components/admin/CollectionsPanel';
import { SSOPanel } from '../components/admin/SSOPanel';
import { SCIMPanel } from '../components/admin/SCIMPanel';
import { RolesPanel } from '../components/admin/RolesPanel';
import { GroupsPanel } from '../components/admin/GroupsPanel';
import { IntegrationsPanel } from '../components/admin/IntegrationsPanel';

const SECTIONS = [
  {
    label: 'People',
    items: [
      { id: 'members', label: 'Members', icon: '👥' },
      { id: 'roles', label: 'Roles', icon: '🎭' },
      { id: 'groups', label: 'Groups', icon: '🏘️' },
    ],
  },
  {
    label: 'Data',
    items: [
      { id: 'collections', label: 'Collections', icon: '📁' },
      { id: 'vault', label: 'Vault Access', icon: '🔓' },
      { id: '2fa', label: '2FA Sharing', icon: '🔑' },
    ],
  },
  {
    label: 'Identity',
    items: [
      { id: 'sso', label: 'SSO', icon: '🔐' },
      { id: 'scim', label: 'Directory Sync', icon: '📂' },
    ],
  },
  {
    label: 'Security',
    items: [
      { id: 'policies', label: 'Policies', icon: '📋' },
      { id: 'audit', label: 'Audit Log', icon: '📜' },
      { id: 'integrations', label: 'Integrations', icon: '🔗' },
    ],
  },
] as const;

type TabId = (typeof SECTIONS)[number]['items'][number]['id'];

export function Admin() {
  const [activeTab, setActiveTab] = useState<TabId>('members');
  const { orgId, orgName, token, role, masterKeyHex, setOrg, clearOrg } = useAuthStore();

  // Refresh org info from backend on mount and propagate org keys to all admins
  // Only run if org info is missing — skip if already loaded to reduce API calls.
  const hasOrgRef = React.useRef(false);
  useEffect(() => {
    if (!token) return;
    if (orgId && role === 'admin') {
      // Already have org info — just propagate keys once
      if (!hasOrgRef.current && masterKeyHex) {
        hasOrgRef.current = true;
        window.api.admin.propagateKeys(token, orgId, masterKeyHex).catch(() => {});
      }
      return;
    }
    (async () => {
      try {
        const result = await window.api.admin.getMyOrg(token) as { member?: boolean; org_id?: string; org_name?: string; role?: string };
        if (result.member && result.org_id) {
          setOrg(result.org_id, result.org_name ?? '', result.role ?? 'member');
          // Auto-propagate org keys so all admins can access vault
          if (result.role === 'admin' && masterKeyHex) {
            hasOrgRef.current = true;
            window.api.admin.propagateKeys(token, result.org_id, masterKeyHex).catch(() => {});
          }
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

  const activeSection = SECTIONS.find((s) => s.items.some((i) => i.id === activeTab));
  const activeItem = activeSection?.items.find((i) => i.id === activeTab);

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <div className="w-48 flex-shrink-0 border-r border-surface-800 bg-surface-950/50 overflow-y-auto">
        <div className="px-4 py-4">
          <h1 className="text-sm font-semibold text-surface-100 truncate">Admin</h1>
          <p className="text-xs text-surface-500 mt-0.5 truncate">{orgName || orgId}</p>
        </div>
        <nav className="px-2 pb-4 space-y-4">
          {SECTIONS.map((section) => (
            <div key={section.label}>
              <div className="px-2 mb-1 text-[10px] uppercase tracking-wider text-surface-500 font-medium">
                {section.label}
              </div>
              {section.items.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-sm transition-colors ${
                    activeTab === item.id
                      ? 'bg-accent-600/15 text-accent-400'
                      : 'text-surface-400 hover:bg-surface-800 hover:text-surface-200'
                  }`}
                >
                  <span className="text-xs w-5 text-center flex-shrink-0">{item.icon}</span>
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>
      </div>

      {/* Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Content Header */}
        <div className="flex items-center gap-2 px-6 py-3 border-b border-surface-800">
          {activeItem && (
            <>
              <span className="text-sm">{activeItem.icon}</span>
              <h2 className="text-sm font-medium text-surface-100">{activeItem.label}</h2>
              {activeSection && (
                <span className="text-xs text-surface-500">· {activeSection.label}</span>
              )}
            </>
          )}
        </div>

        {/* Panel */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'members' && <MembersPanel orgId={orgId} />}
          {activeTab === 'roles' && <RolesPanel orgId={orgId} />}
          {activeTab === 'groups' && <GroupsPanel orgId={orgId} />}
          {activeTab === 'collections' && <CollectionsPanel orgId={orgId} />}
          {activeTab === 'vault' && <VaultAccessPanel orgId={orgId} />}
          {activeTab === '2fa' && <TwoFactorSharePanel orgId={orgId} />}
          {activeTab === 'sso' && <SSOPanel orgId={orgId} />}
          {activeTab === 'scim' && <SCIMPanel orgId={orgId} />}
          {activeTab === 'policies' && <PoliciesPanel orgId={orgId} />}
          {activeTab === 'audit' && <AuditLogPanel orgId={orgId} />}
          {activeTab === 'integrations' && <IntegrationsPanel orgId={orgId} />}
        </div>
      </div>
    </div>
  );
}
