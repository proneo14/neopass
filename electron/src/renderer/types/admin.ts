export interface OrgMember {
  org_id: string;
  user_id: string;
  email?: string;
  role: string;
  role_id?: string;
  joined_at: string;
}

export interface Invitation {
  id: string;
  org_id: string;
  email: string;
  role: string;
  invited_by: string;
  accepted: boolean;
  created_at: string;
}

export interface Organization {
  id: string;
  name: string;
  created_at: string;
}

export interface OrgPolicy {
  require_2fa: boolean;
  min_password_length: number;
  rotation_days: number;
}

export interface DecryptedEntry {
  id: string;
  entry_type: string;
  data: Record<string, unknown>;
  version: number;
}

export interface AuditEntry {
  id: string;
  actor_id?: string;
  target_id?: string;
  action: string;
  details?: Record<string, unknown>;
  created_at: string;
}

export interface AuditFilters {
  actor_id?: string;
  target_id?: string;
  action?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

// --- Custom Roles ---

export interface Role {
  id: string;
  org_id: string;
  name: string;
  description?: string;
  permissions: string[];
  is_builtin: boolean;
  created_at: string;
}

export const ALL_PERMISSIONS = [
  { key: 'vault.read', label: 'Read own vault entries' },
  { key: 'vault.write', label: 'Create/edit/delete own vault entries' },
  { key: 'vault.export', label: 'Export vault data' },
  { key: 'collection.read', label: 'Read collection entries' },
  { key: 'collection.write', label: 'Edit collection entries' },
  { key: 'collection.manage', label: 'Manage collection members' },
  { key: 'org.invite', label: 'Invite users to org' },
  { key: 'org.remove', label: 'Remove users from org' },
  { key: 'org.policy', label: 'Manage org policies' },
  { key: 'org.audit', label: 'View audit logs' },
  { key: 'org.vault_access', label: 'Access other users\' vaults (escrow)' },
  { key: 'org.sso', label: 'Manage SSO configuration' },
  { key: 'org.scim', label: 'Manage SCIM provisioning' },
] as const;

// --- Groups ---

export interface Group {
  id: string;
  org_id: string;
  name: string;
  external_id?: string;
  created_at: string;
}

export interface GroupMember {
  group_id: string;
  user_id: string;
  email?: string;
}

// --- Collection-Group assignments ---

export interface CollectionGroup {
  collection_id: string;
  group_id: string;
  group_name?: string;
  permission: string;
}

// --- Webhooks ---

export interface Webhook {
  id: string;
  org_id: string;
  url: string;
  events: string[];
  enabled: boolean;
  created_at: string;
  recent_deliveries?: WebhookDelivery[];
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_id: string;
  status: 'pending' | 'delivered' | 'failed';
  response_code?: number;
  attempts: number;
  last_attempt_at?: string;
  created_at: string;
}
