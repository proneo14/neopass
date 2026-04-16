export interface OrgMember {
  org_id: string;
  user_id: string;
  email?: string;
  role: string;
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
