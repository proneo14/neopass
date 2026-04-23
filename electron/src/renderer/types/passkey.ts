export interface PasskeyCredential {
  id: string;
  user_id: string;
  credential_id: string; // base64
  rp_id: string;
  rp_name: string;
  user_handle: string; // base64
  username: string;
  display_name: string;
  public_key_cbor: string; // base64
  sign_count: number;
  aaguid: string; // base64
  transports: string[];
  discoverable: boolean;
  backed_up: boolean;
  algorithm: number;
  created_at: string;
  last_used_at: string | null;
}

export interface HardwareAuthKey {
  id: string;
  user_id: string;
  credential_id: string;
  public_key_cbor: string;
  sign_count: number;
  aaguid: string;
  transports: string[];
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export const ALGORITHM_LABELS: Record<number, string> = {
  [-7]: 'ES256 (P-256)',
  [-8]: 'EdDSA (Ed25519)',
  [-257]: 'RS256',
};
