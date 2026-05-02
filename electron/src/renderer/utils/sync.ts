import { useVaultStore, type EntryFields } from '../store/vaultStore';
import { useSyncStore } from '../store/syncStore';
import type { VaultEntry } from '../types/vault';

interface SyncEntryWire {
  id: string;
  entry_type: string;
  encrypted_data: string;
  nonce: string;
  version: number;
  folder_id: string | null;
  is_deleted: boolean;
  is_favorite: boolean;
  is_archived: boolean;
  deleted_at: string | null;
  updated_at: string;
}

interface SyncPullResponse {
  entries: SyncEntryWire[];
  sync_at: string;
  error?: string;
}

interface SyncPushResponse {
  applied: number;
  conflicts: Array<{
    entry_id: string;
    server_version: number;
    client_version: number;
    server_data: SyncEntryWire;
    client_data: SyncEntryWire;
  }>;
  error?: string;
}

/**
 * Parse a decrypted JSON plaintext into the EntryFields format used by the vault store.
 * Mirrors the parsing logic in Vault.tsx loadVault.
 */
function parsePlaintextToFields(plaintext: string): EntryFields | null {
  try {
    const parsed = JSON.parse(plaintext) as Record<string, unknown>;
    const fields: EntryFields = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (k === 'passwordHistory') {
        fields._passwordHistory = JSON.stringify(v);
      } else if (k === 'uris') {
        fields._uris = JSON.stringify(v);
      } else if (k === 'reprompt') {
        fields._reprompt = String(v === 1 || v === '1' ? '1' : '0');
      } else {
        fields[k] = String(v ?? '');
      }
    }
    return fields;
  } catch {
    return null;
  }
}

function wireToVaultEntry(entry: SyncEntryWire): VaultEntry {
  return {
    id: entry.id,
    entry_type: entry.entry_type as VaultEntry['entry_type'],
    encrypted_data: entry.encrypted_data,
    nonce: entry.nonce,
    version: entry.version,
    folder_id: entry.folder_id ?? null,
    is_favorite: entry.is_favorite,
    is_archived: entry.is_archived,
    deleted_at: entry.deleted_at ?? null,
    created_at: '', // sync doesn't include created_at
    updated_at: entry.updated_at,
  };
}

export interface SyncResult {
  pulled: number;
  pushed: number;
  conflicts: number;
  deleted: number;
  error?: string;
}

/**
 * Perform a full sync cycle: push local changes, then pull remote changes and merge.
 *
 * Since the current architecture sends all CRUD operations directly to the server,
 * the push step mostly confirms the server is up-to-date. The pull step is the main
 * value — it fetches changes made by other devices and merges them into the local store.
 */
export async function performSync(
  token: string,
  masterKeyHex: string,
  deviceId: string,
): Promise<SyncResult> {
  const syncStore = useSyncStore.getState();
  const vaultStore = useVaultStore.getState();
  const result: SyncResult = { pulled: 0, pushed: 0, conflicts: 0, deleted: 0 };

  syncStore.setStatus('syncing', 'Syncing…');

  try {
    // ── Step 1: Push local entries that may have changed ───────────────────
    // In the current architecture, all changes go directly to the server via
    // vault:create/update/delete. But if the user was offline or there were
    // transient failures, some local entries might be ahead. We push entries
    // whose version might differ.
    // For now, we skip the push step since the app always writes directly.
    // A future offline-first mode would track dirty entries and push them here.

    // ── Step 2: Pull changes from server since last sync ──────────────────
    const pullResult = await window.api.sync.pull(
      token,
      deviceId,
      syncStore.lastSyncAt || undefined,
    ) as SyncPullResponse;

    if (pullResult.error) {
      syncStore.setStatus('error', pullResult.error);
      return { ...result, error: pullResult.error };
    }

    const entries = pullResult.entries || [];
    if (entries.length === 0) {
      // Nothing changed — just update the cursor
      syncStore.setLastSyncAt(pullResult.sync_at);
      syncStore.setStatus('success', 'Already up to date');
      return result;
    }

    // ── Step 3: Merge pulled entries into local store ──────────────────────
    const currentEntries = [...vaultStore.entries];
    const currentFields = { ...vaultStore.entryFields };
    const entryMap = new Map(currentEntries.map(e => [e.id, e]));

    for (const syncEntry of entries) {
      if (syncEntry.is_deleted) {
        // Remove deleted entries from local store
        entryMap.delete(syncEntry.id);
        delete currentFields[syncEntry.id];
        result.deleted++;
        continue;
      }

      const existing = entryMap.get(syncEntry.id);

      // Skip if local version is same or newer (shouldn't happen with direct writes)
      if (existing && existing.version >= syncEntry.version) {
        continue;
      }

      // Decrypt the entry
      const decResult = await window.api.vault.decrypt(
        masterKeyHex,
        syncEntry.encrypted_data,
        syncEntry.nonce,
      );
      if (decResult.error || !decResult.plaintext) {
        // Can't decrypt — skip (might be a collection entry encrypted with different key)
        continue;
      }

      const fields = parsePlaintextToFields(decResult.plaintext);
      if (!fields) continue;

      // Upsert into local store
      const vaultEntry = wireToVaultEntry(syncEntry);
      // Preserve created_at from existing entry if we have it
      if (existing) {
        vaultEntry.created_at = existing.created_at;
      }

      entryMap.set(syncEntry.id, vaultEntry);
      currentFields[syncEntry.id] = fields;
      result.pulled++;
    }

    // Apply merged state to store
    const mergedEntries = Array.from(entryMap.values());
    vaultStore.setEntries(mergedEntries);
    // Update fields for all changed entries
    for (const [id, fields] of Object.entries(currentFields)) {
      vaultStore.updateEntryFields(id, fields);
    }

    // ── Step 4: Update sync cursor ────────────────────────────────────────
    syncStore.setLastSyncAt(pullResult.sync_at);

    const parts: string[] = [];
    if (result.pulled > 0) parts.push(`${result.pulled} updated`);
    if (result.deleted > 0) parts.push(`${result.deleted} removed`);
    const msg = parts.length > 0 ? parts.join(', ') : 'Already up to date';
    syncStore.setStatus('success', msg);
    return result;
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Sync failed';
    syncStore.setStatus('error', msg);
    return { ...result, error: msg };
  }
}
