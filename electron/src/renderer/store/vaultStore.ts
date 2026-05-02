import { create } from 'zustand';
import type { VaultEntry, Folder } from '../types/vault';

export interface EntryFields {
  [key: string]: string;
}

/** TTL in ms for reprompt approvals (5 minutes). */
const REPROMPT_TTL_MS = 5 * 60 * 1000;

/** Per-entry health indicators cached for the session. */
export interface EntryHealthFlags {
  weak?: boolean;
  reused?: boolean;
  breached?: boolean;
  breachCount?: number;
  old?: boolean;
  insecureUri?: boolean;
}

interface VaultState {
  entries: VaultEntry[];
  entryFields: Record<string, EntryFields>; // id -> decrypted field data
  folders: Folder[];
  searchQuery: string;
  sortBy: 'name' | 'updated_at' | 'entry_type';
  selectedFolderId: string | null;
  selectedTypeFilter: string | null;
  activeFilter: 'all' | 'favorites' | 'archived' | 'trash';
  selectedCollectionId: string | null;
  /** Bump to trigger sidebar collection list refresh. */
  collectionsVersion: number;

  /** Selected tags for filtering. */
  selectedTags: string[];

  /** Cache of entry IDs that have been approved for reprompt bypass, with expiry timestamps. */
  repromptApprovals: Record<string, number>;

  /** Per-entry health flags, populated after vault analysis. */
  healthFlags: Record<string, EntryHealthFlags>;
  /** Whether the health analysis has run at least once this session. */
  healthAnalyzed: boolean;

  setEntries: (entries: VaultEntry[]) => void;
  setFolders: (folders: Folder[]) => void;
  addEntry: (entry: VaultEntry, fields: EntryFields) => void;
  updateEntryFields: (id: string, fields: EntryFields) => void;
  updateEntry: (entry: VaultEntry) => void;
  removeEntry: (id: string) => void;
  setSearchQuery: (query: string) => void;
  setSortBy: (sort: 'name' | 'updated_at' | 'entry_type') => void;
  setSelectedFolderId: (id: string | null) => void;
  setSelectedTypeFilter: (type: string | null) => void;
  setActiveFilter: (filter: 'all' | 'favorites' | 'archived' | 'trash') => void;
  setSelectedCollectionId: (id: string | null) => void;
  /** Bump to trigger sidebar collection list refresh. */
  bumpCollectionsVersion: () => void;
  setSelectedTags: (tags: string[]) => void;
  toggleTag: (tag: string) => void;

  /** Grant a 5-minute reprompt approval for a specific entry. */
  approveReprompt: (entryId: string) => void;
  /** Check whether an entry has a valid (non-expired) reprompt approval. */
  isRepromptApproved: (entryId: string) => boolean;
  /** Clear all reprompt approvals (e.g. on lock). */
  clearRepromptApprovals: () => void;

  /** Set health flags for entries after analysis. */
  setHealthFlags: (flags: Record<string, EntryHealthFlags>) => void;
  /** Merge additional health flags (e.g. breach results) into existing flags. */
  mergeHealthFlags: (flags: Record<string, Partial<EntryHealthFlags>>) => void;
  /** Mark health analysis as complete. */
  setHealthAnalyzed: (v: boolean) => void;
  /** Clear health data (e.g. on lock/logout). */
  clearHealth: () => void;
}

export const useVaultStore = create<VaultState>((set, get) => ({
  entries: [],
  entryFields: {},
  folders: [],
  searchQuery: '',
  sortBy: 'updated_at',
  selectedFolderId: null,
  selectedTypeFilter: null,
  activeFilter: 'all',
  selectedCollectionId: null,
  collectionsVersion: 0,
  selectedTags: [],
  repromptApprovals: {},
  healthFlags: {},
  healthAnalyzed: false,

  setEntries: (entries) => set({ entries }),
  setFolders: (folders) => set({ folders }),
  addEntry: (entry, fields) =>
    set((s) => ({
      entries: [entry, ...s.entries],
      entryFields: { ...s.entryFields, [entry.id]: fields },
    })),
  updateEntryFields: (id, fields) =>
    set((s) => ({
      entryFields: { ...s.entryFields, [id]: fields },
    })),
  updateEntry: (entry) =>
    set((s) => ({ entries: s.entries.map((e) => (e.id === entry.id ? entry : e)) })),
  removeEntry: (id) =>
    set((s) => {
      const { [id]: _, ...rest } = s.entryFields;
      return { entries: s.entries.filter((e) => e.id !== id), entryFields: rest };
    }),
  setSearchQuery: (searchQuery) => set({ searchQuery }),
  setSortBy: (sortBy) => set({ sortBy }),
  setSelectedFolderId: (selectedFolderId) => set({ selectedFolderId }),
  setSelectedTypeFilter: (selectedTypeFilter) => set({ selectedTypeFilter }),
  setActiveFilter: (activeFilter) => set({ activeFilter }),
  setSelectedCollectionId: (selectedCollectionId) => set({ selectedCollectionId }),
  bumpCollectionsVersion: () => set((s) => ({ collectionsVersion: s.collectionsVersion + 1 })),
  setSelectedTags: (selectedTags) => set({ selectedTags }),
  toggleTag: (tag) =>
    set((s) => ({
      selectedTags: s.selectedTags.includes(tag)
        ? s.selectedTags.filter((t) => t !== tag)
        : [...s.selectedTags, tag],
    })),

  approveReprompt: (entryId) =>
    set((s) => ({
      repromptApprovals: { ...s.repromptApprovals, [entryId]: Date.now() + REPROMPT_TTL_MS },
    })),
  isRepromptApproved: (entryId) => {
    const expiry = get().repromptApprovals[entryId];
    return !!expiry && Date.now() < expiry;
  },
  clearRepromptApprovals: () => set({ repromptApprovals: {} }),

  setHealthFlags: (healthFlags) => set({ healthFlags, healthAnalyzed: true }),
  mergeHealthFlags: (flags) =>
    set((s) => {
      const merged = { ...s.healthFlags };
      for (const [id, partial] of Object.entries(flags)) {
        merged[id] = { ...merged[id], ...partial };
      }
      return { healthFlags: merged };
    }),
  setHealthAnalyzed: (healthAnalyzed) => set({ healthAnalyzed }),
  clearHealth: () => set({ healthFlags: {}, healthAnalyzed: false }),
}));
