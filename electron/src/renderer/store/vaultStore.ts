import { create } from 'zustand';
import type { VaultEntry, Folder } from '../types/vault';

export interface EntryFields {
  [key: string]: string;
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
}

export const useVaultStore = create<VaultState>((set) => ({
  entries: [],
  entryFields: {},
  folders: [],
  searchQuery: '',
  sortBy: 'updated_at',
  selectedFolderId: null,
  selectedTypeFilter: null,
  activeFilter: 'all',

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
}));
