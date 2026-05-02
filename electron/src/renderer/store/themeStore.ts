import { create } from 'zustand';

export type ThemeMode = 'dark' | 'light' | 'system';
export type ResolvedTheme = 'dark' | 'light';

const THEME_STORAGE_KEY = 'lgi-pass-theme';

function loadPersistedTheme(): ThemeMode {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (raw === 'dark' || raw === 'light' || raw === 'system') return raw;
  } catch { /* ignore */ }
  return 'dark';
}

function resolveTheme(mode: ThemeMode): ResolvedTheme {
  if (mode === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return mode;
}

interface ThemeState {
  theme: ThemeMode;
  resolvedTheme: ResolvedTheme;
  setTheme: (theme: ThemeMode) => void;
}

export const useThemeStore = create<ThemeState>((set) => {
  const initial = loadPersistedTheme();
  const resolved = resolveTheme(initial);

  // Listen for system theme changes
  const mql = window.matchMedia('(prefers-color-scheme: dark)');
  mql.addEventListener('change', () => {
    const state = useThemeStore.getState();
    if (state.theme === 'system') {
      const newResolved = resolveTheme('system');
      set({ resolvedTheme: newResolved });
      applyThemeClass(newResolved);
    }
  });

  return {
    theme: initial,
    resolvedTheme: resolved,
    setTheme: (theme) => {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
      const newResolved = resolveTheme(theme);
      set({ theme, resolvedTheme: newResolved });
      applyThemeClass(newResolved);
    },
  };
});

function applyThemeClass(resolved: ResolvedTheme) {
  if (resolved === 'dark') {
    document.documentElement.classList.add('dark');
  } else {
    document.documentElement.classList.remove('dark');
  }
}

// Apply on initial load
applyThemeClass(resolveTheme(loadPersistedTheme()));
