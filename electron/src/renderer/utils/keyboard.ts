import { useEffect } from 'react';

export interface ShortcutDef {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  description: string;
  category: 'Navigation' | 'Vault' | 'Entry' | 'General';
  action: () => void;
}

/**
 * Returns true if the event target is an input/textarea/contenteditable element.
 * Escape is special-cased to work even inside inputs.
 */
function isInputFocused(e: KeyboardEvent): boolean {
  const tag = (e.target as HTMLElement)?.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if ((e.target as HTMLElement)?.isContentEditable) return true;
  return false;
}

// Map from character to its physical KeyboardEvent.code
const KEY_TO_CODE: Record<string, string> = {
  '/': 'Slash', '.': 'Period', ',': 'Comma', ';': 'Semicolon',
  "'": 'Quote', '[': 'BracketLeft', ']': 'BracketRight',
  '\\': 'Backslash', '-': 'Minus', '=': 'Equal', '`': 'Backquote',
};

function matchesShortcut(e: KeyboardEvent, def: ShortcutDef): boolean {
  const ctrl = def.ctrl ?? false;
  const shift = def.shift ?? false;
  const alt = def.alt ?? false;

  if ((e.ctrlKey || e.metaKey) !== ctrl) return false;
  if (e.shiftKey !== shift) return false;
  if (e.altKey !== alt) return false;

  // Direct key match (works for unshifted keys)
  if (e.key.toLowerCase() === def.key.toLowerCase()) return true;
  // Match via physical key code for letter keys
  if (e.code.toLowerCase() === `key${def.key}`.toLowerCase()) return true;
  // Match via physical key code for symbol keys (e.g. '/' → 'Slash')
  const expectedCode = KEY_TO_CODE[def.key];
  if (expectedCode && e.code === expectedCode) return true;

  return false;
}

export function useKeyboardShortcuts(shortcuts: ShortcutDef[]) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      for (const def of shortcuts) {
        if (matchesShortcut(e, def)) {
          // Allow Escape even inside inputs
          if (def.key === 'Escape') {
            e.preventDefault();
            def.action();
            return;
          }
          // Don't trigger shortcuts when in input fields
          if (isInputFocused(e)) return;
          e.preventDefault();
          def.action();
          return;
        }
      }
    };

    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [shortcuts]);
}

/** Static shortcut definitions for the help modal. */
export const SHORTCUT_DEFINITIONS: Omit<ShortcutDef, 'action'>[] = [
  { key: 'n', ctrl: true, description: 'New vault entry', category: 'Vault' },
  { key: 'f', ctrl: true, description: 'Focus search bar', category: 'Navigation' },
  { key: 'g', ctrl: true, description: 'Open password generator', category: 'General' },
  { key: 'l', ctrl: true, description: 'Lock vault', category: 'General' },
  { key: ',', ctrl: true, description: 'Open settings', category: 'Navigation' },
  { key: 'c', ctrl: true, shift: true, description: 'Copy password', category: 'Entry' },
  { key: 'u', ctrl: true, shift: true, description: 'Copy username', category: 'Entry' },
  { key: 'Escape', description: 'Close modal / dialog', category: 'General' },
  { key: '/', ctrl: true, shift: true, description: 'Show keyboard shortcuts', category: 'General' },
];

/** Format a shortcut for display. */
export function formatShortcut(def: Omit<ShortcutDef, 'action'>): string {
  const parts: string[] = [];
  if (def.ctrl) parts.push('Ctrl');
  if (def.shift) parts.push('Shift');
  if (def.alt) parts.push('Alt');
  const keyLabel = def.key === ',' ? ',' : def.key === '/' ? '?' : def.key === 'Escape' ? 'Esc' : def.key.toUpperCase();
  parts.push(keyLabel);
  return parts.join('+');
}
