import React from 'react';
import { SHORTCUT_DEFINITIONS, formatShortcut } from '../utils/keyboard';

export function ShortcutHelp({ onClose }: { onClose: () => void }) {
  const categories = ['Navigation', 'Vault', 'Entry', 'General'] as const;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="bg-surface-800 rounded-lg p-5 w-[480px] max-h-[80vh] overflow-auto shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-surface-100">Keyboard Shortcuts</h3>
          <button
            onClick={onClose}
            className="text-surface-500 hover:text-surface-300 text-lg leading-none"
          >
            ×
          </button>
        </div>

        <div className="space-y-4">
          {categories.map((category) => {
            const defs = SHORTCUT_DEFINITIONS.filter((d) => d.category === category);
            if (defs.length === 0) return null;
            return (
              <div key={category}>
                <h4 className="text-[10px] font-semibold text-surface-500 uppercase tracking-wider mb-2">
                  {category}
                </h4>
                <div className="space-y-1">
                  {defs.map((def) => (
                    <div
                      key={def.description}
                      className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-surface-700/50"
                    >
                      <span className="text-xs text-surface-200">{def.description}</span>
                      <kbd className="text-[10px] font-mono bg-surface-900 text-surface-300 px-2 py-0.5 rounded border border-surface-700">
                        {formatShortcut(def)}
                      </kbd>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
