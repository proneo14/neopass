import React from 'react';

export function Vault() {
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-lg font-semibold text-surface-100">Vault</h1>
        <button className="px-3 py-1.5 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
          + Add Entry
        </button>
      </div>

      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search vault…"
          className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:border-transparent"
        />
      </div>

      {/* Empty state */}
      <div className="flex flex-col items-center justify-center py-20 text-surface-500">
        <span className="text-5xl mb-4">🔐</span>
        <p className="text-sm">Your vault is empty</p>
        <p className="text-xs mt-1">Add your first entry to get started</p>
      </div>
    </div>
  );
}
