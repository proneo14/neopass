import React from 'react';

export function Settings() {
  return (
    <div>
      <h1 className="text-lg font-semibold text-surface-100 mb-4">Settings</h1>

      <div className="space-y-6 max-w-lg">
        <section>
          <h2 className="text-sm font-medium text-surface-300 mb-3">Account</h2>
          <div className="space-y-2">
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors">
              Change Master Password
            </button>
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors">
              Two-Factor Authentication
            </button>
          </div>
        </section>

        <section>
          <h2 className="text-sm font-medium text-surface-300 mb-3">Security</h2>
          <div className="space-y-2">
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors">
              Biometric Unlock
            </button>
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors">
              Auto-Lock Timeout
            </button>
          </div>
        </section>

        <section>
          <h2 className="text-sm font-medium text-surface-300 mb-3">Data</h2>
          <div className="space-y-2">
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors">
              Sync Settings
            </button>
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-surface-200 transition-colors">
              Export Vault
            </button>
            <button className="w-full text-left px-4 py-3 rounded-md bg-surface-800 hover:bg-surface-700 text-sm text-red-400 transition-colors">
              Clear Local Cache
            </button>
          </div>
        </section>

        <div className="pt-4 border-t border-surface-700">
          <p className="text-xs text-surface-500">Quantum Password Manager v1.0.0</p>
        </div>
      </div>
    </div>
  );
}
