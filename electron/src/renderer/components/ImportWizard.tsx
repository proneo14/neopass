import React, { useState, useRef } from 'react';
import { useAuthStore } from '../store/authStore';
import { useVaultStore } from '../store/vaultStore';
import {
  IMPORT_SOURCES,
  parseImportFile,
  type ImportedEntry,
  type ImportSource,
} from '../utils/importers';

type Step = 'source' | 'file' | 'preview' | 'importing' | 'done';

export function ImportWizard({ onClose }: { onClose: () => void }) {
  const { token, masterKeyHex } = useAuthStore();
  const { addEntry } = useVaultStore();
  const [step, setStep] = useState<Step>('source');
  const [selectedSource, setSelectedSource] = useState<ImportSource | null>(null);
  const [parsedEntries, setParsedEntries] = useState<ImportedEntry[]>([]);
  const [parseErrors, setParseErrors] = useState<string[]>([]);
  const [importProgress, setImportProgress] = useState(0);
  const [importTotal, setImportTotal] = useState(0);
  const [importErrors, setImportErrors] = useState<string[]>([]);
  const [importedCount, setImportedCount] = useState(0);
  const [duplicatesSkipped, setDuplicatesSkipped] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSourceSelect = (source: ImportSource) => {
    setSelectedSource(source);
    setStep('file');
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selectedSource) return;

    try {
      const text = await file.text();
      const result = parseImportFile(selectedSource.id, text, file.name);
      setParsedEntries(result.entries);
      setParseErrors(result.errors);
      setStep('preview');
    } catch (err) {
      setParseErrors([`Failed to read file: ${err instanceof Error ? err.message : 'Unknown error'}`]);
      setStep('preview');
    }
  };

  const handleImport = async () => {
    if (!token || !masterKeyHex || parsedEntries.length === 0) return;

    setStep('importing');
    setImportTotal(parsedEntries.length);
    setImportProgress(0);
    setImportErrors([]);

    const existingEntries = useVaultStore.getState().entries;
    const existingFields = useVaultStore.getState().entryFields;

    let imported = 0;
    let skipped = 0;
    const errors: string[] = [];

    for (let i = 0; i < parsedEntries.length; i++) {
      const entry = parsedEntries[i];
      setImportProgress(i + 1);

      // Simple duplicate detection: same type + name + username/uri
      const isDuplicate = existingEntries.some((existing) => {
        if (existing.entry_type !== entry.type) return false;
        const ef = existingFields[existing.id];
        if (!ef) return false;
        if (ef.name !== entry.fields.name) return false;
        if (entry.type === 'login') {
          return ef.username === entry.fields.username && ef.uri === entry.fields.uri;
        }
        return true;
      });

      if (isDuplicate) {
        skipped++;
        continue;
      }

      try {
        // Build plaintext object
        const plaintextObj: Record<string, unknown> = { ...entry.fields };
        if (entry.type === 'login' && entry.fields.uri) {
          plaintextObj.uris = [{ uri: entry.fields.uri, match: 'base_domain' }];
        }

        const plaintext = JSON.stringify(plaintextObj);
        const encResult = await window.api.vault.encrypt(masterKeyHex, plaintext);
        if (encResult.error) {
          errors.push(`"${entry.name}": Encryption failed`);
          continue;
        }

        const createResult = await window.api.vault.create(token, {
          entry_type: entry.type,
          encrypted_data: encResult.encrypted_data,
          nonce: encResult.nonce,
        }) as { id?: string; entry_type?: string; encrypted_data?: string; nonce?: string; version?: number; folder_id?: string | null; created_at?: string; updated_at?: string; error?: string };

        if (createResult.error) {
          errors.push(`"${entry.name}": ${createResult.error}`);
          continue;
        }

        if (createResult.id) {
          addEntry(
            {
              id: createResult.id,
              entry_type: (createResult.entry_type || entry.type) as any,
              encrypted_data: createResult.encrypted_data || encResult.encrypted_data,
              nonce: createResult.nonce || encResult.nonce,
              version: createResult.version || 1,
              folder_id: createResult.folder_id ?? null,
              is_favorite: entry.favorite || false,
              is_archived: false,
              deleted_at: null,
              created_at: createResult.created_at || new Date().toISOString(),
              updated_at: createResult.updated_at || new Date().toISOString(),
            },
            entry.fields,
          );
          imported++;

          // Set favorite if the imported entry was favorited
          if (entry.favorite && createResult.id) {
            window.api.vault.setFavorite(token, createResult.id, true).catch(() => {});
          }
        }
      } catch (err) {
        errors.push(`"${entry.name}": ${err instanceof Error ? err.message : 'Failed'}`);
      }
    }

    setImportedCount(imported);
    setDuplicatesSkipped(skipped);
    setImportErrors(errors);
    setStep('done');
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="bg-surface-800 rounded-lg shadow-2xl w-[520px] max-h-[80vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-surface-700">
          <h2 className="text-sm font-semibold text-surface-100">Import Passwords</h2>
          <button
            onClick={onClose}
            className="text-surface-500 hover:text-surface-300 transition-colors text-lg"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-5">
          {/* Step 1: Source Selection */}
          {step === 'source' && (
            <div>
              <p className="text-sm text-surface-400 mb-4">
                Select the password manager you're importing from:
              </p>
              <div className="grid grid-cols-2 gap-2">
                {IMPORT_SOURCES.map((source) => (
                  <button
                    key={source.id}
                    onClick={() => handleSourceSelect(source)}
                    className="flex items-center gap-3 px-4 py-3 rounded-lg bg-surface-900 hover:bg-surface-700 border border-surface-700 hover:border-accent-600 transition-all text-left"
                  >
                    <span className="text-2xl">{source.icon}</span>
                    <div>
                      <p className="text-sm font-medium text-surface-200">{source.name}</p>
                      <p className="text-xs text-surface-500">{source.formats}</p>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Step 2: File Selection */}
          {step === 'file' && selectedSource && (
            <div>
              <button
                onClick={() => { setStep('source'); setSelectedSource(null); }}
                className="text-xs text-accent-400 hover:text-accent-300 mb-4 flex items-center gap-1"
              >
                ← Back to source selection
              </button>
              <div className="flex items-center gap-3 mb-4">
                <span className="text-2xl">{selectedSource.icon}</span>
                <div>
                  <p className="text-sm font-medium text-surface-200">Import from {selectedSource.name}</p>
                  <p className="text-xs text-surface-500">Select your exported {selectedSource.formats} file</p>
                </div>
              </div>

              <div className="border-2 border-dashed border-surface-600 rounded-lg p-8 text-center hover:border-accent-600 transition-colors">
                <p className="text-surface-400 text-sm mb-3">
                  Drop your file here or click to browse
                </p>
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-4 py-2 bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-md transition-colors"
                >
                  Choose File
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept={selectedSource.accept}
                  onChange={handleFileSelect}
                  className="hidden"
                />
              </div>

              <div className="mt-4 p-3 bg-surface-900 rounded-md">
                <p className="text-xs font-medium text-surface-300 mb-1">
                  How to export from {selectedSource.name}:
                </p>
                <p className="text-xs text-surface-500">
                  {getExportInstructions(selectedSource.id)}
                </p>
              </div>
            </div>
          )}

          {/* Step 3: Preview */}
          {step === 'preview' && (
            <div>
              <button
                onClick={() => { setStep('file'); setParsedEntries([]); setParseErrors([]); }}
                className="text-xs text-accent-400 hover:text-accent-300 mb-4 flex items-center gap-1"
              >
                ← Choose a different file
              </button>

              {parseErrors.length > 0 && (
                <div className="mb-4 p-3 bg-red-900/20 border border-red-800 rounded-md">
                  <p className="text-xs font-medium text-red-400 mb-1">
                    {parseErrors.length} warning{parseErrors.length > 1 ? 's' : ''} during parsing:
                  </p>
                  <div className="max-h-20 overflow-auto">
                    {parseErrors.slice(0, 5).map((e, i) => (
                      <p key={i} className="text-xs text-red-400/80">{e}</p>
                    ))}
                    {parseErrors.length > 5 && (
                      <p className="text-xs text-red-400/60">...and {parseErrors.length - 5} more</p>
                    )}
                  </div>
                </div>
              )}

              {parsedEntries.length === 0 ? (
                <div className="text-center py-8">
                  <p className="text-surface-400 text-sm">No entries found in the file.</p>
                  <p className="text-surface-500 text-xs mt-1">Make sure the file format matches the selected source.</p>
                </div>
              ) : (
                <>
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-sm text-surface-300">
                      Found <span className="font-semibold text-surface-100">{parsedEntries.length}</span> entries to import
                    </p>
                  </div>

                  {/* Type breakdown */}
                  <div className="flex gap-3 mb-4">
                    {(['login', 'secure_note', 'credit_card', 'identity'] as const).map((type) => {
                      const count = parsedEntries.filter(e => e.type === type).length;
                      if (count === 0) return null;
                      const icons = { login: '🔑', secure_note: '📝', credit_card: '💳', identity: '👤' };
                      const labels = { login: 'Logins', secure_note: 'Notes', credit_card: 'Cards', identity: 'Identities' };
                      return (
                        <div key={type} className="flex items-center gap-1 text-xs text-surface-400">
                          <span>{icons[type]}</span>
                          <span>{count} {labels[type]}</span>
                        </div>
                      );
                    })}
                  </div>

                  {/* Entry list preview */}
                  <div className="max-h-48 overflow-auto border border-surface-700 rounded-md divide-y divide-surface-700">
                    {parsedEntries.slice(0, 50).map((entry, i) => (
                      <div key={i} className="flex items-center gap-3 px-3 py-2">
                        <span className="text-sm">
                          {{ login: '🔑', secure_note: '📝', credit_card: '💳', identity: '👤' }[entry.type]}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-surface-200 truncate">{entry.name}</p>
                          {entry.fields.username && (
                            <p className="text-xs text-surface-500 truncate">{entry.fields.username}</p>
                          )}
                        </div>
                        {entry.folder && (
                          <span className="text-xs text-surface-600 truncate max-w-24">{entry.folder}</span>
                        )}
                      </div>
                    ))}
                    {parsedEntries.length > 50 && (
                      <div className="px-3 py-2 text-xs text-surface-500 text-center">
                        ...and {parsedEntries.length - 50} more entries
                      </div>
                    )}
                  </div>

                  <p className="text-xs text-surface-500 mt-3">
                    Duplicates (same name, username, and URL) will be automatically skipped.
                  </p>
                </>
              )}
            </div>
          )}

          {/* Step 4: Importing */}
          {step === 'importing' && (
            <div className="text-center py-8">
              <div className="inline-block w-10 h-10 border-2 border-accent-600 border-t-transparent rounded-full animate-spin mb-4" />
              <p className="text-sm text-surface-200 mb-2">
                Importing entries...
              </p>
              <p className="text-xs text-surface-500">
                {importProgress} of {importTotal}
              </p>
              <div className="w-full max-w-xs mx-auto mt-3 h-1.5 bg-surface-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-accent-600 transition-all duration-150"
                  style={{ width: `${importTotal > 0 ? (importProgress / importTotal) * 100 : 0}%` }}
                />
              </div>
            </div>
          )}

          {/* Step 5: Done */}
          {step === 'done' && (
            <div className="text-center py-6">
              <span className="text-4xl mb-4 block">✅</span>
              <p className="text-sm font-medium text-surface-100 mb-2">Import Complete</p>
              <div className="space-y-1 mb-4">
                <p className="text-xs text-surface-400">
                  <span className="text-green-400 font-medium">{importedCount}</span> entries imported successfully
                </p>
                {duplicatesSkipped > 0 && (
                  <p className="text-xs text-surface-400">
                    <span className="text-yellow-400 font-medium">{duplicatesSkipped}</span> duplicates skipped
                  </p>
                )}
                {importErrors.length > 0 && (
                  <p className="text-xs text-surface-400">
                    <span className="text-red-400 font-medium">{importErrors.length}</span> failed
                  </p>
                )}
              </div>

              {importErrors.length > 0 && (
                <div className="text-left mb-4 p-3 bg-red-900/20 border border-red-800 rounded-md max-h-32 overflow-auto">
                  {importErrors.slice(0, 10).map((e, i) => (
                    <p key={i} className="text-xs text-red-400/80">{e}</p>
                  ))}
                  {importErrors.length > 10 && (
                    <p className="text-xs text-red-400/60">...and {importErrors.length - 10} more</p>
                  )}
                </div>
              )}

              <button
                onClick={onClose}
                className="px-5 py-2 bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-md transition-colors"
              >
                Done
              </button>
            </div>
          )}
        </div>

        {/* Footer */}
        {step === 'preview' && parsedEntries.length > 0 && (
          <div className="px-5 py-4 border-t border-surface-700 flex justify-end gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-surface-700 hover:bg-surface-600 text-surface-300 text-sm rounded-md transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleImport}
              className="px-4 py-2 bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium rounded-md transition-colors"
            >
              Import {parsedEntries.length} Entries
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function getExportInstructions(sourceId: string): string {
  switch (sourceId) {
    case 'bitwarden':
      return 'Go to Settings → Export Vault → select CSV or JSON format → Export.';
    case '1password':
      return 'Go to File → Export → select CSV format → Export.';
    case 'lastpass':
      return 'Go to Account Options → Advanced → Export → you\'ll get a CSV file.';
    case 'chrome':
      return 'Go to chrome://password-manager/settings → Download file (CSV).';
    case 'firefox':
      return 'Go to about:logins → ⋯ menu → Export Logins → Save as CSV.';
    case 'keepass':
      return 'Go to File → Export → select KeePass XML (2.x) format → OK.';
    default:
      return 'Export your passwords from the application settings.';
  }
}
