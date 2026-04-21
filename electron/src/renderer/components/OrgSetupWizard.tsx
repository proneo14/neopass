import React, { useState } from 'react';

type Step = 'intro' | 'connect' | 'testing' | 'migrating' | 'success' | 'error';

export function OrgSetupWizard({ onClose, onComplete }: { onClose: () => void; onComplete: () => void }) {
  const [step, setStep] = useState<Step>('intro');
  const [mode, setMode] = useState<'docker' | 'manual'>('docker');
  const [host, setHost] = useState('localhost');
  const [port, setPort] = useState('5432');
  const [database, setDatabase] = useState('password_manager');
  const [username, setUsername] = useState('pmuser');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [migrationResult, setMigrationResult] = useState<Record<string, number> | null>(null);

  const generatedPassword = useState(() => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    return Array.from({ length: 24 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  })[0];

  const buildConnectionString = () =>
    `postgres://${encodeURIComponent(username)}:${encodeURIComponent(password)}@${host}:${port}/${database}?sslmode=disable`;

  const dockerCommand = `docker run -d --name lgipass-db \\
  -e POSTGRES_DB=${database} \\
  -e POSTGRES_USER=${username} \\
  -e POSTGRES_PASSWORD=${generatedPassword} \\
  -p 5432:5432 postgres:16-alpine`;

  const handleTestConnection = async () => {
    setStep('testing');
    setError('');
    try {
      const connStr = mode === 'docker'
        ? `postgres://${username}:${generatedPassword}@localhost:5432/${database}?sslmode=disable`
        : buildConnectionString();
      const result = await window.api.storage.testPgConnection(connStr);
      if (result.error) {
        setError(result.error);
        setStep('connect');
      } else {
        handleMigrate(connStr);
      }
    } catch {
      setError('Connection test failed');
      setStep('connect');
    }
  };

  const handleMigrate = async (connStr: string) => {
    setStep('migrating');
    setError('');
    try {
      const result = await window.api.storage.migrateToPostgres(connStr);
      if (result.error) {
        setError(result.error);
        setStep('error');
      } else {
        const { error: _err, ...counts } = result;
        setMigrationResult(counts as Record<string, number>);
        setStep('success');
      }
    } catch {
      setError('Migration failed');
      setStep('error');
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface-800 rounded-lg p-6 w-[480px] shadow-2xl max-h-[85vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
        <h3 className="text-base font-semibold text-surface-100 mb-4">Enable Organization Features</h3>

        {step === 'intro' && (
          <div className="space-y-4">
            <p className="text-sm text-surface-400">
              Organization features (admin panel, member management, escrow recovery) require a PostgreSQL database.
            </p>
            <p className="text-sm text-surface-400">
              Your vault data will be migrated from the local SQLite database to PostgreSQL. The local file will be kept as a backup.
            </p>
            <div className="flex gap-2 pt-2">
              <button onClick={onClose} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Cancel
              </button>
              <button onClick={() => setStep('connect')} className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
                Continue
              </button>
            </div>
          </div>
        )}

        {step === 'connect' && (
          <div className="space-y-4">
            <div className="flex gap-2 mb-3">
              <button
                onClick={() => setMode('docker')}
                className={`flex-1 py-2 rounded-md text-sm transition-colors ${mode === 'docker' ? 'bg-accent-600 text-white' : 'bg-surface-700 text-surface-300'}`}
              >
                Use Docker
              </button>
              <button
                onClick={() => setMode('manual')}
                className={`flex-1 py-2 rounded-md text-sm transition-colors ${mode === 'manual' ? 'bg-accent-600 text-white' : 'bg-surface-700 text-surface-300'}`}
              >
                Connect Existing
              </button>
            </div>

            {mode === 'docker' ? (
              <div className="space-y-3">
                <p className="text-xs text-surface-400">Run this command to start a PostgreSQL container:</p>
                <pre className="text-xs text-surface-300 bg-surface-900 rounded-md p-3 overflow-x-auto whitespace-pre-wrap font-mono">
                  {dockerCommand}
                </pre>
                <p className="text-xs text-surface-500">
                  Generated password: <code className="text-surface-300">{generatedPassword}</code>
                </p>
                <p className="text-xs text-surface-500">
                  Wait a few seconds for the container to start, then click Test &amp; Migrate.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="Host" className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500" />
                <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="Port" className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500" />
                <input value={database} onChange={(e) => setDatabase(e.target.value)} placeholder="Database" className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500" />
                <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500" />
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" className="w-full px-3 py-2 rounded-md bg-surface-900 border border-surface-600 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500" />
              </div>
            )}

            {error && <p className="text-xs text-red-400">{error}</p>}

            <div className="flex gap-2 pt-2">
              <button onClick={() => setStep('intro')} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Back
              </button>
              <button onClick={handleTestConnection} className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
                Test &amp; Migrate
              </button>
            </div>
          </div>
        )}

        {step === 'testing' && (
          <div className="text-center py-8">
            <p className="text-sm text-surface-300 animate-pulse">Testing PostgreSQL connection...</p>
          </div>
        )}

        {step === 'migrating' && (
          <div className="text-center py-8">
            <p className="text-sm text-surface-300 animate-pulse">Migrating data to PostgreSQL...</p>
            <p className="text-xs text-surface-500 mt-2">This may take a moment.</p>
          </div>
        )}

        {step === 'success' && (
          <div className="space-y-4">
            <div className="text-center py-4">
              <span className="text-3xl">✅</span>
              <p className="text-sm text-surface-200 mt-2">Migration complete!</p>
            </div>
            {migrationResult && (
              <div className="bg-surface-900 rounded-md p-3 space-y-1">
                {Object.entries(migrationResult).filter(([, v]) => typeof v === 'number').map(([k, v]) => (
                  <div key={k} className="flex justify-between text-xs">
                    <span className="text-surface-400">{k.replace(/_/g, ' ')}</span>
                    <span className="text-surface-200">{v}</span>
                  </div>
                ))}
              </div>
            )}
            <p className="text-xs text-surface-500">
              Your SQLite database has been backed up. You can now create or join an organization.
            </p>
            <button
              onClick={() => { onComplete(); onClose(); }}
              className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors"
            >
              Done
            </button>
          </div>
        )}

        {step === 'error' && (
          <div className="space-y-4">
            <div className="text-center py-4">
              <span className="text-3xl">❌</span>
              <p className="text-sm text-red-400 mt-2">Migration failed</p>
            </div>
            {error && <p className="text-xs text-red-400 bg-surface-900 rounded-md p-3">{error}</p>}
            <p className="text-xs text-surface-500">Your SQLite data is unchanged. You can try again.</p>
            <div className="flex gap-2">
              <button onClick={onClose} className="flex-1 py-2 rounded-md bg-surface-700 text-surface-300 text-sm hover:bg-surface-600 transition-colors">
                Close
              </button>
              <button onClick={() => setStep('connect')} className="flex-1 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors">
                Try Again
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
