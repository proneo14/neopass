import React, { useState, useCallback, useEffect } from 'react';

export type UsernameMode = 'word_number' | 'random' | 'uuid' | 'catchall' | 'service';
type AliasService = 'simplelogin' | 'addyio';

interface UsernameGeneratorProps {
  onUse?: (username: string) => void;
  defaultMode?: UsernameMode;
}

const WORD_LIST = [
  'anchor', 'beacon', 'cipher', 'drift', 'ember', 'falcon', 'glacier', 'harbor',
  'iron', 'jade', 'karma', 'lantern', 'maple', 'nebula', 'oracle', 'prism',
  'quartz', 'river', 'summit', 'thunder', 'umbra', 'vertex', 'willow', 'zenith',
  'amber', 'blaze', 'coral', 'delta', 'epoch', 'flare', 'grain', 'haven',
  'ivory', 'jungle', 'knight', 'lotus', 'meadow', 'nexus', 'opal', 'palace',
  'raven', 'solar', 'tidal', 'ultra', 'vivid', 'warden', 'xenon', 'yield',
  'aurora', 'bridge', 'castle', 'dragon', 'frost', 'garden', 'island', 'comet',
  'shield', 'vault', 'crystal', 'spark', 'ocean', 'pine', 'storm', 'flame',
  'silver', 'copper', 'shadow', 'echo', 'breeze', 'stone', 'arrow', 'hawk',
  'wolf', 'tiger', 'lunar', 'stellar', 'nova', 'pixel', 'quantum', 'rapid',
  'sage', 'terra', 'vine', 'wave', 'atlas', 'bolt', 'crest', 'dune',
  'fern', 'glow', 'haze', 'ink', 'jet', 'keen', 'lark', 'mist',
  'north', 'onyx', 'peak', 'reef', 'silk', 'trail', 'unity', 'vale',
];

function generateWordNumber(digitCount: number, capitalize: boolean, separator: string): string {
  const arr = new Uint32Array(2);
  crypto.getRandomValues(arr);
  let word = WORD_LIST[arr[0] % WORD_LIST.length];
  if (capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
  const maxNum = Math.pow(10, digitCount);
  const num = arr[1] % maxNum;
  const numStr = String(num).padStart(digitCount, '0');
  return `${word}${separator}${numStr}`;
}

function generateRandomChars(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr, (v) => chars[v % chars.length]).join('');
}

function generateUUID(): string {
  return crypto.randomUUID();
}

function generateCatchAll(domain: string): string {
  const random = generateRandomChars(7);
  return `${random}@${domain}`;
}

export function UsernameGenerator({ onUse, defaultMode = 'word_number' }: UsernameGeneratorProps) {
  const [mode, setMode] = useState<UsernameMode>(defaultMode);
  const [generated, setGenerated] = useState('');
  const [copied, setCopied] = useState(false);

  // Word+Number options
  const [digitCount, setDigitCount] = useState(4);
  const [capitalize, setCapitalize] = useState(true);
  const [separator, setSeparator] = useState('');

  // Random chars options
  const [charLength, setCharLength] = useState(12);

  // Catch-all options
  const [catchAllDomain, setCatchAllDomain] = useState(() => {
    try { return localStorage.getItem('neopass-catchall-domain') || ''; } catch { return ''; }
  });

  // Service options
  const [aliasService, setAliasService] = useState<AliasService>('simplelogin');
  const [serviceLoading, setServiceLoading] = useState(false);
  const [serviceError, setServiceError] = useState('');

  const generate = useCallback(() => {
    let result = '';
    switch (mode) {
      case 'word_number':
        result = generateWordNumber(digitCount, capitalize, separator);
        break;
      case 'random':
        result = generateRandomChars(charLength);
        break;
      case 'uuid':
        result = generateUUID();
        break;
      case 'catchall':
        if (catchAllDomain.trim()) {
          result = generateCatchAll(catchAllDomain.trim());
        } else {
          result = '(set domain in settings)';
        }
        break;
      case 'service':
        // Service generation is handled separately via API
        return;
    }
    setGenerated(result);
    setCopied(false);
  }, [mode, digitCount, capitalize, separator, charLength, catchAllDomain]);

  useEffect(() => {
    generate();
  }, [generate]);

  const handleCopy = async () => {
    if (!generated) return;
    await navigator.clipboard.writeText(generated);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const generateFromService = async () => {
    setServiceError('');
    setServiceLoading(true);
    try {
      let apiKey = '';
      let url = '';
      let headers: Record<string, string> = {};

      if (aliasService === 'simplelogin') {
        apiKey = localStorage.getItem('neopass-simplelogin-key') || '';
        if (!apiKey) { setServiceError('SimpleLogin API key not configured. Set it in Settings.'); return; }
        url = 'https://app.simplelogin.io/api/alias/random/new';
        headers = { 'Authentication': apiKey, 'Content-Type': 'application/json' };
      } else {
        apiKey = localStorage.getItem('neopass-addyio-key') || '';
        if (!apiKey) { setServiceError('Addy.io API key not configured. Set it in Settings.'); return; }
        url = 'https://app.addy.io/api/v1/aliases';
        headers = { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
      }

      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(aliasService === 'simplelogin' ? { mode: 'uuid' } : { domain: 'anonaddy.me' }),
      });

      if (!response.ok) {
        const errText = await response.text().catch(() => '');
        setServiceError(`API error ${response.status}: ${errText.slice(0, 100)}`);
        return;
      }

      const data = await response.json();
      const alias = aliasService === 'simplelogin'
        ? (data.alias || data.email || '')
        : (data.data?.email || data.email || '');

      if (alias) {
        setGenerated(alias);
        setCopied(false);
      } else {
        setServiceError('No alias returned from service');
      }
    } catch (err: any) {
      setServiceError(err?.message || 'Failed to generate alias');
    } finally {
      setServiceLoading(false);
    }
  };

  const modes: { value: UsernameMode; label: string }[] = [
    { value: 'word_number', label: 'Word+Number' },
    { value: 'random', label: 'Random' },
    { value: 'uuid', label: 'UUID' },
    { value: 'catchall', label: 'Catch-all' },
    { value: 'service', label: 'Service' },
  ];

  return (
    <div className="space-y-4">
      {/* Generated username display */}
      <div className="bg-surface-800 rounded-md p-3 flex items-center gap-2">
        <code className="flex-1 text-sm text-surface-100 font-mono break-all select-all">
          {generated || '—'}
        </code>
        <button
          onClick={handleCopy}
          disabled={!generated}
          className="shrink-0 px-2 py-1 rounded text-xs bg-surface-700 hover:bg-surface-600 text-surface-300 transition-colors disabled:opacity-50"
        >
          {copied ? '✓' : 'Copy'}
        </button>
        {mode !== 'service' && (
          <button
            onClick={generate}
            className="shrink-0 px-2 py-1 rounded text-xs bg-surface-700 hover:bg-surface-600 text-surface-300 transition-colors"
          >
            ↻
          </button>
        )}
      </div>

      {/* Mode selector */}
      <div className="flex flex-wrap gap-1 bg-surface-800 rounded-md p-1">
        {modes.map((m) => (
          <button
            key={m.value}
            onClick={() => setMode(m.value)}
            className={`py-1.5 px-3 text-xs rounded font-medium transition-colors whitespace-nowrap ${
              mode === m.value ? 'bg-surface-600 text-surface-100' : 'text-surface-400 hover:text-surface-200'
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>

      {/* Mode-specific options */}
      {mode === 'word_number' && (
        <div className="space-y-3">
          <div>
            <div className="flex justify-between mb-1">
              <label className="text-xs text-surface-400">Number digits</label>
              <span className="text-xs text-surface-300 font-mono">{digitCount}</span>
            </div>
            <input
              type="range" min={2} max={6} value={digitCount}
              onChange={(e) => setDigitCount(Number(e.target.value))}
              className="w-full accent-accent-500"
            />
          </div>
          <label className="flex items-center gap-2 px-3 py-2 rounded-md bg-surface-800 text-sm cursor-pointer hover:bg-surface-700 transition-colors">
            <input type="checkbox" checked={capitalize} onChange={(e) => setCapitalize(e.target.checked)} className="rounded accent-accent-500" />
            <span className="text-surface-300 text-xs">Capitalize first letter</span>
          </label>
          <div>
            <label className="text-xs text-surface-400 block mb-1">Separator</label>
            <div className="flex gap-1">
              {['', '-', '_', '.'].map((s) => (
                <button
                  key={s}
                  onClick={() => setSeparator(s)}
                  className={`px-3 py-1.5 rounded text-xs font-mono transition-colors ${
                    separator === s ? 'bg-accent-600 text-white' : 'bg-surface-800 text-surface-400 hover:bg-surface-700'
                  }`}
                >
                  {s === '' ? 'none' : s}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {mode === 'random' && (
        <div>
          <div className="flex justify-between mb-1">
            <label className="text-xs text-surface-400">Length</label>
            <span className="text-xs text-surface-300 font-mono">{charLength}</span>
          </div>
          <input
            type="range" min={8} max={20} value={charLength}
            onChange={(e) => setCharLength(Number(e.target.value))}
            className="w-full accent-accent-500"
          />
        </div>
      )}

      {mode === 'catchall' && (
        <div>
          <label className="text-xs text-surface-400 block mb-1">Catch-all domain</label>
          <input
            type="text"
            value={catchAllDomain}
            onChange={(e) => {
              setCatchAllDomain(e.target.value);
              localStorage.setItem('neopass-catchall-domain', e.target.value);
            }}
            placeholder="mydomain.com"
            className="w-full px-3 py-2 rounded-md bg-surface-800 border border-surface-700 text-surface-100 text-sm placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-accent-500"
          />
          {!catchAllDomain.trim() && (
            <p className="text-xs text-surface-500 mt-1">Enter a domain with catch-all email enabled</p>
          )}
        </div>
      )}

      {mode === 'service' && (
        <div className="space-y-3">
          <div className="flex gap-1 bg-surface-800 rounded-md p-1">
            <button
              onClick={() => setAliasService('simplelogin')}
              className={`flex-1 py-1.5 text-xs rounded font-medium transition-colors ${
                aliasService === 'simplelogin' ? 'bg-surface-600 text-surface-100' : 'text-surface-400 hover:text-surface-200'
              }`}
            >
              SimpleLogin
            </button>
            <button
              onClick={() => setAliasService('addyio')}
              className={`flex-1 py-1.5 text-xs rounded font-medium transition-colors ${
                aliasService === 'addyio' ? 'bg-surface-600 text-surface-100' : 'text-surface-400 hover:text-surface-200'
              }`}
            >
              Addy.io
            </button>
          </div>
          <button
            onClick={generateFromService}
            disabled={serviceLoading}
            className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
          >
            {serviceLoading ? 'Generating…' : 'Generate Alias'}
          </button>
          {serviceError && <p className="text-xs text-red-400">{serviceError}</p>}
        </div>
      )}

      {/* Use button */}
      {onUse && generated && !generated.startsWith('(') && (
        <button
          onClick={() => onUse(generated)}
          className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors"
        >
          Use this username
        </button>
      )}
    </div>
  );
}
