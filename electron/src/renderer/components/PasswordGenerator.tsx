import React, { useState, useCallback } from 'react';

interface PasswordGeneratorProps {
  onUse?: (password: string) => void;
}

function generatePassword(
  length: number,
  uppercase: boolean,
  lowercase: boolean,
  digits: boolean,
  symbols: boolean,
): string {
  let chars = '';
  if (uppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (digits) chars += '0123456789';
  if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (chars.length === 0) chars = 'abcdefghijklmnopqrstuvwxyz';

  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, (v) => chars[v % chars.length]).join('');
}

function generatePassphrase(wordCount: number, separator: string, capitalize: boolean): string {
  const words = [
    'correct', 'horse', 'battery', 'staple', 'quantum', 'cipher', 'shield', 'vault',
    'anchor', 'bridge', 'castle', 'dragon', 'falcon', 'garden', 'harbor', 'island',
    'jungle', 'knight', 'lantern', 'meadow', 'nebula', 'oracle', 'palace', 'quartz',
    'river', 'summit', 'temple', 'umbra', 'vertex', 'willow', 'zenith', 'aurora',
    'beacon', 'comet', 'delta', 'ember', 'frost', 'glacier', 'Haven', 'ivory',
    'jade', 'karma', 'lotus', 'maple', 'nexus', 'opal', 'prism', 'raven',
    'solar', 'tidal', 'ultra', 'vivid', 'warden', 'xenon', 'yield', 'zephyr',
    'amber', 'blaze', 'coral', 'drift', 'epoch', 'flare', 'grain', 'haze',
  ];
  const array = new Uint32Array(wordCount);
  crypto.getRandomValues(array);
  return Array.from(array, (v) => {
    const word = words[v % words.length];
    return capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word;
  }).join(separator);
}

function getStrengthInfo(pw: string): { label: string; color: string; percent: number } {
  if (pw.length === 0) return { label: '', color: 'bg-surface-700', percent: 0 };
  const hasUpper = /[A-Z]/.test(pw);
  const hasLower = /[a-z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSymbol = /[^A-Za-z0-9]/.test(pw);
  const varieties = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
  const entropy = pw.length * varieties;
  if (entropy >= 80) return { label: 'Very Strong', color: 'bg-green-400', percent: 100 };
  if (entropy >= 60) return { label: 'Strong', color: 'bg-green-500', percent: 80 };
  if (entropy >= 40) return { label: 'Good', color: 'bg-yellow-500', percent: 60 };
  if (entropy >= 20) return { label: 'Fair', color: 'bg-orange-500', percent: 40 };
  return { label: 'Weak', color: 'bg-red-500', percent: 20 };
}

export function PasswordGenerator({ onUse }: PasswordGeneratorProps) {
  const [mode, setMode] = useState<'password' | 'passphrase'>('password');
  const [length, setLength] = useState(20);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [wordCount, setWordCount] = useState(5);
  const [separator, setSeparator] = useState('-');
  const [capitalize, setCapitalize] = useState(true);
  const [generated, setGenerated] = useState('');
  const [copied, setCopied] = useState(false);

  const generate = useCallback(() => {
    const pw =
      mode === 'password'
        ? generatePassword(length, uppercase, lowercase, digits, symbols)
        : generatePassphrase(wordCount, separator, capitalize);
    setGenerated(pw);
    setCopied(false);
  }, [mode, length, uppercase, lowercase, digits, symbols, wordCount, separator, capitalize]);

  React.useEffect(() => {
    generate();
  }, [generate]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(generated);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const strength = getStrengthInfo(generated);

  return (
    <div className="space-y-4">
      {/* Generated password display */}
      <div className="bg-surface-800 rounded-md p-3 flex items-center gap-2">
        <code className="flex-1 text-sm text-surface-100 font-mono break-all select-all">
          {generated}
        </code>
        <button
          onClick={handleCopy}
          className="shrink-0 px-2 py-1 rounded text-xs bg-surface-700 hover:bg-surface-600 text-surface-300 transition-colors"
        >
          {copied ? '✓' : 'Copy'}
        </button>
        <button
          onClick={generate}
          className="shrink-0 px-2 py-1 rounded text-xs bg-surface-700 hover:bg-surface-600 text-surface-300 transition-colors"
        >
          ↻
        </button>
      </div>

      {/* Strength bar */}
      <div className="flex items-center gap-2">
        <div className="flex-1 h-1.5 bg-surface-700 rounded-full overflow-hidden">
          <div
            className={`h-full ${strength.color} rounded-full transition-all`}
            style={{ width: `${strength.percent}%` }}
          />
        </div>
        <span className="text-xs text-surface-400 w-20 text-right">{strength.label}</span>
      </div>

      {/* Mode toggle */}
      <div className="flex gap-1 bg-surface-800 rounded-md p-1">
        <button
          onClick={() => setMode('password')}
          className={`flex-1 py-1.5 text-xs rounded font-medium transition-colors ${
            mode === 'password' ? 'bg-surface-600 text-surface-100' : 'text-surface-400 hover:text-surface-200'
          }`}
        >
          Password
        </button>
        <button
          onClick={() => setMode('passphrase')}
          className={`flex-1 py-1.5 text-xs rounded font-medium transition-colors ${
            mode === 'passphrase' ? 'bg-surface-600 text-surface-100' : 'text-surface-400 hover:text-surface-200'
          }`}
        >
          Passphrase
        </button>
      </div>

      {mode === 'password' ? (
        <div className="space-y-3">
          {/* Length slider */}
          <div>
            <div className="flex justify-between mb-1">
              <label className="text-xs text-surface-400">Length</label>
              <span className="text-xs text-surface-300 font-mono">{length}</span>
            </div>
            <input
              type="range"
              min={8}
              max={128}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="w-full accent-accent-500"
            />
          </div>

          {/* Character toggles */}
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: 'A-Z', checked: uppercase, set: setUppercase },
              { label: 'a-z', checked: lowercase, set: setLowercase },
              { label: '0-9', checked: digits, set: setDigits },
              { label: '!@#$', checked: symbols, set: setSymbols },
            ].map((opt) => (
              <label
                key={opt.label}
                className="flex items-center gap-2 px-3 py-2 rounded-md bg-surface-800 text-sm cursor-pointer hover:bg-surface-700 transition-colors"
              >
                <input
                  type="checkbox"
                  checked={opt.checked}
                  onChange={(e) => opt.set(e.target.checked)}
                  className="rounded accent-accent-500"
                />
                <span className="text-surface-300 font-mono text-xs">{opt.label}</span>
              </label>
            ))}
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {/* Word count */}
          <div>
            <div className="flex justify-between mb-1">
              <label className="text-xs text-surface-400">Words</label>
              <span className="text-xs text-surface-300 font-mono">{wordCount}</span>
            </div>
            <input
              type="range"
              min={3}
              max={10}
              value={wordCount}
              onChange={(e) => setWordCount(Number(e.target.value))}
              className="w-full accent-accent-500"
            />
          </div>

          {/* Separator */}
          <div>
            <label className="text-xs text-surface-400 block mb-1">Separator</label>
            <div className="flex gap-1">
              {['-', '.', '_', ' '].map((s) => (
                <button
                  key={s}
                  onClick={() => setSeparator(s)}
                  className={`px-3 py-1.5 rounded text-xs font-mono transition-colors ${
                    separator === s
                      ? 'bg-accent-600 text-white'
                      : 'bg-surface-800 text-surface-400 hover:bg-surface-700'
                  }`}
                >
                  {s === ' ' ? '⎵' : s}
                </button>
              ))}
            </div>
          </div>

          {/* Capitalize toggle */}
          <label className="flex items-center gap-2 px-3 py-2 rounded-md bg-surface-800 text-sm cursor-pointer hover:bg-surface-700 transition-colors">
            <input
              type="checkbox"
              checked={capitalize}
              onChange={(e) => setCapitalize(e.target.checked)}
              className="rounded accent-accent-500"
            />
            <span className="text-surface-300 text-xs">Capitalize words</span>
          </label>
        </div>
      )}

      {/* Use button */}
      {onUse && (
        <button
          onClick={() => onUse(generated)}
          className="w-full py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors"
        >
          Use this password
        </button>
      )}
    </div>
  );
}
