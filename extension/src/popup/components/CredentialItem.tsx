import React from 'react';
import type { Credential } from '../../lib/messages';

interface CredentialItemProps {
  credential: Credential;
  showDomain?: boolean;
  onSelect: (cred: Credential) => void;
  onFill: (cred: Credential) => void;
  fillButtonClass?: string;
}

export function CredentialItem({ credential: cred, showDomain, onSelect, onFill, fillButtonClass = 'bg-accent-500 hover:bg-accent-600' }: CredentialItemProps) {
  return (
    <div
      onClick={() => onSelect(cred)}
      className="flex items-center justify-between px-4 py-2.5 hover:bg-surface-900 transition-colors cursor-pointer group"
    >
      <div className="flex-1 min-w-0 mr-3">
        <p className="text-sm font-medium text-surface-100 truncate flex items-center gap-1">
          {cred.is_favorite && (
            <svg className="w-3 h-3 text-amber-400 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.286 3.957a1 1 0 00.95.69h4.162c.969 0 1.371 1.24.588 1.81l-3.37 2.448a1 1 0 00-.364 1.118l1.287 3.957c.3.921-.755 1.688-1.54 1.118l-3.37-2.448a1 1 0 00-1.176 0l-3.37 2.448c-.784.57-1.838-.197-1.539-1.118l1.287-3.957a1 1 0 00-.364-1.118L2.065 9.384c-.783-.57-.38-1.81.588-1.81h4.162a1 1 0 00.95-.69l1.284-3.957z" />
            </svg>
          )}
          {!!cred.reprompt && <span className="text-[10px] text-surface-500" title="Re-prompt required">🔒</span>}
          {cred.name || cred.domain}
        </p>
        <p className="text-xs text-surface-400 truncate">
          {cred.username}{showDomain && cred.domain ? ` · ${cred.domain}` : ''}
        </p>
      </div>
      <button
        onClick={(e) => { e.stopPropagation(); onFill(cred); }}
        className={`px-3 py-1 text-xs ${fillButtonClass} text-white rounded transition-colors opacity-0 group-hover:opacity-100`}
      >
        Fill
      </button>
    </div>
  );
}
