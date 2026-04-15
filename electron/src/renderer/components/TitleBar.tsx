import React from 'react';

export function TitleBar({ title }: { title?: string }) {
  return (
    <div
      className="fixed top-0 left-0 right-0 h-9 flex items-center px-4 z-50 select-none"
      style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}
    >
      {title && (
        <span className="text-xs text-surface-500 font-medium tracking-wide">{title}</span>
      )}
    </div>
  );
}
