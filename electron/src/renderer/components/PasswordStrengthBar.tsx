import React from 'react';
import { scorePassword, type PasswordStrength } from '../utils/passwordHealth';

export function PasswordStrengthBar({ password }: { password: string }) {
  if (!password) return null;

  const strength: PasswordStrength = scorePassword(password);
  const segments = 5;

  return (
    <div className="space-y-1">
      <div className="flex gap-1">
        {Array.from({ length: segments }).map((_, i) => (
          <div
            key={i}
            className={`h-1.5 flex-1 rounded-full transition-colors ${
              i <= strength.score ? strength.bgColor : 'bg-surface-700'
            }`}
          />
        ))}
      </div>
      <p className={`text-xs ${strength.color}`}>{strength.label}</p>
    </div>
  );
}
