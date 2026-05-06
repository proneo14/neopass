import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useVaultStore, type EntryHealthFlags } from '../store/vaultStore';
import { useAuthStore } from '../store/authStore';
import {
  analyzeVault,
  calculateOverallScore,
  scorePassword,
  type PasswordHealthEntry,
  type HealthReport as HealthReportType,
} from '../utils/passwordHealth';
import { checkBreaches, type BreachResult } from '../utils/hibp';

function ScoreRing({ score }: { score: number }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color =
    score >= 80
      ? 'text-emerald-400'
      : score >= 60
        ? 'text-yellow-400'
        : score >= 40
          ? 'text-orange-400'
          : 'text-red-400';
  return (
    <div className="relative w-36 h-36">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="currentColor" strokeWidth="8" className="text-surface-800" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className={`${color} transition-all duration-1000`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-bold ${color}`}>{score}</span>
        <span className="text-[10px] text-surface-500 uppercase tracking-wide">Score</span>
      </div>
    </div>
  );
}

function StatCard({
  icon,
  label,
  count,
  severity,
  onClick,
}: {
  icon: string;
  label: string;
  count: number;
  severity: 'critical' | 'warning' | 'info' | 'success';
  onClick?: () => void;
}) {
  const colors = {
    critical: 'border-red-500/30 bg-red-500/5',
    warning: 'border-orange-500/30 bg-orange-500/5',
    info: 'border-blue-500/30 bg-blue-500/5',
    success: 'border-emerald-500/30 bg-emerald-500/5',
  };
  const textColors = {
    critical: 'text-red-400',
    warning: 'text-orange-400',
    info: 'text-blue-400',
    success: 'text-emerald-400',
  };

  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${colors[severity]} hover:brightness-110 transition-all text-left w-full`}
    >
      <span className="text-2xl">{icon}</span>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-surface-500">{label}</p>
        <p className={`text-lg font-semibold ${count > 0 ? textColors[severity] : 'text-surface-300'}`}>{count}</p>
      </div>
    </button>
  );
}

function EntryRow({
  entry,
  badge,
  badgeColor,
  onClick,
}: {
  entry: PasswordHealthEntry;
  badge: string;
  badgeColor: string;
  onClick: () => void;
}) {
  return (
    <button onClick={onClick} className="flex items-center gap-3 w-full px-3 py-2 rounded-md hover:bg-surface-800/60 text-left transition-colors">
      <span className="text-lg w-8 text-center shrink-0">🔑</span>
      <div className="flex-1 min-w-0">
        <p className="text-sm text-surface-100 truncate">{entry.name || 'Untitled'}</p>
        {entry.username && <p className="text-xs text-surface-500 truncate">{entry.username}</p>}
      </div>
      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${badgeColor}`}>{badge}</span>
    </button>
  );
}

type SectionKey = 'breached' | 'weak' | 'reused' | 'old' | 'insecure' | 'missingTotp';

export function HealthReport() {
  const navigate = useNavigate();
  const { token, masterKeyHex } = useAuthStore();
  const entries = useVaultStore((s) => s.entries);
  const entryFields = useVaultStore((s) => s.entryFields);
  const healthFlags = useVaultStore((s) => s.healthFlags);
  const setHealthFlags = useVaultStore((s) => s.setHealthFlags);
  const mergeHealthFlags = useVaultStore((s) => s.mergeHealthFlags);

  const [report, setReport] = useState<HealthReportType | null>(null);
  const [expandedSection, setExpandedSection] = useState<SectionKey | null>(null);
  const [breachChecking, setBreachChecking] = useState(false);
  const [breachProgress, setBreachProgress] = useState({ checked: 0, total: 0 });
  const [breachError, setBreachError] = useState('');
  const [loadingVault, setLoadingVault] = useState(false);

  // Load vault entries if not already loaded (user navigated here before visiting Vault page)
  useEffect(() => {
    if (!token || !masterKeyHex) return;
    // If we already have decrypted fields, no need to load
    if (Object.keys(entryFields).length > 0) return;
    let cancelled = false;
    setLoadingVault(true);

    (async () => {
      try {
        const listResult = await window.api.vault.list(token) as Array<{ id: string; entry_type: string; encrypted_data: string; nonce: string; folder_id: string | null; version: number; is_favorite?: boolean; is_archived?: boolean; deleted_at?: string | null; created_at: string; updated_at: string }> | { error?: string };
        if (!Array.isArray(listResult) || cancelled) return;

        const loadedEntries: import('../types/vault').VaultEntry[] = [];
        const loadedFields: Record<string, Record<string, string>> = {};

        for (const summary of listResult) {
          if (cancelled) return;
          if (!summary.encrypted_data || !summary.nonce) continue;

          const decResult = await window.api.vault.decrypt(masterKeyHex, summary.encrypted_data, summary.nonce);
          if (decResult.error || !decResult.plaintext) continue;

          try {
            const parsed = JSON.parse(decResult.plaintext) as Record<string, unknown>;
            const fields: Record<string, string> = {};
            for (const [k, v] of Object.entries(parsed)) {
              if (k === 'passwordHistory') fields._passwordHistory = JSON.stringify(v);
              else if (k === 'uris') fields._uris = JSON.stringify(v);
              else if (k === 'reprompt') fields._reprompt = String(v === 1 || v === '1' ? '1' : '0');
              else fields[k] = String(v ?? '');
            }
            loadedEntries.push({
              id: summary.id,
              entry_type: summary.entry_type as import('../types/vault').VaultEntry['entry_type'],
              encrypted_data: summary.encrypted_data,
              nonce: summary.nonce,
              version: summary.version,
              folder_id: summary.folder_id ?? null,
              is_favorite: summary.is_favorite ?? false,
              is_archived: summary.is_archived ?? false,
              deleted_at: summary.deleted_at ?? null,
              created_at: summary.created_at,
              updated_at: summary.updated_at,
            });
            loadedFields[summary.id] = fields;
          } catch { /* skip */ }
        }

        if (!cancelled) {
          useVaultStore.getState().setEntries(loadedEntries);
          for (const [id, fields] of Object.entries(loadedFields)) {
            useVaultStore.getState().updateEntryFields(id, fields);
          }
        }
      } catch (err) {
        console.error('[health] Failed to load vault:', err);
      } finally {
        if (!cancelled) setLoadingVault(false);
      }
    })();

    return () => { cancelled = true; };
  }, [token, masterKeyHex]);

  // Build health entries from decrypted vault data
  const healthEntries = useMemo<PasswordHealthEntry[]>(() => {
    return entries
      .filter((e) => e.entry_type === 'login' && !e.deleted_at)
      .map((e) => {
        const f = entryFields[e.id];
        return {
          entryId: e.id,
          name: f?.name ?? '',
          username: f?.username ?? '',
          password: f?.password ?? '',
          uri: f?.uri ?? '',
          updatedAt: e.updated_at,
        };
      })
      .filter((e) => e.password); // only entries with passwords
  }, [entries, entryFields]);

  // Run local analysis when healthEntries change, incorporating persisted breach data
  useEffect(() => {
    if (healthEntries.length === 0) {
      setReport({
        totalLogins: 0,
        weakPasswords: [],
        reusedGroups: [],
        oldPasswords: [],
        insecureURIs: [],
        breachedPasswords: [],
        missingTotp: [],
        overallScore: 100,
      });
      return;
    }
    const partial = analyzeVault(healthEntries);

    // Restore breach results from persisted healthFlags in the store
    const breachedPasswords = healthEntries.filter((e) => healthFlags[e.entryId]?.breached);

    const fullReport: HealthReportType = {
      ...partial,
      breachedPasswords,
      overallScore: calculateOverallScore({
        ...partial,
        breachedPasswords,
      }),
    };
    setReport(fullReport);

    // Build health flags (preserve existing breach flags)
    const flags: Record<string, EntryHealthFlags> = {};
    for (const e of partial.weakPasswords) flags[e.entryId] = { ...flags[e.entryId], weak: true };
    for (const group of partial.reusedGroups) {
      for (const e of group) flags[e.entryId] = { ...flags[e.entryId], reused: true };
    }
    for (const e of partial.oldPasswords) flags[e.entryId] = { ...flags[e.entryId], old: true };
    for (const e of partial.insecureURIs) flags[e.entryId] = { ...flags[e.entryId], insecureUri: true };
    // Carry over breach flags from the store
    for (const [id, f] of Object.entries(healthFlags)) {
      if (f.breached) {
        flags[id] = { ...flags[id], breached: true, breachCount: f.breachCount };
      }
    }
    setHealthFlags(flags);
  }, [healthEntries]);

  const handleBreachCheck = useCallback(async () => {
    if (breachChecking || healthEntries.length === 0) return;
    setBreachChecking(true);
    setBreachError('');
    setBreachProgress({ checked: 0, total: healthEntries.length });

    try {
      const results = await checkBreaches(healthEntries, (checked, total) => {
        setBreachProgress({ checked, total });
      });

      // Merge breach flags into store — the analysis effect will pick them up
      const breachFlags: Record<string, { breached: boolean; breachCount: number }> = {};
      for (const r of results) {
        breachFlags[r.entryId] = { breached: true, breachCount: r.count };
      }
      mergeHealthFlags(breachFlags);

      // Also update the local report immediately so the user sees results
      const breachedEntries = results
        .map((r) => healthEntries.find((e) => e.entryId === r.entryId))
        .filter(Boolean) as PasswordHealthEntry[];

      setReport((prev) =>
        prev
          ? {
              ...prev,
              breachedPasswords: breachedEntries,
              overallScore: calculateOverallScore({ ...prev, breachedPasswords: breachedEntries }),
            }
          : prev,
      );
    } catch (err) {
      setBreachError('Failed to check breaches. Check your internet connection.');
    } finally {
      setBreachChecking(false);
    }
  }, [healthEntries, breachChecking, mergeHealthFlags]);

  const toggleSection = (key: SectionKey) => {
    setExpandedSection((prev) => (prev === key ? null : key));
  };

  if (loadingVault || !report) {
    return (
      <div className="flex items-center justify-center h-full text-surface-400">
        <span className="animate-pulse">{loadingVault ? 'Loading vault…' : 'Analyzing vault…'}</span>
      </div>
    );
  }

  const reusedCount = report.reusedGroups.reduce((sum, g) => sum + g.length, 0);

  return (
    <div className="max-w-3xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-xl font-semibold text-surface-100">Vault Health</h1>
          <p className="text-sm text-surface-500 mt-1">
            Security analysis of your {report.totalLogins} login{report.totalLogins !== 1 ? 's' : ''}
          </p>
        </div>
        <ScoreRing score={report.overallScore} />
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-3 mb-8">
        <StatCard
          icon="🔓"
          label="Exposed Passwords"
          count={report.breachedPasswords.length}
          severity={report.breachedPasswords.length > 0 ? 'critical' : 'success'}
          onClick={() => toggleSection('breached')}
        />
        <StatCard
          icon="⚠️"
          label="Weak Passwords"
          count={report.weakPasswords.length}
          severity={report.weakPasswords.length > 0 ? 'warning' : 'success'}
          onClick={() => toggleSection('weak')}
        />
        <StatCard
          icon="♻️"
          label="Reused Passwords"
          count={reusedCount}
          severity={reusedCount > 0 ? 'warning' : 'success'}
          onClick={() => toggleSection('reused')}
        />
        <StatCard
          icon="📅"
          label="Old Passwords (>90 days)"
          count={report.oldPasswords.length}
          severity={report.oldPasswords.length > 0 ? 'info' : 'success'}
          onClick={() => toggleSection('old')}
        />
        <StatCard
          icon="🔗"
          label="Insecure Sites (HTTP)"
          count={report.insecureURIs.length}
          severity={report.insecureURIs.length > 0 ? 'warning' : 'success'}
          onClick={() => toggleSection('insecure')}
        />
        <StatCard
          icon="🔐"
          label="Missing 2FA / TOTP"
          count={report.missingTotp.length}
          severity={report.missingTotp.length > 0 ? 'info' : 'success'}
          onClick={() => toggleSection('missingTotp')}
        />
      </div>

      {/* Breach Check Banner */}
      <div className="rounded-lg border border-surface-700 bg-surface-900/50 p-4 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-surface-200 font-medium">Data Breach Check</p>
            <p className="text-xs text-surface-500 mt-0.5">
              Uses k-anonymity — your passwords never leave this device
            </p>
          </div>
          <button
            onClick={handleBreachCheck}
            disabled={breachChecking || healthEntries.length === 0}
            className="px-4 py-2 rounded-md bg-accent-600 hover:bg-accent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {breachChecking ? 'Checking…' : report.breachedPasswords.length > 0 ? 'Re-check' : 'Check Now'}
          </button>
        </div>
        {breachChecking && (
          <div className="mt-3">
            <div className="flex justify-between text-xs text-surface-500 mb-1">
              <span>Checking passwords…</span>
              <span>
                {breachProgress.checked} / {breachProgress.total}
              </span>
            </div>
            <div className="w-full bg-surface-800 rounded-full h-1.5">
              <div
                className="bg-accent-500 h-1.5 rounded-full transition-all duration-300"
                style={{ width: `${(breachProgress.checked / Math.max(breachProgress.total, 1)) * 100}%` }}
              />
            </div>
          </div>
        )}
        {breachError && <p className="text-xs text-red-400 mt-2">{breachError}</p>}
      </div>

      {/* Expanded Section */}
      {expandedSection === 'breached' && report.breachedPasswords.length > 0 && (
        <Section title="Exposed Passwords" subtitle="These passwords appeared in known data breaches. Change them immediately.">
          {report.breachedPasswords.map((e) => (
            <EntryRow key={e.entryId} entry={e} badge="BREACHED" badgeColor="bg-red-500/20 text-red-400" onClick={() => navigate(`/vault/${e.entryId}`, { state: { edit: true } })} />
          ))}
        </Section>
      )}

      {expandedSection === 'weak' && report.weakPasswords.length > 0 && (
        <Section title="Weak Passwords" subtitle="These passwords are too short, simple, or commonly used.">
          {report.weakPasswords.map((e) => {
            const s = scorePassword(e.password);
            return (
              <EntryRow key={e.entryId} entry={e} badge={s.label} badgeColor={`bg-surface-800 ${s.color}`} onClick={() => navigate(`/vault/${e.entryId}`, { state: { edit: true } })} />
            );
          })}
        </Section>
      )}

      {expandedSection === 'reused' && report.reusedGroups.length > 0 && (
        <Section title="Reused Passwords" subtitle="These entries share the same password. Use a unique password for each account.">
          {report.reusedGroups.map((group, i) => (
            <div key={i} className="mb-4">
              <p className="text-xs text-surface-500 px-3 mb-1">Group {i + 1} — {group.length} entries</p>
              {group.map((e) => (
                <EntryRow key={e.entryId} entry={e} badge="REUSED" badgeColor="bg-orange-500/20 text-orange-400" onClick={() => navigate(`/vault/${e.entryId}`, { state: { edit: true } })} />
              ))}
            </div>
          ))}
        </Section>
      )}

      {expandedSection === 'old' && report.oldPasswords.length > 0 && (
        <Section title="Old Passwords" subtitle="These passwords haven't been changed in over 90 days.">
          {report.oldPasswords.map((e) => {
            const days = Math.floor((Date.now() - new Date(e.updatedAt).getTime()) / (24 * 60 * 60 * 1000));
            return (
              <EntryRow key={e.entryId} entry={e} badge={`${days}d`} badgeColor="bg-blue-500/20 text-blue-400" onClick={() => navigate(`/vault/${e.entryId}`, { state: { edit: true } })} />
            );
          })}
        </Section>
      )}

      {expandedSection === 'insecure' && report.insecureURIs.length > 0 && (
        <Section title="Insecure Sites" subtitle="These entries use HTTP instead of HTTPS. Your credentials may be transmitted in plain text.">
          {report.insecureURIs.map((e) => (
            <EntryRow key={e.entryId} entry={e} badge="HTTP" badgeColor="bg-orange-500/20 text-orange-400" onClick={() => navigate(`/vault/${e.entryId}`, { state: { edit: true } })} />
          ))}
        </Section>
      )}

      {expandedSection === 'missingTotp' && report.missingTotp.length > 0 && (
        <Section title="Missing TOTP" subtitle="These entries are on sites that support two-factor authentication but don't have TOTP configured.">
          {report.missingTotp.map((e) => (
            <EntryRow key={e.entryId} entry={e} badge="No 2FA" badgeColor="bg-blue-500/20 text-blue-400" onClick={() => navigate(`/vault/${e.entryId}`, { state: { edit: true } })} />
          ))}
        </Section>
      )}

      {expandedSection && (() => {
        const sectionData: Record<SectionKey, unknown[]> = {
          breached: report.breachedPasswords,
          weak: report.weakPasswords,
          reused: report.reusedGroups,
          old: report.oldPasswords,
          insecure: report.insecureURIs,
          missingTotp: report.missingTotp,
        };
        return sectionData[expandedSection].length === 0 ? (
          <div className="text-center py-8 text-surface-500 text-sm">
            <span className="text-3xl block mb-2">✅</span>
            No issues found in this category
          </div>
        ) : null;
      })()}
    </div>
  );
}

function Section({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-surface-700 bg-surface-900/50 p-4 mb-6">
      <h2 className="text-sm font-semibold text-surface-200 mb-0.5">{title}</h2>
      <p className="text-xs text-surface-500 mb-3">{subtitle}</p>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}
