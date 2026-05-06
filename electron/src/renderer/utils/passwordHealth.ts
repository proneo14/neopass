export interface PasswordHealthEntry {
  entryId: string;
  name: string;
  username: string;
  password: string;
  uri: string;
  updatedAt: string;
}

export interface PasswordStrength {
  score: number; // 0-4
  label: 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong';
  color: string; // tailwind text color class
  bgColor: string; // tailwind bg color class
}

export interface HealthReport {
  totalLogins: number;
  weakPasswords: PasswordHealthEntry[];
  reusedGroups: PasswordHealthEntry[][]; // groups of entries sharing the same password
  oldPasswords: PasswordHealthEntry[]; // not changed in > 90 days
  insecureURIs: PasswordHealthEntry[]; // http:// URIs
  breachedPasswords: PasswordHealthEntry[]; // populated after HIBP check
  missingTotp: PasswordHealthEntry[]; // login entries on 2FA-supporting sites without TOTP
  overallScore: number; // 0-100
}

const COMMON_PASSWORDS = new Set([
  'password', '123456', '12345678', '123456789', '1234567890',
  'qwerty', 'abc123', 'password1', 'iloveyou', 'admin',
  'letmein', 'welcome', 'monkey', 'dragon', 'master',
  'login', 'princess', 'football', 'shadow', 'sunshine',
  'trustno1', 'passw0rd', 'whatever', 'qwerty123', 'password123',
]);

export function scorePassword(password: string): PasswordStrength {
  if (!password) {
    return { score: 0, label: 'Very Weak', color: 'text-red-400', bgColor: 'bg-red-500' };
  }

  let score = 0;

  // Length scoring
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;

  // Character variety
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);
  const varietyCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  if (varietyCount >= 3) score++;
  if (varietyCount === 4) score++;

  // Penalties
  if (password.length < 8) score = Math.max(score - 2, 0);
  if (COMMON_PASSWORDS.has(password.toLowerCase())) score = 0;
  if (/^(.)\1+$/.test(password)) score = 0; // all same character
  if (/^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)+$/i.test(password)) {
    score = Math.max(score - 2, 0);
  }

  // Clamp to 0-4
  const clamped = Math.max(0, Math.min(4, score));

  const levels: PasswordStrength[] = [
    { score: 0, label: 'Very Weak', color: 'text-red-400', bgColor: 'bg-red-500' },
    { score: 1, label: 'Weak', color: 'text-orange-400', bgColor: 'bg-orange-500' },
    { score: 2, label: 'Fair', color: 'text-yellow-400', bgColor: 'bg-yellow-500' },
    { score: 3, label: 'Strong', color: 'text-green-400', bgColor: 'bg-green-500' },
    { score: 4, label: 'Very Strong', color: 'text-emerald-400', bgColor: 'bg-emerald-500' },
  ];

  return levels[clamped];
}

export function findReusedPasswords(entries: PasswordHealthEntry[]): PasswordHealthEntry[][] {
  const groups = new Map<string, PasswordHealthEntry[]>();
  for (const entry of entries) {
    if (!entry.password) continue;
    const existing = groups.get(entry.password);
    if (existing) {
      existing.push(entry);
    } else {
      groups.set(entry.password, [entry]);
    }
  }
  return Array.from(groups.values()).filter((g) => g.length > 1);
}

export function findWeakPasswords(entries: PasswordHealthEntry[]): PasswordHealthEntry[] {
  return entries.filter((e) => e.password && scorePassword(e.password).score <= 1);
}

export function findOldPasswords(entries: PasswordHealthEntry[], maxAgeDays = 90): PasswordHealthEntry[] {
  const cutoff = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
  return entries.filter((e) => {
    if (!e.password) return false;
    const updated = new Date(e.updatedAt).getTime();
    return updated < cutoff;
  });
}

export function findInsecureURIs(entries: PasswordHealthEntry[]): PasswordHealthEntry[] {
  return entries.filter((e) => {
    if (!e.uri) return false;
    try {
      const url = new URL(e.uri);
      return url.protocol === 'http:';
    } catch {
      return false;
    }
  });
}

// Popular sites that support 2FA/TOTP
const TOTP_SUPPORTED_DOMAINS = new Set([
  'google.com', 'github.com', 'gitlab.com', 'bitbucket.org',
  'amazon.com', 'aws.amazon.com', 'facebook.com', 'twitter.com', 'x.com',
  'microsoft.com', 'live.com', 'outlook.com', 'apple.com',
  'dropbox.com', 'slack.com', 'discord.com', 'reddit.com',
  'linkedin.com', 'instagram.com', 'twitch.tv', 'paypal.com',
  'stripe.com', 'digitalocean.com', 'cloudflare.com', 'heroku.com',
  'npmjs.com', 'pypi.org', 'docker.com', 'hub.docker.com',
  'coinbase.com', 'binance.com', 'kraken.com',
  'proton.me', 'protonmail.com', 'tutanota.com',
  'namecheap.com', 'godaddy.com', 'hover.com',
  'wordpress.com', 'tumblr.com', 'evernote.com',
]);

/**
 * Find login entries whose URI matches a known 2FA-supporting site
 * but do not have TOTP configured.
 * @param entries - password health entries (login type only)
 * @param entryIdsWithTotp - set of entry IDs that already have TOTP secrets
 */
export function findMissingTOTP(
  entries: PasswordHealthEntry[],
  entryIdsWithTotp: Set<string>,
): PasswordHealthEntry[] {
  return entries.filter((e) => {
    if (entryIdsWithTotp.has(e.entryId)) return false;
    if (!e.uri) return false;
    try {
      const hostname = new URL(e.uri).hostname.replace(/^www\./, '');
      // Check exact match or parent domain
      return TOTP_SUPPORTED_DOMAINS.has(hostname) ||
        Array.from(TOTP_SUPPORTED_DOMAINS).some((d) => hostname.endsWith('.' + d));
    } catch {
      return false;
    }
  });
}

export function calculateOverallScore(report: Omit<HealthReport, 'overallScore'>): number {
  if (report.totalLogins === 0) return 100;

  const total = report.totalLogins;
  const weakRatio = report.weakPasswords.length / total;
  const reusedCount = report.reusedGroups.reduce((sum, g) => sum + g.length, 0);
  const reusedRatio = reusedCount / total;
  const oldRatio = report.oldPasswords.length / total;
  const insecureRatio = report.insecureURIs.length / total;
  const breachedRatio = report.breachedPasswords.length / total;

  // Weighted penalties
  let score = 100;
  score -= weakRatio * 25;
  score -= reusedRatio * 25;
  score -= oldRatio * 15;
  score -= insecureRatio * 15;
  score -= breachedRatio * 20;

  return Math.max(0, Math.round(score));
}

export function analyzeVault(entries: PasswordHealthEntry[], entryIdsWithTotp: Set<string> = new Set()): Omit<HealthReport, 'breachedPasswords'> {
  const weakPasswords = findWeakPasswords(entries);
  const reusedGroups = findReusedPasswords(entries);
  const oldPasswords = findOldPasswords(entries);
  const insecureURIs = findInsecureURIs(entries);
  const missingTotp = findMissingTOTP(entries, entryIdsWithTotp);

  const partial = {
    totalLogins: entries.length,
    weakPasswords,
    reusedGroups,
    oldPasswords,
    insecureURIs,
    missingTotp,
  };

  return {
    ...partial,
    overallScore: calculateOverallScore({ ...partial, breachedPasswords: [] }),
  };
}
