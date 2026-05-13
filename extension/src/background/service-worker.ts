import type { Runtime } from 'webextension-polyfill';
import jsQR from 'jsqr';
import { browserAPI, extractDomain } from '../lib/browser-api';
import type {
  ExtensionMessage,
  NativeHostResponse,
  Credential,
} from '../lib/messages';

const NATIVE_HOST_ID = 'com.quantum.passwordmanager';

/** Timeout for native host connections (5 seconds). */
const NATIVE_HOST_TIMEOUT_MS = 5000;

/** Storage key for the offline credential queue. */
const CREDENTIAL_QUEUE_KEY = 'neopass_credential_queue';

/** Storage key for pending save prompts (survives service worker restarts). */
const PENDING_PROMPTS_KEY = 'neopass_pending_save_prompts';

/** Alarm name for periodic credential queue flush. */
const QUEUE_FLUSH_ALARM = 'neopass_flush_queue';

/** Pending save prompts stored in-memory for fast access, synced to storage. */
let pendingSavePrompts = new Map<
  number,
  { domain: string; username: string; password: string }
>();

/** Load pending prompts from storage on startup. */
async function loadPendingPrompts() {
  const data = await browserAPI.storage.get(PENDING_PROMPTS_KEY);
  const stored = (data as Record<string, Record<string, { domain: string; username: string; password: string }>>)[PENDING_PROMPTS_KEY];
  if (stored && typeof stored === 'object') {
    pendingSavePrompts = new Map(
      Object.entries(stored).map(([k, v]) => [Number(k), v])
    );
  }
}

/** Persist pending prompts to storage. */
async function savePendingPrompts() {
  const obj: Record<string, { domain: string; username: string; password: string }> = {};
  for (const [k, v] of pendingSavePrompts) {
    obj[String(k)] = v;
  }
  await browserAPI.storage.set({ [PENDING_PROMPTS_KEY]: obj });
}

// Load prompts on startup
loadPendingPrompts();

/* ------------------------------------------------------------------ */
/*  Offline Credential Queue                                           */
/* ------------------------------------------------------------------ */

interface QueuedCredential {
  domain: string;
  username: string;
  password: string;
  timestamp: number;
}

/** Add a credential to the offline queue in extension local storage. */
async function enqueueCredential(cred: Omit<QueuedCredential, 'timestamp'>) {
  const data = await browserAPI.storage.get(CREDENTIAL_QUEUE_KEY);
  const queue: QueuedCredential[] = (data as Record<string, QueuedCredential[]>)[CREDENTIAL_QUEUE_KEY] ?? [];

  // Prevent duplicates in the queue itself
  const isDuplicate = queue.some(
    (q) => q.domain === cred.domain && q.username === cred.username
  );
  if (isDuplicate) return;

  queue.push({ ...cred, timestamp: Date.now() });
  await browserAPI.storage.set({ [CREDENTIAL_QUEUE_KEY]: queue });
  console.debug('[NeoPass] Credential queued for later sync:', cred.domain, cred.username);
}

/** Try to flush the queued credentials to the native host. */
async function flushCredentialQueue() {
  const data = await browserAPI.storage.get(CREDENTIAL_QUEUE_KEY);
  const queue: QueuedCredential[] = (data as Record<string, QueuedCredential[]>)[CREDENTIAL_QUEUE_KEY] ?? [];
  if (queue.length === 0) return;

  // Check if the app is available and unlocked
  const statusResponse = await sendNativeMessage({ action: 'getStatus' });
  if (statusResponse.error || statusResponse.locked) return;

  const remaining: QueuedCredential[] = [];

  for (const cred of queue) {
    // Check for existing duplicates before saving
    const existing = await getCredentialsForDomain(cred.domain);
    const isDuplicate = existing.some(
      (c) => c.username === cred.username && c.domain === cred.domain
    );
    if (isDuplicate) {
      console.debug('[NeoPass] Skipping queued duplicate:', cred.domain, cred.username);
      continue;
    }

    const response = await sendNativeMessage({
      action: 'saveCredential',
      domain: cred.domain,
      username: cred.username,
      encryptedPassword: cred.password,
    });

    if (response.error) {
      // Keep in queue for retry if save failed
      remaining.push(cred);
    } else {
      console.debug('[NeoPass] Queued credential saved:', cred.domain, cred.username);
    }
  }

  await browserAPI.storage.set({ [CREDENTIAL_QUEUE_KEY]: remaining });
}

// Use alarms API for periodic flush — survives MV3 service worker termination
browserAPI.alarms.create(QUEUE_FLUSH_ALARM, { periodInMinutes: 1 });
browserAPI.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === QUEUE_FLUSH_ALARM) {
    flushCredentialQueue();
  }
});

// Also flush on service worker startup
flushCredentialQueue();

/**
 * Validate that a native host response has the expected shape.
 */
function validateNativeResponse(response: unknown): NativeHostResponse {
  if (response === null || response === undefined) {
    return { error: 'No response from native host' };
  }
  if (typeof response !== 'object') {
    return { error: 'Invalid response format' };
  }
  return response as NativeHostResponse;
}

/**
 * Send a message to the native host and wait for a response.
 * Uses one-shot sendNativeMessage with a timeout to avoid hanging.
 */
function sendNativeMessage(
  message: Record<string, unknown>
): Promise<NativeHostResponse> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ error: 'Native host connection timed out' });
    }, NATIVE_HOST_TIMEOUT_MS);

    try {
      browserAPI.runtime.sendNativeMessage(
        NATIVE_HOST_ID,
        message
      ).then((response: unknown) => {
        clearTimeout(timer);
        resolve(validateNativeResponse(response));
      }).catch(() => {
        clearTimeout(timer);
        resolve({ error: 'Desktop app not running' });
      });
    } catch {
      clearTimeout(timer);
      resolve({ error: 'Desktop app not running' });
    }
  });
}

/**
 * Get credentials for a domain from the native host.
 * Validates response shape before returning.
 */
async function getCredentialsForDomain(
  domain: string
): Promise<Credential[]> {
  if (!domain || typeof domain !== 'string') return [];
  try {
    const response = await sendNativeMessage({
      action: 'getCredentials',
      domain,
    });
    if (!Array.isArray(response.credentials)) return [];
    // Validate each credential has required fields
    const creds = response.credentials.filter(
      (c: unknown): c is Credential =>
        typeof c === 'object' && c !== null &&
        typeof (c as Credential).username === 'string' &&
        typeof (c as Credential).password === 'string'
    );
    // Update the known-credentials cache with successful results
    if (creds.length > 0) {
      updateKnownCredentials(domain, creds);
    }
    return creds;
  } catch {
    return [];
  }
}

/* ------------------------------------------------------------------ */
/*  Known-Credentials Cache (for offline duplicate detection)          */
/*  Stores domain+username pairs — no passwords.                       */
/* ------------------------------------------------------------------ */

const KNOWN_CREDS_KEY = 'neopass_known_credentials';

interface KnownCredEntry {
  domain: string;
  username: string;
}

/** Update the cache with credentials we just fetched from the app. */
async function updateKnownCredentials(domain: string, creds: Credential[]) {
  const data = await browserAPI.storage.get(KNOWN_CREDS_KEY);
  const known: KnownCredEntry[] = (data as Record<string, KnownCredEntry[]>)[KNOWN_CREDS_KEY] ?? [];

  // Remove stale entries for this domain, then add current ones
  const filtered = known.filter((k) => k.domain !== domain);
  for (const c of creds) {
    filtered.push({ domain: c.domain || domain, username: c.username });
  }
  await browserAPI.storage.set({ [KNOWN_CREDS_KEY]: filtered });
  console.debug('[NeoPass] Known credentials cache updated for', domain, '— total entries:', filtered.length);
}

/** Add a single entry to the cache (after a successful save). */
async function addKnownCredential(domain: string, username: string) {
  const data = await browserAPI.storage.get(KNOWN_CREDS_KEY);
  const known: KnownCredEntry[] = (data as Record<string, KnownCredEntry[]>)[KNOWN_CREDS_KEY] ?? [];
  if (!known.some((k) => k.domain === domain && k.username === username)) {
    known.push({ domain, username });
    await browserAPI.storage.set({ [KNOWN_CREDS_KEY]: known });
    console.debug('[NeoPass] Added to known credentials cache:', domain, username);
  }
}

/** Check cache (and offline queue) for a known credential. */
async function isKnownCredential(domain: string, username: string): Promise<boolean> {
  // Check the known-credentials cache
  const data = await browserAPI.storage.get([KNOWN_CREDS_KEY, CREDENTIAL_QUEUE_KEY]);
  const record = data as Record<string, unknown>;
  const known: KnownCredEntry[] = (record[KNOWN_CREDS_KEY] as KnownCredEntry[]) ?? [];
  const cached = known.some((k) => k.domain === domain && k.username === username);
  if (cached) {
    console.debug('[NeoPass] Duplicate found in known-credentials cache:', domain, username);
    return true;
  }

  // Also check the offline queue (credentials waiting to be saved)
  const queue: QueuedCredential[] = (record[CREDENTIAL_QUEUE_KEY] as QueuedCredential[]) ?? [];
  const queued = queue.some((q) => q.domain === domain && q.username === username);
  if (queued) {
    console.debug('[NeoPass] Duplicate found in offline queue:', domain, username);
    return true;
  }

  console.debug('[NeoPass] Not in cache or queue:', domain, username);
  return false;
}

/**
 * Update badge with credential count for the given tab.
 */
async function updateBadgeForTab(tabId: number, url?: string) {
  if (!url) {
    await browserAPI.action.setBadgeText({ text: '', tabId });
    return;
  }

  const domain = extractDomain(url);
  if (!domain) {
    await browserAPI.action.setBadgeText({ text: '', tabId });
    return;
  }

  const credentials = await getCredentialsForDomain(domain);
  const count = credentials.length;

  await browserAPI.action.setBadgeText({
    text: count > 0 ? String(count) : '',
    tabId,
  });
  await browserAPI.action.setBadgeBackgroundColor({
    color: '#6366f1',
    tabId,
  });
}

/**
 * Broadcast vaultLocked to all tabs so content scripts clear their UI.
 */
async function broadcastVaultLocked() {
  const tabs = await browserAPI.tabs.query({});
  for (const tab of tabs) {
    if (tab.id !== undefined) {
      browserAPI.tabs.sendMessage(tab.id, { type: 'vaultLocked' }).catch(() => {});
    }
  }
}

/**
 * Handle messages from popup and content scripts.
 */
browserAPI.runtime.onMessage.addListener(
  (
    message: ExtensionMessage,
    sender: Runtime.MessageSender
  ): Promise<unknown> | undefined => {
    switch (message.type) {
      case 'requestCredentials':
        return getCredentialsForDomain(message.domain).then((credentials) => ({
          type: 'credentialsResponse' as const,
          credentials,
        }));

      case 'getStatus':
        return sendNativeMessage({ action: 'getStatus' }).then(async (response) => {
          if (response.error) {
            // App not running — clear panels on all tabs
            await broadcastVaultLocked();
            return { type: 'statusResponse', status: 'no-desktop-app' };
          }
          if (response.locked) {
            // Vault locked — clear panels on all tabs
            await broadcastVaultLocked();
          } else {
            // Flush queued credentials when app becomes available
            flushCredentialQueue();
          }
          return {
            type: 'statusResponse',
            status: response.locked ? 'locked' : 'unlocked',
            vaultCount: response.vaultCount,
            theme: response.theme || 'dark',
          };
        });

      case 'saveCredential':
        // Check for duplicate before saving, queue if app unavailable
        return (async () => {
          // Always check the local cache first (works offline)
          if (await isKnownCredential(message.domain, message.username)) {
            return { status: 'duplicate', error: 'Credential already exists for this user and domain' };
          }

          // Check if app is available
          const statusCheck = await sendNativeMessage({ action: 'getStatus' });
          if (statusCheck.error || statusCheck.locked) {
            // App not running or locked — queue for later
            await enqueueCredential({
              domain: message.domain,
              username: message.username,
              password: message.password,
            });
            return { status: 'queued', message: 'Credential saved offline, will sync when app is unlocked' };
          }

          // Live duplicate check against the vault
          const existing = await getCredentialsForDomain(message.domain);
          const isDuplicate = existing.some(
            (c) => c.username === message.username && c.domain === message.domain
          );
          if (isDuplicate) {
            return { status: 'duplicate', error: 'Credential already exists for this user and domain' };
          }

          const response = await sendNativeMessage({
            action: 'saveCredential',
            domain: message.domain,
            username: message.username,
            encryptedPassword: message.password,
          });

          // If save failed, queue it
          if (response.error) {
            await enqueueCredential({
              domain: message.domain,
              username: message.username,
              password: message.password,
            });
            return { status: 'queued', message: 'Save failed, credential queued for retry' };
          }

          // Update the local cache with the newly saved credential
          await addKnownCredential(message.domain, message.username);
          return { status: response.status ?? 'saved' };
        })();

      case 'lock':
        return sendNativeMessage({ action: 'lock' }).then(async () => {
          await broadcastVaultLocked();
          return { status: 'locked' };
        });

      case 'openApp':
        // Ask native host to focus/launch the desktop app
        return sendNativeMessage({ action: 'openApp' }).then(() => ({
          status: 'ok',
        }));

      case 'secureCopy':
        return sendNativeMessage({
          action: 'secureCopy',
          text: message.text,
        }).then((response) => ({
          status: response.status ?? 'error',
          error: response.error,
        }));

      case 'verifyMasterPassword':
        return sendNativeMessage({
          action: 'verifyPassword',
          email: message.email,
          password: message.password,
        }).then((response) => ({
          verified: response.verified ?? false,
          error: response.error,
        }));

      case 'fillCredential':
        // Return the async result so MV3 service worker stays alive.
        // Uses chrome.scripting.executeScript with execCommand('insertText')
        // which creates trusted InputEvents that frameworks (Google, React) accept.
        return (async () => {
          const tabs = await browserAPI.tabs.query({
            active: true,
            currentWindow: true,
          });
          const tabId = tabs[0]?.id;
          if (tabId === undefined) return { status: 'error' };

          // Wait for popup to close and page to regain focus
          await new Promise((r) => setTimeout(r, 350));

          const chromeGlobal = globalThis as unknown as { chrome?: { scripting?: { executeScript: (opts: unknown) => Promise<unknown> } } };

          if (chromeGlobal.chrome?.scripting?.executeScript) {
            try {
              await chromeGlobal.chrome.scripting.executeScript({
                target: { tabId },
                func: (username: string, password: string) => {
                  const HINTS = /user|email|login|username|account|identifier|handle|phone|signin/i;

                  function fillField(el: HTMLInputElement, value: string) {
                    el.focus();
                    // Select any existing text so insertText replaces it
                    el.select();

                    // execCommand('insertText') creates events with isTrusted:true
                    if (!document.execCommand('insertText', false, value)) {
                      // Fallback: native value setter + synthetic events
                      const setter = Object.getOwnPropertyDescriptor(
                        HTMLInputElement.prototype,
                        'value'
                      )?.set;
                      if (setter) setter.call(el, value);
                      else el.value = value;
                      el.dispatchEvent(
                        new InputEvent('input', {
                          bubbles: true,
                          inputType: 'insertText',
                          data: value,
                        })
                      );
                      el.dispatchEvent(new Event('change', { bubbles: true }));
                    }
                  }

                  // Find password field
                  const pwField = document.querySelector<HTMLInputElement>(
                    'input[type="password"]:not([aria-hidden="true"])'
                  );

                  // Find username field
                  let userField: HTMLInputElement | null = null;
                  const inputs = document.querySelectorAll<HTMLInputElement>(
                    'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
                  );
                  for (const input of inputs) {
                    if (input.type === 'hidden' || input.type === 'submit') continue;
                    const rect = input.getBoundingClientRect();
                    if (rect.width === 0 || rect.height === 0) continue;
                    const attrs = [
                      input.name,
                      input.id,
                      input.autocomplete,
                      input.placeholder,
                      input.getAttribute('aria-label') || '',
                    ].join(' ');
                    if (HINTS.test(attrs)) {
                      userField = input;
                      break;
                    }
                  }

                  if (userField) fillField(userField, username);
                  if (pwField) fillField(pwField, password);

                  // If neither found, fill first visible input
                  if (!userField && !pwField) {
                    for (const input of inputs) {
                      if (input.type === 'hidden' || input.type === 'submit') continue;
                      const rect = input.getBoundingClientRect();
                      if (rect.width > 0 && rect.height > 0) {
                        fillField(input, username || password);
                        break;
                      }
                    }
                  }
                },
                args: [message.username, message.password],
              });
              return { status: 'ok' };
            } catch {
              // scripting.executeScript failed — fall through to content script
            }
          }

          // Fallback: send message to content script
          try {
            await browserAPI.tabs.sendMessage(tabId, {
              type: 'autofill',
              username: message.username,
              password: message.password,
            });
          } catch {
            // Content script not available
          }
          return { status: 'ok' };
        })();

      case 'formDetected':
        if (sender.tab?.id) {
          updateBadgeForTab(sender.tab.id, sender.tab.url);

          // If there's a pending save prompt for this tab, show it now
          const pending = pendingSavePrompts.get(sender.tab.id);
          if (pending) {
            pendingSavePrompts.delete(sender.tab.id);
            savePendingPrompts();
            // Check cache first (works offline), then live check
            isKnownCredential(pending.domain, pending.username).then(async (cached) => {
              if (cached) return; // Already known — skip prompt
              const existing = await getCredentialsForDomain(pending.domain);
              const isDuplicate = existing.some(
                (c) => c.username === pending.username && c.domain === pending.domain
              );
              if (!isDuplicate && sender.tab?.id) {
                browserAPI.tabs.sendMessage(sender.tab.id, {
                  type: 'showSavePrompt',
                  domain: pending.domain,
                  username: pending.username,
                  password: pending.password,
                });
              }
            });
          }
        }
        return undefined;

      case 'savePrompt':
        // Content script captured credentials before navigation.
        // Check for duplicates before storing/showing the save prompt.
        if (sender.tab?.id) {
          const tabId = sender.tab.id;
          // Check cache first (works offline), then live check
          return isKnownCredential(message.domain, message.username).then(async (cached) => {
            if (cached) return undefined; // Already known — skip prompt
            const existing = await getCredentialsForDomain(message.domain);
            const isDuplicate = existing.some(
              (c) => c.username === message.username && c.domain === message.domain
            );
            if (isDuplicate) {
              // Credential already exists — don't prompt
              return undefined;
            }

            pendingSavePrompts.set(tabId, {
              domain: message.domain,
              username: message.username,
              password: message.password,
            });
            savePendingPrompts();
            // Also try to show immediately if the tab is still alive
            setTimeout(() => {
              const entry = pendingSavePrompts.get(tabId);
              if (entry) {
                pendingSavePrompts.delete(tabId);
                savePendingPrompts();
                browserAPI.tabs.sendMessage(tabId, {
                  type: 'showSavePrompt',
                  domain: entry.domain,
                  username: entry.username,
                  password: entry.password,
                }).catch(() => {
                  // Content script not ready yet — will be shown on formDetected
                  pendingSavePrompts.set(tabId, entry);
                  savePendingPrompts();
                });
              }
            }, 1500);
            return undefined;
          });
        }
        return undefined;

      case 'autofillComplete':
        return undefined;

      case 'passkeyCreate':
        return sendNativeMessage({
          action: 'passkeyCreate',
          rpId: message.rpId,
          rpName: message.rpName,
          userName: message.userName,
          displayName: message.displayName,
          algorithm: message.algorithm,
          challenge: message.challenge,
          origin: message.origin,
          userId: message.userId,
        }).then((response) => {
          // Notify user that a passkey was created
          if (!response.error && response.options) {
            // Show in-page toast notification via content script
            browserAPI.tabs.query({ active: true, currentWindow: true })
              .then((tabs) => {
                const tabId = tabs[0]?.id;
                if (tabId) {
                  browserAPI.tabs.sendMessage(tabId, {
                    type: 'showToast',
                    message: `Passkey for ${message.rpId} saved to NeoPass`,
                    icon: browserAPI.runtime.getURL('icons/icon-128.png'),
                  }).catch(() => {});
                }
              }).catch(() => {});
            // Also notify popup if it's open
            browserAPI.runtime.sendMessage({
              type: 'passkeyCreated',
              rpId: message.rpId,
            }).catch(() => {});
          }
          return {
            type: 'passkeyResponse',
            action: 'create',
            options: response.options,
            error: response.error,
          };
        });

      case 'passkeyGet':
        return sendNativeMessage({
          action: 'passkeyGet',
          rpId: message.rpId,
          allowCredentials: message.allowCredentials,
        }).then((response) => ({
          type: 'passkeyResponse',
          action: 'get',
          passkeys: response.passkeys,
          error: response.error,
        }));

      case 'passkeySign':
        return sendNativeMessage({
          action: 'passkeySign',
          credentialId: message.credentialId,
          rpId: message.rpId,
          origin: message.origin,
          challenge: message.challenge,
        }).then((response) => ({
          type: 'passkeyResponse',
          action: 'sign',
          assertion: response.assertion,
          error: response.error,
        }));

      case 'passkeyList':
        return sendNativeMessage({
          action: 'passkeyList',
          rpId: message.rpId,
        }).then((response) => ({
          type: 'passkeyResponse',
          action: 'list',
          passkeys: response.passkeys,
          error: response.error,
        }));

      case 'scanQR':
        // Capture the visible tab and scan for QR codes containing otpauth:// URIs
        return (async () => {
          try {
            // captureVisibleTab returns a data URL of the screenshot
            const dataUrl = await browserAPI.tabs.captureVisibleTab(
              undefined,
              { format: 'png' }
            );
            if (!dataUrl) return { error: 'Failed to capture tab' };

            // Decode the data URL into ImageData using OffscreenCanvas
            const response = await fetch(dataUrl);
            const blob = await response.blob();
            const bitmap = await createImageBitmap(blob);

            const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
            const ctx = canvas.getContext('2d');
            if (!ctx) return { error: 'Canvas not available' };

            ctx.drawImage(bitmap, 0, 0);
            const imageData = ctx.getImageData(0, 0, bitmap.width, bitmap.height);

            // Scan the full screenshot
            const result = jsQR(imageData.data, imageData.width, imageData.height);
            if (result?.data) {
              const otpauthMatch = result.data.match(/otpauth:\/\/totp\/[^\s"'<>]+/i);
              if (otpauthMatch) {
                try {
                  const url = new URL(otpauthMatch[0]);
                  const secret = url.searchParams.get('secret');
                  if (secret) {
                    return { secret, otpauthUri: otpauthMatch[0] };
                  }
                } catch { /* invalid URL */ }
              }
            }

            // If full screenshot didn't work, try scanning sub-regions
            // QR codes can be anywhere: center, left, right of the page
            const w = bitmap.width;
            const h = bitmap.height;
            const regions = [
              // Center region
              { x: Math.floor(w * 0.2), y: Math.floor(h * 0.1), w: Math.floor(w * 0.6), h: Math.floor(h * 0.6) },
              // Top-left quadrant
              { x: 0, y: 0, w: Math.floor(w / 2), h: Math.floor(h / 2) },
              // Top-center
              { x: Math.floor(w * 0.25), y: 0, w: Math.floor(w * 0.5), h: Math.floor(h * 0.5) },
              // Center of page
              { x: Math.floor(w * 0.25), y: Math.floor(h * 0.25), w: Math.floor(w * 0.5), h: Math.floor(h * 0.5) },
              // Left half
              { x: 0, y: 0, w: Math.floor(w * 0.6), h: h },
              // Right half
              { x: Math.floor(w * 0.4), y: 0, w: Math.floor(w * 0.6), h: h },
            ];
            for (const r of regions) {
              if (r.w < 50 || r.h < 50) continue;
              const regionData = ctx.getImageData(r.x, r.y, r.w, r.h);
              const regionResult = jsQR(regionData.data, regionData.width, regionData.height);
              if (regionResult?.data) {
                const match = regionResult.data.match(/otpauth:\/\/totp\/[^\s"'<>]+/i);
                if (match) {
                  try {
                    const url = new URL(match[0]);
                    const secret = url.searchParams.get('secret');
                    if (secret) {
                      return { secret, otpauthUri: match[0] };
                    }
                  } catch { /* invalid URL */ }
                }
              }
            }

            return { error: 'No QR code found' };
          } catch (err) {
            console.debug('[NeoPass] QR scan error:', err);
            return { error: 'QR scan failed' };
          }
        })();

      case 'saveTOTP':
        // Save a TOTP secret to an existing credential.
        // If credentialId is provided, update that entry directly.
        // Otherwise, find the first matching credential for the domain.
        return (async () => {
          const domain = message.domain;
          const secret = message.secret;
          if (!domain || !secret) {
            return { status: 'error', error: 'domain and secret are required' };
          }

          let targetId = message.credentialId;
          let targetCred: Credential | undefined;

          if (!targetId) {
            // Find matching credential
            const creds = await getCredentialsForDomain(domain);
            if (creds.length === 0) {
              return { status: 'error', error: 'No credentials found for this domain' };
            }
            targetCred = creds.find((c) => c.matched) ?? creds[0];
            targetId = targetCred.id;
          } else {
            const creds = await getCredentialsForDomain(domain);
            targetCred = creds.find((c) => c.id === targetId);
          }

          if (!targetId || !targetCred) {
            return { status: 'error', error: 'No matching credential found' };
          }

          // Update the credential with the TOTP secret
          const response = await sendNativeMessage({
            action: 'updateCredential',
            id: targetId,
            name: targetCred.name,
            username: targetCred.username,
            password: targetCred.password,
            uri: targetCred.uri,
            notes: targetCred.notes,
            totp: secret,
          });

          if (response.error) {
            return { status: 'error', error: response.error };
          }

          // Show toast on the active tab
          if (sender.tab?.id) {
            browserAPI.tabs.sendMessage(sender.tab.id, {
              type: 'showToast',
              title: 'TOTP Saved',
              message: `TOTP saved to "${targetCred.name}"`,
            }).catch(() => {});
          }

          return { status: 'saved' };
        })();

      default:
        return undefined;
    }
  }
);

// Update badge when active tab changes
browserAPI.tabs.onActivated.addListener(async (activeInfo) => {
  const tabs = await browserAPI.tabs.query({
    active: true,
    currentWindow: true,
  });
  if (tabs[0]?.url) {
    updateBadgeForTab(activeInfo.tabId, tabs[0].url);
  }
});

// Update badge when tab URL changes
browserAPI.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (changeInfo.url && tab.id !== undefined && tab.active) {
    updateBadgeForTab(tab.id, changeInfo.url);
  }
});
