import type { Runtime } from 'webextension-polyfill';
import { browserAPI, extractDomain } from '../lib/browser-api';
import type {
  ExtensionMessage,
  NativeHostResponse,
  Credential,
  SavePromptMessage,
} from '../lib/messages';

const NATIVE_HOST_ID = 'com.quantum.passwordmanager';

/** Timeout for native host connections (5 seconds). */
const NATIVE_HOST_TIMEOUT_MS = 5000;

/** Pending save prompts: domain → credential info.  Shown on next page load. */
const pendingSavePrompts = new Map<
  number,
  { domain: string; username: string; password: string }
>();

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
    return response.credentials.filter(
      (c: unknown): c is Credential =>
        typeof c === 'object' && c !== null &&
        typeof (c as Credential).username === 'string' &&
        typeof (c as Credential).password === 'string'
    );
  } catch {
    return [];
  }
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
        return sendNativeMessage({ action: 'getStatus' }).then((response) => {
          if (response.error) {
            return { type: 'statusResponse', status: 'no-desktop-app' };
          }
          return {
            type: 'statusResponse',
            status: response.locked ? 'locked' : 'unlocked',
            vaultCount: response.vaultCount,
          };
        });

      case 'saveCredential':
        return sendNativeMessage({
          action: 'saveCredential',
          domain: message.domain,
          username: message.username,
          encryptedPassword: message.password,
        }).then((response) => ({
          status: response.status ?? 'error',
          error: response.error,
        }));

      case 'lock':
        return sendNativeMessage({ action: 'lock' }).then(() => ({
          status: 'locked',
        }));

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
            browserAPI.tabs.sendMessage(sender.tab.id, {
              type: 'showSavePrompt',
              domain: pending.domain,
              username: pending.username,
              password: pending.password,
            });
          }
        }
        return undefined;

      case 'savePrompt':
        // Content script captured credentials before navigation.
        // Store them so we can show a save prompt on the next page.
        if (sender.tab?.id) {
          pendingSavePrompts.set(sender.tab.id, {
            domain: message.domain,
            username: message.username,
            password: message.password,
          });
          // Also try to show immediately if the tab is still alive
          setTimeout(() => {
            if (!sender.tab?.id) return;
            const entry = pendingSavePrompts.get(sender.tab.id);
            if (entry) {
              pendingSavePrompts.delete(sender.tab.id);
              browserAPI.tabs.sendMessage(sender.tab.id, {
                type: 'showSavePrompt',
                domain: entry.domain,
                username: entry.username,
                password: entry.password,
              }).catch(() => {
                // Content script not ready yet — will be shown on formDetected
                pendingSavePrompts.set(sender.tab!.id!, entry);
              });
            }
          }, 1500);
        }
        return undefined;

      case 'autofillComplete':
        return undefined;

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
