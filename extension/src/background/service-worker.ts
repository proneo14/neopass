import type { Runtime } from 'webextension-polyfill';
import { browserAPI, extractDomain } from '../lib/browser-api';
import type {
  ExtensionMessage,
  NativeHostResponse,
  Credential,
} from '../lib/messages';

const NATIVE_HOST_ID = 'com.quantum.passwordmanager';

/**
 * Send a message to the native host and wait for a response.
 * Uses one-shot sendNativeMessage to avoid response correlation issues.
 */
function sendNativeMessage(
  message: Record<string, unknown>
): Promise<NativeHostResponse> {
  return new Promise((resolve) => {
    try {
      browserAPI.runtime.sendNativeMessage(
        NATIVE_HOST_ID,
        message
      ).then((response: NativeHostResponse) => {
        resolve(response ?? { error: 'No response' });
      }).catch(() => {
        resolve({ error: 'Desktop app not running' });
      });
    } catch {
      resolve({ error: 'Desktop app not running' });
    }
  });
}

/**
 * Get credentials for a domain from the native host.
 */
async function getCredentialsForDomain(
  domain: string
): Promise<Credential[]> {
  try {
    const response = await sendNativeMessage({
      action: 'getCredentials',
      domain,
    });
    return response.credentials ?? [];
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

      case 'formDetected':
        if (sender.tab?.id) {
          updateBadgeForTab(sender.tab.id, sender.tab.url);
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
