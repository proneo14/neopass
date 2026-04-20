/**
 * Unified browser API wrapper for Chrome/Edge (MV3) and Firefox (MV2).
 * Uses webextension-polyfill for cross-browser compatibility.
 */
import browser from 'webextension-polyfill';

export const browserAPI = {
  runtime: {
    sendMessage: (message: unknown) => browser.runtime.sendMessage(message),

    onMessage: browser.runtime.onMessage,

    connectNative: (application: string) =>
      browser.runtime.connectNative(application),

    getURL: (path: string) => browser.runtime.getURL(path),

    sendNativeMessage: (application: string, message: object) =>
      browser.runtime.sendNativeMessage(application, message),
  },

  storage: {
    get: (keys: string | string[]) => browser.storage.local.get(keys),
    set: (items: Record<string, unknown>) => browser.storage.local.set(items),
    remove: (keys: string | string[]) => browser.storage.local.remove(keys),
  },

  tabs: {
    query: (queryInfo: browser.Tabs.QueryQueryInfoType) =>
      browser.tabs.query(queryInfo),

    sendMessage: (tabId: number, message: unknown) =>
      browser.tabs.sendMessage(tabId, message),

    get onActivated() { return browser.tabs.onActivated; },
    get onUpdated() { return browser.tabs.onUpdated; },
  },

  scripting: {
    executeScript: (tabId: number, files: string[]) => {
      // MV3 only — chrome.scripting API
      const chromeGlobal = globalThis as any;
      if (chromeGlobal.chrome?.scripting?.executeScript) {
        return chromeGlobal.chrome.scripting.executeScript({
          target: { tabId },
          files,
        });
      }
      // Firefox MV2 fallback
      return browser.tabs.executeScript(tabId, { file: files[0] });
    },
  },

  action: {
    setBadgeText: (details: { text: string; tabId?: number }) => {
      // MV3 uses action, MV2 uses browserAction — polyfill handles this
      if (browser.action) {
        return browser.action.setBadgeText(details);
      }
      return (browser as any).browserAction.setBadgeText(details);
    },

    setBadgeBackgroundColor: (details: { color: string; tabId?: number }) => {
      if (browser.action) {
        return browser.action.setBadgeBackgroundColor(details);
      }
      return (browser as any).browserAction.setBadgeBackgroundColor(details);
    },
  },
};

/**
 * Extract the domain from a URL string.
 */
export function extractDomain(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return null;
  }
}
