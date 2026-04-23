import { browserAPI, extractDomain } from '../lib/browser-api';
import type { AutofillMessage, ShowSavePromptMessage, VaultLockedMessage, Credential } from '../lib/messages';
import {
  detectLoginForms,
  autofill,
  simulateInput,
  findVisibleLoginField,
  attachFieldListeners,
  attachGlobalFocusListener,
  showSidePanel,
  clearAllUI,
  watchFormSubmissions,
  handleShowSavePrompt,
  type FormInfo,
} from './autofill';

// ── Passkey bridge (runs FIRST at module load) ──────────────────
// The passkey-provider.js runs in the MAIN world (injected via manifest
// "world":"MAIN" at document_start). It cannot access extension APIs,
// so it posts messages to this ISOLATED-world script, which relays them
// to the service worker and returns the response.

const PASSKEY_REQ = 'lgipass-passkey-request';
const PASSKEY_RES = 'lgipass-passkey-response';

window.addEventListener('message', (event: MessageEvent) => {
  if (event.source !== window || event.data?.type !== PASSKEY_REQ) return;

  const { id, payload } = event.data;
  if (!id || !payload?.action) return;

  browserAPI.runtime.sendMessage({ type: payload.action, ...payload })
    .then((response: unknown) => {
      window.postMessage({ type: PASSKEY_RES, id, payload: response }, '*');
    })
    .catch(() => {
      window.postMessage({ type: PASSKEY_RES, id, payload: { error: 'bridge failed' } }, '*');
    });
});

// ── In-page toast notifications from service worker ─────────────
browserAPI.runtime.onMessage.addListener((msg: { type?: string; message?: string; icon?: string }) => {
  if (msg?.type !== 'showToast' || !msg.message) return;
  showInPageToast(msg.message, msg.icon);
});

function showInPageToast(message: string, iconUrl?: string) {
  const container = document.createElement('div');
  container.id = 'lgipass-toast';
  container.style.cssText = `
    position: fixed; top: 16px; right: 16px; z-index: 2147483647;
    display: flex; align-items: center; gap: 10px;
    background: #1e1b2e; border: 1px solid #6c5ce7;
    border-radius: 10px; padding: 12px 18px;
    box-shadow: 0 8px 32px rgba(108,92,231,0.25);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #e2e0f0; font-size: 13px;
    opacity: 0; transform: translateY(-12px) scale(0.96);
    transition: opacity 0.3s ease, transform 0.3s ease;
    pointer-events: auto; max-width: 380px;
  `;

  if (iconUrl) {
    const img = document.createElement('img');
    img.src = iconUrl;
    img.style.cssText = 'width: 28px; height: 28px; border-radius: 6px; flex-shrink: 0;';
    img.onerror = () => {
      // Fallback: inline shield SVG if extension icon can't load
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('viewBox', '0 0 24 24');
      svg.setAttribute('fill', 'none');
      svg.style.cssText = 'width: 28px; height: 28px; flex-shrink: 0;';
      svg.innerHTML = '<path d="M12 2L4 6v5c0 5.25 3.4 10.15 8 11.25C16.6 21.15 20 16.25 20 11V6l-8-4z" fill="#6c5ce7"/><path d="M10 14.5l-2.5-2.5 1.41-1.41L10 11.67l4.09-4.08L15.5 9 10 14.5z" fill="#fff"/>';
      img.replaceWith(svg);
    };
    container.appendChild(img);
  }

  const textWrap = document.createElement('div');
  textWrap.style.cssText = 'display: flex; flex-direction: column; gap: 1px;';

  const title = document.createElement('div');
  title.textContent = 'Passkey Saved';
  title.style.cssText = 'font-weight: 600; font-size: 13px; color: #a29bfe;';
  textWrap.appendChild(title);

  const body = document.createElement('div');
  body.textContent = message;
  body.style.cssText = 'font-size: 12px; color: #b8b5cc;';
  textWrap.appendChild(body);

  container.appendChild(textWrap);

  const close = document.createElement('button');
  close.textContent = '✕';
  close.style.cssText = `
    background: none; border: none; color: #6c6888; cursor: pointer;
    font-size: 14px; padding: 0 0 0 8px; flex-shrink: 0; line-height: 1;
  `;
  close.onclick = () => dismiss();
  container.appendChild(close);

  // Remove any existing toast
  document.getElementById('lgipass-toast')?.remove();
  document.body.appendChild(container);

  // Animate in
  requestAnimationFrame(() => {
    container.style.opacity = '1';
    container.style.transform = 'translateY(0) scale(1)';
  });

  function dismiss() {
    container.style.opacity = '0';
    container.style.transform = 'translateY(-12px) scale(0.96)';
    setTimeout(() => container.remove(), 300);
  }

  // Auto dismiss after 4 seconds
  setTimeout(dismiss, 4000);
}

// Fallback: inject passkey-provider.js for Firefox MV2 (no "world":"MAIN" support).
// Chrome uses manifest-based MAIN world injection; the dedup guard prevents double-run.
try {
  const isFirefox = (globalThis as Record<string, unknown>).browser !== undefined;
  if (isFirefox) {
    const s = document.createElement('script');
    s.src = browserAPI.runtime.getURL('passkey-provider.js');
    s.onload = () => s.remove();
    (document.head || document.documentElement).appendChild(s);
  }
} catch {
  // Not critical — Chrome uses manifest injection
}

// ── Autofill ────────────────────────────────────────────────────

/**
 * Content script — detects login forms on the page, shows autofill
 * overlays, handles credential filling, and prompts to save new logins.
 */

let currentForms: FormInfo[] = [];
let currentCredentials: Credential[] = [];

/**
 * Fetch credentials for the current domain from the background script.
 */
async function fetchCredentials(domain: string): Promise<Credential[]> {
  try {
    const response = await browserAPI.runtime.sendMessage({
      type: 'requestCredentials' as const,
      domain,
    });
    return (response as { credentials?: Credential[] })?.credentials ?? [];
  } catch {
    return [];
  }
}

/**
 * Run form detection, fetch credentials, and wire everything up.
 */
async function scanAndAttach() {
  const forms = detectLoginForms();
  console.debug('[QPM] scanAndAttach: detected', forms.length, 'forms');
  if (forms.length === 0) return;

  // Merge with existing forms (avoid duplicates)
  for (const f of forms) {
    const key = f.usernameField ?? f.passwordField;
    if (key && !currentForms.some((cf) => cf.usernameField === key || cf.passwordField === key)) {
      currentForms.push(f);
    }
  }
  if (currentForms.length === 0) currentForms = forms;

  const domain = forms[0].domain;

  // Notify background about detected forms
  browserAPI.runtime.sendMessage({
    type: 'formDetected' as const,
    domain,
    fieldCount: forms.length,
  });

  // Fetch matching credentials
  const credentials = await fetchCredentials(domain);
  currentCredentials = credentials;
  console.debug('[QPM] fetched', credentials.length, 'credentials for', domain);

  // Attach focus listeners for overlay — pass getters so listeners
  // always read the latest credentials, not stale snapshots.
  attachFieldListeners(
    currentForms,
    currentCredentials,
    () => currentCredentials,
    () => currentForms
  );

  // Watch for form submissions to prompt save
  watchFormSubmissions(currentForms);
}

/**
 * Handle messages from background / popup (e.g. "autofill this credential").
 */
browserAPI.runtime.onMessage.addListener(
  (message: AutofillMessage | ShowSavePromptMessage | VaultLockedMessage) => {
    if (message.type === 'vaultLocked') {
      // Vault was locked — clear all UI and cached credentials
      currentCredentials = [];
      clearAllUI();
      console.debug('[QPM] vault locked — cleared UI and credentials');
      return;
    }

    if (message.type === 'autofill') {
      // Always re-scan the DOM to get current state
      const freshForms = detectLoginForms();
      if (freshForms.length > 0) {
        currentForms = freshForms;
      }

      let filled = false;

      if (currentForms.length > 0) {
        const info = currentForms[0];
        autofill(info.usernameField, info.passwordField, message.username, message.password);
        filled = true;
      }

      if (!filled) {
        // Fallback: find any visible login-like input on the page
        const field = findVisibleLoginField();
        if (field) {
          const isPassword = field.type === 'password';
          simulateInput(field, isPassword ? message.password : message.username);
          filled = true;
        }
      }

      if (filled) {
        browserAPI.runtime.sendMessage({
          type: 'autofillComplete' as const,
          domain: extractDomain(window.location.href) ?? '',
        });
      }
      return;
    }

    if (message.type === 'showSavePrompt') {
      handleShowSavePrompt(message.domain, message.username, message.password);
      return;
    }
  }
);

/**
 * Initialize: detect forms, attach listeners, observe DOM mutations.
 * Guard against double-init from scripting.executeScript re-injection.
 */
function init() {
  if ((window as any).__qpmContentInit) return;
  (window as any).__qpmContentInit = true;
  console.debug('[QPM] content script initializing');

  // Pre-fetch credentials so they're ready when forms are detected.
  // Don't show the pill yet — wait for scanAndAttach to find login forms.
  const domain = extractDomain(window.location.href) ?? '';
  console.debug('[QPM] domain:', domain);
  if (domain) {
    fetchCredentials(domain).then((creds) => {
      console.debug('[QPM] pre-fetch got', creds.length, 'credentials');
      if (creds.length > 0) {
        currentCredentials = creds;
      }
    });
  }

  // Global focusin listener catches fields focused before per-field
  // listeners are attached (e.g. user clicked the field before our
  // script finished loading). Also fetches credentials on-demand.
  attachGlobalFocusListener(
    () => currentCredentials,
    () => currentForms,
    async (field: HTMLInputElement) => {
      // Fetch credentials on-demand when user focuses a login field
      // before scanAndAttach has completed
      const domain = extractDomain(window.location.href) ?? '';
      console.debug('[QPM] fetchAndShow: domain =', domain, 'field =', field.id || field.name);
      if (!domain) return;
      const creds = await fetchCredentials(domain);
      console.debug('[QPM] fetchAndShow: got', creds.length, 'credentials');
      if (creds.length === 0) return;
      currentCredentials = creds;

      // Build a form entry for this field if we don't have one
      if (!currentForms.some((f) => f.usernameField === field || f.passwordField === field)) {
        const isPassword = field.type === 'password';
        currentForms.push({
          form: field.closest('form'),
          usernameField: isPassword ? null : field,
          passwordField: isPassword ? field : null,
          domain,
        });
      }

      // Show side panel now that we have credentials
      showSidePanel(currentCredentials, currentForms, () => currentCredentials, () => currentForms);
    }
  );

  scanAndAttach();

  // Watch for dynamically added forms (SPAs)
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  const observer = new MutationObserver(() => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      scanAndAttach();
    }, 300);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

// Run when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
