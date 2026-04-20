import { browserAPI, extractDomain } from '../lib/browser-api';
import type { AutofillMessage, ShowSavePromptMessage, Credential } from '../lib/messages';
import {
  detectLoginForms,
  autofill,
  simulateInput,
  findVisibleLoginField,
  attachFieldListeners,
  attachGlobalFocusListener,
  showSidePanel,
  resetPanelDismissed,
  watchFormSubmissions,
  handleShowSavePrompt,
  type FormInfo,
} from './autofill';

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
  (message: AutofillMessage | ShowSavePromptMessage) => {
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
