import { browserAPI, extractDomain } from '../lib/browser-api';

/**
 * Content script — detects login forms on the page and communicates
 * with the background service worker for autofill operations.
 * Full autofill logic will be implemented in Prompt 15.
 */

interface FormInfo {
  form: HTMLFormElement | null;
  usernameField: HTMLInputElement | null;
  passwordField: HTMLInputElement | null;
  domain: string;
}

/**
 * Detect login forms on the current page.
 */
function detectLoginForms(): FormInfo[] {
  const domain = extractDomain(window.location.href) ?? '';
  const passwordFields = document.querySelectorAll<HTMLInputElement>(
    'input[type="password"]'
  );

  const forms: FormInfo[] = [];

  for (const pwField of passwordFields) {
    const form = pwField.closest('form');
    const usernameField = findUsernameField(pwField, form);

    forms.push({
      form,
      usernameField,
      passwordField: pwField,
      domain,
    });
  }

  return forms;
}

/**
 * Find the most likely username field near a password field.
 */
function findUsernameField(
  passwordField: HTMLInputElement,
  form: HTMLFormElement | null
): HTMLInputElement | null {
  const container = form ?? document;
  const candidates = container.querySelectorAll<HTMLInputElement>(
    'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
  );

  const usernameHints =
    /user|email|login|username|account|identifier|handle|phone/i;

  // Prefer fields with username-like attributes
  for (const candidate of candidates) {
    const attrs = [
      candidate.name,
      candidate.id,
      candidate.autocomplete,
      candidate.placeholder,
    ].join(' ');

    if (usernameHints.test(attrs)) {
      return candidate;
    }
  }

  // Fallback: nearest preceding text/email input
  const allInputs = Array.from(
    container.querySelectorAll<HTMLInputElement>('input')
  );
  const pwIndex = allInputs.indexOf(passwordField);

  for (let i = pwIndex - 1; i >= 0; i--) {
    const input = allInputs[i];
    const type = input.type.toLowerCase();
    if (type === 'text' || type === 'email' || type === '' || type === 'tel') {
      return input;
    }
  }

  return null;
}

/**
 * Run initial form detection and notify the background script.
 */
function init() {
  const forms = detectLoginForms();

  if (forms.length > 0) {
    browserAPI.runtime.sendMessage({
      type: 'formDetected',
      domain: forms[0].domain,
      fieldCount: forms.length,
    });
  }

  // Watch for dynamically added forms (SPAs)
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  const observer = new MutationObserver(() => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const newForms = detectLoginForms();
      if (newForms.length > 0) {
        browserAPI.runtime.sendMessage({
          type: 'formDetected',
          domain: newForms[0].domain,
          fieldCount: newForms.length,
        });
      }
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
