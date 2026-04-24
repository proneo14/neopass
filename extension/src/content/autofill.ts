import { browserAPI, extractDomain } from '../lib/browser-api';
import type { Credential } from '../lib/messages';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export interface FormInfo {
  form: HTMLFormElement | null;
  usernameField: HTMLInputElement | null;
  passwordField: HTMLInputElement | null;
  domain: string;
}

/* ------------------------------------------------------------------ */
/*  Form Detection                                                     */
/* ------------------------------------------------------------------ */

const USERNAME_HINTS =
  /user|email|login|username|account|identifier|handle|phone|signin/i;

const _LOGIN_ACTION_HINTS =
  /login|signin|sign-in|auth|session|account|logon/i;

/** URL path patterns that indicate a login / authentication page. */
const LOGIN_PATH_HINTS =
  /\/(log[_-]?in|sign[_-]?in|auth(enticate|orize)?|sso|session[s]?(\/new)?|logon|log[_-]?on|oauth|openid|saml|cas\/login|unlock|lock(ed)?)\b/i;

/** Hostnames that are dedicated login portals. */
const LOGIN_HOST_HINTS =
  /^(login|signin|sign-in|auth|sso|accounts?|id|identity|passport|myaccount)\./i;

/**
 * Heuristic: is the current page likely a login / authentication page?
 *
 * True when any of:
 *  1. A visible password field exists on the page
 *  2. The URL path contains login-related keywords
 *  3. The hostname is a known login sub-domain pattern
 */
function isLikelyLoginPage(): boolean {
  // 1. Visible password field is a strong signal
  const pw = document.querySelector<HTMLInputElement>('input[type="password"]');
  if (pw && isVisible(pw)) return true;

  // 2. URL path
  const path = window.location.pathname + window.location.search;
  if (LOGIN_PATH_HINTS.test(path)) return true;

  // 3. Hostname
  if (LOGIN_HOST_HINTS.test(window.location.hostname)) return true;

  return false;
}

/** Track fields already processed by detectUsernameOnlyForms */
const seenFields = new WeakSet<HTMLInputElement>();

/** Track fields already instrumented with overlay listeners */
const instrumentedFields = new WeakSet<HTMLInputElement>();

/**
 * Find the most likely username field near a password field.
 */
function findUsernameField(
  passwordField: HTMLInputElement,
  container: HTMLElement | Document
): HTMLInputElement | null {
  const candidates = container.querySelectorAll<HTMLInputElement>(
    'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
  );

  // Prefer fields with username-like attributes
  for (const candidate of candidates) {
    if (candidate.type === 'hidden' || candidate.type === 'submit') continue;
    const attrs = [
      candidate.name,
      candidate.id,
      candidate.autocomplete,
      candidate.placeholder,
      candidate.getAttribute('aria-label') ?? '',
    ].join(' ');

    if (USERNAME_HINTS.test(attrs)) {
      return candidate;
    }
  }

  // Fallback: nearest preceding visible text/email input
  const allInputs = Array.from(
    container.querySelectorAll<HTMLInputElement>('input')
  );
  const pwIndex = allInputs.indexOf(passwordField);

  for (let i = pwIndex - 1; i >= 0; i--) {
    const input = allInputs[i];
    const type = (input.type || 'text').toLowerCase();
    if (
      (type === 'text' || type === 'email' || type === 'tel') &&
      isVisible(input)
    ) {
      return input;
    }
  }

  return null;
}

/**
 * Scan the page (including shadow DOMs) for password fields and
 * build FormInfo descriptors.  Also detects multi-step login pages
 * that show only a username/email field first (e.g. Google, Microsoft).
 */
export function detectLoginForms(): FormInfo[] {
  const domain = extractDomain(window.location.href) ?? '';
  const forms: FormInfo[] = [];
  const seen = new WeakSet<HTMLInputElement>();

  function scan(root: Document | ShadowRoot) {
    const passwordFields = root.querySelectorAll<HTMLInputElement>(
      'input[type="password"]'
    );

    for (const pwField of passwordFields) {
      if (seen.has(pwField)) continue;
      seen.add(pwField);

      const form = pwField.closest('form');
      const container = (form ?? root) as HTMLElement | Document;
      const usernameField = findUsernameField(pwField, container);

      forms.push({ form, usernameField, passwordField: pwField, domain });
    }

    // Traverse shadow DOMs
    root.querySelectorAll('*').forEach((el) => {
      if (el.shadowRoot) scan(el.shadowRoot);
    });
  }

  scan(document);

  // If no password fields found, check for multi-step login pages
  // that only show a username/email field first.
  // Only do this on pages that look like login pages (URL heuristic)
  // to avoid false positives on random pages with email/name fields.
  if (forms.length === 0 && isLikelyLoginPage()) {
    const usernameOnly = detectUsernameOnlyForms(domain);
    forms.push(...usernameOnly);
  }

  return forms;
}

/**
 * Detect pages that only show a username/email field (multi-step login flow).
 * Scans for any visible username-like input — no URL heuristic required.
 */
function detectUsernameOnlyForms(domain: string): FormInfo[] {
  const forms: FormInfo[] = [];
  const candidates = document.querySelectorAll<HTMLInputElement>(
    'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
  );

  for (const field of candidates) {
    if (field.type === 'hidden' || field.type === 'submit') continue;
    if (!isVisible(field)) continue;
    if (seenFields.has(field)) continue;

    const attrs = [
      field.name, field.id, field.autocomplete,
      field.placeholder, field.getAttribute('aria-label') ?? '',
    ].join(' ');

    if (USERNAME_HINTS.test(attrs)) {
      seenFields.add(field);
      const form = field.closest('form');
      forms.push({ form, usernameField: field, passwordField: null, domain });
      console.debug('[QPM] detected username-only field:', field.id || field.name, 'attrs:', attrs);
    }
  }

  return forms;
}

/* ------------------------------------------------------------------ */
/*  Autofill                                                           */
/* ------------------------------------------------------------------ */

/**
 * Set a value on an input field so that all frameworks recognise it.
 * Uses the native HTMLInputElement value setter (bypasses React/Angular
 * wrappers) then dispatches a real InputEvent.
 */
export function simulateInput(field: HTMLInputElement, value: string) {
  field.focus();

  // Use the native value setter from the prototype — this bypasses
  // any framework wrapper (React installs its own setter).
  const nativeSetter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    'value'
  )?.set;

  if (nativeSetter) {
    nativeSetter.call(field, value);
  } else {
    field.value = value;
  }

  // Dispatch InputEvent — React 16+ and Google Closure both listen for this
  field.dispatchEvent(
    new InputEvent('input', {
      bubbles: true,
      cancelable: true,
      inputType: 'insertText',
      data: value,
    })
  );

  field.dispatchEvent(new Event('change', { bubbles: true }));

  console.debug('[QPM] simulateInput done:', field.id || field.name, 'value:', field.value);
}

/**
 * Fill username and/or password fields on the page.
 * Handles multi-step flows where only one field may be present.
 * Clears credential values from local variables after use.
 */
export function autofill(
  usernameField: HTMLInputElement | null,
  passwordField: HTMLInputElement | null,
  username: string,
  password: string
) {
  if (usernameField) {
    simulateInput(usernameField, username);
  }
  if (passwordField) {
    simulateInput(passwordField, password);
  }
}

/**
 * Find any visible text/email/password input that looks like a login field.
 * Used as a fallback when popup Fill is clicked but no forms were detected.
 */
export function findVisibleLoginField(): HTMLInputElement | null {
  // Try password field first
  const pwField = document.querySelector<HTMLInputElement>(
    'input[type="password"]:not([aria-hidden="true"])'
  );
  if (pwField && isVisible(pwField)) return pwField;

  // Then try username-like fields
  const inputs = document.querySelectorAll<HTMLInputElement>(
    'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
  );
  for (const input of inputs) {
    if (input.type === 'hidden' || input.type === 'submit') continue;
    if (!isVisible(input)) continue;
    const attrs = [
      input.name, input.id, input.autocomplete,
      input.placeholder, input.getAttribute('aria-label') ?? '',
    ].join(' ');
    if (USERNAME_HINTS.test(attrs)) return input;
  }

  // Last resort: first visible text/email input
  for (const input of inputs) {
    if (input.type === 'hidden' || input.type === 'submit') continue;
    if (isVisible(input)) return input;
  }

  return null;
}

/* ------------------------------------------------------------------ */
/*  Side Panel (slides in from right when login form detected)         */
/* ------------------------------------------------------------------ */

const PANEL_ID = 'qpm-side-panel';
let activePanel: HTMLElement | null = null;
let activePanelDismissed = false;

function removePanel() {
  if (activePanel) {
    activePanel.remove();
    activePanel = null;
  }
}

/**
 * Show a compact pill in the top-right corner.  Hover to expand and
 * see the credential list.  Click a credential to fill.
 */
export function showSidePanel(
  credentials: Credential[],
  detectedForms: FormInfo[],
  getCredentials: () => Credential[],
  getForms: () => FormInfo[]
) {
  console.debug('[QPM] showSidePanel called, creds:', credentials.length, 'dismissed:', activePanelDismissed);
  if (credentials.length === 0) return;
  if (activePanelDismissed) return;

  // Only show the pill on pages that look like login pages
  if (!isLikelyLoginPage()) {
    console.debug('[QPM] not a login page — suppressing pill');
    return;
  }

  if (activePanel) {
    const prev = activePanel.getAttribute('data-qpm-count');
    if (prev === String(credentials.length)) return;
    removePanel();
  }

  const panel = document.createElement('div');
  panel.id = PANEL_ID;
  panel.setAttribute('data-qpm', 'true');
  panel.setAttribute('data-qpm-count', String(credentials.length));

  const shadow = panel.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = `
    :host { all: initial; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }

    .qpm-wrapper {
      position: fixed;
      top: 8px;
      right: 8px;
      z-index: 2147483647;
    }

    .qpm-pill {
      display: flex;
      align-items: center;
      gap: 6px;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 20px;
      padding: 5px 12px;
      cursor: pointer;
      box-shadow: 0 2px 12px rgba(0,0,0,0.4);
      transition: all 0.2s ease;
      user-select: none;
    }
    .qpm-pill:hover {
      background: #334155;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    }
    .qpm-pill-label {
      font-size: 11px;
      font-weight: 600;
      color: #818cf8;
      letter-spacing: 0.02em;
    }
    .qpm-pill-badge {
      background: #818cf8;
      color: #fff;
      font-size: 10px;
      font-weight: 700;
      min-width: 16px;
      height: 16px;
      line-height: 16px;
      text-align: center;
      border-radius: 8px;
      padding: 0 4px;
    }
    .qpm-pill-close {
      background: none;
      border: none;
      color: #64748b;
      font-size: 14px;
      cursor: pointer;
      padding: 0 0 0 2px;
      line-height: 1;
      transition: color 0.15s;
    }
    .qpm-pill-close:hover { color: #f1f5f9; }

    /* Dropdown — overlaps pill bottom so mouse can travel seamlessly */
    .qpm-dropdown {
      position: absolute;
      top: 100%;
      right: 0;
      margin-top: -2px;
      padding-top: 4px;
      width: 260px;
      max-height: 320px;
      display: none;
      flex-direction: column;
    }
    .qpm-dropdown-inner {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 10px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      overflow: hidden;
      display: flex;
      flex-direction: column;
      max-height: 320px;
      animation: qpm-fade-in 0.15s ease-out;
    }
    @keyframes qpm-fade-in {
      from { opacity: 0; transform: translateY(-4px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .qpm-wrapper:hover .qpm-dropdown {
      display: flex;
    }

    .qpm-dd-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 8px 12px;
      font-size: 11px;
      color: #818cf8;
      font-weight: 600;
      border-bottom: 1px solid #1e293b;
    }
    .qpm-dd-header-domain {
      font-size: 10px;
      color: #64748b;
      font-weight: 400;
    }
    .qpm-dd-section {
      padding: 6px 12px 2px;
      font-size: 9px;
      font-weight: 700;
      color: #818cf8;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .qpm-dd-list {
      flex: 1;
      overflow-y: auto;
      padding: 2px 0;
      scrollbar-width: none;
      -ms-overflow-style: none;
    }
    .qpm-dd-list::-webkit-scrollbar {
      display: none;
    }
    .qpm-dd-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      cursor: pointer;
      transition: background 0.12s;
    }
    .qpm-dd-item:hover { background: #1e293b; }
    .qpm-dd-avatar {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: #334155;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      color: #818cf8;
      font-weight: 700;
      flex-shrink: 0;
    }
    .qpm-dd-info { flex: 1; min-width: 0; }
    .qpm-dd-name {
      font-size: 12px;
      color: #f1f5f9;
      font-weight: 500;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .qpm-dd-user {
      font-size: 10px;
      color: #94a3b8;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .qpm-dd-fill {
      background: #818cf8;
      color: white;
      border: none;
      padding: 4px 10px;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 500;
      cursor: pointer;
      flex-shrink: 0;
      transition: background 0.12s;
    }
    .qpm-dd-fill:hover { background: #6366f1; }
  `;
  shadow.appendChild(style);

  // Wrapper holds pill + dropdown — hover on wrapper keeps dropdown open
  const wrapper = document.createElement('div');
  wrapper.className = 'qpm-wrapper';

  // --- Pill ---
  const pill = document.createElement('div');
  pill.className = 'qpm-pill';
  pill.innerHTML = `
    <span class="qpm-pill-label">LGI Pass</span>
    <span class="qpm-pill-badge">${credentials.length}</span>
  `;
  const closeBtn = document.createElement('button');
  closeBtn.className = 'qpm-pill-close';
  closeBtn.textContent = '\u00D7';
  closeBtn.title = 'Dismiss';
  closeBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    activePanelDismissed = true;
    removePanel();
  });
  pill.appendChild(closeBtn);
  wrapper.appendChild(pill);

  // --- Dropdown ---
  const dropdown = document.createElement('div');
  dropdown.className = 'qpm-dropdown';

  const ddInner = document.createElement('div');
  ddInner.className = 'qpm-dropdown-inner';

  const domain = detectedForms[0]?.domain ?? '';
  const ddHeader = document.createElement('div');
  ddHeader.className = 'qpm-dd-header';
  const headerLabel = document.createElement('span');
  headerLabel.textContent = 'LGI Pass';
  ddHeader.appendChild(headerLabel);
  if (domain) {
    const headerDomain = document.createElement('span');
    headerDomain.className = 'qpm-dd-header-domain';
    headerDomain.textContent = domain;
    ddHeader.appendChild(headerDomain);
  }
  ddInner.appendChild(ddHeader);

  const sectionLabel = document.createElement('div');
  sectionLabel.className = 'qpm-dd-section';
  sectionLabel.textContent = 'For this site';
  ddInner.appendChild(sectionLabel);

  const ddList = document.createElement('div');
  ddList.className = 'qpm-dd-list';

  const matchedCreds = credentials.filter((c) => c.matched);
  const otherCreds = credentials.filter((c) => !c.matched);

  function addCredItem(cred: Credential, container: HTMLElement) {
    const item = document.createElement('div');
    item.className = 'qpm-dd-item';

    const initial = (cred.name || cred.username || '?')[0].toUpperCase();

    const avatar = document.createElement('div');
    avatar.className = 'qpm-dd-avatar';
    avatar.textContent = initial;

    const info = document.createElement('div');
    info.className = 'qpm-dd-info';
    info.innerHTML = `
      <div class="qpm-dd-name">${escapeHtml(cred.name || cred.domain)}</div>
      <div class="qpm-dd-user">${escapeHtml(cred.username)}</div>
    `;

    const fillBtn = document.createElement('button');
    fillBtn.className = 'qpm-dd-fill';
    fillBtn.textContent = 'Fill';
    fillBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fillFromPanel(cred, getForms());
    });

    item.addEventListener('click', () => {
      fillFromPanel(cred, getForms());
    });

    item.appendChild(avatar);
    item.appendChild(info);
    item.appendChild(fillBtn);
    container.appendChild(item);
  }

  matchedCreds.forEach((cred) => addCredItem(cred, ddList));

  if (otherCreds.length > 0) {
    const otherLabel = document.createElement('div');
    otherLabel.className = 'qpm-dd-section';
    otherLabel.textContent = 'Other logins';
    ddList.appendChild(otherLabel);
    otherCreds.forEach((cred) => addCredItem(cred, ddList));
  }

  ddInner.appendChild(ddList);
  dropdown.appendChild(ddInner);
  wrapper.appendChild(dropdown);
  shadow.appendChild(wrapper);

  panel.style.cssText = 'position:fixed;top:0;right:0;z-index:2147483647;pointer-events:auto;';

  document.body.appendChild(panel);
  activePanel = panel;
  console.debug('[QPM] pill appended to DOM, credentials:', credentials.length);
}

function fillFromPanel(cred: Credential, detectedForms: FormInfo[]) {
  // Fill the first detected form
  if (detectedForms.length > 0) {
    const first = detectedForms[0];
    autofill(first.usernameField, first.passwordField, cred.username, cred.password);
  } else {
    // Fallback: find any visible login field
    const field = findVisibleLoginField();
    if (field) {
      const isPassword = field.type === 'password';
      simulateInput(field, isPassword ? cred.password : cred.username);
    }
  }

  removePanel();

  // Also request the background to do a scripting.executeScript fill
  // as a backup (trusted events that work on Google etc.)
  browserAPI.runtime.sendMessage({
    type: 'fillCredential' as const,
    username: cred.username,
    password: cred.password,
  });

  browserAPI.runtime.sendMessage({
    type: 'autofillComplete' as const,
    domain: extractDomain(window.location.href) ?? '',
  });
}

/** Reset dismissed state on navigation (SPA page changes). */
export function resetPanelDismissed() {
  activePanelDismissed = false;
}

/* Keep the old overlay functions as internal helpers — they're still
   used by the popup Fill flow (via content script message handler).   */
const OVERLAY_ID = 'qpm-autofill-overlay';
let activeOverlay: HTMLElement | null = null;
let activeField: HTMLInputElement | null = null;

function removeOverlay() {
  if (activeOverlay) {
    activeOverlay.remove();
    activeOverlay = null;
  }
  activeField = null;
}

function createOverlayElement(): HTMLElement {
  const overlay = document.createElement('div');
  overlay.id = OVERLAY_ID;
  overlay.setAttribute('data-qpm', 'true');

  // Shadow DOM so page styles don't leak in
  const shadow = overlay.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = `
    :host {
      all: initial;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .qpm-overlay {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.4);
      overflow: hidden;
      max-height: 240px;
      overflow-y: auto;
    }
    .qpm-header {
      padding: 6px 10px;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #818cf8;
      font-weight: 600;
      border-bottom: 1px solid #334155;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .qpm-item {
      display: flex;
      align-items: center;
      padding: 8px 10px;
      cursor: pointer;
      transition: background 0.15s;
    }
    .qpm-item:hover, .qpm-item.qpm-focused {
      background: #334155;
    }
    .qpm-item-info {
      flex: 1;
      min-width: 0;
    }
    .qpm-item-name {
      font-size: 13px;
      color: #f1f5f9;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .qpm-item-user {
      font-size: 11px;
      color: #94a3b8;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .qpm-empty {
      padding: 12px 10px;
      font-size: 12px;
      color: #64748b;
      text-align: center;
    }
  `;

  shadow.appendChild(style);

  const container = document.createElement('div');
  container.className = 'qpm-overlay';
  shadow.appendChild(container);

  return overlay;
}

/**
 * Show the autofill overlay below a field with matching credentials.
 */
export function showAutofillOverlay(
  field: HTMLInputElement,
  credentials: Credential[],
  detectedForms: FormInfo[]
) {
  // Check BEFORE removing — stale closure callers may pass empty arrays
  // and we must not destroy an overlay another caller just created.
  if (credentials.length === 0) return;

  removeOverlay();

  activeField = field;
  const overlay = createOverlayElement();
  const shadow = overlay.shadowRoot!;
  const container = shadow.querySelector('.qpm-overlay')!;

  // Header
  const header = document.createElement('div');
  header.className = 'qpm-header';
  header.textContent = 'LGI Pass';
  container.appendChild(header);

  let focusedIndex = -1;
  const items: HTMLElement[] = [];

  // List credentials
  credentials.forEach((cred, idx) => {
    const item = document.createElement('div');
    item.className = 'qpm-item';
    item.setAttribute('role', 'option');

    item.innerHTML = `
      <div class="qpm-item-info">
        <div class="qpm-item-name">${escapeHtml(cred.name || cred.domain)}</div>
        <div class="qpm-item-user">${escapeHtml(cred.username)}</div>
      </div>
    `;

    item.addEventListener('mousedown', (e) => {
      e.preventDefault(); // Prevent blur on the field
      fillFromOverlay(cred, detectedForms);
    });

    item.addEventListener('mouseenter', () => {
      setFocused(idx);
    });

    container.appendChild(item);
    items.push(item);
  });

  function setFocused(idx: number) {
    items.forEach((el) => el.classList.remove('qpm-focused'));
    if (idx >= 0 && idx < items.length) {
      items[idx].classList.add('qpm-focused');
    }
    focusedIndex = idx;
  }

  // Keyboard navigation on the field
  function onKeydown(e: KeyboardEvent) {
    if (!activeOverlay) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setFocused(Math.min(focusedIndex + 1, items.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setFocused(Math.max(focusedIndex - 1, 0));
    } else if (e.key === 'Enter' && focusedIndex >= 0) {
      e.preventDefault();
      fillFromOverlay(credentials[focusedIndex], detectedForms);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      removeOverlay();
    }
  }

  field.addEventListener('keydown', onKeydown);

  const rect = field.getBoundingClientRect();
  overlay.style.position = 'fixed';
  overlay.style.left = `${rect.left}px`;
  overlay.style.top = `${rect.bottom + 2}px`;
  overlay.style.width = `${Math.max(rect.width, 260)}px`;
  overlay.style.zIndex = '2147483647';

  document.body.appendChild(overlay);
  activeOverlay = overlay;

  // Cleanup listeners when overlay is removed
  const originalRemove = overlay.remove.bind(overlay);
  overlay.remove = () => {
    field.removeEventListener('keydown', onKeydown);
    originalRemove();
  };
}

function fillFromOverlay(cred: Credential, detectedForms: FormInfo[]) {
  // Find the form that contains the active field
  const info = detectedForms.find(
    (f) => f.usernameField === activeField || f.passwordField === activeField
  );

  if (info) {
    autofill(info.usernameField, info.passwordField, cred.username, cred.password);
  } else if (detectedForms.length > 0) {
    // Fallback to first detected form
    const first = detectedForms[0];
    autofill(first.usernameField, first.passwordField, cred.username, cred.password);
  }

  removeOverlay();
  removePanel();

  browserAPI.runtime.sendMessage({
    type: 'autofillComplete' as const,
    domain: extractDomain(window.location.href) ?? '',
  });
}

/* ------------------------------------------------------------------ */
/*  Save Prompt (after form submission)                                */
/* ------------------------------------------------------------------ */

const SAVE_PROMPT_ID = 'qpm-save-prompt';

/** Inline SVG for the LGI Pass shield logo */
const LGI_LOGO_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4" stroke="#818cf8" stroke-width="2"/></svg>`;

/**
 * Show a compact "Save this password?" popup on the right side of the page.
 */
function showSavePrompt(domain: string, username: string, password: string) {
  // Don't show if one is already visible
  if (document.getElementById(SAVE_PROMPT_ID)) return;

  const banner = document.createElement('div');
  banner.id = SAVE_PROMPT_ID;
  banner.setAttribute('data-qpm', 'true');

  const shadow = banner.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = `
    :host {
      all: initial;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .qpm-save-popup {
      position: fixed;
      top: 12px;
      right: 12px;
      width: 280px;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 12px;
      z-index: 2147483647;
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      animation: qpm-slide-in 0.2s ease-out;
    }
    @keyframes qpm-slide-in {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    .qpm-save-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
    }
    .qpm-save-logo {
      display: flex;
      align-items: center;
      flex-shrink: 0;
    }
    .qpm-save-title {
      font-size: 11px;
      font-weight: 600;
      color: #818cf8;
      letter-spacing: 0.02em;
    }
    .qpm-save-close {
      margin-left: auto;
      background: none;
      border: none;
      color: #64748b;
      font-size: 14px;
      cursor: pointer;
      padding: 0;
      line-height: 1;
      transition: color 0.15s;
    }
    .qpm-save-close:hover { color: #f1f5f9; }
    .qpm-save-info {
      margin-bottom: 10px;
    }
    .qpm-save-label {
      color: #94a3b8;
      font-size: 11px;
      margin-bottom: 2px;
    }
    .qpm-save-user {
      color: #f1f5f9;
      font-size: 13px;
      font-weight: 500;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .qpm-save-domain {
      color: #64748b;
      font-size: 10px;
      margin-top: 2px;
    }
    .qpm-save-actions {
      display: flex;
      gap: 8px;
    }
    .qpm-btn {
      flex: 1;
      padding: 6px 0;
      border-radius: 6px;
      border: none;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s;
      text-align: center;
    }
    .qpm-btn-save {
      background: #818cf8;
      color: white;
    }
    .qpm-btn-save:hover { background: #6366f1; }
    .qpm-btn-dismiss {
      background: #1e293b;
      color: #94a3b8;
      border: 1px solid #334155;
    }
    .qpm-btn-dismiss:hover { color: #f1f5f9; border-color: #475569; }
  `;
  shadow.appendChild(style);

  const container = document.createElement('div');
  container.className = 'qpm-save-popup';

  // Header with logo
  const header = document.createElement('div');
  header.className = 'qpm-save-header';
  header.innerHTML = `
    <span class="qpm-save-logo">${LGI_LOGO_SVG}</span>
    <span class="qpm-save-title">LGI Pass</span>
  `;
  const closeBtn = document.createElement('button');
  closeBtn.className = 'qpm-save-close';
  closeBtn.textContent = '\u00D7';
  closeBtn.addEventListener('click', () => banner.remove());
  header.appendChild(closeBtn);
  container.appendChild(header);

  // Credential info
  const info = document.createElement('div');
  info.className = 'qpm-save-info';
  info.innerHTML = `
    <div class="qpm-save-label">Save password for</div>
    <div class="qpm-save-user">${escapeHtml(username)}</div>
    <div class="qpm-save-domain">${escapeHtml(domain)}</div>
  `;
  container.appendChild(info);

  // Action buttons
  const actions = document.createElement('div');
  actions.className = 'qpm-save-actions';

  const saveBtn = document.createElement('button');
  saveBtn.className = 'qpm-btn qpm-btn-save';
  saveBtn.textContent = 'Save';
  saveBtn.addEventListener('click', () => {
    browserAPI.runtime.sendMessage({
      type: 'saveCredential' as const,
      domain,
      username,
      password,
    });
    banner.remove();
  });

  const dismissBtn = document.createElement('button');
  dismissBtn.className = 'qpm-btn qpm-btn-dismiss';
  dismissBtn.textContent = 'Not now';
  dismissBtn.addEventListener('click', () => {
    banner.remove();
  });

  actions.appendChild(saveBtn);
  actions.appendChild(dismissBtn);
  container.appendChild(actions);
  shadow.appendChild(container);

  banner.style.cssText =
    'position:fixed;top:0;right:0;z-index:2147483647;pointer-events:auto;';

  document.body.appendChild(banner);

  // Auto-dismiss after 30 seconds
  setTimeout(() => {
    banner.remove();
  }, 30000);
}

/* ------------------------------------------------------------------ */
/*  Form Submission Detection                                          */
/* ------------------------------------------------------------------ */

/** Track values captured before form submission */
let capturedCredentials: { domain: string; username: string; password: string } | null =
  null;

/**
 * Watch forms for submit events and capture credentials.
 */
export function watchFormSubmissions(detectedForms: FormInfo[]) {
  for (const info of detectedForms) {
    const { form, usernameField, passwordField, domain } = info;

    // Capture on submit event
    const submitHandler = () => {
      const password = passwordField?.value ?? '';
      const username = usernameField?.value ?? '';
      if (password) {
        capturedCredentials = { domain, username, password };
      }
    };

    if (form) {
      form.addEventListener('submit', submitHandler, { capture: true });
    }

    // Capture when Enter is pressed in password field
    if (passwordField) {
      passwordField.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          submitHandler();
        }
      });
    }
  }

  // Listen for navigation that indicates successful login
  // Use beforeunload to catch the moment right before page change
  window.addEventListener('beforeunload', () => {
    if (capturedCredentials) {
      // Send to background via synchronous message
      browserAPI.runtime.sendMessage({
        type: 'savePrompt' as const,
        domain: capturedCredentials.domain,
        username: capturedCredentials.username,
        password: capturedCredentials.password,
      });
      capturedCredentials = null;
    }
  });
}

/**
 * Handle the background script asking us to show a save prompt.
 */
export function handleShowSavePrompt(
  domain: string,
  username: string,
  password: string
) {
  showSavePrompt(domain, username, password);
}

/* ------------------------------------------------------------------ */
/*  Overlay Focus Listeners                                            */
/* ------------------------------------------------------------------ */

/**
 * Attach focus/blur listeners to detected form fields so the overlay
 * appears when the user focuses a login field.
 */
export function attachFieldListeners(
  detectedForms: FormInfo[],
  credentials: Credential[],
  getCredentials?: () => Credential[],
  getForms?: () => FormInfo[]
) {
  const liveCreds = getCredentials ?? (() => credentials);
  const liveForms = getForms ?? (() => detectedForms);

  // Show the side panel automatically when credentials exist
  if (credentials.length > 0) {
    showSidePanel(credentials, detectedForms, liveCreds, liveForms);
  }
}

/**
 * Instrument a single field (minimal — just track it).
 */
function _instrumentField(
  field: HTMLInputElement,
  _getCredentials: () => Credential[],
  _getForms: () => FormInfo[]
) {
  if (instrumentedFields.has(field)) return;
  instrumentedFields.add(field);
}

/**
 * Global input listener — catches fields via both focusin and click events.
 * Fetches credentials on-demand if they aren't loaded yet.
 *
 * Note: globalListenerAttached uses a window-level flag so that
 * re-injection of the content script doesn't duplicate listeners.
 */

export function attachGlobalFocusListener(
  getCredentials: () => Credential[],
  getForms: () => FormInfo[],
  fetchAndShow: (field: HTMLInputElement) => Promise<void>
) {
  // Use window-level flag to survive content script re-injection
  if ((window as any).__qpmGlobalListener) return;
  (window as any).__qpmGlobalListener = true;

  const handler = (e: Event) => {
    const target = e.target;
    if (!(target instanceof HTMLInputElement)) return;
    // Don't re-show if overlay is already visible for this field
    if (activeOverlay && activeField === target) return;

    const type = (target.type || 'text').toLowerCase();
    if (
      type !== 'text' &&
      type !== 'email' &&
      type !== 'tel' &&
      type !== 'password'
    )
      return;

    // Check if it looks like a login field
    const attrs = [
      target.name, target.id, target.autocomplete,
      target.placeholder, target.getAttribute('aria-label') ?? '',
    ].join(' ');

    const isLoginField = USERNAME_HINTS.test(attrs) || type === 'password';
    if (!isLoginField) return;

    console.debug('[QPM] global handler fired:', e.type, 'field:', target.id || target.name);

    // Re-show pill if user focuses a login field after dismissing
    if (activePanelDismissed) {
      activePanelDismissed = false;
    }

    const creds = getCredentials();
    const forms = getForms();
    if (creds.length > 0) {
      showSidePanel(creds, forms, getCredentials, getForms);
    } else {
      // Credentials not loaded yet — fetch on demand
      console.debug('[QPM] no cached creds, fetching on demand...');
      fetchAndShow(target);
    }
  };

  // Listen for BOTH focusin and click on capture phase
  document.addEventListener('focusin', handler, true);
  document.addEventListener('click', handler, true);
}

/* ------------------------------------------------------------------ */
/*  Dismiss overlay on outside click                                   */
/* ------------------------------------------------------------------ */

document.addEventListener(
  'click',
  (e) => {
    if (!activeOverlay) return;
    const target = e.target as HTMLElement;
    if (
      target.id !== OVERLAY_ID &&
      !target.closest?.(`#${OVERLAY_ID}`) &&
      target !== activeField
    ) {
      removeOverlay();
    }
  },
  true
);

/**
 * Remove all LGI Pass UI from the page (panel, overlay, save prompt).
 * Called when the vault is locked.
 */
export function clearAllUI() {
  removePanel();
  // Remove overlay
  if (activeOverlay) {
    activeOverlay.remove();
    activeOverlay = null;
    activeField = null;
  }
  // Remove save prompt
  const savePrompt = document.getElementById(SAVE_PROMPT_ID);
  if (savePrompt) savePrompt.remove();
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Visibility check that works in more CSS contexts than offsetParent.
 * offsetParent returns null inside position:fixed containers, but
 * getBoundingClientRect always works.
 */
function isVisible(el: HTMLElement): boolean {
  if (el.hidden) return false;
  const style = getComputedStyle(el);
  if (style.display === 'none' || style.visibility === 'hidden') return false;
  const rect = el.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
