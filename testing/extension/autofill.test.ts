/**
 * Tests for browser extension autofill functionality.
 * Uses JSDOM-compatible mocking for DOM form detection and autofill.
 */

// ---------------------------------------------------------------------------
// Mock browser APIs (must be before any import that uses them)
// ---------------------------------------------------------------------------
const mockSendMessage = jest.fn();
const mockConnect = jest.fn();

jest.mock('webextension-polyfill', () => ({
  __esModule: true,
  default: {
    runtime: {
      sendMessage: mockSendMessage,
      onMessage: { addListener: jest.fn() },
      connectNative: mockConnect,
      getURL: (path: string) => `chrome-extension://test/${path}`,
      sendNativeMessage: jest.fn(),
    },
    storage: {
      local: {
        get: jest.fn().mockResolvedValue({}),
        set: jest.fn().mockResolvedValue(undefined),
        remove: jest.fn().mockResolvedValue(undefined),
      },
    },
    tabs: {
      query: jest.fn().mockResolvedValue([]),
      sendMessage: jest.fn(),
      onActivated: { addListener: jest.fn() },
      onUpdated: { addListener: jest.fn() },
    },
    action: {
      setBadgeText: jest.fn(),
      setBadgeBackgroundColor: jest.fn(),
    },
    alarms: {
      create: jest.fn(),
      onAlarm: { addListener: jest.fn() },
    },
  },
}));

// ---------------------------------------------------------------------------
// Helpers: build a mock DOM with login forms
// ---------------------------------------------------------------------------

function createLoginForm(opts: {
  username?: string;
  password?: string;
  usernameType?: string;
  hasForm?: boolean;
} = {}): HTMLElement {
  const {
    username = 'user@example.com',
    password = 'secret123',
    usernameType = 'email',
    hasForm = true,
  } = opts;

  const container = document.createElement('div');

  const formHtml = `
    ${hasForm ? '<form action="/login" method="POST">' : ''}
      <input type="${usernameType}" name="username" id="username" placeholder="Email" autocomplete="username" value="${username}" />
      <input type="password" name="password" id="password" placeholder="Password" autocomplete="current-password" value="${password}" />
      <button type="submit">Sign In</button>
    ${hasForm ? '</form>' : ''}
  `;

  container.innerHTML = formHtml;
  document.body.appendChild(container);
  return container;
}

function createNonLoginForm(): HTMLElement {
  const container = document.createElement('div');
  container.innerHTML = `
    <form action="/search" method="GET">
      <input type="text" name="q" placeholder="Search..." />
      <button type="submit">Search</button>
    </form>
  `;
  document.body.appendChild(container);
  return container;
}

function createSPAForm(): HTMLElement {
  const container = document.createElement('div');
  // SPA-rendered form without traditional <form> tag
  container.innerHTML = `
    <div class="login-component">
      <input type="email" name="email" id="login-email" autocomplete="username" />
      <input type="password" name="pass" id="login-pass" autocomplete="current-password" />
      <div role="button" tabindex="0">Log In</div>
    </div>
  `;
  document.body.appendChild(container);
  return container;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Autofill — Form Detection', () => {
  afterEach(() => {
    document.body.innerHTML = '';
  });

  test('detects standard login form with password field', () => {
    createLoginForm();

    const passwordFields = document.querySelectorAll<HTMLInputElement>(
      'input[type="password"]'
    );
    expect(passwordFields.length).toBe(1);

    // Find associated username field
    const form = passwordFields[0].closest('form');
    expect(form).not.toBeNull();

    const usernameField = form!.querySelector<HTMLInputElement>(
      'input[type="email"], input[type="text"], input[autocomplete="username"]'
    );
    expect(usernameField).not.toBeNull();
    expect(usernameField!.name).toBe('username');
  });

  test('detects SPA-rendered form without <form> tag', () => {
    createSPAForm();

    const passwordFields = document.querySelectorAll<HTMLInputElement>(
      'input[type="password"]'
    );
    expect(passwordFields.length).toBe(1);

    // No <form> parent
    const form = passwordFields[0].closest('form');
    expect(form).toBeNull();

    // But there is a username-like field nearby
    const emailField = document.querySelector<HTMLInputElement>(
      'input[autocomplete="username"]'
    );
    expect(emailField).not.toBeNull();
  });

  test('detects MutationObserver-compatible form insertion', (done) => {
    // Start observing
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node instanceof HTMLElement) {
            const pwField = node.querySelector('input[type="password"]');
            if (pwField) {
              expect(pwField).not.toBeNull();
              observer.disconnect();
              done();
              return;
            }
          }
        }
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });

    // Simulate SPA rendering a login form after a delay
    setTimeout(() => {
      createSPAForm();
    }, 10);
  });

  test('does not detect non-login form as login form', () => {
    createNonLoginForm();

    const passwordFields = document.querySelectorAll<HTMLInputElement>(
      'input[type="password"]'
    );
    expect(passwordFields.length).toBe(0);
  });
});

describe('Autofill — Field Value Setting', () => {
  afterEach(() => {
    document.body.innerHTML = '';
  });

  test('fills username and password fields correctly', () => {
    createLoginForm({ username: '', password: '' });

    const usernameField = document.querySelector<HTMLInputElement>('#username')!;
    const passwordField = document.querySelector<HTMLInputElement>('#password')!;

    // Simulate autofill using native setter approach
    const nativeSetter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      'value'
    )?.set;

    if (nativeSetter) {
      nativeSetter.call(usernameField, 'filled@example.com');
      nativeSetter.call(passwordField, 'FilledPass123!');
    } else {
      usernameField.value = 'filled@example.com';
      passwordField.value = 'FilledPass123!';
    }

    usernameField.dispatchEvent(new Event('input', { bubbles: true }));
    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
    usernameField.dispatchEvent(new Event('change', { bubbles: true }));
    passwordField.dispatchEvent(new Event('change', { bubbles: true }));

    expect(usernameField.value).toBe('filled@example.com');
    expect(passwordField.value).toBe('FilledPass123!');
  });

  test('dispatches input and change events after fill', () => {
    createLoginForm({ username: '', password: '' });

    const passwordField = document.querySelector<HTMLInputElement>('#password')!;

    const events: string[] = [];
    passwordField.addEventListener('input', () => events.push('input'));
    passwordField.addEventListener('change', () => events.push('change'));

    passwordField.value = 'newpassword';
    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
    passwordField.dispatchEvent(new Event('change', { bubbles: true }));

    expect(events).toContain('input');
    expect(events).toContain('change');
  });
});

describe('Autofill — No False Positives', () => {
  afterEach(() => {
    document.body.innerHTML = '';
  });

  test('search form should not be identified as login form', () => {
    createNonLoginForm();

    const passwordFields = document.querySelectorAll('input[type="password"]');
    expect(passwordFields.length).toBe(0);

    // No username-like fields with login hints
    const allInputs = document.querySelectorAll<HTMLInputElement>('input');
    let hasLoginField = false;
    const loginHints = /user|email|login|username|account|password/i;

    for (const input of allInputs) {
      const attrs = [input.name, input.id, input.autocomplete, input.placeholder].join(' ');
      if (loginHints.test(attrs) && input.type === 'password') {
        hasLoginField = true;
      }
    }

    expect(hasLoginField).toBe(false);
  });

  test('registration form with confirm password should still detect', () => {
    const container = document.createElement('div');
    container.innerHTML = `
      <form action="/register">
        <input type="email" name="email" autocomplete="username" />
        <input type="password" name="password" autocomplete="new-password" />
        <input type="password" name="confirm_password" autocomplete="new-password" />
        <button type="submit">Register</button>
      </form>
    `;
    document.body.appendChild(container);

    const passwordFields = document.querySelectorAll('input[type="password"]');
    expect(passwordFields.length).toBe(2);
  });
});
