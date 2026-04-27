package api

import (
	"net/http"
)

// sendReceivePageHTML is a self-contained HTML page for receiving a Secure Send.
// The decryption key lives in the URL fragment (never sent to the server).
// All decryption happens client-side using the Web Crypto API.
const sendReceivePageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LGI Pass — Secure Send</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; max-width: 600px; width: 90%; }
  h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 0.25rem; }
  .brand { color: #94a3b8; font-size: 0.75rem; margin-bottom: 1.5rem; }
  .brand a { color: #60a5fa; text-decoration: none; }
  .error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #f87171; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.875rem; }
  .info { color: #94a3b8; font-size: 0.875rem; margin-bottom: 1rem; }
  .content-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 1rem; white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow-y: auto; font-size: 0.875rem; line-height: 1.5; margin-bottom: 1rem; }
  .meta { display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.75rem; color: #64748b; margin-bottom: 1rem; }
  button { background: #3b82f6; color: white; border: none; padding: 0.625rem 1.25rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: background 0.2s; }
  button:hover { background: #2563eb; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-row { display: flex; gap: 0.5rem; }
  input[type="password"] { width: 100%; padding: 0.625rem; background: #0f172a; border: 1px solid #475569; border-radius: 6px; color: #e2e8f0; font-size: 0.875rem; margin-bottom: 1rem; outline: none; }
  input[type="password"]:focus { border-color: #3b82f6; }
  .loading { text-align: center; padding: 2rem; color: #94a3b8; }
  .spinner { display: inline-block; width: 24px; height: 24px; border: 3px solid #334155; border-top-color: #3b82f6; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="card">
  <h1>🔒 Secure Send</h1>
  <div class="brand">Sent via <a href="#">LGI Pass</a></div>

  <div id="loading" class="loading"><div class="spinner"></div><p style="margin-top:0.5rem">Loading…</p></div>
  <div id="error" class="error" style="display:none"></div>
  <div id="password-form" style="display:none">
    <p class="info">This send is password protected. Enter the password to continue.</p>
    <input type="password" id="pw-input" placeholder="Password" autocomplete="off" />
    <button onclick="submitPassword()">Unlock</button>
  </div>
  <div id="result" style="display:none">
    <div id="meta" class="meta"></div>
    <div id="content-area"></div>
    <div class="btn-row" id="actions"></div>
  </div>
</div>

<script>
(async function() {
  const slug = location.pathname.split('/').filter(Boolean).pop();
  const fragment = location.hash.slice(1);
  const loadingEl = document.getElementById('loading');
  const errorEl = document.getElementById('error');
  const resultEl = document.getElementById('result');
  const pwFormEl = document.getElementById('password-form');

  if (!fragment) { showError('No decryption key found in URL.'); return; }

  try {
    const res = await fetch('/api/v1/send/' + encodeURIComponent(slug));
    if (res.status === 401) {
      const data = await res.json();
      if (data.requires_password) {
        loadingEl.style.display = 'none';
        pwFormEl.style.display = 'block';
        window._slug = slug;
        window._fragment = fragment;
        return;
      }
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showError(data.error || 'Failed to access this send (HTTP ' + res.status + ')');
      return;
    }
    const data = await res.json();
    await decryptAndShow(data, fragment);
  } catch (e) {
    showError('Failed to load send: ' + e.message);
  }
})();

async function submitPassword() {
  const pw = document.getElementById('pw-input').value;
  if (!pw) return;
  const pwFormEl = document.getElementById('password-form');
  const loadingEl = document.getElementById('loading');
  pwFormEl.style.display = 'none';
  loadingEl.style.display = 'block';
  try {
    const res = await fetch('/api/v1/send/' + encodeURIComponent(window._slug) + '/access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      if (res.status === 401) {
        loadingEl.style.display = 'none';
        pwFormEl.style.display = 'block';
        showError('Incorrect password');
        return;
      }
      showError(data.error || 'Access failed');
      return;
    }
    const data = await res.json();
    await decryptAndShow(data, window._fragment);
  } catch (e) {
    showError('Failed: ' + e.message);
  }
}

async function decryptAndShow(data, keyB64) {
  const loadingEl = document.getElementById('loading');
  const resultEl = document.getElementById('result');
  const metaEl = document.getElementById('meta');
  const contentArea = document.getElementById('content-area');
  const actionsEl = document.getElementById('actions');

  try {
    // Decode the key from base64url
    const b64 = keyB64.replace(/-/g, '+').replace(/_/g, '/');
    const keyBytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);

    // Decode encrypted data
    const encBytes = hexToBytes(data.encrypted_data);
    const nonce = hexToBytes(data.nonce);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, encBytes);

    // Meta info
    const metaParts = [];
    if (data.sender_email) metaParts.push('From: ' + data.sender_email);
    if (data.expires_at) metaParts.push('Expires: ' + new Date(data.expires_at).toLocaleString());
    metaEl.textContent = metaParts.join(' · ');

    if (data.type === 'text') {
      const text = new TextDecoder().decode(decrypted);
      const box = document.createElement('div');
      box.className = 'content-box';
      box.textContent = text;
      contentArea.appendChild(box);

      const copyBtn = document.createElement('button');
      copyBtn.textContent = 'Copy Text';
      copyBtn.onclick = () => { navigator.clipboard.writeText(text); copyBtn.textContent = 'Copied!'; setTimeout(() => copyBtn.textContent = 'Copy Text', 2000); };
      actionsEl.appendChild(copyBtn);
    } else {
      const fn = data.file_name || 'download';
      const sz = data.file_size ? formatSize(data.file_size) : '';
      const info = document.createElement('p');
      info.className = 'info';
      info.textContent = '📄 ' + fn + (sz ? ' (' + sz + ')' : '');
      contentArea.appendChild(info);

      const dlBtn = document.createElement('button');
      dlBtn.textContent = 'Download File';
      dlBtn.onclick = () => {
        const blob = new Blob([decrypted]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = fn; a.click();
        URL.revokeObjectURL(url);
      };
      actionsEl.appendChild(dlBtn);
    }

    loadingEl.style.display = 'none';
    resultEl.style.display = 'block';
  } catch (e) {
    showError('Decryption failed. The link may be invalid or corrupted.');
  }
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function showError(msg) {
  document.getElementById('loading').style.display = 'none';
  const el = document.getElementById('error');
  el.textContent = msg;
  el.style.display = 'block';
}
</script>
</body>
</html>`

// ServeSendReceivePage serves the public Secure Send receive page.
func ServeSendReceivePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sendReceivePageHTML))
}
