import React, { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '../store/authStore';

interface SendSummary {
  id: string;
  slug: string;
  send_type: 'text' | 'file';
  has_password: boolean;
  max_access_count?: number;
  access_count: number;
  file_name?: string;
  file_size?: number;
  expires_at: string;
  disabled: boolean;
  hide_email: boolean;
  created_at: string;
  encrypted_name?: string;
  name_nonce?: string;
}

type SendTab = 'create' | 'list';
type ShareMode = 'file' | 'link';

const EXPIRY_OPTIONS = [
  { label: '1 hour', hours: 1 },
  { label: '1 day', hours: 24 },
  { label: '2 days', hours: 48 },
  { label: '3 days', hours: 72 },
  { label: '7 days', hours: 168 },
  { label: '14 days', hours: 336 },
  { label: '30 days', hours: 720 },
];

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function toBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generate a self-contained HTML file that decrypts and displays the send.
 * If a password is set, the AES key is wrapped with a PBKDF2-derived key,
 * and the recipient must enter the password to unlock.
 * If no password, the AES key is embedded and content decrypts immediately.
 */
async function generateSendHTML(opts: {
  sendType: 'text' | 'file';
  encryptedDataHex: string;
  nonceHex: string;
  keyBytes: Uint8Array;
  password: string;
  fileName?: string;
  expiresAt: string;
  senderEmail?: string;
}): Promise<string> {
  let keyPayload: string;
  if (opts.password) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const pwKey = await crypto.subtle.importKey('raw', enc.encode(opts.password), 'PBKDF2', false, ['deriveKey']);
    const wrappingKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      pwKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
    );
    const wrapIv = crypto.getRandomValues(new Uint8Array(12));
    const wrappedKey = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wrapIv }, wrappingKey, opts.keyBytes as BufferSource);
    keyPayload = JSON.stringify({
      protected: true,
      salt: bytesToHex(salt),
      wrapIv: bytesToHex(wrapIv),
      wrappedKey: bytesToHex(new Uint8Array(wrappedKey)),
    });
  } else {
    keyPayload = JSON.stringify({
      protected: false,
      key: toBase64Url(opts.keyBytes),
    });
  }

  const meta: Record<string, string> = {};
  if (opts.expiresAt) meta.expires = opts.expiresAt;
  if (opts.senderEmail) meta.from = opts.senderEmail;
  if (opts.fileName) meta.fileName = opts.fileName;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LGI Pass \u2014 Secure Send</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;max-width:600px;width:90%}
h1{font-size:1.25rem;font-weight:600;margin-bottom:.25rem}
.brand{color:#94a3b8;font-size:.75rem;margin-bottom:1.5rem}
.error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#f87171;padding:.75rem;border-radius:8px;margin-bottom:1rem;font-size:.875rem;display:none}
.info{color:#94a3b8;font-size:.875rem;margin-bottom:1rem}
.content-box{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:1rem;white-space:pre-wrap;word-break:break-word;max-height:400px;overflow-y:auto;font-size:.875rem;line-height:1.5;margin-bottom:1rem}
.meta{display:flex;gap:1rem;flex-wrap:wrap;font-size:.75rem;color:#64748b;margin-bottom:1rem}
button{background:#3b82f6;color:#fff;border:none;padding:.625rem 1.25rem;border-radius:6px;cursor:pointer;font-size:.875rem;font-weight:500;transition:background .2s}
button:hover{background:#2563eb}
.btn-row{display:flex;gap:.5rem}
input[type="password"]{width:100%;padding:.625rem;background:#0f172a;border:1px solid #475569;border-radius:6px;color:#e2e8f0;font-size:.875rem;margin-bottom:1rem;outline:none}
input[type="password"]:focus{border-color:#3b82f6}
.loading{text-align:center;padding:2rem;color:#94a3b8}
.expired{text-align:center;padding:2rem}
.expired-icon{font-size:2rem;margin-bottom:.5rem}
</style>
</head>
<body>
<div class="card">
<h1>\ud83d\udd12 Secure Send</h1>
<div class="brand">Sent via LGI Pass</div>
<div id="loading" class="loading">Decrypting\u2026</div>
<div id="error" class="error"></div>
<div id="pw-form" style="display:none">
<p class="info">This send is password protected.</p>
<input type="password" id="pw" placeholder="Enter password" autocomplete="off" />
<button onclick="unlock()">Unlock</button>
</div>
<div id="result" style="display:none">
<div id="meta" class="meta"></div>
<div id="content"></div>
<div class="btn-row" id="actions"></div>
</div>
</div>
<script>
var D=${JSON.stringify({ type: opts.sendType, data: opts.encryptedDataHex, nonce: opts.nonceHex, meta })};
var K=${keyPayload};
(async function(){
try{
var exp=D.meta&&D.meta.expires?new Date(D.meta.expires):null;
if(exp&&exp<new Date()){
document.getElementById('loading').style.display='none';
document.getElementById('result').style.display='block';
document.getElementById('content').innerHTML='<div class="expired"><div class="expired-icon">&#9200;</div><p>This send has expired.</p></div>';
return}
if(K.protected){document.getElementById('loading').style.display='none';document.getElementById('pw-form').style.display='block';return}
var b64=K.key.replace(/-/g,'+').replace(/_/g,'/');
var kb=Uint8Array.from(atob(b64),function(c){return c.charCodeAt(0)});
await show(kb)
}catch(e){err(e.message)}
})();
async function unlock(){
var pw=document.getElementById('pw').value;
if(!pw)return;
document.getElementById('pw-form').style.display='none';
document.getElementById('loading').style.display='block';
document.getElementById('error').style.display='none';
try{
var enc=new TextEncoder();
var salt=hexB(K.salt);
var pwk=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']);
var wk=await crypto.subtle.deriveKey({name:'PBKDF2',salt:salt,iterations:100000,hash:'SHA-256'},pwk,{name:'AES-GCM',length:256},false,['decrypt']);
var iv=hexB(K.wrapIv);
var wrapped=hexB(K.wrappedKey);
var raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},wk,wrapped);
await show(new Uint8Array(raw))
}catch(e){
document.getElementById('loading').style.display='none';
document.getElementById('pw-form').style.display='block';
err('Incorrect password or corrupted data')}
}
async function show(keyBytes){
var ck=await crypto.subtle.importKey('raw',keyBytes,'AES-GCM',false,['decrypt']);
var ct=hexB(D.data);
var iv=hexB(D.nonce);
var dec=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},ck,ct);
var metaEl=document.getElementById('meta');
var contentEl=document.getElementById('content');
var actEl=document.getElementById('actions');
var parts=[];
if(D.meta.from)parts.push('From: '+D.meta.from);
if(D.meta.expires)parts.push('Expires: '+new Date(D.meta.expires).toLocaleString());
metaEl.textContent=parts.join(' \\u00b7 ');
if(D.type==='text'){
var txt=new TextDecoder().decode(dec);
var box=document.createElement('div');box.className='content-box';box.textContent=txt;
contentEl.appendChild(box);
var cb=document.createElement('button');cb.textContent='Copy Text';
cb.onclick=function(){navigator.clipboard.writeText(txt);cb.textContent='Copied!';setTimeout(function(){cb.textContent='Copy Text'},2000)};
actEl.appendChild(cb)
}else{
var fn=D.meta.fileName||'download';
var info=document.createElement('p');info.className='info';info.textContent='\\ud83d\\udcc4 '+fn;
contentEl.appendChild(info);
var db=document.createElement('button');db.textContent='Download File';
db.onclick=function(){var b=new Blob([dec]);var u=URL.createObjectURL(b);var a=document.createElement('a');a.href=u;a.download=fn;a.click();URL.revokeObjectURL(u)};
actEl.appendChild(db)
}
document.getElementById('loading').style.display='none';
document.getElementById('result').style.display='block'
}
function hexB(h){var b=new Uint8Array(h.length/2);for(var i=0;i<h.length;i+=2)b[i/2]=parseInt(h.substr(i,2),16);return b}
function err(m){var e=document.getElementById('error');e.textContent=m;e.style.display='block'}
</script>
</body>
</html>`;
}

export function Send() {
  const { email, token, masterKeyHex } = useAuthStore();
  const [activeTab, setActiveTab] = useState<SendTab>('create');
  const [sends, setSends] = useState<SendSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Create form state
  const [sendType, setSendType] = useState<'text' | 'file'>('text');
  const [textContent, setTextContent] = useState('');
  const [sendName, setSendName] = useState('');
  const [expiryHours, setExpiryHours] = useState(24);
  const [password, setPassword] = useState('');
  const [hideEmail, setHideEmail] = useState(false);
  const [creating, setCreating] = useState(false);

  // Share mode
  const [sendDomain, setSendDomain] = useState('');
  const [shareMode, setShareMode] = useState<ShareMode>('file');
  const [maxAccess, setMaxAccess] = useState('');
  const [shareUrl, setShareUrl] = useState('');

  // File state
  const [fileName, setFileName] = useState('');
  const [fileData, setFileData] = useState<ArrayBuffer | null>(null);

  // Deletion confirm
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  useEffect(() => {
    window.api.send.getDomain().then((d) => {
      setSendDomain(d);
      if (d) setShareMode('link');
    }).catch(() => {});
  }, []);

  const fetchSends = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const result = await window.api.send.list(token);
      if (Array.isArray(result)) {
        setSends(result);
      }
    } catch {
      setError('Failed to load sends');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (activeTab === 'list') {
      fetchSends();
    }
  }, [activeTab, fetchSends]);

  const handleCreate = async () => {
    if (!token || !masterKeyHex) return;
    setError('');
    setSuccess('');
    setShareUrl('');

    if (sendType === 'text' && !textContent.trim()) {
      setError('Please enter text content to send');
      return;
    }
    if (sendType === 'file' && !fileData) {
      setError('Please select a file to send');
      return;
    }

    setCreating(true);
    try {
      // Generate a random 32-byte key for this send
      const keyBytes = new Uint8Array(32);
      crypto.getRandomValues(keyBytes);

      // Encode content
      const contentBytes = sendType === 'text'
        ? new TextEncoder().encode(textContent)
        : new Uint8Array(fileData!);

      // Encrypt with AES-256-GCM
      const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, contentBytes);
      const encryptedHex = bytesToHex(new Uint8Array(encrypted));
      const nonceHex = bytesToHex(nonce);
      const keyB64 = toBase64Url(keyBytes);

      const expiresAt = new Date(Date.now() + expiryHours * 3600_000).toISOString();

      if (shareMode === 'link' && sendDomain) {
        // --- Link mode: create on server, return URL with key in fragment ---
        const data: Record<string, unknown> = {
          type: sendType,
          encrypted_data: encryptedHex,
          nonce: nonceHex,
          expires_in_hours: expiryHours,
          hide_email: hideEmail,
        };
        if (password) data.password = password;
        if (maxAccess && parseInt(maxAccess) > 0) data.max_access_count = parseInt(maxAccess);
        if (sendType === 'file') {
          data.file_name = fileName;
          data.file_size = contentBytes.length;
        }

        const result = await window.api.send.create(token, data) as { slug?: string; error?: string };
        if (result.error) {
          setError(result.error);
          setCreating(false);
          return;
        }

        const domain = sendDomain.replace(/\/+$/, '');
        const url = `${domain}/send/${result.slug}#${keyB64}`;
        setShareUrl(url);
        setSuccess('Link created! The decryption key is in the URL fragment and never sent to the server.');
      } else {
        // --- File mode: generate self-contained HTML ---
        const html = await generateSendHTML({
          sendType,
          encryptedDataHex: encryptedHex,
          nonceHex,
          keyBytes,
          password,
          fileName: sendType === 'file' ? fileName : undefined,
          expiresAt,
          senderEmail: hideEmail ? undefined : (email ?? undefined),
        });

        const defaultName = sendName
          ? `${sendName.replace(/[^a-zA-Z0-9_-]/g, '_')}.html`
          : `lgipass-send-${new Date().toISOString().slice(0, 10)}.html`;

        const saveResult = await window.api.send.saveFile(html, defaultName);
        if (saveResult.cancelled) {
          setCreating(false);
          return;
        }
        if (saveResult.error) {
          setError(saveResult.error);
          setCreating(false);
          return;
        }

        // Fire-and-forget backend save for tracking
        const data: Record<string, unknown> = {
          type: sendType,
          encrypted_data: encryptedHex,
          nonce: nonceHex,
          expires_in_hours: expiryHours,
          hide_email: hideEmail,
        };
        if (password) data.password = password;
        if (sendType === 'file') {
          data.file_name = fileName;
          data.file_size = contentBytes.length;
        }
        window.api.send.create(token, data).catch(() => {});

        setSuccess(`Saved to ${saveResult.path}. Share this file — the recipient opens it in any browser.`);
      }

      // Reset form
      setTextContent('');
      setSendName('');
      setPassword('');
      setMaxAccess('');
      setFileName('');
      setFileData(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create send');
    } finally {
      setCreating(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 100 * 1024 * 1024) {
      setError('File size exceeds 100MB limit');
      return;
    }
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => setFileData(reader.result as ArrayBuffer);
    reader.readAsArrayBuffer(file);
  };

  const handleDelete = async (sendId: string) => {
    if (!token) return;
    try {
      const result = await window.api.send.delete(token, sendId) as { error?: string };
      if (result.error) {
        setError(result.error);
        return;
      }
      setSends((prev) => prev.filter((s) => s.id !== sendId));
      setConfirmDelete(null);
    } catch {
      setError('Failed to delete send');
    }
  };

  const handleDisable = async (sendId: string) => {
    if (!token) return;
    try {
      const result = await window.api.send.disable(token, sendId) as { error?: string };
      if (result.error) {
        setError(result.error);
        return;
      }
      setSends((prev) => prev.map((s) => s.id === sendId ? { ...s, disabled: true } : s));
    } catch {
      setError('Failed to disable send');
    }
  };

  const copyToClipboard = async (text: string, label = 'Link') => {
    await navigator.clipboard.writeText(text);
    setSuccess(`${label} copied to clipboard!`);
    setTimeout(() => setSuccess((s) => s.includes('copied') ? '' : s), 2000);
  };

  const getSendStatus = (send: SendSummary): { label: string; color: string } => {
    if (send.disabled) return { label: 'Disabled', color: 'text-surface-500' };
    const expired = new Date(send.expires_at) < new Date();
    if (expired) return { label: 'Expired', color: 'text-red-400' };
    if (send.max_access_count && send.access_count >= send.max_access_count)
      return { label: 'Max reached', color: 'text-orange-400' };
    return { label: 'Active', color: 'text-green-400' };
  };

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold text-surface-100 mb-6">Secure Send</h1>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-surface-800 rounded-lg p-1">
        {(['create', 'list'] as SendTab[]).map((tab) => (
          <button
            key={tab}
            onClick={() => { setActiveTab(tab); setError(''); setSuccess(''); setShareUrl(''); }}
            className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab
                ? 'bg-accent-600 text-white'
                : 'text-surface-400 hover:text-surface-200'
            }`}
          >
            {tab === 'create' ? 'Create Send' : 'My Sends'}
          </button>
        ))}
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-md bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 p-3 rounded-md bg-green-500/10 border border-green-500/30 text-green-400 text-sm">
          {success}
        </div>
      )}

      {/* Share URL display */}
      {shareUrl && (
        <div className="mb-4 p-4 rounded-md bg-accent-600/10 border border-accent-500/30">
          <p className="text-sm text-surface-300 mb-2 font-medium">Share this link:</p>
          <div className="flex gap-2">
            <input
              type="text"
              readOnly
              value={shareUrl}
              className="flex-1 px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 text-sm font-mono"
            />
            <button
              onClick={() => copyToClipboard(shareUrl)}
              className="px-4 py-2 bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-md whitespace-nowrap"
            >
              Copy
            </button>
          </div>
          <p className="text-xs text-surface-500 mt-2">
            The decryption key is in the # fragment — it&apos;s never sent to the server.
            {password && ' The recipient will also need the password you set.'}
          </p>
        </div>
      )}

      {activeTab === 'create' && (
        <div className="space-y-5">
          {/* Share mode selector (only when domain is configured) */}
          {sendDomain && (
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-2">Share Method</label>
              <div className="flex gap-2">
                <button
                  onClick={() => setShareMode('link')}
                  className={`flex-1 px-4 py-2 rounded-md text-sm font-medium border transition-colors ${
                    shareMode === 'link'
                      ? 'border-accent-500 bg-accent-600/20 text-accent-400'
                      : 'border-surface-600 text-surface-400 hover:border-surface-500'
                  }`}
                >
                  🔗 Link
                </button>
                <button
                  onClick={() => setShareMode('file')}
                  className={`flex-1 px-4 py-2 rounded-md text-sm font-medium border transition-colors ${
                    shareMode === 'file'
                      ? 'border-accent-500 bg-accent-600/20 text-accent-400'
                      : 'border-surface-600 text-surface-400 hover:border-surface-500'
                  }`}
                >
                  📁 File
                </button>
              </div>
              <p className="text-xs text-surface-500 mt-1">
                {shareMode === 'link'
                  ? 'Share a URL. Password protection, access limits, and disable are enforced server-side.'
                  : 'Generate a self-contained HTML file. No server needed — works offline in any browser.'}
              </p>
            </div>
          )}

          {/* Type selector */}
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-2">Type</label>
            <div className="flex gap-2">
              <button
                onClick={() => setSendType('text')}
                className={`flex-1 px-4 py-2 rounded-md text-sm font-medium border transition-colors ${
                  sendType === 'text'
                    ? 'border-accent-500 bg-accent-600/20 text-accent-400'
                    : 'border-surface-600 text-surface-400 hover:border-surface-500'
                }`}
              >
                📝 Text
              </button>
              <button
                onClick={() => setSendType('file')}
                className={`flex-1 px-4 py-2 rounded-md text-sm font-medium border transition-colors ${
                  sendType === 'file'
                    ? 'border-accent-500 bg-accent-600/20 text-accent-400'
                    : 'border-surface-600 text-surface-400 hover:border-surface-500'
                }`}
              >
                📄 File
              </button>
            </div>
          </div>

          {/* Content */}
          {sendType === 'text' ? (
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-2">Content</label>
              <textarea
                value={textContent}
                onChange={(e) => setTextContent(e.target.value)}
                rows={6}
                placeholder="Enter the text you want to share securely…"
                className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 focus:border-accent-500 resize-y"
              />
            </div>
          ) : (
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-2">File</label>
              <div className="border-2 border-dashed border-surface-600 rounded-md p-6 text-center">
                {fileName ? (
                  <div className="text-surface-200">
                    <span className="text-lg">📄</span> {fileName}
                    {fileData && <span className="text-surface-500 ml-2">({formatSize(fileData.byteLength)})</span>}
                    <button
                      onClick={() => { setFileName(''); setFileData(null); }}
                      className="ml-3 text-red-400 hover:text-red-300 text-sm"
                    >
                      Remove
                    </button>
                  </div>
                ) : (
                  <label className="cursor-pointer">
                    <span className="text-surface-400">Click to select a file or drag & drop</span>
                    <span className="block text-surface-500 text-xs mt-1">Max 100MB</span>
                    <input type="file" className="hidden" onChange={handleFileSelect} />
                  </label>
                )}
              </div>
            </div>
          )}

          {/* Options */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1">Name (optional)</label>
              <input
                type="text"
                value={sendName}
                onChange={(e) => setSendName(e.target.value)}
                placeholder="Descriptive name"
                className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1">Expiration</label>
              <select
                value={expiryHours}
                onChange={(e) => setExpiryHours(Number(e.target.value))}
                className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
              >
                {EXPIRY_OPTIONS.map((opt) => (
                  <option key={opt.hours} value={opt.hours}>{opt.label}</option>
                ))}
              </select>
            </div>
            <div className={shareMode === 'link' && sendDomain ? '' : 'col-span-2'}>
              <label className="block text-sm font-medium text-surface-300 mb-1">Password (optional)</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Recipient must enter this to decrypt"
                className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
              />
            </div>
            {shareMode === 'link' && sendDomain && (
              <div>
                <label className="block text-sm font-medium text-surface-300 mb-1">Max accesses</label>
                <input
                  type="number"
                  min="1"
                  value={maxAccess}
                  onChange={(e) => setMaxAccess(e.target.value)}
                  placeholder="Unlimited"
                  className="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"
                />
              </div>
            )}
          </div>

          <label className="flex items-center gap-2 text-sm text-surface-300">
            <input
              type="checkbox"
              checked={hideEmail}
              onChange={(e) => setHideEmail(e.target.checked)}
              className="rounded border-surface-600 bg-surface-800 text-accent-500 focus:ring-accent-500"
            />
            Hide my email from recipients
          </label>

          <button
            onClick={handleCreate}
            disabled={creating}
            className="w-full py-2.5 bg-accent-600 hover:bg-accent-500 text-white font-medium rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {creating
              ? 'Creating…'
              : shareMode === 'link' && sendDomain
                ? 'Create & Copy Link'
                : 'Create & Save File'}
          </button>

          <p className="text-xs text-surface-500 text-center">
            {shareMode === 'link' && sendDomain
              ? 'Creates a server-hosted send with a shareable link. Password verification and access limits are enforced server-side.'
              : 'Generates a self-contained HTML file. Share it via email, messaging, USB — the recipient opens it in any browser. No server or account needed.'}
            {!sendDomain && (
              <span className="block mt-1 text-surface-600">
                Tip: Set a domain in Settings → Secure Send to enable link-based sharing.
              </span>
            )}
          </p>
        </div>
      )}

      {activeTab === 'list' && (
        <div>
          {loading ? (
            <div className="text-center py-8 text-surface-500">Loading…</div>
          ) : sends.length === 0 ? (
            <div className="text-center py-8 text-surface-500">
              <p className="text-lg mb-1">No sends yet</p>
              <p className="text-sm">Create a send to share text or files securely.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {sends.map((send) => {
                const status = getSendStatus(send);
                return (
                  <div key={send.id} className="p-4 bg-surface-800 rounded-lg border border-surface-700">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span>{send.send_type === 'text' ? '📝' : '📄'}</span>
                        <span className="text-surface-200 font-medium text-sm">
                          {send.file_name || 'Unnamed send'}
                        </span>
                        <span className={`text-xs font-medium ${status.color}`}>{status.label}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {sendDomain && send.slug && !send.disabled && status.label === 'Active' && (
                          <button
                            onClick={() => copyToClipboard(`${sendDomain.replace(/\/+$/, '')}/send/${send.slug}`, 'Link')}
                            className="px-2 py-1 text-xs text-accent-400 hover:text-accent-300 border border-accent-600/50 rounded transition-colors"
                            title="Copy link (you'll need to append the key fragment)"
                          >
                            Copy Link
                          </button>
                        )}
                        {!send.disabled && status.label === 'Active' && (
                          <button
                            onClick={() => handleDisable(send.id)}
                            className="px-2 py-1 text-xs text-orange-400 hover:text-orange-300 border border-orange-600/50 rounded transition-colors"
                          >
                            Disable
                          </button>
                        )}
                        {confirmDelete === send.id ? (
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => handleDelete(send.id)}
                              className="px-2 py-1 text-xs text-red-400 hover:text-red-300 border border-red-600/50 rounded"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setConfirmDelete(null)}
                              className="px-2 py-1 text-xs text-surface-400 hover:text-surface-300 border border-surface-600 rounded"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmDelete(send.id)}
                            className="px-2 py-1 text-xs text-red-400 hover:text-red-300 border border-red-600/50 rounded transition-colors"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-surface-500">
                      <span>Created: {formatDate(send.created_at)}</span>
                      <span>Expires: {formatDate(send.expires_at)}</span>
                      {send.has_password && <span>🔒 Password</span>}
                      {send.max_access_count && (
                        <span>👁 {send.access_count}/{send.max_access_count}</span>
                      )}
                      {send.file_size && <span>{formatSize(send.file_size)}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
