import{u as xe,r as a,j as e}from"./index-D4o5uMNm.js";const pe=[{label:"1 hour",hours:1},{label:"1 day",hours:24},{label:"2 days",hours:48},{label:"3 days",hours:72},{label:"7 days",hours:168},{label:"14 days",hours:336},{label:"30 days",hours:720}];function j(s){return Array.from(s).map(n=>n.toString(16).padStart(2,"0")).join("")}function ee(s){return btoa(String.fromCharCode(...s)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"")}async function fe(s){let n;if(s.password){const u=new TextEncoder,N=crypto.getRandomValues(new Uint8Array(16)),S=await crypto.subtle.importKey("raw",u.encode(s.password),"PBKDF2",!1,["deriveKey"]),y=await crypto.subtle.deriveKey({name:"PBKDF2",salt:N,iterations:1e5,hash:"SHA-256"},S,{name:"AES-GCM",length:256},!1,["encrypt"]),C=crypto.getRandomValues(new Uint8Array(12)),E=await crypto.subtle.encrypt({name:"AES-GCM",iv:C},y,s.keyBytes);n=JSON.stringify({protected:!0,salt:j(N),wrapIv:j(C),wrappedKey:j(new Uint8Array(E))})}else n=JSON.stringify({protected:!1,key:ee(s.keyBytes)});const f={};return s.expiresAt&&(f.expires=s.expiresAt),s.senderEmail&&(f.from=s.senderEmail),s.fileName&&(f.fileName=s.fileName),`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LGI Pass — Secure Send</title>
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
<h1>🔒 Secure Send</h1>
<div class="brand">Sent via LGI Pass</div>
<div id="loading" class="loading">Decrypting…</div>
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
var D=${JSON.stringify({type:s.sendType,data:s.encryptedDataHex,nonce:s.nonceHex,meta:f})};
var K=${n};
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
<\/script>
</body>
</html>`}function he(){const{email:s,token:n,masterKeyHex:f}=xe(),[u,N]=a.useState("create"),[S,y]=a.useState([]),[C,E]=a.useState(!1),[P,o]=a.useState(""),[R,b]=a.useState(""),[c,G]=a.useState("text"),[T,O]=a.useState(""),[I,V]=a.useState(""),[D,te]=a.useState(24),[x,J]=a.useState(""),[B,re]=a.useState(!1),[Y,g]=a.useState(!1),[d,ae]=a.useState(""),[m,K]=a.useState("file"),[A,X]=a.useState(""),[U,F]=a.useState(""),[v,M]=a.useState(""),[_,L]=a.useState(null),[se,$]=a.useState(null);a.useEffect(()=>{window.api.send.getDomain().then(t=>{ae(t),t&&K("link")}).catch(()=>{})},[]);const Z=a.useCallback(async()=>{if(n){E(!0);try{const t=await window.api.send.list(n);Array.isArray(t)&&y(t)}catch{o("Failed to load sends")}finally{E(!1)}}},[n]);a.useEffect(()=>{u==="list"&&Z()},[u,Z]);const ne=async()=>{if(!(!n||!f)){if(o(""),b(""),F(""),c==="text"&&!T.trim()){o("Please enter text content to send");return}if(c==="file"&&!_){o("Please select a file to send");return}g(!0);try{const t=new Uint8Array(32);crypto.getRandomValues(t);const r=c==="text"?new TextEncoder().encode(T):new Uint8Array(_),i=await crypto.subtle.importKey("raw",t,"AES-GCM",!1,["encrypt"]),l=crypto.getRandomValues(new Uint8Array(12)),de=await crypto.subtle.encrypt({name:"AES-GCM",iv:l},i,r),z=j(new Uint8Array(de)),H=j(l),me=ee(t),ue=new Date(Date.now()+D*36e5).toISOString();if(m==="link"&&d){const p={type:c,encrypted_data:z,nonce:H,expires_in_hours:D,hide_email:B};x&&(p.password=x),A&&parseInt(A)>0&&(p.max_access_count=parseInt(A)),c==="file"&&(p.file_name=v,p.file_size=r.length);const w=await window.api.send.create(n,p);if(w.error){o(w.error),g(!1);return}const h=`${d.replace(/\/+$/,"")}/send/${w.slug}#${me}`;F(h),b("Link created! The decryption key is in the URL fragment and never sent to the server.")}else{const p=await fe({sendType:c,encryptedDataHex:z,nonceHex:H,keyBytes:t,password:x,fileName:c==="file"?v:void 0,expiresAt:ue,senderEmail:B?void 0:s??void 0}),w=I?`${I.replace(/[^a-zA-Z0-9_-]/g,"_")}.html`:`lgipass-send-${new Date().toISOString().slice(0,10)}.html`,k=await window.api.send.saveFile(p,w);if(k.cancelled){g(!1);return}if(k.error){o(k.error),g(!1);return}const h={type:c,encrypted_data:z,nonce:H,expires_in_hours:D,hide_email:B};x&&(h.password=x),c==="file"&&(h.file_name=v,h.file_size=r.length),window.api.send.create(n,h).catch(()=>{}),b(`Saved to ${k.path}. Share this file — the recipient opens it in any browser.`)}O(""),V(""),J(""),X(""),M(""),L(null)}catch(t){o(t instanceof Error?t.message:"Failed to create send")}finally{g(!1)}}},oe=t=>{var l;const r=(l=t.target.files)==null?void 0:l[0];if(!r)return;if(r.size>100*1024*1024){o("File size exceeds 100MB limit");return}M(r.name);const i=new FileReader;i.onload=()=>L(i.result),i.readAsArrayBuffer(r)},ce=async t=>{if(n)try{const r=await window.api.send.delete(n,t);if(r.error){o(r.error);return}y(i=>i.filter(l=>l.id!==t)),$(null)}catch{o("Failed to delete send")}},ie=async t=>{if(n)try{const r=await window.api.send.disable(n,t);if(r.error){o(r.error);return}y(i=>i.map(l=>l.id===t?{...l,disabled:!0}:l))}catch{o("Failed to disable send")}},q=async(t,r="Link")=>{await navigator.clipboard.writeText(t),b(`${r} copied to clipboard!`),setTimeout(()=>b(i=>i.includes("copied")?"":i),2e3)},le=t=>t.disabled?{label:"Disabled",color:"text-surface-500"}:new Date(t.expires_at)<new Date?{label:"Expired",color:"text-red-400"}:t.max_access_count&&t.access_count>=t.max_access_count?{label:"Max reached",color:"text-orange-400"}:{label:"Active",color:"text-green-400"},Q=t=>new Date(t).toLocaleDateString(void 0,{month:"short",day:"numeric",year:"numeric",hour:"2-digit",minute:"2-digit"}),W=t=>t<1024?`${t} B`:t<1024*1024?`${(t/1024).toFixed(1)} KB`:`${(t/(1024*1024)).toFixed(1)} MB`;return e.jsxs("div",{className:"p-6 max-w-3xl mx-auto",children:[e.jsx("h1",{className:"text-2xl font-bold text-surface-100 mb-6",children:"Secure Send"}),e.jsx("div",{className:"flex gap-1 mb-6 bg-surface-800 rounded-lg p-1",children:["create","list"].map(t=>e.jsx("button",{onClick:()=>{N(t),o(""),b(""),F("")},className:`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors ${u===t?"bg-accent-600 text-white":"text-surface-400 hover:text-surface-200"}`,children:t==="create"?"Create Send":"My Sends"},t))}),P&&e.jsx("div",{className:"mb-4 p-3 rounded-md bg-red-500/10 border border-red-500/30 text-red-400 text-sm",children:P}),R&&e.jsx("div",{className:"mb-4 p-3 rounded-md bg-green-500/10 border border-green-500/30 text-green-400 text-sm",children:R}),U&&e.jsxs("div",{className:"mb-4 p-4 rounded-md bg-accent-600/10 border border-accent-500/30",children:[e.jsx("p",{className:"text-sm text-surface-300 mb-2 font-medium",children:"Share this link:"}),e.jsxs("div",{className:"flex gap-2",children:[e.jsx("input",{type:"text",readOnly:!0,value:U,className:"flex-1 px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 text-sm font-mono"}),e.jsx("button",{onClick:()=>q(U),className:"px-4 py-2 bg-accent-600 hover:bg-accent-500 text-white text-sm rounded-md whitespace-nowrap",children:"Copy"})]}),e.jsxs("p",{className:"text-xs text-surface-500 mt-2",children:["The decryption key is in the # fragment — it's never sent to the server.",x&&" The recipient will also need the password you set."]})]}),u==="create"&&e.jsxs("div",{className:"space-y-5",children:[d&&e.jsxs("div",{children:[e.jsx("label",{className:"block text-sm font-medium text-surface-300 mb-2",children:"Share Method"}),e.jsxs("div",{className:"flex gap-2",children:[e.jsx("button",{onClick:()=>K("link"),className:`flex-1 px-4 py-2 rounded-md text-sm font-medium border transition-colors ${m==="link"?"border-accent-500 bg-accent-600/20 text-accent-400":"border-surface-600 text-surface-400 hover:border-surface-500"}`,children:"🔗 Link"}),e.jsx("button",{onClick:()=>K("file"),className:`flex-1 px-4 py-2 rounded-md text-sm font-medium border transition-colors ${m==="file"?"border-accent-500 bg-accent-600/20 text-accent-400":"border-surface-600 text-surface-400 hover:border-surface-500"}`,children:"📁 File"})]}),e.jsx("p",{className:"text-xs text-surface-500 mt-1",children:m==="link"?"Share a URL. Password protection, access limits, and disable are enforced server-side.":"Generate a self-contained HTML file. No server needed — works offline in any browser."})]}),e.jsxs("div",{children:[e.jsx("label",{className:"block text-sm font-medium text-surface-300 mb-2",children:"Type"}),e.jsxs("div",{className:"flex gap-2",children:[e.jsx("button",{onClick:()=>G("text"),className:`flex-1 px-4 py-2 rounded-md text-sm font-medium border transition-colors ${c==="text"?"border-accent-500 bg-accent-600/20 text-accent-400":"border-surface-600 text-surface-400 hover:border-surface-500"}`,children:"📝 Text"}),e.jsx("button",{onClick:()=>G("file"),className:`flex-1 px-4 py-2 rounded-md text-sm font-medium border transition-colors ${c==="file"?"border-accent-500 bg-accent-600/20 text-accent-400":"border-surface-600 text-surface-400 hover:border-surface-500"}`,children:"📄 File"})]})]}),c==="text"?e.jsxs("div",{children:[e.jsx("label",{className:"block text-sm font-medium text-surface-300 mb-2",children:"Content"}),e.jsx("textarea",{value:T,onChange:t=>O(t.target.value),rows:6,placeholder:"Enter the text you want to share securely…",className:"w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 focus:border-accent-500 resize-y"})]}):e.jsxs("div",{children:[e.jsx("label",{className:"block text-sm font-medium text-surface-300 mb-2",children:"File"}),e.jsx("div",{className:"border-2 border-dashed border-surface-600 rounded-md p-6 text-center",children:v?e.jsxs("div",{className:"text-surface-200",children:[e.jsx("span",{className:"text-lg",children:"📄"})," ",v,_&&e.jsxs("span",{className:"text-surface-500 ml-2",children:["(",W(_.byteLength),")"]}),e.jsx("button",{onClick:()=>{M(""),L(null)},className:"ml-3 text-red-400 hover:text-red-300 text-sm",children:"Remove"})]}):e.jsxs("label",{className:"cursor-pointer",children:[e.jsx("span",{className:"text-surface-400",children:"Click to select a file or drag & drop"}),e.jsx("span",{className:"block text-surface-500 text-xs mt-1",children:"Max 100MB"}),e.jsx("input",{type:"file",className:"hidden",onChange:oe})]})})]}),e.jsxs("div",{className:"grid grid-cols-2 gap-4",children:[e.jsxs("div",{children:[e.jsx("label",{className:"block text-sm font-medium text-surface-300 mb-1",children:"Name (optional)"}),e.jsx("input",{type:"text",value:I,onChange:t=>V(t.target.value),placeholder:"Descriptive name",className:"w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"})]}),e.jsxs("div",{children:[e.jsx("label",{className:"block text-sm font-medium text-surface-300 mb-1",children:"Expiration"}),e.jsx("select",{value:D,onChange:t=>te(Number(t.target.value)),className:"w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm",children:pe.map(t=>e.jsx("option",{value:t.hours,children:t.label},t.hours))})]}),e.jsxs("div",{className:m==="link"&&d?"":"col-span-2",children:[e.jsx("label",{className:"block text-sm font-medium text-surface-300 mb-1",children:"Password (optional)"}),e.jsx("input",{type:"password",value:x,onChange:t=>J(t.target.value),placeholder:"Recipient must enter this to decrypt",className:"w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"})]}),m==="link"&&d&&e.jsxs("div",{children:[e.jsx("label",{className:"block text-sm font-medium text-surface-300 mb-1",children:"Max accesses"}),e.jsx("input",{type:"number",min:"1",value:A,onChange:t=>X(t.target.value),placeholder:"Unlimited",className:"w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-md text-surface-100 placeholder-surface-500 focus:outline-none focus:ring-1 focus:ring-accent-500 text-sm"})]})]}),e.jsxs("label",{className:"flex items-center gap-2 text-sm text-surface-300",children:[e.jsx("input",{type:"checkbox",checked:B,onChange:t=>re(t.target.checked),className:"rounded border-surface-600 bg-surface-800 text-accent-500 focus:ring-accent-500"}),"Hide my email from recipients"]}),e.jsx("button",{onClick:ne,disabled:Y,className:"w-full py-2.5 bg-accent-600 hover:bg-accent-500 text-white font-medium rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed",children:Y?"Creating…":m==="link"&&d?"Create & Copy Link":"Create & Save File"}),e.jsxs("p",{className:"text-xs text-surface-500 text-center",children:[m==="link"&&d?"Creates a server-hosted send with a shareable link. Password verification and access limits are enforced server-side.":"Generates a self-contained HTML file. Share it via email, messaging, USB — the recipient opens it in any browser. No server or account needed.",!d&&e.jsx("span",{className:"block mt-1 text-surface-600",children:"Tip: Set a domain in Settings → Secure Send to enable link-based sharing."})]})]}),u==="list"&&e.jsx("div",{children:C?e.jsx("div",{className:"text-center py-8 text-surface-500",children:"Loading…"}):S.length===0?e.jsxs("div",{className:"text-center py-8 text-surface-500",children:[e.jsx("p",{className:"text-lg mb-1",children:"No sends yet"}),e.jsx("p",{className:"text-sm",children:"Create a send to share text or files securely."})]}):e.jsx("div",{className:"space-y-3",children:S.map(t=>{const r=le(t);return e.jsxs("div",{className:"p-4 bg-surface-800 rounded-lg border border-surface-700",children:[e.jsxs("div",{className:"flex items-center justify-between mb-2",children:[e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx("span",{children:t.send_type==="text"?"📝":"📄"}),e.jsx("span",{className:"text-surface-200 font-medium text-sm",children:t.file_name||"Unnamed send"}),e.jsx("span",{className:`text-xs font-medium ${r.color}`,children:r.label})]}),e.jsxs("div",{className:"flex items-center gap-2",children:[d&&t.slug&&!t.disabled&&r.label==="Active"&&e.jsx("button",{onClick:()=>q(`${d.replace(/\/+$/,"")}/send/${t.slug}`,"Link"),className:"px-2 py-1 text-xs text-accent-400 hover:text-accent-300 border border-accent-600/50 rounded transition-colors",title:"Copy link (you'll need to append the key fragment)",children:"Copy Link"}),!t.disabled&&r.label==="Active"&&e.jsx("button",{onClick:()=>ie(t.id),className:"px-2 py-1 text-xs text-orange-400 hover:text-orange-300 border border-orange-600/50 rounded transition-colors",children:"Disable"}),se===t.id?e.jsxs("div",{className:"flex items-center gap-1",children:[e.jsx("button",{onClick:()=>ce(t.id),className:"px-2 py-1 text-xs text-red-400 hover:text-red-300 border border-red-600/50 rounded",children:"Confirm"}),e.jsx("button",{onClick:()=>$(null),className:"px-2 py-1 text-xs text-surface-400 hover:text-surface-300 border border-surface-600 rounded",children:"Cancel"})]}):e.jsx("button",{onClick:()=>$(t.id),className:"px-2 py-1 text-xs text-red-400 hover:text-red-300 border border-red-600/50 rounded transition-colors",children:"Delete"})]})]}),e.jsxs("div",{className:"flex items-center gap-4 text-xs text-surface-500",children:[e.jsxs("span",{children:["Created: ",Q(t.created_at)]}),e.jsxs("span",{children:["Expires: ",Q(t.expires_at)]}),t.has_password&&e.jsx("span",{children:"🔒 Password"}),t.max_access_count&&e.jsxs("span",{children:["👁 ",t.access_count,"/",t.max_access_count]}),t.file_size&&e.jsx("span",{children:W(t.file_size)})]})]},t.id)})})})]})}export{he as Send};
