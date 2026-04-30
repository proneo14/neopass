// Trigger org key propagation from user 2
const nodeCrypto = require('crypto');

const API = 'http://localhost:8444';
const email = 'nprohnitchi@lancastergroup.ca';
const password = 'Poisawesome14$';

async function main() {
  // Derive auth hash same as Electron client
  const salt = nodeCrypto.createHash('sha256').update(email).digest();
  const derived = nodeCrypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  const masterKeyHex = derived.subarray(0, 32).toString('hex');
  const authHashHex = derived.subarray(32, 64).toString('hex');

  console.log('masterKeyHex:', masterKeyHex);

  // Login
  const loginRes = await fetch(`${API}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, auth_hash: authHashHex }),
  });
  if (!loginRes.ok) {
    console.error('Login failed:', loginRes.status, await loginRes.text());
    process.exit(1);
  }
  const loginData = await loginRes.json();
  const token = loginData.access_token;
  console.log('Logged in as', email);

  // Get org ID
  const orgRes = await fetch(`${API}/api/v1/admin/my-org`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!orgRes.ok) {
    console.error('Get orgs failed:', orgRes.status, await orgRes.text());
    process.exit(1);
  }
  const orgs = await orgRes.json();
  console.log('Orgs:', JSON.stringify(orgs));
  
  const orgId = orgs.org_id || (Array.isArray(orgs) ? orgs[0].id : orgs.id);
  console.log('orgId:', orgId);

  // Call propagate-keys
  const propRes = await fetch(`${API}/api/v1/admin/orgs/${orgId}/propagate-keys`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ master_key: masterKeyHex }),
  });
  if (!propRes.ok) {
    console.error('Propagate failed:', propRes.status, await propRes.text());
    process.exit(1);
  }
  const propData = await propRes.json();
  console.log('Propagation result:', JSON.stringify(propData));
}

main().catch(err => { console.error(err); process.exit(1); });
