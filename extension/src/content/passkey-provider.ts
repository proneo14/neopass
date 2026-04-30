/**
 * Passkey provider – intercepts navigator.credentials.create/get
 * and routes WebAuthn requests through the LGI Pass extension.
 *
 * This script runs in the MAIN world (page context) so it has NO access
 * to chrome.runtime / browser extension APIs.  Communication goes through
 * window.postMessage ↔ content-script (ISOLATED world) ↔ service-worker.
 *
 * Injected from content.ts via <script src="passkey-provider.js">.
 */

// Guard against double injection
if ((window as any).__lgiPasskeyProvider) {
  // Already injected, skip
} else {
(window as any).__lgiPasskeyProvider = true;

const PASSKEY_REQ = 'lgipass-passkey-request';
const PASSKEY_RES = 'lgipass-passkey-response';

let reqCounter = 0;

console.debug('[LGI Pass] passkey provider loaded on', window.location.hostname);

/** Decode a base64url string to a Uint8Array. */
const b64urlToBytes = (b64: string): Uint8Array => {
  let s = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Encode a Uint8Array or ArrayBuffer to base64url (no padding). */
const bytesToB64url = (buf: ArrayBuffer | Uint8Array): string => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Send a message to the ISOLATED-world content script and wait for a reply. */
const sendPasskeyMessage = (payload: Record<string, unknown>): Promise<Record<string, unknown>> => {
  return new Promise((resolve) => {
    const id = `pk_${++reqCounter}_${Date.now()}`;

    function onReply(event: MessageEvent) {
      if (
        event.source !== window ||
        event.data?.type !== PASSKEY_RES ||
        event.data?.id !== id
      ) return;
      window.removeEventListener('message', onReply);
      resolve(event.data.payload ?? { error: 'empty response' });
    }

    window.addEventListener('message', onReply);
    window.postMessage({ type: PASSKEY_REQ, id, payload }, '*');

    // Timeout after 15 s so we don't hang forever
    setTimeout(() => {
      window.removeEventListener('message', onReply);
      resolve({ error: 'timeout' });
    }, 15_000);
  });
}

/**
 * Build a PublicKeyCredential for navigator.credentials.create().
 * Websites call getClientExtensionResults(), response.getTransports(), etc.
 */
const buildCreateCredential = (data: Record<string, unknown>, challenge: string): PublicKeyCredential => {
  const credIdBytes = b64urlToBytes(data.credential_id as string);
  const attestObjBytes = b64urlToBytes(data.attestation_object as string);
  const clientDataJSON = b64urlToBytes(data.client_data_json as string);
  const authDataBytes = b64urlToBytes(data.auth_data as string);
  const publicKeyBytes = data.public_key_spki
    ? b64urlToBytes(data.public_key_spki as string)
    : b64urlToBytes(data.public_key as string);
  const transports = (data.transports as string[]) || ['internal'];
  const algorithm = (data.public_key_algorithm as number) || -7;

  const response = {
    attestationObject: attestObjBytes.buffer,
    clientDataJSON: clientDataJSON.buffer,
    getTransports: () => transports,
    getAuthenticatorData: () => authDataBytes.buffer,
    getPublicKey: () => publicKeyBytes.buffer,
    getPublicKeyAlgorithm: () => algorithm,
  };

  const credential = Object.create(PublicKeyCredential.prototype);
  Object.defineProperties(credential, {
    id:       { value: data.credential_id as string, enumerable: true },
    rawId:    { value: credIdBytes.buffer, enumerable: true },
    type:     { value: 'public-key', enumerable: true },
    response: { value: response, enumerable: true },
    authenticatorAttachment: { value: 'platform', enumerable: true },
  });
  credential.getClientExtensionResults = () => ({});

  return credential;
}

/**
 * Build a PublicKeyCredential for navigator.credentials.get().
 */
const buildGetCredential = (data: Record<string, unknown>): PublicKeyCredential => {
  const credIdBytes = b64urlToBytes(data.credential_id as string);
  const authDataBytes = b64urlToBytes(data.authenticator_data as string);
  const clientDataJSON = b64urlToBytes(data.client_data_json as string);
  const signatureBytes = b64urlToBytes(data.signature as string);
  const userHandleBytes = data.user_handle
    ? b64urlToBytes(data.user_handle as string)
    : new Uint8Array(0);

  const response = {
    authenticatorData: authDataBytes.buffer,
    clientDataJSON: clientDataJSON.buffer,
    signature: signatureBytes.buffer,
    userHandle: userHandleBytes.buffer,
  };

  const credential = Object.create(PublicKeyCredential.prototype);
  Object.defineProperties(credential, {
    id:       { value: bytesToB64url(credIdBytes), enumerable: true },
    rawId:    { value: credIdBytes.buffer, enumerable: true },
    type:     { value: 'public-key', enumerable: true },
    response: { value: response, enumerable: true },
    authenticatorAttachment: { value: 'cross-platform', enumerable: true },
  });
  credential.getClientExtensionResults = () => ({});

  return credential;
}

// Save the original methods from the prototype (more robust than instance methods)
const CredProto = CredentialsContainer.prototype;
const originalCreate = CredProto.create;
const originalGet = CredProto.get;

// Override at the prototype level so pages can't bypass us by caching
// a reference to navigator.credentials.create before our override.
CredProto.create = async function (
  this: CredentialsContainer,
  options?: CredentialCreationOptions
): Promise<Credential | null> {
  if (!options?.publicKey) return originalCreate.call(this, options);

  const pk = options.publicKey;
  const rpId = pk.rp?.id || window.location.hostname;
  const rpName = pk.rp?.name || rpId;
  const userName = pk.user?.name || '';
  const displayName = pk.user?.displayName || userName;
  const algorithm = pk.pubKeyCredParams?.[0]?.alg ?? -7;
  const challenge = bytesToB64url(pk.challenge as ArrayBuffer);
  const origin = window.location.origin;
  const userId = pk.user?.id ? bytesToB64url(pk.user.id as ArrayBuffer) : '';

  console.debug('[LGI Pass] intercepted credentials.create for', rpId, '(user:', userName, ')');

  try {
    const response = await sendPasskeyMessage({
      action: 'passkeyCreate',
      rpId,
      rpName,
      userName,
      displayName,
      algorithm,
      challenge,
      origin,
      userId,
    });

    console.debug('[LGI Pass] create response:', JSON.stringify(response).slice(0, 200));

    if (response.error) {
      console.warn('[LGI Pass] create error, falling back to browser:', response.error);
      return originalCreate.call(this, options);
    }

    // The service worker wraps the sidecar response under `options`
    const inner = (response.options ?? response) as Record<string, unknown>;

    if (inner.credential_id && inner.attestation_object) {
      console.info('[LGI Pass] passkey created successfully for', rpId);
      return buildCreateCredential(inner, challenge);
    }

    console.warn('[LGI Pass] unexpected response shape, falling back');
  } catch (err) {
    console.warn('[LGI Pass] create exception, falling back:', err);
  }

  return originalCreate.call(this, options);
};

CredProto.get = async function (
  this: CredentialsContainer,
  options?: CredentialRequestOptions
): Promise<Credential | null> {
  if (!options?.publicKey) return originalGet.call(this, options);

  const pk = options.publicKey;
  const rpId = pk.rpId || window.location.hostname;
  const challenge = bytesToB64url(pk.challenge as ArrayBuffer);
  const allowCredentials = pk.allowCredentials?.map((c) =>
    bytesToB64url(c.id as ArrayBuffer)
  );
  const mediation = (options as any).mediation as string | undefined;

  console.debug('[LGI Pass] intercepted credentials.get for', rpId, 'mediation:', mediation);

  try {
    const response = await sendPasskeyMessage({
      action: 'passkeyGet',
      rpId,
      allowCredentials,
    });

    const passkeys = response.passkeys as { credentialId: string }[] | undefined;

    if (response.error || !passkeys?.length) {
      console.debug('[LGI Pass] no passkeys found for', rpId, ', falling back');
      // For conditional mediation (autofill), don't trigger native dialog
      if (mediation === 'conditional') {
        return originalGet.call(this, options);
      }
      return originalGet.call(this, options);
    }

    console.debug('[LGI Pass] found', passkeys.length, 'passkey(s) for', rpId);

    const cred = passkeys[0];

    const signResponse = await sendPasskeyMessage({
      action: 'passkeySign',
      credentialId: cred.credentialId,
      rpId,
      origin: window.location.origin,
      challenge,
    });

    if (signResponse.error) {
      console.warn('[LGI Pass] sign failed, falling back:', signResponse.error);
      return originalGet.call(this, options);
    }

    const assertion = (signResponse.assertion ?? signResponse) as Record<string, unknown>;

    if (assertion.credential_id && assertion.signature) {
      console.info('[LGI Pass] passkey assertion signed for', rpId);
      return buildGetCredential(assertion);
    }
  } catch (err) {
    console.warn('[LGI Pass] get exception, falling back:', err);
  }

  return originalGet.call(this, options);
};

console.debug('[LGI Pass] WebAuthn override installed on CredentialsContainer.prototype');

} // end dedup guard
