/**
 * Browser-side WebAuthn helpers for K11 enrollment.
 *
 * Maps daemon /v1/k11/enroll/begin JSON → navigator.credentials.create() args,
 * and the resulting PublicKeyCredential → daemon /v1/k11/enroll/finish payload.
 *
 * arch.md §10.2 stage 2 ("master binding ceremony — WebAuthn") is what
 * this drives. The challenge bytes themselves are constructed by the
 * daemon (sha256(binding_nonce || D_pub)); the browser is just the
 * relying-party transport.
 */

export function base64UrlDecode(s: string): Uint8Array {
  const padded = s.padEnd(s.length + ((4 - (s.length % 4)) % 4), '=').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64UrlEncode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export interface CreationOptionsJson {
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  excludeCredentials?: { type: 'public-key'; id: string; transports?: AuthenticatorTransport[] }[];
}

export function jsonToCreationOptions(json: CreationOptionsJson): PublicKeyCredentialCreationOptions {
  return {
    rp: { id: json.rp.id, name: json.rp.name },
    user: {
      id: base64UrlDecode(json.user.id),
      name: json.user.name,
      displayName: json.user.displayName,
    },
    challenge: base64UrlDecode(json.challenge),
    pubKeyCredParams: json.pubKeyCredParams,
    timeout: json.timeout,
    attestation: json.attestation,
    authenticatorSelection: json.authenticatorSelection,
    excludeCredentials: json.excludeCredentials?.map((c) => ({
      type: 'public-key',
      id: base64UrlDecode(c.id),
      transports: c.transports,
    })),
  };
}

export interface FinishPayload {
  credentialId: string;
  attestationObject: string;
  clientDataJSON: string;
}

export function credentialToFinishPayload(cred: PublicKeyCredential): FinishPayload {
  const att = cred.response as AuthenticatorAttestationResponse;
  return {
    credentialId: base64UrlEncode(cred.rawId),
    attestationObject: base64UrlEncode(att.attestationObject),
    clientDataJSON: base64UrlEncode(att.clientDataJSON),
  };
}

export function webauthnAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator.credentials?.create === 'function'
  );
}

function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/^0x/, '');
  const out = new Uint8Array(Math.floor(h.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// #225 E7 — the raw WebAuthn assertion over the accept UserOp hash. The broker
// encodes these into the P256Account UserOp signature (abi.encode(credIdHash,
// authData, clientDataJSON, loc, r, s); same format as the Rust CLI's
// `k11 webauthn-userop-sign`) before EntryPoint.handleOps.
export interface AcceptAssertion {
  authenticator_data: string; // base64url
  client_data_json: string; // base64url
  signature: string; // base64url (DER ECDSA)
  credential_id: string; // base64url
}

/** Touch ID over the accept `userOpHash`. The hash IS the WebAuthn challenge —
 *  raw, no sha256 wrap (arch.md §22b.1) — so the passkey signs the full intent. */
export async function getAssertionOverHash(
  userOpHashHex: string,
  allowCredentialIdsB64Url?: string[],
): Promise<AcceptAssertion> {
  const challenge = hexToBytes(userOpHashHex);
  // Pin the master passkey so the browser auto-selects it (and the user can't
  // accidentally sign with the wrong key → on-chain rejection). Empty/absent ⇒
  // the browser shows its full picker (legacy behavior).
  //
  // `transports: ['internal']` is load-bearing: the master passkey is ALWAYS a
  // local platform credential (Touch ID / Secure Enclave). Without the hint
  // Chrome can't tell the named credential lives on THIS device, so it shows the
  // cross-device "Passkeys & Security Keys" picker (QR + security key) instead of
  // routing straight to Touch ID — the exact jarring 2nd prompt in onboarding.
  // Pinning 'internal' forces the local authenticator and suppresses the
  // hybrid/QR + USB fallbacks (we never want a cross-device master signature).
  const allowCredentials = (allowCredentialIdsB64Url ?? [])
    .filter(Boolean)
    .map((id) => ({
      type: 'public-key' as const,
      id: base64UrlDecode(id),
      transports: ['internal'] as AuthenticatorTransport[],
    }));
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge,
      userVerification: 'required',
      timeout: 60_000,
      ...(allowCredentials.length ? { allowCredentials } : {}),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('no assertion (Touch ID cancelled)');
  const a = cred.response as AuthenticatorAssertionResponse;
  return {
    authenticator_data: base64UrlEncode(a.authenticatorData),
    client_data_json: base64UrlEncode(a.clientDataJSON),
    signature: base64UrlEncode(a.signature),
    credential_id: base64UrlEncode(cred.rawId),
  };
}

/**
 * #225 E7 — best-effort check that the master passkey still EXISTS (the operator may
 * have deleted it in the OS password manager → System Settings ▸ Passwords). WebAuthn
 * has no SILENT existence API (privacy by design), so this does a real `get()` and WILL
 * prompt Touch ID. Returns true if the credential signs, false if the authenticator
 * reports no such credential (NotAllowedError) — or the user cancels. Use only when an
 * explicit check is worth a prompt (before "reset master", or after an accept fails).
 */
export async function masterPasskeyPresent(credentialIdB64Url: string): Promise<boolean> {
  if (!webauthnAvailable() || !credentialIdB64Url) return false;
  try {
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [
          {
            type: 'public-key',
            id: base64UrlDecode(credentialIdB64Url),
            transports: ['internal'] as AuthenticatorTransport[],
          },
        ],
        userVerification: 'discouraged',
        timeout: 60_000,
      },
    });
    return !!cred;
  } catch {
    return false; // NotAllowedError ⇒ no matching credential (deleted) or cancelled
  }
}

export async function platformAuthenticatorAvailable(): Promise<boolean> {
  if (!webauthnAvailable()) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}
