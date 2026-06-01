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

export async function platformAuthenticatorAvailable(): Promise<boolean> {
  if (!webauthnAvailable()) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}
