import { loadWasmModule } from './client/wasm-module';
import { base64UrlDecode, base64UrlEncode } from './webauthn';
import type { BrowserAssertion } from './generated/BrowserAssertion';

export interface HostedBrowserCredential {
  brokerUrl: string;
  omni: string;
  credentialId: string;
  publicKeyX: string;
  publicKeyY: string;
  deviceKeyHash: string;
  prfSalt: string;
}
export interface HostedBrowserIdentity extends HostedBrowserCredential {
  secretHex: string;
  consoleSecretHex: string;
}

const STORAGE_PREFIX = 'agentkeys:hosted-master:v2:';
const normalizeOmni = (omni: string) => omni.replace(/^0x/, '').toLowerCase();
const normalizeBroker = (brokerUrl: string) => new URL(brokerUrl).href.replace(/\/$/, '');
const prefixFor = (brokerUrl: string) => `${STORAGE_PREFIX}${encodeURIComponent(normalizeBroker(brokerUrl))}:`;
const keyFor = (brokerUrl: string, omni: string) => `${prefixFor(brokerUrl)}${normalizeOmni(omni)}`;
const bytesHex = (bytes: Uint8Array) => `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
const hexBytes = (hex: string) => {
  if (!/^0x[a-f0-9]{64}$/i.test(hex)) throw new Error('Expected a 32-byte challenge.');
  return new Uint8Array(hex.slice(2).match(/../g)!.map((byte) => parseInt(byte, 16)));
};
type PrfOutput = AuthenticationExtensionsClientOutputs & { prf?: { enabled?: boolean; results?: { first: ArrayBuffer } } };
const prfExtensions = (salt: string) => ({ prf: { eval: { first: base64UrlDecode(salt) } } }) as AuthenticationExtensionsClientInputs;
const prfResult = (credential: PublicKeyCredential): ArrayBuffer => {
  const result = (credential.getClientExtensionResults() as PrfOutput).prf?.results?.first;
  if (!result || result.byteLength !== 32) throw new Error('This browser or authenticator does not support passkey PRF. Browser access cannot be enabled here; use your original console. No device secret was saved.');
  return result;
};

export function loadHostedIdentity(brokerUrl: string, omni: string): HostedBrowserCredential | null {
  const saved = localStorage.getItem(keyFor(brokerUrl, omni));
  if (!saved) return null;
  const credential = JSON.parse(saved) as HostedBrowserCredential & Record<string, unknown>;
  if ('secretHex' in credential || 'consoleSecretHex' in credential || 'session_jwt' in credential
    || credential.brokerUrl !== normalizeBroker(brokerUrl) || credential.omni !== normalizeOmni(omni)
    || !/^[a-f0-9]{64}$/.test(credential.omni) || !/^[A-Za-z0-9_-]+$/.test(credential.credentialId)
    || ![credential.deviceKeyHash, credential.publicKeyX, credential.publicKeyY].every((value) => /^0x[a-f0-9]{64}$/.test(value))
    || base64UrlDecode(credential.prfSalt).byteLength !== 32) throw new Error('The saved public browser identity is invalid. It was not replaced.');
  return credential;
}

export function listHostedIdentities(brokerUrl: string): HostedBrowserCredential[] {
  const prefix = prefixFor(brokerUrl);
  const credentials: HostedBrowserCredential[] = [];
  for (let index = 0; index < localStorage.length; index += 1) {
    const key = localStorage.key(index);
    if (!key?.startsWith(prefix)) continue;
    const credential = loadHostedIdentity(brokerUrl, key.slice(prefix.length));
    if (credential) credentials.push(credential);
  }
  return credentials;
}

export function saveHostedCredential(credential: HostedBrowserCredential): void {
  const { brokerUrl, omni, credentialId, publicKeyX, publicKeyY, deviceKeyHash, prfSalt } = credential;
  localStorage.setItem(keyFor(brokerUrl, omni), JSON.stringify({ brokerUrl, omni, credentialId, publicKeyX, publicKeyY, deviceKeyHash, prfSalt }));
}

async function deriveIdentity(credential: HostedBrowserCredential, output: ArrayBuffer): Promise<HostedBrowserIdentity> {
  const input = await crypto.subtle.importKey('raw', output, 'HKDF', false, ['deriveBits']);
  const derive = async (purpose: string) => new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: base64UrlDecode(credential.prfSalt), info: new TextEncoder().encode(`agentkeys:hosted:${purpose}:v1:${credential.brokerUrl}:${credential.omni}`) }, input, 256));
  const wasm = await loadWasmModule();
  const device = wasm.DeviceIdentity.fromRandomBytes(await derive('master-k10'));
  const consoleDevice = wasm.DeviceIdentity.fromRandomBytes(await derive('console-k10'));
  try {
    const deviceKeyHash = device.deviceKeyHash();
    if (credential.deviceKeyHash && credential.deviceKeyHash !== deviceKeyHash) throw new Error('This passkey produced a different browser identity. Existing access was not replaced.');
    return { ...credential, deviceKeyHash, secretHex: device.secretHex(), consoleSecretHex: consoleDevice.secretHex() };
  } finally { device.free(); consoleDevice.free(); new Uint8Array(output).fill(0); }
}

export async function unlockHostedIdentity(credential: HostedBrowserCredential, challenge: string): Promise<{ identity: HostedBrowserIdentity; assertion: BrowserAssertion }> {
  const response = await navigator.credentials.get({ publicKey: {
    challenge: hexBytes(challenge), rpId: location.hostname, userVerification: 'required',
    allowCredentials: [{ type: 'public-key', id: base64UrlDecode(credential.credentialId), transports: ['internal'] }],
    extensions: prfExtensions(credential.prfSalt),
  } }) as PublicKeyCredential | null;
  if (!response) throw new Error('Touch ID was cancelled.');
  if (base64UrlEncode(response.rawId) !== credential.credentialId) throw new Error('The selected passkey differs from this browser identity.');
  const assertionResponse = response.response as AuthenticatorAssertionResponse;
  const assertion: BrowserAssertion = { authenticator_data: base64UrlEncode(assertionResponse.authenticatorData), client_data_json: base64UrlEncode(assertionResponse.clientDataJSON), signature: base64UrlEncode(assertionResponse.signature), credential_id: credential.credentialId };
  return { identity: await deriveIdentity(credential, prfResult(response)), assertion };
}

export async function createHostedIdentity(brokerUrl: string, omni: string): Promise<HostedBrowserIdentity> {
  const challenge = bytesHex(crypto.getRandomValues(new Uint8Array(32)));
  const existing = loadHostedIdentity(brokerUrl, omni);
  if (existing) return (await unlockHostedIdentity(existing, challenge)).identity;
  if (!/^[a-f0-9]{64}$/.test(normalizeOmni(omni))) throw new Error('A verified account is required.');
  const prfSalt = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const response = await navigator.credentials.create({ publicKey: {
    rp: { id: location.hostname, name: 'Agent Terrier' },
    user: { id: new TextEncoder().encode(normalizeOmni(omni)), name: normalizeOmni(omni), displayName: 'Agent Terrier account' },
    challenge: hexBytes(challenge), pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
    attestation: 'none', extensions: prfExtensions(prfSalt),
  } }) as PublicKeyCredential | null;
  if (!response) throw new Error('Passkey creation was cancelled.');
  const publicKey = (response.response as AuthenticatorAttestationResponse).getPublicKey?.();
  if (!publicKey) throw new Error('This browser cannot export the passkey public key. Use your original console.');
  const imported = await crypto.subtle.importKey('spki', publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const jwk = await crypto.subtle.exportKey('jwk', imported);
  if (!jwk.x || !jwk.y) throw new Error('Passkey public key is not P-256.');
  const credential: HostedBrowserCredential = { brokerUrl: normalizeBroker(brokerUrl), omni: normalizeOmni(omni), credentialId: base64UrlEncode(response.rawId), publicKeyX: bytesHex(base64UrlDecode(jwk.x)), publicKeyY: bytesHex(base64UrlDecode(jwk.y)), deviceKeyHash: '', prfSalt };
  const creationPrf = (response.getClientExtensionResults() as PrfOutput).prf;
  const identity = creationPrf?.results?.first ? await deriveIdentity(credential, creationPrf.results.first)
    : (await unlockHostedIdentity(credential, challenge)).identity;
  saveHostedCredential(identity);
  return identity;
}

export async function signHostedEnrollment(identity: HostedBrowserIdentity, challenge: string): Promise<string> {
  return (await loadWasmModule()).hostedEnrollmentDeviceProof(identity.secretHex, challenge);
}
