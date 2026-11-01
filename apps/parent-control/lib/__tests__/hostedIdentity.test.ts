import { beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto, createHash } from 'node:crypto';
import { createHostedIdentity, loadHostedIdentity, saveHostedCredential, unlockHostedIdentity, type HostedBrowserCredential } from '../hostedIdentity';

vi.mock('../client/wasm-module', () => ({ loadWasmModule: async () => ({
  DeviceIdentity: { fromRandomBytes: (bytes: Uint8Array) => ({
    secretHex: () => `0x${Buffer.from(bytes).toString('hex')}`,
    deviceKeyHash: () => `0x${createHash('sha256').update(bytes).digest('hex')}`,
    free: () => {},
  }) },
}) }));

const credential = (): HostedBrowserCredential => ({ brokerUrl: 'https://broker.example.test', omni: '11'.repeat(32), credentialId: 'AQID', publicKeyX: `0x${'22'.repeat(32)}`, publicKeyY: `0x${'33'.repeat(32)}`, deviceKeyHash: '', prfSalt: Buffer.alloc(32, 4).toString('base64url') });
const challenge = `0x${'55'.repeat(32)}`;
const getCredential = vi.fn();
const createCredential = vi.fn();
let saved: Map<string, string>;
function assertion(prf = true) {
  return { rawId: new Uint8Array([1, 2, 3]).buffer,
    response: { authenticatorData: new Uint8Array([1]).buffer, clientDataJSON: new Uint8Array([2]).buffer, signature: new Uint8Array([3]).buffer },
    getClientExtensionResults: () => prf ? { prf: { results: { first: new Uint8Array(32).fill(7).buffer } } } : {},
  };
}
beforeEach(() => {
  saved = new Map();
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('location', { hostname: 'console.example.test' });
  vi.stubGlobal('navigator', { credentials: { get: getCredential, create: createCredential } });
  vi.stubGlobal('localStorage', { getItem: (key: string) => saved.get(key) ?? null, setItem: (key: string, value: string) => saved.set(key, value), key: (index: number) => [...saved.keys()][index] ?? null, get length() { return saved.size; } });
  getCredential.mockReset().mockImplementation(async () => assertion());
  createCredential.mockReset();
});

describe('browser PRF identity custody', () => {
  it('rederives the same RAM keys and separates master, console, and browser salts', async () => {
    const first = await unlockHostedIdentity(credential(), challenge);
    const second = await unlockHostedIdentity(credential(), challenge);
    expect(first.identity.secretHex).toBe(second.identity.secretHex);
    expect(first.identity.consoleSecretHex).not.toBe(first.identity.secretHex);
    expect(first.assertion.credential_id).toBe('AQID');
    const changed = await unlockHostedIdentity({ ...credential(), prfSalt: Buffer.alloc(32, 9).toString('base64url') }, challenge);
    expect(changed.identity.secretHex).not.toBe(first.identity.secretHex);
    expect(saved.size).toBe(0);
  });
  it('persists only explicit public coordinates even when passed an unlocked identity', async () => {
    const { identity } = await unlockHostedIdentity(credential(), challenge);
    saveHostedCredential(identity);
    const serialized = [...saved.values()][0];
    expect(serialized).not.toContain(identity.secretHex);
    expect(serialized).not.toContain(identity.consoleSecretHex);
    expect(serialized).not.toContain('secretHex');
    expect(serialized).not.toContain('session_jwt');
    expect(loadHostedIdentity(identity.brokerUrl, identity.omni)).toEqual({ brokerUrl: identity.brokerUrl, omni: identity.omni, credentialId: identity.credentialId, publicKeyX: identity.publicKeyX, publicKeyY: identity.publicKeyY, deviceKeyHash: identity.deviceKeyHash, prfSalt: identity.prfSalt });
  });
  it('fails explicitly without PRF and never falls back to stored secrets', async () => {
    getCredential.mockResolvedValue(assertion(false));
    await expect(unlockHostedIdentity(credential(), challenge)).rejects.toThrow('does not support passkey PRF');
    expect(saved.size).toBe(0);
  });
  it('refuses a different device identity for an enrolled public credential', async () => {
    await expect(unlockHostedIdentity({ ...credential(), deviceKeyHash: `0x${'ff'.repeat(32)}` }, challenge)).rejects.toThrow('different browser identity');
    expect(saved.size).toBe(0);
  });
  it('creates with a platform P-256 passkey and persists no private output', async () => {
    const key = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = await webcrypto.subtle.exportKey('spki', key.publicKey);
    createCredential.mockResolvedValue({ ...assertion(), response: { getPublicKey: () => spki } });
    const identity = await createHostedIdentity(credential().brokerUrl, credential().omni);
    expect(createCredential.mock.calls[0][0].publicKey.authenticatorSelection).toMatchObject({ authenticatorAttachment: 'platform', userVerification: 'required' });
    expect([...saved.values()][0]).not.toContain(identity.secretHex);
    expect([...saved.values()][0]).not.toContain(identity.consoleSecretHex);
    expect(loadHostedIdentity(identity.brokerUrl, identity.omni)?.credentialId).toBe('AQID');
  });
});
