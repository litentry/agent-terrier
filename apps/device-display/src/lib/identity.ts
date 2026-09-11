// The device's K10 secret lives in THIS browser (arch.md §10.2 rule 1: the
// machine generates its key on itself; it never leaves). One secret per
// install; the wasm `DeviceIdentity` derives the address / key hash / PoP.

export const SECRET_KEY = 'agentkeys.device.secret';

type StorageLike = Pick<Storage, 'getItem' | 'setItem'>;

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function isSecretHex(s: string): boolean {
  return /^0x[0-9a-f]{64}$/.test(s);
}

/** The persisted secret, or a fresh one from `random(32)` (crypto.getRandomValues). */
export function loadOrCreateSecretHex(
  storage: StorageLike | null,
  random: (n: number) => Uint8Array,
): string {
  try {
    const existing = storage?.getItem(SECRET_KEY);
    if (existing && isSecretHex(existing)) return existing;
  } catch {
    /* fall through to a fresh key */
  }
  const secret = `0x${bytesToHex(random(32))}`;
  try {
    storage?.setItem(SECRET_KEY, secret);
  } catch {
    /* private mode: the key lives only for this session (re-pair next time) */
  }
  return secret;
}
