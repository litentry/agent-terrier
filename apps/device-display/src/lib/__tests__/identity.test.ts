import { describe, expect, it } from 'vitest';
import { bytesToHex, isSecretHex, loadOrCreateSecretHex, SECRET_KEY } from '../identity';

describe('device identity secret', () => {
  it('mints once and reloads the same secret', () => {
    const m = new Map<string, string>();
    const st = { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
    const random = (n: number) => new Uint8Array(n).map((_, i) => i + 1);
    const a = loadOrCreateSecretHex(st, random);
    expect(isSecretHex(a)).toBe(true);
    expect(a).toBe(`0x${bytesToHex(random(32))}`);
    expect(m.get(SECRET_KEY)).toBe(a);
    const b = loadOrCreateSecretHex(st, () => new Uint8Array(32));
    expect(b).toBe(a);
  });

  it('refuses a corrupt stored value and mints afresh', () => {
    const m = new Map<string, string>([[SECRET_KEY, 'garbage']]);
    const st = { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
    const s = loadOrCreateSecretHex(st, (n) => new Uint8Array(n).fill(7));
    expect(s).toBe(`0x${'07'.repeat(32)}`);
  });
});
