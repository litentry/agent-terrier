import { describe, expect, it } from 'vitest';

import { parseSandboxExpiry, sandboxExpiryLabel } from '../client/sandboxExpiry';

// The instant under test throughout: the lease MEASURED on the live VE broker
// 2026-08-14 — `2026-08-15 15:50:54 +0800` = 2026-08-15T07:50:54Z.
const EXPIRY_UTC_MS = Date.parse('2026-08-15T07:50:54Z');
// "now" one hour before it, so a correct renderer says ~1h.
const NOW = EXPIRY_UTC_MS - 60 * 60 * 1000;

describe('sandbox lease rendering', () => {
  it('renders the normalized RFC3339 lease the broker now emits', () => {
    expect(sandboxExpiryLabel('2026-08-15T15:50:54+08:00', NOW)).toBe(' · expires in 1h');
    // Same instant, UTC spelling — identical answer.
    expect(sandboxExpiryLabel('2026-08-15T07:50:54Z', NOW)).toBe(' · expires in 1h');
  });

  it('REFUSES the vendor-native Go layout instead of rendering a 14h lie', () => {
    // The regression: `Date.parse` does not fail on this string — V8 reads the
    // trailing `CST` as US Central (−6) and drops `+0800`, which used to
    // render a 24h lease as "expires in 38h". We render it verbatim instead.
    const raw = '2026-08-15 15:50:54 +0800 CST';
    expect(parseSandboxExpiry(raw)).toBeNull();
    expect(sandboxExpiryLabel(raw, NOW)).toBe(` · expires ${raw}`);
    // Proof the naive parse really is wrong by exactly 14 hours (the bug this
    // guard exists for) — so this test fails loudly if someone "simplifies"
    // the guard away.
    expect(Date.parse(raw) - EXPIRY_UTC_MS).toBe(14 * 60 * 60 * 1000);
  });

  it('handles no-lease, past, and sub-hour cases', () => {
    for (const empty of ['', null, undefined]) {
      expect(sandboxExpiryLabel(empty, NOW)).toBe('');
    }
    expect(sandboxExpiryLabel('2026-08-15T07:50:54Z', EXPIRY_UTC_MS + 1000)).toBe(' · expired');
    expect(
      sandboxExpiryLabel('2026-08-15T07:50:54Z', EXPIRY_UTC_MS - 25 * 60 * 1000),
    ).toBe(' · expires in 25m');
  });

  it('renders an unparseable value verbatim rather than guessing', () => {
    expect(sandboxExpiryLabel('next tuesday', NOW)).toBe(' · expires next tuesday');
    expect(parseSandboxExpiry('1786246717')).toBeNull();
  });
});
