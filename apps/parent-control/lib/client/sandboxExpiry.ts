// #577/#594 — rendering a delegate sandbox's veFaaS lease deadline.
//
// Extracted from the pairing card so it can be regression-tested: the naive
// version (`Date.parse(raw)`) rendered a countdown that was WRONG BY 14 HOURS
// on the live VE stack, and did it silently.
//
// Why: veFaaS returns Go's `time.Time` layout — `2026-08-15 15:50:54 +0800 CST`
// — not RFC3339. `Date.parse` does NOT reject that string; V8 honors the
// trailing zone ABBREVIATION `CST` as *US Central* (−6) and ignores the
// authoritative `+0800`, so a 24-hour lease rendered as "expires in 38h"
// (measured 2026-08-14: parses to 21:50:54Z instead of 07:50:54Z). The broker
// now normalizes to RFC3339 at its driver boundary (`ve_faas::normalize_
// expire_at`) — this guard is the second half: only a strict ISO-8601 instant
// is trusted, so a pre-fix broker (or any future vendor shape) renders
// verbatim instead of confidently lying.

/** Strict ISO-8601 instant with a date/time separator — what the normalized
 *  broker emits. Deliberately NOT a full RFC3339 validator: it is a gate that
 *  refuses the ambiguous vendor forms, and `Date.parse` does the rest. */
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

/** Milliseconds for an expiry string, or `null` when it is not a shape we
 *  trust (empty, vendor-native, or unparseable). Never guesses. */
export function parseSandboxExpiry(expireAt: string | null | undefined): number | null {
  if (!expireAt) return null;
  const raw = expireAt.trim();
  if (!ISO_INSTANT.test(raw)) return null;
  const t = Date.parse(raw);
  return Number.isNaN(t) ? null : t;
}

/** The compact card suffix: relative when we trust the value ("· expires in
 *  3h"), verbatim when we do not, empty when the backend has no lease (ECS).
 *  `now` is injectable so tests don't depend on wall-clock time. */
export function sandboxExpiryLabel(
  expireAt: string | null | undefined,
  now: number = Date.now(),
): string {
  if (!expireAt) return '';
  const t = parseSandboxExpiry(expireAt);
  if (t === null) return ` · expires ${expireAt}`;
  const mins = Math.round((t - now) / 60000);
  if (mins <= 0) return ' · expired';
  if (mins < 60) return ` · expires in ${mins}m`;
  return ` · expires in ${Math.round(mins / 60)}h`;
}
