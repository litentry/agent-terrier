// Render normalized runtime deadlines; preserve unknown formats verbatim.

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
 *  3h"), verbatim when we do not, empty when the backend has no lease.
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
