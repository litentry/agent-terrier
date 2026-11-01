// Greppable structured console logging for the passkey ↔ master-account flow.
//
// Touch-ID / "wrong passkey" / SIG_VALIDATION_FAILED bugs are diagnosed by comparing
// the master ACCOUNT and the signing PASSKEY (WebAuthn credential id) across the two
// moments they must agree — **onboarding** (which passkey the account was bound with)
// vs **accept** (which passkey actually signed). Filter the browser console by
// `[agentkeys]` to see the whole trail; if `boundCredentialId` (onboarding) ≠
// `signingCredentialId` (accept), or the `account` differs, that's the bug.
export function akLog(event: string, data: Record<string, unknown> = {}): void {
  try {
    // eslint-disable-next-line no-console
    console.info(`[agentkeys] ${event}`, data);
  } catch {
    /* console may be unavailable (SSR / locked-down env) — logging is best-effort */
  }
}
