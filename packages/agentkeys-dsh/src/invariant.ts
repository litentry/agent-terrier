/**
 * @module @agentkeys/dsh-suite/invariant — the #619 boot assertion.
 *
 * Asserts at activation that the composed approval configuration carries NO
 * standing allow rules. Today this is structurally guaranteed — dsh's
 * `ApprovalOutcome` has no durable grant variant and `ApprovalPolicy` is
 * `ask | never` — so the check is a TRIPWIRE for the day a future dsh release
 * adds one and a profile (or a stray settings section) configures it. Paired
 * with the `dsh-bump` permission-contract diff: that catches the vocabulary
 * change at bump time, this catches an actually-configured standing allow at
 * boot, and fails the profile loud rather than running permissive.
 *
 * Registered through dsh's own `ctx.invariants` registry when present (a dev/CI
 * composition — shipped hosts do not load it), so this file is additionally
 * exported as a plain predicate the guard's unit tests exercise directly.
 *
 * NO default export (dsh postmortem 0001).
 */
import type { Context } from '@deepseek-ai/cordis';

export const PACKAGE_NAME = '@agentkeys/dsh-suite';
export const name = 'agentkeys-suite-invariant';
export const inject = ['invariants'];

/** The approval-policy values that are safe for a delegate profile. Anything
 *  else — notably a future durable/standing grant — is a hard stop. */
export const ALLOWED_POLICIES: readonly string[] = ['ask', 'never'];

export interface ApprovalConfigLike {
  policy?: unknown;
  /** A future dsh may grow one of these; any non-empty value is a standing
   *  allow and must fail the profile. Named defensively on purpose. */
  rules?: unknown;
  allow?: unknown;
  alwaysAllow?: unknown;
}

/** Pure check (exported for tests): returns a failure reason, or undefined. */
export function standingAllowViolation(config: ApprovalConfigLike | undefined): string | undefined {
  if (!config) return undefined;
  if (config.policy !== undefined && !ALLOWED_POLICIES.includes(String(config.policy))) {
    return `approval policy ${JSON.stringify(config.policy)} is outside the reviewed vocabulary ${JSON.stringify(ALLOWED_POLICIES)} — a standing grant must not ship without a spec §4.6 review`;
  }
  for (const key of ['rules', 'allow', 'alwaysAllow'] as const) {
    const value = config[key];
    const nonEmpty = Array.isArray(value)
      ? value.length > 0
      : value !== undefined && value !== null && (typeof value !== 'object' || Object.keys(value as object).length > 0);
    if (nonEmpty) {
      return `approval config carries standing allow rules under "${key}" — AgentKeys grants are the only durable authority (spec §4.2 invariant 1)`;
    }
  }
  return undefined;
}

export const apply = (ctx: Context): Promise<() => void> => {
  const install = (_c: Context, failWith: (message: string) => never): void => {
    const approvalConfig = (ctx as unknown as { approval?: { config?: ApprovalConfigLike } }).approval?.config;
    const violation = standingAllowViolation(approvalConfig);
    if (violation) failWith(`AgentKeys: ${violation}`);
  };
  const registry = (ctx as unknown as {
    invariants?: { register: (pkg: string, installer: typeof install) => () => void };
  }).invariants;
  if (!registry) return Promise.resolve(() => {});
  return Promise.resolve(registry.register(PACKAGE_NAME, install));
};
