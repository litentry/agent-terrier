/**
 * Tool→capability-class mapping and the always-allowed baseline (spec
 * docs/spec/delegate-runtime-dsh.md §4.2, #611).
 *
 * The classes MUST stay in lockstep with the enumerable candidates the daemon
 * names hashes with (`CAPABILITY_TOOL_CLASSES` in ui_bridge.rs, #614): the
 * daemon recovers `tool:<class>` names from chain hashes; this module decides
 * which registered tool names each class governs.
 *
 * Baseline = tools with no effect beyond the sandbox the outer boundary
 * already contains: the delegate's own filesystem workspace, its own bounded
 * OpenViking store (mirror-bounded, #566), todo/plan/report bookkeeping, and
 * asking its own owner a question. Everything unmapped is DENIED — new tools a
 * future dsh version introduces arrive inside the deny-by-absence envelope.
 *
 * Advertised actions (2026-09-24, plan dsh-plugin-abstraction PR 1) are the
 * daemon's own verbs: the `actions` plugin registers them from
 * `GET /v1/sandbox/self/actions`, and each names the GRANT FAMILY it needs —
 * publishing IS the `channel-pub:<id>` data service, proposing IS the
 * `proposal:<ns>` one. The guard allows the verb when the delegate holds ANY
 * grant of that family; WHICH feed / namespace is the cap-mint's verdict at
 * the daemon. Denied outright without one: an allow-once cannot mint a feed,
 * so asking would only mislead.
 */

/** Grant-classed tools: running one requires the matching `tool:<class>` grant. */
export const DEFAULT_TOOL_CLASSES: Readonly<Record<string, readonly string[]>> = {
  web: ['web_fetch', 'web_search'],
  code: ['bash', 'pwsh', 'run_code', 'terminal_open', 'terminal_send', 'terminal_read', 'terminal_close', 'terminal_list', 'terminal_signal'],
  schedule: ['schedule_create', 'schedule_delete', 'schedule_list'],
};

/** The two verbs every delegate daemon advertises, and their grant families
 *  (agentkeys-protocol `sandbox_actions`). Seeded here so the guard's verdict
 *  never depends on the advertisement having arrived; the actions plugin
 *  replaces the set with what the daemon actually advertises. */
export const PUBLISH_ACTION = 'publish_to_slot';
export const PROPOSE_ACTION = 'propose_to_owner';
export const PUBLISH_SERVICE_PREFIX = 'channel-pub:';
export const PROPOSE_SERVICE_PREFIX = 'proposal:';

const ADVERTISED = new Map<string, string>([
  [PUBLISH_ACTION, PUBLISH_SERVICE_PREFIX],
  [PROPOSE_ACTION, PROPOSE_SERVICE_PREFIX],
]);

/** Replace the advertised set with the daemon's list (name → grant family).
 *  Module-level on purpose: the actions plugin (writer) and the guard /
 *  answerer (readers) ship in this package and run in one process. */
export function registerAdvertised(entries: Iterable<{ name: string; requires_grant_prefix: string }>): void {
  const next: Array<[string, string]> = [];
  for (const e of entries) next.push([e.name, e.requires_grant_prefix.toLowerCase()]);
  ADVERTISED.clear();
  for (const [n, p] of next) ADVERTISED.set(n, p);
}

/** The grant family an advertised tool needs, or undefined when it is not one. */
export function advertisedGrantPrefix(name: string): string | undefined {
  return ADVERTISED.get(name);
}

/** Does the (lower-cased) grant view hold any service of the family? */
export function holdsGrantWithPrefix(services: ReadonlySet<string>, prefix: string): boolean {
  const p = prefix.toLowerCase();
  for (const s of services) if (s.startsWith(p)) return true;
  return false;
}

/** Always-allowed baseline (no grant consulted). */
export const DEFAULT_BASELINE: readonly string[] = [
  'read', 'write', 'edit', 'read_image', 'str_replace_editor', 'glob', 'grep',
  'todo_write', 'exit_plan_mode', 'ask_user_question', 'report',
  'job_list', 'job_output', 'job_kill',
];

/** Tools this deployment switches off: the bridge masks them out of every
 *  agent's view, and the guard denies them as the backstop. `remember` asks
 *  OpenViking to extract memories from a throwaway session, and the sandbox's
 *  OpenViking runs without an extraction model (start-openviking.sh), so it
 *  would answer "stored" and store nothing (#726 turns extraction on). */
export const DEFAULT_HIDDEN_TOOLS: readonly string[] = ['mcp__openviking__remember', 'viking_remember'];

/** OpenViking memory tools ride the delegate's own bounded store — baseline.
 *  Matches both the 0.1.0 native names (`viking_*`) and the 0.2.1 MCP-proxy
 *  names (`mcp__<server>__*` where the server is the in-image OpenViking). */
export const OPENVIKING_TOOL_PATTERNS: readonly RegExp[] = [
  /^viking_[a-z_]+$/,
  /^mcp__openviking[a-z0-9_-]*__[a-z_]+$/i,
];

export interface MappingConfig {
  readonly toolClasses?: Readonly<Record<string, readonly string[]>>;
  readonly baseline?: readonly string[];
  readonly hiddenTools?: readonly string[];
}

export type ToolVerdict =
  | { kind: 'baseline' }
  | { kind: 'classed'; toolClass: string; service: string }
  | { kind: 'advertised'; requiresPrefix: string }
  | { kind: 'hidden' }
  | { kind: 'unmapped' };

/** Pure classification of a registered tool name. */
export function classifyTool(name: string, config: MappingConfig = {}): ToolVerdict {
  // Schemastery materializes array/dict schema fields as EMPTY collections, so
  // "absent" arrives as [] / {} — treat empty as "use the defaults" (an
  // operator overriding the mapping always supplies a non-empty value).
  const hidden = config.hiddenTools?.length ? config.hiddenTools : DEFAULT_HIDDEN_TOOLS;
  if (hidden.includes(name)) return { kind: 'hidden' };
  const baseline = config.baseline?.length ? config.baseline : DEFAULT_BASELINE;
  if (baseline.includes(name)) return { kind: 'baseline' };
  if (OPENVIKING_TOOL_PATTERNS.some((re) => re.test(name))) return { kind: 'baseline' };
  const requiresPrefix = advertisedGrantPrefix(name);
  if (requiresPrefix !== undefined) return { kind: 'advertised', requiresPrefix };
  const classes =
    config.toolClasses && Object.keys(config.toolClasses).length > 0
      ? config.toolClasses
      : DEFAULT_TOOL_CLASSES;
  for (const [toolClass, names] of Object.entries(classes)) {
    if (names.includes(name)) return { kind: 'classed', toolClass, service: `tool:${toolClass}` };
  }
  return { kind: 'unmapped' };
}
