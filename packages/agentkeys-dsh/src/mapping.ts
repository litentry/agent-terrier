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
 */

/** Grant-classed tools: running one requires the matching `tool:<class>` grant. */
export const DEFAULT_TOOL_CLASSES: Readonly<Record<string, readonly string[]>> = {
  web: ['web_fetch', 'web_search'],
  code: ['bash', 'pwsh', 'run_code', 'terminal_open', 'terminal_send', 'terminal_read', 'terminal_close', 'terminal_list', 'terminal_signal'],
  schedule: ['schedule_create', 'schedule_delete', 'schedule_list'],
};

/** Always-allowed baseline (no grant consulted). */
export const DEFAULT_BASELINE: readonly string[] = [
  'read', 'write', 'edit', 'read_image', 'str_replace_editor', 'glob', 'grep',
  'todo_write', 'exit_plan_mode', 'ask_user_question', 'report',
  'job_list', 'job_output', 'job_kill',
];

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
}

export type ToolVerdict =
  | { kind: 'baseline' }
  | { kind: 'classed'; toolClass: string; service: string }
  | { kind: 'unmapped' };

/** Pure classification of a registered tool name. */
export function classifyTool(name: string, config: MappingConfig = {}): ToolVerdict {
  // Schemastery materializes array/dict schema fields as EMPTY collections, so
  // "absent" arrives as [] / {} — treat empty as "use the defaults" (an
  // operator overriding the mapping always supplies a non-empty value).
  const baseline = config.baseline?.length ? config.baseline : DEFAULT_BASELINE;
  if (baseline.includes(name)) return { kind: 'baseline' };
  if (OPENVIKING_TOOL_PATTERNS.some((re) => re.test(name))) return { kind: 'baseline' };
  const classes =
    config.toolClasses && Object.keys(config.toolClasses).length > 0
      ? config.toolClasses
      : DEFAULT_TOOL_CLASSES;
  for (const [toolClass, names] of Object.entries(classes)) {
    if (names.includes(name)) return { kind: 'classed', toolClass, service: `tool:${toolClass}` };
  }
  return { kind: 'unmapped' };
}
