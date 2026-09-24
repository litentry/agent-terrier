/**
 * @module @agentkeys/dsh-suite/guard — the in-loop AgentKeys tool gate (#611).
 *
 * Two layers, per the dsh pipeline (docs/tool-execution-pipeline.md):
 *  - a `tools/pre-execute` waterfall listener: allow baseline, `ask` for
 *    grant-classed tools whose `tool:<class>` grant is absent (the ask routes
 *    to ctx.approval → the AgentKeys answerer → owner push), deny unmapped;
 *  - a MONOTONIC `ctx.tools.guard()`: the backstop no listener ordering can
 *    override — denies unmapped tools and ungranted classed tools UNLESS the
 *    exact callId was `allowed-once` by the answerer (the one-shot ledger), so
 *    a rogue pre-execute `allow` cannot bypass grants while an owner-approved
 *    call still runs.
 *
 * An ADVERTISED action (the daemon's own verbs, mapping.ts) is allowed when
 * the delegate holds any grant of the family the daemon declared for it and
 * denied outright otherwise — a feed or a namespace is granted at install,
 * never by an allow-once.
 *
 * NO default export (dsh postmortem 0001 — Loader drops `inject` otherwise).
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { PreToolDecision, ToolExecution, ToolGuard } from '@deepseek-ai/dsh-tools';
import { classifyTool, holdsGrantWithPrefix, type MappingConfig } from './mapping.js';
import { consumeApprovedCall, DEFAULT_GRANTS_URL, GrantsCache } from './grants.js';

export const name = 'agentkeys-guard';
export const inject = ['tools'];

export interface Config extends MappingConfig {
  grantsUrl?: string;
  bridgeToken?: string;
  ttlMs?: number;
  toolClasses?: Record<string, string[]>;
  baseline?: string[];
  hiddenTools?: string[];
}

export const Config: z<Config> = z.object({
  grantsUrl: z.string().default(DEFAULT_GRANTS_URL),
  bridgeToken: z.string(),
  ttlMs: z.number().default(60_000),
  toolClasses: z.dict(z.array(z.string())),
  baseline: z.array(z.string()),
  hiddenTools: z.array(z.string()),
});

/** Pure decision core (exported for tests): what does a tool name deserve
 *  given the current grant view? */
export function decide(
  toolName: string,
  services: ReadonlySet<string>,
  available: boolean,
  config: MappingConfig,
): PreToolDecision {
  const verdict = classifyTool(toolName, config);
  switch (verdict.kind) {
    case 'baseline':
      return { kind: 'allow' };
    case 'classed':
      if (!available) {
        return {
          kind: 'deny',
          reason: `AgentKeys: grant view unavailable (daemon unreachable) — ${verdict.service} cannot be verified, failing closed`,
        };
      }
      if (services.has(verdict.service)) return { kind: 'allow' };
      return {
        kind: 'ask',
        reason: `AgentKeys: requires the ${verdict.service} grant (not held by this delegate)`,
      };
    case 'advertised':
      if (!available) {
        return {
          kind: 'deny',
          reason: `AgentKeys: grant view unavailable (daemon unreachable) — the ${verdict.requiresPrefix}<…> grants cannot be verified, failing closed`,
        };
      }
      if (holdsGrantWithPrefix(services, verdict.requiresPrefix)) return { kind: 'allow' };
      return {
        kind: 'deny',
        reason: `AgentKeys: ${JSON.stringify(toolName)} needs a ${verdict.requiresPrefix}<…> grant and this delegate holds none — it is granted at install (a bound slot, the application's own namespace), never by an allow-once`,
      };
    case 'hidden':
      return {
        kind: 'deny',
        reason: `AgentKeys: ${JSON.stringify(toolName)} is switched off here — this sandbox's OpenViking has no extraction model, so it would store nothing (#726). Save the fact as a file with mcp__openviking__write instead.`,
      };
    case 'unmapped':
      return {
        kind: 'deny',
        reason: `AgentKeys: tool ${JSON.stringify(toolName)} is not covered by any capability class — deny by absence (spec §4.2)`,
      };
  }
}

export function apply(ctx: Context, config: Config): void {
  const grants = new GrantsCache(config);

  ctx.on('tools/pre-execute', async (exec: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision> => {
    const view = await grants.ensureFresh();
    const decision = decide(exec.name, view.services, view.available, config);
    if (decision.kind === 'allow') return next();
    return decision;
  });

  const guard: ToolGuard = (exec) => {
    // An owner's `allowed-once` (recorded by the AgentKeys answerer) authorizes
    // exactly this callId, once — the designed iOS-"Allow Once" escape hatch.
    // Checked FIRST: the owner approved THIS call, so grant-view availability
    // is irrelevant to it (and a cold cache must not eat an approval).
    const verdict = classifyTool(exec.name, config);
    if (verdict.kind === 'classed' && consumeApprovedCall(String(exec.callId))) return undefined;
    const view = grants.current();
    if (!view.available) void grants.ensureFresh(); // sync guard: kick a background warm-up
    const decision = decide(exec.name, view.services, view.available, config);
    if (decision.kind === 'allow') return undefined;
    return decision.reason ?? 'AgentKeys: denied';
  };
  ctx.effect(() => ctx.tools.guard(guard), 'agentkeys-guard: monotonic grant backstop');
}
