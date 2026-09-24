/**
 * @module @agentkeys/dsh-suite/presets — the grant view compiled into each
 * agent's TOOL SCHEMA (plan docs/plan/dsh-plugin-abstraction.md PR 2; spec
 * §4.2 "mount / call class": an ungranted class is ABSENT from the model's
 * schema, not merely refused). The guard stays the monotonic backstop for a
 * call that reaches the pipeline anyway; this plugin makes the ordinary case
 * cheaper and quieter — no tokens spent on tools the delegate cannot use, no
 * deny round-trips, and the deployment's hidden tools (`remember`, #726) go
 * out of view the same way.
 *
 * Mechanism: on `agent/created` the plugin reads the grant view (the same
 * `GET /v1/sandbox/self/grants` the guard reads — a cache of chain state,
 * never authority, D1) and calls `agent.ctx.tools.restrict({ deny })` per
 * name (dsh refuses unknown names, so one call per name, each failure
 * contained). It re-projects on `tools/change` (a tool registered later —
 * the daemon-advertised verbs arrive after boot) and on the grant refresh
 * cadence, so a grant ceremony mounts or unmounts a class live, with no
 * restart (spec §4.2's "revocation = live unmount"). Restrictions intersect
 * in dsh, so each re-projection lifts the previous set first.
 *
 * What is hidden (`deniedTools`, pure): hidden tools; every tool of a
 * `tool:<class>` the delegate lacks; an advertised verb whose grant family
 * it lacks; unmapped tools (deny-by-absence, invariant 2). While the grant
 * view is unavailable every classed / advertised tool is hidden — fail
 * closed, like the guard.
 *
 * Reach (measured on the image smoke, 2026-09-24): `restrict` masks GLOBAL
 * registrations only — dsh-base's tools and the daemon-advertised verbs.
 * A tool registered through an agent's own scope (the OpenViking MCP tools
 * `mcp__openviking__*`, dsh-schedule's reminders) is not in the global list
 * and `restrict` refuses its name, so it stays visible; the guard's verdict
 * is the enforcement there (`remember` is refused at call time, #726). The
 * projection log names what it could not mask so the gap is never silent.
 * NO default export (dsh postmortem 0001).
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { Agent } from '@deepseek-ai/dsh-agent';
import { classifyTool, holdsGrantWithPrefix, type MappingConfig } from './mapping.js';
import { DEFAULT_GRANTS_URL, GrantsCache } from './grants.js';

export const name = 'agentkeys-presets';
export const inject = ['tools', 'agents'];

export interface Config extends MappingConfig {
  grantsUrl?: string;
  bridgeToken?: string;
  ttlMs?: number;
  toolClasses?: Record<string, string[]>;
  baseline?: string[];
  hiddenTools?: string[];
  /** How often the grant view is re-read and every agent re-projected
   *  (a grant ceremony lands within this bound, no restart). */
  refreshMs?: number;
}

export const Config: z<Config> = z.object({
  grantsUrl: z.string().default(DEFAULT_GRANTS_URL),
  bridgeToken: z.string(),
  ttlMs: z.number().default(60_000),
  toolClasses: z.dict(z.array(z.string())),
  baseline: z.array(z.string()),
  hiddenTools: z.array(z.string()),
  refreshMs: z.number().default(60_000),
});

/** The registered tool names an agent must NOT see (pure). */
export function deniedTools(
  names: readonly string[],
  services: ReadonlySet<string>,
  available: boolean,
  config: MappingConfig,
): string[] {
  const denied: string[] = [];
  for (const toolName of names) {
    const verdict = classifyTool(toolName, config);
    switch (verdict.kind) {
      case 'baseline':
        break;
      case 'hidden':
      case 'unmapped':
        denied.push(toolName);
        break;
      case 'classed':
        if (!available || !services.has(verdict.service)) denied.push(toolName);
        break;
      case 'advertised':
        if (!available || !holdsGrantWithPrefix(services, verdict.requiresPrefix)) denied.push(toolName);
        break;
    }
  }
  return denied;
}

export interface ToolScope {
  restrict(filter: { deny: string[] }): () => void;
}

/** Apply one restriction per name (dsh refuses unknown / reserved names —
 *  each failure is contained). Returns the disposers and what took. */
export function applyRestrictions(scope: ToolScope, denied: readonly string[]): { disposers: Array<() => void>; applied: string[]; refused: string[] } {
  const disposers: Array<() => void> = [];
  const applied: string[] = [];
  const refused: string[] = [];
  for (const toolName of denied) {
    try {
      disposers.push(scope.restrict({ deny: [toolName] }));
      applied.push(toolName);
    } catch {
      refused.push(toolName);
    }
  }
  return { disposers, applied, refused };
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((x) => set.has(x));
}

interface Projection {
  agent: Agent;
  disposers: Array<() => void>;
  denied: string[];
  /** Per-agent serialization: `tools/change` and the refresh can overlap. */
  busy: Promise<void>;
}

export function apply(ctx: Context, config: Config): void {
  const grants = new GrantsCache(config);
  const projections = new Map<Agent, Projection>();
  const registeredNames = (): string[] => {
    try {
      return ctx.tools
        .schemas()
        .map((s) => String((s as { name?: unknown }).name ?? ''))
        .filter((n) => n.length > 0);
    } catch {
      return [];
    }
  };

  function lift(p: Projection): void {
    for (const off of p.disposers.splice(0)) {
      try {
        off();
      } catch {
        /* already lifted with the agent */
      }
    }
  }

  function project(p: Projection): Promise<void> {
    p.busy = p.busy.then(async () => {
      if (!projections.has(p.agent)) return;
      const view = await grants.ensureFresh();
      const names = registeredNames();
      const denied = deniedTools(names, view.services, view.available, config);
      if (sameSet(denied, p.denied) && p.disposers.length === denied.length) return;
      lift(p);
      const scope = (p.agent.ctx as unknown as { tools?: ToolScope }).tools;
      if (!scope) return;
      const { disposers, applied, refused } = applyRestrictions(scope, denied);
      p.disposers = disposers;
      p.denied = denied;
      console.log(
        `agentkeys-presets: agent sees ${names.length - applied.length} of ${names.length} tools` +
          (view.available ? '' : ' (grant view unavailable — every classed tool hidden, fail closed)') +
          (applied.length > 0 ? `; hidden: ${applied.join(', ')}` : '') +
          (refused.length > 0 ? `; not maskable (scoped or not yet registered — the guard denies them): ${refused.join(', ')}` : ''),
      );
    }).catch((e: unknown) => {
      // Loud, never fatal: the guard still denies what this projection would
      // have hidden; the next tools/change or refresh re-projects.
      console.error(`agentkeys-presets: projection failed — ${e instanceof Error ? e.message : String(e)}`);
    });
    return p.busy;
  }

  ctx.on('agent/created', ({ agent }: { agent: Agent }) => {
    const p: Projection = { agent, disposers: [], denied: [], busy: Promise.resolve() };
    projections.set(agent, p);
    void project(p);
  });
  ctx.on('agent/disposed', ({ agent }: { agent: Agent }) => {
    const p = projections.get(agent);
    if (!p) return;
    projections.delete(agent);
    lift(p);
  });
  ctx.on('tools/change', () => {
    for (const p of projections.values()) void project(p);
  });
  const timer = setInterval(() => {
    void grants.refresh().then(() => {
      for (const p of projections.values()) void project(p);
    });
  }, config.refreshMs ?? 60_000);
  timer.unref?.();
  ctx.effect(() => () => clearInterval(timer), 'agentkeys-presets: grant refresh');
  ctx.effect(
    () => () => {
      for (const p of projections.values()) lift(p);
      projections.clear();
    },
    'agentkeys-presets: lift every projection',
  );
}
