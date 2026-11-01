/**
 * @module @agentkeys/dsh-suite/answerer — the AgentKeys approval answerer (#611).
 *
 * Resolves every `approval/request` against the delegate's on-chain grant view:
 *  - grant-classed tool whose `tool:<class>` IS granted → `allowed-once`
 *    (recorded in the one-shot ledger the guard consumes);
 *  - classed but ungranted → the RUNTIME ASK (spec §4.4): a grant request
 *    filed with the owner through the daemon's `POST /v1/sandbox/self/propose`
 *    (the advertised propose verb's route, the app's own `proposal:<ns>`
 *    queue — the daemon's rate/size gates apply), then `rejected`; the owner
 *    grants on chain and the next attempt passes without asking;
 *  - baseline (never should ask), advertised, hidden and unmapped → `rejected`.
 *
 * The ask never blocks or fails the deny: one ask per class per window, a
 * stable key per class so a repeat refines the item instead of piling up, and
 * a failed ask is a console error carrying the daemon's reason that releases
 * the throttle so the next deny retries. (Until 2026-09-24 this spawned the
 * image's shell helper at a path the image no longer had, with the text on
 * stdin the helper never read, and swallowed the error — no owner ever saw an
 * ask; measured in the local twin, PR #727.)
 *
 * Single-answerer deployment: this never calls `next()` — there is no other
 * answerer to defer to in the sandbox profile, and falling through would land
 * on the fail-closed `unavailable`. NO default export (postmortem 0001).
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { ApprovalOutcome, ApprovalRequest } from '@deepseek-ai/dsh-user-approval';
import { classifyTool, type MappingConfig } from './mapping.js';
import { DEFAULT_GRANTS_URL, GrantsCache, recordApprovedCall } from './grants.js';
import { DaemonClient, DEFAULT_DAEMON_URL } from './daemon-client.js';

export const name = 'agentkeys-answerer';
export const inject = ['approval'];

export const DEFAULT_PROPOSE_URL = `${DEFAULT_DAEMON_URL}/v1/sandbox/self/propose`;
/** One ask per capability class per window — the owner sees ONE request,
 *  not one per denied call while the model keeps trying. */
export const PROPOSE_THROTTLE_MS = 10 * 60_000;
const PROPOSE_TIMEOUT_MS = 60_000;

export interface Config extends MappingConfig {
  grantsUrl?: string;
  bridgeToken?: string;
  ttlMs?: number;
  toolClasses?: Record<string, string[]>;
  baseline?: string[];
  hiddenTools?: string[];
  /** The daemon's proposal route the runtime ask is filed through (bearer =
   *  the in-pod bridge token like the grant view). Empty disables the ask —
   *  the deny then stands alone. */
  proposeUrl?: string;
}

export const Config: z<Config> = z.object({
  grantsUrl: z.string().default(DEFAULT_GRANTS_URL),
  bridgeToken: z.string(),
  ttlMs: z.number().default(60_000),
  toolClasses: z.dict(z.array(z.string())),
  baseline: z.array(z.string()),
  hiddenTools: z.array(z.string()),
  proposeUrl: z.string().default(DEFAULT_PROPOSE_URL),
});

export function proposeBody(service: string, toolName: string): string {
  return [
    `# Grant request: ${service}`,
    '',
    `The delegate tried to use the tool ${JSON.stringify(toolName)}, which requires the ${service} capability grant.`,
    `Approve it from the permissions page (the toggle mints the grant), or ignore to keep it denied.`,
  ].join('\n');
}

/** A stable inbox key per class, so a repeated ask for the same capability
 *  refines the earlier item instead of piling up (`tool:web` →
 *  `grant-request-tool-web`). */
export function proposeKey(service: string): string {
  return `grant-request-${service.toLowerCase().replace(/[^a-z0-9._-]+/g, '-')}`;
}

/** Per-class duplicate suppression for the ask. One per `apply()` — a plain
 *  object so tests own their own clock and window. */
export class ProposeThrottle {
  private readonly lastByService = new Map<string, number>();
  constructor(private readonly windowMs = PROPOSE_THROTTLE_MS) {}

  /** Claim the window for `service`; false while a claim is still fresh. */
  claim(service: string, now = Date.now()): boolean {
    const last = this.lastByService.get(service) ?? 0;
    if (now - last < this.windowMs) return false;
    this.lastByService.set(service, now);
    return true;
  }

  /** Give the window back — a failed ask must not silence the next deny. */
  release(service: string): void {
    this.lastByService.delete(service);
  }
}

export type ProposeOutcome = 'filed' | 'throttled' | 'disabled' | 'failed';

/** File the runtime ask for `service` (denied on `toolName`) with the owner.
 *  Never throws and never blocks the deny: a failure is a console error
 *  carrying the daemon's reason (a refused namespace, an unreachable daemon)
 *  and releases the throttle so the next deny retries. */
export async function maybePropose(
  config: Pick<Config, 'proposeUrl' | 'bridgeToken'>,
  service: string,
  toolName: string,
  throttle: ProposeThrottle,
  now = Date.now(),
): Promise<ProposeOutcome> {
  const url = config.proposeUrl ?? DEFAULT_PROPOSE_URL;
  if (!url) return 'disabled';
  if (!throttle.claim(service, now)) return 'throttled';
  const label = `runtime ask for ${service} (denied ${JSON.stringify(toolName)})`;
  try {
    const client = new DaemonClient({ bridgeToken: config.bridgeToken });
    const receipt = await client.postJson<{ namespace?: unknown; key?: unknown }>(
      url,
      { text: proposeBody(service, toolName), key: proposeKey(service) },
      { timeoutMs: PROPOSE_TIMEOUT_MS },
    );
    const where = typeof receipt.namespace === 'string' && typeof receipt.key === 'string' ? ` → ${receipt.namespace}/${receipt.key}` : '';
    console.log(`agentkeys-answerer: ${label} filed in the owner's review queue${where}`);
    return 'filed';
  } catch (e) {
    throttle.release(service);
    const reason = e instanceof Error ? e.message : String(e);
    console.error(
      `agentkeys-answerer: ${label} did NOT reach the owner — ${reason} (${url}); the deny stands, but the owner sees no request until this is fixed`,
    );
    return 'failed';
  }
}

/** Pure outcome core (exported for tests). */
export function answer(
  toolName: string,
  callId: string | undefined,
  services: ReadonlySet<string>,
  available: boolean,
  config: MappingConfig,
  effects: { record: (callId: string) => void; propose: (service: string) => void },
): ApprovalOutcome {
  const verdict = classifyTool(toolName, config);
  if (verdict.kind !== 'classed') return 'rejected';
  if (available && services.has(verdict.service)) {
    if (callId) effects.record(callId);
    return 'allowed-once';
  }
  if (available) effects.propose(verdict.service);
  return 'rejected';
}

export function apply(ctx: Context, config: Config): void {
  const grants = new GrantsCache(config);
  const throttle = new ProposeThrottle();
  ctx.on('approval/request', async (req: ApprovalRequest, _next: () => Promise<ApprovalOutcome>): Promise<ApprovalOutcome> => {
    const view = await grants.ensureFresh();
    return answer(
      req.toolName,
      req.callId === undefined ? undefined : String(req.callId),
      view.services,
      view.available,
      config,
      {
        record: recordApprovedCall,
        // Fire-and-forget by design: a deny never waits on a cap mint.
        propose: (service) => void maybePropose(config, service, req.toolName, throttle),
      },
    );
  });
}
