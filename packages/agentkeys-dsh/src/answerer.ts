/**
 * @module @agentkeys/dsh-suite/answerer — the AgentKeys approval answerer (#611).
 *
 * Resolves every `approval/request` against the delegate's on-chain grant view:
 *  - grant-classed tool whose `tool:<class>` IS granted → `allowed-once`
 *    (recorded in the one-shot ledger the guard consumes);
 *  - classed but ungranted → best-effort propose-to-owner (#573 inbox, the
 *    daemon's own rate/size gates apply), then `rejected` — the owner grants on
 *    chain and the next attempt passes without asking;
 *  - baseline (never should ask) and unmapped → `rejected`.
 *
 * Single-answerer deployment: this never calls `next()` — there is no other
 * answerer to defer to in the sandbox profile, and falling through would land
 * on the fail-closed `unavailable`. NO default export (postmortem 0001).
 */
import { spawn } from 'node:child_process';
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { ApprovalOutcome, ApprovalRequest } from '@deepseek-ai/dsh-user-approval';
import { classifyTool, type MappingConfig } from './mapping.js';
import { DEFAULT_GRANTS_URL, GrantsCache, recordApprovedCall } from './grants.js';

export const name = 'agentkeys-answerer';
export const inject = ['approval'];

export interface Config extends MappingConfig {
  grantsUrl?: string;
  bridgeToken?: string;
  ttlMs?: number;
  toolClasses?: Record<string, string[]>;
  baseline?: string[];
  publishTools?: string[];
  proposeTools?: string[];
  /** Best-effort propose-to-owner command (the #573 wrapper baked into the
   *  sandbox image); empty disables. The daemon enforces its own rate + size
   *  caps — this plugin only throttles duplicates per class. */
  proposeCommand?: string;
}

export const Config: z<Config> = z.object({
  grantsUrl: z.string().default(DEFAULT_GRANTS_URL),
  bridgeToken: z.string(),
  ttlMs: z.number().default(60_000),
  toolClasses: z.dict(z.array(z.string())),
  baseline: z.array(z.string()),
  publishTools: z.array(z.string()),
  proposeTools: z.array(z.string()),
  proposeCommand: z.string().default('/opt/agentkeys/propose-to-owner'),
});

const PROPOSE_THROTTLE_MS = 10 * 60_000;
const lastProposeByService = new Map<string, number>();

export function proposeBody(service: string, toolName: string): string {
  return [
    `# Grant request: ${service}`,
    '',
    `The delegate tried to use the tool ${JSON.stringify(toolName)}, which requires the ${service} capability grant.`,
    `Approve it from the permissions page (the toggle mints the grant), or ignore to keep it denied.`,
  ].join('\n');
}

function maybePropose(config: Config, service: string, toolName: string, now = Date.now()): void {
  const command = config.proposeCommand ?? '';
  if (!command) return;
  const last = lastProposeByService.get(service) ?? 0;
  if (now - last < PROPOSE_THROTTLE_MS) return;
  lastProposeByService.set(service, now);
  try {
    const child = spawn(command, [], { stdio: ['pipe', 'ignore', 'ignore'], detached: false });
    child.on('error', () => {});
    child.stdin.write(proposeBody(service, toolName));
    child.stdin.end();
  } catch {
    // best-effort by design: a missing wrapper never blocks the rejection
  }
}

/** Pure outcome core (exported for tests). */
export function answer(
  toolName: string,
  callId: string | undefined,
  services: ReadonlySet<string>,
  available: boolean,
  config: Config,
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
        propose: (service) => maybePropose(config, service, req.toolName),
      },
    );
  });
}
