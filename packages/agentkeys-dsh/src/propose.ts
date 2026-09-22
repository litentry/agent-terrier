/**
 * @module @agentkeys/dsh-suite/propose — the delegate's "propose" verb as a
 * first-class tool (2026-09-18): `propose_to_owner` pushes ONE durable
 * learning into the owner's review queue (the #339/#573 absorption bridge).
 * The owner accepts it on the Knowledge page, where it becomes an item of a
 * household namespace and reaches every application granted that namespace
 * as a resource — the only way anything an agent learns crosses applications.
 *
 * It is the in-process twin of the image's `propose-to-owner` shell helper:
 * the same `agentkeys-daemon --propose-once` invocation (the daemon signs as
 * this delegate and cap-mints against the on-chain `proposal:<ns>` grant; an
 * ungranted namespace is refused at cap-mint with the worker's reason; rate-
 * and size-bounded there), reachable WITHOUT the `tool:code` grant the helper
 * needed — which no application sheet grants, so no application could
 * propose (the publish-to-slot lesson of 2026-09-17).
 *
 * Guard: verdict `propose` (mapping.ts) — allowed when the delegate holds any
 * `proposal:<ns>` data service (every installed application holds its own);
 * WHICH namespace is the cap-mint's verdict. NO default export (dsh
 * postmortem 0001).
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { runDaemon, stderrTail } from './publish.js';

export const name = 'agentkeys-propose';
export const inject = ['tools'];

export const PROPOSE_TOOL_NAME = 'propose_to_owner';
/** The context kinds a proposal may carry (`persona` is never adoptable). */
export const PROPOSAL_KINDS = ['knowledge', 'skill'] as const;
const DEFAULT_DAEMON_COMMAND = 'agentkeys-daemon';
const DEFAULT_TIMEOUT_MS = 60_000;

export interface Config {
  /** The daemon binary — a PATH lookup by default (the image installs it in
   *  /usr/local/bin, exactly what the shell helper resolves). */
  daemonCommand?: string;
  /** Budget for one proposal: the cap mint + the inbox append. */
  timeoutMs?: number;
}

export const Config: z<Config> = z.object({
  daemonCommand: z.string().default(DEFAULT_DAEMON_COMMAND),
  timeoutMs: z.number().default(DEFAULT_TIMEOUT_MS),
});

export interface ProposeArgs {
  text: string;
  namespace?: string;
  key?: string;
  kind?: string;
}

/** The daemon argv for one proposal (pure): what `propose-to-owner` runs. */
export function proposeArgv(a: ProposeArgs): string[] {
  const argv = ['--propose-once'];
  const namespace = (a.namespace ?? '').trim();
  if (namespace) argv.push('--propose-ns', namespace);
  const key = (a.key ?? '').trim();
  if (key) argv.push('--propose-key', key);
  const kind = (a.kind ?? '').trim();
  if (kind) argv.push('--propose-kind', kind);
  return argv;
}

/** The namespace a proposal lands in when none is named: the delegate's own
 *  (the first of the spawn's `AGENTKEYS_MEMORY_NAMESPACES`, the daemon's own
 *  default). Pure; empty when the env carries none. */
export function defaultProposalNamespace(env: Record<string, string | undefined>): string {
  // The application's OWN namespace first (`AGENTKEYS_MEMORY_NS` — the inbox
  // every install is granted, `proposal:app-<label>`), else the first of the
  // pull list. The pull list OPENS with the household namespaces the app only
  // READS, which it can never propose into — measured 2026-09-18: chef's list
  // was `household,personal,…` while its only proposal grant was `app-chef`.
  const own = (env.AGENTKEYS_MEMORY_NS ?? '').trim();
  if (own) return own;
  const first = (env.AGENTKEYS_MEMORY_NAMESPACES ?? '').split(',')[0] ?? '';
  return first.trim();
}

/** The daemon's receipt (its stdout, pretty JSON). A type alias on purpose:
 *  the tool's output schema is an open object. */
export type ProposalReceipt = {
  outcome: string;
  namespace: string;
  key: string;
  kind: string;
  content_hash: string;
};

/** Parse the receipt, or null when stdout is not one (pure). */
export function parseProposalReceipt(stdout: string): ProposalReceipt | null {
  const start = stdout.indexOf('{');
  if (start < 0) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(start));
  } catch {
    return null;
  }
  const r = (parsed ?? {}) as Record<string, unknown>;
  if (typeof r.namespace !== 'string' || typeof r.key !== 'string' || typeof r.kind !== 'string') return null;
  return {
    outcome: typeof r.outcome === 'string' ? r.outcome : 'proposed',
    namespace: r.namespace,
    key: r.key,
    kind: r.kind,
    content_hash: typeof r.content_hash === 'string' ? r.content_hash : '',
  };
}

export function apply(ctx: Context, config: Config): void {
  const command = (config.daemonCommand ?? '').trim() || DEFAULT_DAEMON_COMMAND;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const ownNamespace = defaultProposalNamespace(process.env);
  const ownNote = ownNamespace
    ? ` Your own namespace is ${ownNamespace}; that is the default — leave the namespace out unless the owner told you which shared one you may propose into.`
    : '';
  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: PROPOSE_TOOL_NAME,
          description: [
            'Propose ONE durable learning to your owner — a standing preference, a fact about the household, a rule you were told — so it can outlive this sandbox and reach the other applications.',
            'It lands in the owner’s review queue; nothing enters shared knowledge until they accept it. Propose the distilled learning (a few sentences), never a transcript; batch related learnings into one proposal.',
            `A namespace you are not granted to propose into is refused — say so in your reply instead of retrying.${ownNote}`,
          ].join(' '),
          parameters: {
            text: { type: 'string', required: true, description: 'The learning, distilled: what to keep and why it matters.' },
            namespace: { type: 'string', description: 'The knowledge namespace it belongs to (default: your own).' },
            key: { type: 'string', description: 'Optional stable key, so a refined proposal replaces the earlier one.' },
            kind: { type: 'string', enum: [...PROPOSAL_KINDS], description: 'knowledge (default) or skill.' },
          },
          output: {
            schema: {
              type: 'object',
              additionalProperties: true,
              properties: {
                outcome: { type: 'string', required: true },
                namespace: { type: 'string', required: true },
                key: { type: 'string', required: true },
                kind: { type: 'string', required: true },
                content_hash: { type: 'string', required: true },
              },
            },
            render: (_args, value) => [
              {
                type: 'text',
                text: `${value.outcome}: ${value.kind} → ${value.namespace}/${value.key} (awaiting the owner’s review)`,
              },
            ],
          },
          isConcurrencySafe: () => false,
          async execute(args, exec) {
            if (args.text.trim().length === 0) throw new Error(`${PROPOSE_TOOL_NAME}: text is empty — nothing to propose`);
            const run = await runDaemon(command, proposeArgv(args), args.text, { signal: exec.signal, timeoutMs });
            if (run.code !== 0) {
              const why = run.stderr.trim().length > 0 ? ` — ${stderrTail(run.stderr)}` : '';
              throw new Error(`${PROPOSE_TOOL_NAME}: ${command} exited ${run.code ?? 'by signal'}${why}`);
            }
            const receipt = parseProposalReceipt(run.stdout);
            if (receipt === null) {
              throw new Error(`${PROPOSE_TOOL_NAME}: no receipt on stdout (${run.stdout.trim().slice(0, 200) || 'empty'})`);
            }
            return receipt;
          },
        }),
      ),
    'agentkeys-propose: the propose_to_owner tool',
  );
}
