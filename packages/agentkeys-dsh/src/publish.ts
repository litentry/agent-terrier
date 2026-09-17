/**
 * @module @agentkeys/dsh-suite/publish — the delegate's "act" verb as a
 * first-class tool (#669 R3): `publish_to_slot` publishes ONE event to a
 * bound pub slot of this application (or to `opchat`, the owner chat) — a
 * card (`doc`) to the display slot, a `text` line to a messaging slot, a
 * `command` to an actuator.
 *
 * It is the in-process twin of the image's `publish-to-slot` shell helper:
 * the same `agentkeys-daemon --publish-once` invocation (the daemon signs as
 * this delegate and mints the publish cap; an ungranted feed is refused at
 * cap-mint with the worker's reason — never a local rule), reachable WITHOUT
 * the `tool:code` grant. The helper needed `bash`, which no application sheet
 * grants, so a chef told to "publish the card" wrote a file and reported it
 * published (measured 2026-09-17, on the 07:00 clock and on demand).
 *
 * Guard: verdict `publish` (mapping.ts) — allowed when the delegate holds any
 * `channel-pub:<id>` data service; WHICH feed is the cap-mint's verdict.
 * NO default export (dsh postmortem 0001).
 */
import { spawn } from 'node:child_process';
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';

export const name = 'agentkeys-publish';
export const inject = ['tools'];

export const PUBLISH_TOOL_NAME = 'publish_to_slot';
/** The kinds a delegate publishes: the wire's `ChannelEventKind` minus
 *  `lifecycle` (only the runtime emits that). */
export const EVENT_KINDS = ['text', 'doc', 'image', 'command', 'audio-clip', 'frame'] as const;
/** The owner chat: always a valid target (the daemon resolves it itself). */
export const OPCHAT_SLOT = 'opchat';
const DEFAULT_DAEMON_COMMAND = 'agentkeys-daemon';
const DEFAULT_TIMEOUT_MS = 90_000;
const STDERR_TAIL_LINES = 4;

export interface Config {
  /** The daemon binary — a PATH lookup by default (the image installs it in
   *  /usr/local/bin, exactly what the shell helper resolves). */
  daemonCommand?: string;
  /** Budget for one publish: the cap mint + the worker put (+ a by-reference
   *  upload for a large body). */
  timeoutMs?: number;
}

export const Config: z<Config> = z.object({
  daemonCommand: z.string().default(DEFAULT_DAEMON_COMMAND),
  timeoutMs: z.number().default(DEFAULT_TIMEOUT_MS),
});

export interface PublishArgs {
  slot: string;
  kind?: string;
  body: string;
  correlation?: string;
  content_type?: string;
}

/** The daemon argv for one publish (pure): what `publish-to-slot` runs. */
export function publishArgv(a: PublishArgs): string[] {
  const argv = ['--publish-once', '--publish-slot', a.slot.trim(), '--publish-kind', (a.kind ?? 'text').trim() || 'text'];
  const correlation = (a.correlation ?? '').trim();
  if (correlation) argv.push('--publish-correlation', correlation);
  const contentType = (a.content_type ?? '').trim();
  if (contentType) argv.push('--publish-content-type', contentType);
  return argv;
}

/** The slots this delegate can publish to, from the spawn's
 *  `AGENTKEYS_BOUND_CHANNELS` (a `BoundChannel[]`; a `sub`-only slot is
 *  read-only), plus `opchat`. Pure; a malformed env lists only `opchat` —
 *  the daemon reports the env, the tool still exists. */
export function boundPubSlots(env: Record<string, string | undefined>): string[] {
  const slots = new Set<string>();
  try {
    const rows: unknown = JSON.parse(env.AGENTKEYS_BOUND_CHANNELS ?? '[]');
    if (Array.isArray(rows)) {
      for (const row of rows as Array<{ slot?: unknown; direction?: unknown }>) {
        if (typeof row?.slot !== 'string' || row.slot.length === 0) continue;
        if (String(row.direction ?? '').toLowerCase() === 'sub') continue;
        slots.add(row.slot);
      }
    }
  } catch {
    // not this tool's error to raise
  }
  slots.add(OPCHAT_SLOT);
  return [...slots];
}

/** The daemon's receipt (its stdout, pretty JSON). A type alias on purpose:
 *  the tool's output schema is an open object, and an alias carries the
 *  implicit index signature an interface lacks. */
export type Receipt = {
  outcome: string;
  slot: string;
  channel_id: string;
  kind: string;
  bytes: number;
  correlation: string;
};

/** Parse the receipt, or null when stdout is not one (pure). */
export function parseReceipt(stdout: string): Receipt | null {
  const start = stdout.indexOf('{');
  if (start < 0) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(start));
  } catch {
    return null;
  }
  const r = (parsed ?? {}) as Record<string, unknown>;
  if (typeof r.slot !== 'string' || typeof r.channel_id !== 'string' || typeof r.kind !== 'string') return null;
  return {
    outcome: typeof r.outcome === 'string' ? r.outcome : 'published',
    slot: r.slot,
    channel_id: r.channel_id,
    kind: r.kind,
    bytes: typeof r.bytes === 'number' ? r.bytes : 0,
    correlation: typeof r.correlation === 'string' ? r.correlation : '',
  };
}

/** The daemon's last stderr lines on one line — the cap-mint refusal reason
 *  lives there, and the model must see it to tell the owner (pure). */
export function stderrTail(stderr: string): string {
  return stderr
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .slice(-STDERR_TAIL_LINES)
    .join(' | ');
}

export interface DaemonRun {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Run `<command> <argv>` with `body` on stdin. Resolves on exit whatever the
 *  code (the caller reads stderr); rejects only when the process cannot start,
 *  the caller aborts, or the budget runs out (the child is SIGTERMed then). */
export function runDaemon(
  command: string,
  argv: string[],
  body: string,
  opts: { signal?: AbortSignal; timeoutMs: number },
): Promise<DaemonRun> {
  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) {
      reject(new Error(`${PUBLISH_TOOL_NAME}: aborted before the daemon started`));
      return;
    }
    const child = spawn(command, argv, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      fn();
    };
    const onAbort = () => {
      child.kill('SIGTERM');
      settle(() => reject(new Error(`${PUBLISH_TOOL_NAME}: aborted`)));
    };
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      settle(() => reject(new Error(`${PUBLISH_TOOL_NAME}: ${command} did not finish within ${opts.timeoutMs} ms`)));
    }, opts.timeoutMs);
    opts.signal?.addEventListener('abort', onAbort, { once: true });
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString('utf8');
    });
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString('utf8');
    });
    child.on('error', (e) => settle(() => reject(new Error(`${PUBLISH_TOOL_NAME}: cannot run ${command} — ${e.message}`))));
    child.on('close', (code) => settle(() => resolve({ code, stdout, stderr })));
    child.stdin.on('error', () => {
      // EPIPE when the daemon exits before draining stdin — its exit code tells
    });
    child.stdin.end(body);
  });
}

export function apply(ctx: Context, config: Config): void {
  const command = (config.daemonCommand ?? '').trim() || DEFAULT_DAEMON_COMMAND;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const slots = boundPubSlots(process.env);
  const slotList = slots.join(', ');
  ctx.effect(
    () =>
      ctx.tools.register(
        defineTool({
          name: PUBLISH_TOOL_NAME,
          description: [
            'Publish ONE event to a feed this application is bound to — the only way anything reaches a screen, a chat, or a device (a file you write publishes nothing).',
            'kind `doc` with the card JSON as `body` puts a card on a display slot; `text` sends a line to a chat slot; `command` drives an actuator; the `opchat` slot is your owner’s chat.',
            `Slots you can publish to now: ${slotList}.`,
            'A refused slot was not granted at install — say so in your reply instead of retrying.',
          ].join(' '),
          parameters: {
            slot: { type: 'string', required: true, description: `The bound slot name (one of: ${slotList}) or a channel id.` },
            kind: { type: 'string', enum: [...EVENT_KINDS], description: 'The event kind; default text. A card is doc.' },
            body: {
              type: 'string',
              required: true,
              description: 'The event body, verbatim: the card JSON (card: 1 contract) for doc, the message for text, the command JSON for command.',
            },
            correlation: {
              type: 'string',
              description: 'Optional: the id of the event this answers (a command you act on), so the reply threads to it.',
            },
            content_type: { type: 'string', description: 'Optional media type; the default follows the kind (doc = the card type).' },
          },
          output: {
            schema: {
              type: 'object',
              additionalProperties: true,
              properties: {
                outcome: { type: 'string', required: true },
                slot: { type: 'string', required: true },
                channel_id: { type: 'string', required: true },
                kind: { type: 'string', required: true },
                bytes: { type: 'integer', required: true },
                correlation: { type: 'string', required: true },
              },
            },
            render: (_args, value) => [
              {
                type: 'text',
                text: `${value.outcome}: ${value.kind} → ${value.slot} (${value.channel_id}), ${value.bytes} bytes, correlation ${value.correlation}`,
              },
            ],
          },
          isConcurrencySafe: () => false,
          async execute(args, exec) {
            if (args.body.trim().length === 0) throw new Error(`${PUBLISH_TOOL_NAME}: body is empty — nothing to publish`);
            const run = await runDaemon(command, publishArgv(args), args.body, { signal: exec.signal, timeoutMs });
            if (run.code !== 0) {
              const why = run.stderr.trim().length > 0 ? ` — ${stderrTail(run.stderr)}` : '';
              throw new Error(`${PUBLISH_TOOL_NAME}: ${command} exited ${run.code ?? 'by signal'}${why}`);
            }
            const receipt = parseReceipt(run.stdout);
            if (receipt === null) {
              throw new Error(`${PUBLISH_TOOL_NAME}: no receipt on stdout (${run.stdout.trim().slice(0, 200) || 'empty'})`);
            }
            return receipt;
          },
        }),
      ),
    'agentkeys-publish: the publish_to_slot tool',
  );
}
