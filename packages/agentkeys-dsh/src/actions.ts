/**
 * @module @agentkeys/dsh-suite/actions — the daemon-ADVERTISED verbs as tools
 * (plan docs/plan/dsh-plugin-abstraction.md PR 1; spec §4.2 "Advertised
 * actions"): `GET /v1/sandbox/self/actions` names the verbs this delegate
 * may call (`publish_to_slot`, `propose_to_owner`), worded by the daemon with
 * the slots THIS install bound and the app's own namespace; this plugin
 * registers one tool per entry and runs each call as ONE bearer-gated
 * `POST <route>` through the daemon client. The daemon signs as the delegate
 * and cap-mints per call — an ungranted feed or namespace is refused THERE
 * with the worker's reason, which reaches the model verbatim.
 *
 * It replaces the two plugins that forked `agentkeys-daemon --publish-once` /
 * `--propose-once` per call and re-derived the slot list + the namespace
 * default from env in TypeScript (two owners of one fact). The guard's
 * verdict for an advertised tool comes from the same list: allowed when the
 * delegate holds ANY grant of the family the entry declares (mapping.ts).
 *
 * The list is closed and daemon-owned — never an operator-configurable tool
 * server (spec §4.5). NO default export (dsh postmortem 0001).
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { DaemonClient, DaemonError, DEFAULT_DAEMON_URL } from './daemon-client.js';
import { registerAdvertised } from './mapping.js';

export const name = 'agentkeys-actions';
export const inject = ['tools'];

/** The daemon's advertisement route (agentkeys-protocol `sandbox_actions`). */
export const ACTIONS_PATH = '/v1/sandbox/self/actions';

export interface Config {
  daemonUrl?: string;
  bridgeToken?: string;
  /** Budget for one call: the cap mint + the worker put (+ a by-reference
   *  upload for a large body). */
  timeoutMs?: number;
  /** How long to wait between advertisement fetches while the daemon is
   *  still coming up (supervisord starts both; order is not guaranteed). */
  retryMs?: number;
  /** After this long without an advertisement the plugin logs an error (and
   *  keeps retrying at the slow cadence). */
  maxWaitMs?: number;
}

export const Config: z<Config> = z.object({
  daemonUrl: z.string().default(DEFAULT_DAEMON_URL),
  bridgeToken: z.string(),
  timeoutMs: z.number().default(90_000),
  retryMs: z.number().default(2_000),
  maxWaitMs: z.number().default(300_000),
});

const SLOW_RETRY_MS = 60_000;

export interface AdvertisedParam {
  name: string;
  kind: string;
  required: boolean;
  description: string;
  choices?: string[];
}

export interface AdvertisedAction {
  name: string;
  description: string;
  route: string;
  requires_grant_prefix: string;
  parameters: AdvertisedParam[];
  receipt_fields: string[];
}

const TOOL_NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** Parse + validate the daemon's advertisement (pure): a malformed entry is a
 *  daemon bug, so the whole document is refused rather than half-registered. */
export function parseAdvertised(body: unknown): AdvertisedAction[] {
  const doc = body as { actions?: unknown };
  if (!doc || !Array.isArray(doc.actions)) throw new Error('advertisement lacks an actions array');
  const out: AdvertisedAction[] = [];
  for (const raw of doc.actions as unknown[]) {
    const a = raw as Partial<AdvertisedAction>;
    if (typeof a.name !== 'string' || !TOOL_NAME.test(a.name)) throw new Error(`action name ${JSON.stringify(a.name)} is not a tool name`);
    if (typeof a.description !== 'string' || a.description.trim().length === 0) throw new Error(`${a.name}: description missing`);
    if (typeof a.route !== 'string' || !a.route.startsWith('/')) throw new Error(`${a.name}: route must be a daemon path`);
    if (typeof a.requires_grant_prefix !== 'string' || !a.requires_grant_prefix.endsWith(':')) {
      throw new Error(`${a.name}: requires_grant_prefix must name a grant family (…:)`);
    }
    if (!Array.isArray(a.parameters)) throw new Error(`${a.name}: parameters missing`);
    const parameters: AdvertisedParam[] = [];
    for (const p of a.parameters as Partial<AdvertisedParam>[]) {
      if (typeof p.name !== 'string' || !TOOL_NAME.test(p.name)) throw new Error(`${a.name}: bad parameter name ${JSON.stringify(p.name)}`);
      if (p.kind !== 'string') throw new Error(`${a.name}.${p.name}: only string parameters are supported (got ${JSON.stringify(p.kind)})`);
      parameters.push({
        name: p.name,
        kind: p.kind,
        required: p.required === true,
        description: typeof p.description === 'string' ? p.description : '',
        ...(Array.isArray(p.choices) && p.choices.length > 0 ? { choices: p.choices.map(String) } : {}),
      });
    }
    out.push({
      name: a.name,
      description: a.description,
      route: a.route,
      requires_grant_prefix: a.requires_grant_prefix,
      parameters,
      receipt_fields: Array.isArray(a.receipt_fields) ? a.receipt_fields.map(String) : [],
    });
  }
  return out;
}

/** One string parameter in dsh's tool-schema shape (`required` is the
 *  literal `true` or absent — the runtime's own type). */
export type ToolParameter = { type: 'string'; required?: true; description: string; enum?: string[] };

/** The dsh tool-schema parameters for an action (pure). */
export function toolParameters(a: AdvertisedAction): Record<string, ToolParameter> {
  const out: Record<string, ToolParameter> = {};
  for (const p of a.parameters) {
    const spec: ToolParameter = { type: 'string', description: p.description };
    if (p.required) spec.required = true;
    if (p.choices && p.choices.length > 0) spec.enum = [...p.choices];
    out[p.name] = spec;
  }
  return out;
}

/** The POST body for one call (pure): only declared parameters, trimmed, an
 *  optional left blank is omitted (the daemon's defaults apply). */
export function callBody(a: AdvertisedAction, args: Record<string, unknown>): Record<string, string> {
  const body: Record<string, string> = {};
  for (const p of a.parameters) {
    const v = args[p.name];
    if (typeof v !== 'string') continue;
    if (p.required) {
      body[p.name] = v;
      continue;
    }
    const trimmed = v.trim();
    if (trimmed.length > 0) body[p.name] = trimmed;
  }
  return body;
}

/** The required parameters a call left empty (pure). */
export function missingRequired(a: AdvertisedAction, args: Record<string, unknown>): string[] {
  return a.parameters
    .filter((p) => p.required)
    .filter((p) => {
      const v = args[p.name];
      return typeof v !== 'string' || v.trim().length === 0;
    })
    .map((p) => p.name);
}

/** A JSON value — what a daemon reply parses to (the tool runtime's
 *  output type wants lossless JSON, never `unknown`). */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type Receipt = { outcome: string; summary: string } & Record<string, JsonValue>;

/** Normalize a 2xx reply into the receipt the tool returns (pure): `summary`
 *  is the rendered line, so a daemon that omits it still renders. */
export function toReceipt(a: AdvertisedAction, reply: unknown): Receipt {
  const r = (reply && typeof reply === 'object' && !Array.isArray(reply) ? reply : {}) as Record<string, JsonValue>;
  const outcome = typeof r.outcome === 'string' && r.outcome.length > 0 ? r.outcome : 'done';
  const summary = typeof r.summary === 'string' && r.summary.length > 0 ? r.summary : `${outcome}: ${a.name}`;
  return { ...r, outcome, summary };
}

function toolFor(a: AdvertisedAction, client: DaemonClient, timeoutMs: number) {
  return defineTool({
    name: a.name,
    description: a.description,
    parameters: toolParameters(a),
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        properties: {
          outcome: { type: 'string', required: true },
          summary: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: String((value as { summary?: unknown }).summary ?? '') }],
    },
    isConcurrencySafe: () => false,
    async execute(args, exec) {
      const missing = missingRequired(a, args as Record<string, unknown>);
      if (missing.length > 0) throw new Error(`${a.name}: ${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} required`);
      try {
        const reply = await client.postJson<unknown>(a.route, callBody(a, args as Record<string, unknown>), { timeoutMs, signal: exec.signal });
        return toReceipt(a, reply);
      } catch (e) {
        if (e instanceof DaemonError) throw new Error(`${a.name}: ${e.reason} (daemon HTTP ${e.status})`);
        throw new Error(`${a.name}: ${e instanceof Error ? e.message : String(e)}`);
      }
    },
  });
}

let latest: Promise<AdvertisedAction[]> = Promise.resolve([]);

/** Resolves once the most recently mounted plugin has registered its tools
 *  (tests + diagnostics; the plugin runs in a forked context, so this is
 *  module-level rather than keyed on a context). */
export function whenRegistered(): Promise<AdvertisedAction[]> {
  return latest;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export function apply(ctx: Context, config: Config): void {
  const client = new DaemonClient({ baseUrl: config.daemonUrl, bridgeToken: config.bridgeToken });
  const url = client.url(ACTIONS_PATH);
  const timeoutMs = config.timeoutMs ?? 90_000;
  const retryMs = config.retryMs ?? 2_000;
  const maxWaitMs = config.maxWaitMs ?? 300_000;
  let stopped = false;
  ctx.effect(
    () => () => {
      stopped = true;
    },
    'agentkeys-actions: stop fetching on dispose',
  );
  const started = Date.now();
  let warned = false;
  const ready = (async (): Promise<AdvertisedAction[]> => {
    for (;;) {
      if (stopped) return [];
      try {
        const actions = parseAdvertised(await client.getJson<unknown>(url, { timeoutMs: 10_000 }));
        if (stopped) return [];
        registerAdvertised(actions);
        for (const a of actions) {
          ctx.effect(() => ctx.tools.register(toolFor(a, client, timeoutMs)), `agentkeys-actions: ${a.name}`);
        }
        console.log(`agentkeys-actions: registered ${actions.map((a) => a.name).join(', ') || '(none)'} from ${url}`);
        return actions;
      } catch (e) {
        if (e instanceof DaemonError && e.status === 404) {
          console.log(`agentkeys-actions: ${url} answers 404 (not a sandbox delegate daemon) — no verbs registered`);
          return [];
        }
        const reason = e instanceof Error ? e.message : String(e);
        const waited = Date.now() - started;
        if (waited > maxWaitMs && !warned) {
          warned = true;
          console.error(`agentkeys-actions: no advertisement from ${url} after ${Math.round(waited / 1000)}s — ${reason}; the delegate has NO publish/propose verbs until the daemon answers (retrying every ${SLOW_RETRY_MS / 1000}s)`);
        }
        await sleep(warned ? SLOW_RETRY_MS : retryMs);
      }
    }
  })();
  latest = ready;
}
