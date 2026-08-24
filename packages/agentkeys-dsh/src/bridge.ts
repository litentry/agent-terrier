/**
 * @module @agentkeys/dsh-suite/bridge — the in-process AgentKeys sandbox bridge
 * (#613): serves the byte-compatible HTTP contract the FIVE existing consumers
 * speak (daemon chat loop, broker update handler, parent-control, ESP32
 * firmware, dev tooling — spec §3.2), driving a dsh agent instead of Hermes.
 *
 * This PR lands the CORE surface — `/v1/chat` (SSE + non-stream), `/healthz`,
 * `/v1/jobs` — bind-first on :8090. The `/v1/context/*` (persona, #390) and
 * `/v1/sandbox/mgmt/*` (#577/#594) surfaces land with the UI (#617) and
 * checkpoint (#616) work respectively; until then those paths 404, which the
 * daemon already treats as "pre-#428/pre-#577 image" (graceful).
 *
 * Byte-exactness of the wire lives in bridge-frames.ts + bridge-stream.ts
 * (pure, unit-tested). NO default export (dsh postmortem 0001).
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { SessionId } from '@deepseek-ai/dsh-session';
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import type { AgentHandle } from '@deepseek-ai/dsh-agent';
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver';
import { chatReply, encodeFrame, healthzBody } from './bridge-frames.js';
import { exportHome, homeBytes, importHome } from './bridge-mgmt.js';
import { TurnStreamer } from './bridge-stream.js';

export const name = 'agentkeys-bridge';
export const inject = ['agents', 'sessions', 'webServer'];

export interface Config {
  cwd?: string;
  engine?: string;
  provider?: string;
  model?: string;
  /** The runtime home the #616 mgmt surface snapshots. */
  homeDir?: string;
  /** #577 mgmt bearer override (default: env AGENTKEYS_SANDBOX_MGMT_TOKEN).
   *  Empty/absent = the surface answers 404 not-armed (fail closed). */
  mgmtToken?: string;
}

export const Config: z<Config> = z.object({
  cwd: z.string().default('/opt/agentkeys'),
  engine: z.string().default('dsh'),
  provider: z.string().default('gate'),
  model: z.string().default(process.env.LLM_ENDPOINT_ID ?? '(unset)'),
  homeDir: z.string().default(process.env.DSH_HOME ?? '/root/.dsh'),
  mgmtToken: z.string(),
});

interface ModelSelection {
  provider: string;
  model: string;
}

/** The provider/model the agent is created with. `ctx.agents.create` does NOT
 *  consult the profile's `agent-default-model` row on its own (the #631 local
 *  twin: a model-less create succeeds, then every turn ends in error) — so the
 *  bridge reads the shared `agentDefaultModel` service exactly like the
 *  `dsh-headless` runner does, falling back to its own config (same env pair
 *  the profile's rows read) when the service isn't up yet. */
function currentSelection(ctx: Context, config: Config): ModelSelection | undefined {
  const service = (ctx as { get?: (name: string) => unknown }).get?.('agentDefaultModel') as
    | { currentSelection(): ModelSelection }
    | undefined;
  if (service) return service.currentSelection();
  if (config.model && config.model !== '(unset)') {
    return { provider: config.provider ?? 'gate', model: config.model };
  }
  return undefined;
}

const SESSION_ID = 'agentkeys-bridge-session';

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

export function apply(ctx: Context, config: Config): void {
  let handle: AgentHandle | undefined;
  let starting = false;
  const engine = config.engine ?? 'dsh';
  let version = '0.1';
  // One turn at a time (the resident single-session bridge, like hermes): a
  // second /v1/chat waits behind the first.
  let turnLock: Promise<unknown> = Promise.resolve();

  async function ensureAgent(): Promise<AgentHandle | undefined> {
    if (handle) return handle;
    if (starting) return undefined;
    starting = true;
    try {
      const selection = currentSelection(ctx, config);
      handle = await ctx.agents.create({
        sessionId: SessionId(SESSION_ID),
        meta: { cwd: config.cwd ?? '/opt/agentkeys' },
        ...(selection ? { agentOptions: selection } : {}),
      });
      version = handle.agent.options.model ?? version;
      return handle;
    } catch (e) {
      // Loud (→ the dsh unit log): a silently-swallowed create failure reads
      // as an eternal 503 acp_starting from outside.
      console.error(`agentkeys-bridge: agent create failed: ${(e as Error).message}`);
      return undefined;
    } finally {
      starting = false;
    }
  }

  /** Run one turn (serialized): submit the text, project session events into
   *  frames as the agent works, resolve when the agent is idle. Returns the
   *  streamer holding the accumulated reply + usage. */
  async function runTurn(text: string, onFrame?: (frame: string) => void): Promise<TurnStreamer> {
    const agent = handle;
    if (!agent) throw new Error('acp_starting');
    const run = turnLock.then(async () => {
      const streamer = new TurnStreamer();
      const off = ctx.on('session/event', (s: Session, e: SessionEvent) => {
        if (String(s.id) !== SESSION_ID) return;
        for (const frame of streamer.push(e)) if (onFrame) onFrame(encodeFrame(frame));
      });
      try {
        agent.agent.followup(
          createUserMessage({ content: [{ type: 'text', text }], source: { kind: 'user' } }),
        );
        await agent.agent.whenIdle();
        for (const frame of streamer.finish()) if (onFrame) onFrame(encodeFrame(frame));
      } finally {
        off();
      }
      return streamer;
    });
    turnLock = run.catch(() => undefined);
    return run;
  }

  /** #577 fail-closed mgmt auth: unset ⇒ 404 not-armed; wrong ⇒ 403. Never
   *  falls through to the bridge token. Constant-time compare. */
  function mgmtGate(req: IncomingMessage, res: ServerResponse): boolean {
    const expected = config.mgmtToken ?? process.env.AGENTKEYS_SANDBOX_MGMT_TOKEN ?? '';
    if (!expected) {
      sendJson(res, 404, { error: 'mgmt surface not armed (no AGENTKEYS_SANDBOX_MGMT_TOKEN)' });
      return false;
    }
    const presented = String(req.headers.authorization ?? '').replace(/^Bearer /, '');
    const a = Buffer.from(presented);
    const b = Buffer.from(expected);
    const equal = a.length === b.length && a.every((x, i) => x === b[i]);
    if (!equal) {
      sendJson(res, 403, { error: 'mgmt bearer missing or invalid' });
      return false;
    }
    return true;
  }

  const home = () => config.homeDir ?? process.env.DSH_HOME ?? '/root/.dsh';

  const routes: WebRoute[] = [
    {
      kind: 'exact',
      path: '/healthz',
      handler: (_req, res) => {
        const ready = handle !== undefined;
        sendJson(res, ready ? 200 : 503, healthzBody({
          ready,
          down: false,
          engine,
          version,
          model: config.model ?? '(unset)',
        }));
      },
    },
    {
      kind: 'exact',
      path: '/v1/chat',
      handler: async (req, res) => {
        let body: { text?: unknown; query?: unknown; stream?: unknown };
        try {
          body = (await readBody(req)) as typeof body;
        } catch (e) {
          sendJson(res, 400, { error: `bad request: ${(e as Error).message}` });
          return;
        }
        const text = String(body.text ?? body.query ?? '');
        if (!(await ensureAgent())) {
          sendJson(res, 503, { error: 'acp_starting: the agent is still initializing — retry shortly' });
          return;
        }
        const wantStream = Boolean(body.stream);
        if (wantStream) {
          res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
          try {
            await runTurn(text, (frame) => res.write(frame));
          } catch (e) {
            res.write(encodeFrame({ type: 'error', error: `agent error: ${(e as Error).message}` }));
          }
          res.end();
          return;
        }
        try {
          const streamer = await runTurn(text);
          const failure = streamer.errored();
          if (failure !== undefined) {
            sendJson(res, 502, { error: failure });
            return;
          }
          const { reply, totalTokens } = streamer.reply();
          sendJson(res, 200, chatReply(reply, totalTokens));
        } catch (e) {
          sendJson(res, 502, { error: `agent error: ${(e as Error).message}` });
        }
      },
    },
    {
      kind: 'exact',
      path: '/v1/jobs',
      handler: (_req, res) => sendJson(res, 200, { jobs: [] }),
    },
    {
      kind: 'exact',
      path: '/v1/sandbox/mgmt/status',
      handler: async (req, res) => {
        if (!mgmtGate(req, res)) return;
        sendJson(res, 200, {
          ok: true,
          jobs: null,
          hermes_home: home(),
          hermes_home_bytes: await homeBytes(home()),
        });
      },
    },
    {
      kind: 'exact',
      path: '/v1/sandbox/mgmt/session/export',
      handler: async (req, res) => {
        if (!mgmtGate(req, res)) return;
        try {
          sendJson(res, 200, await exportHome(home()));
        } catch (e) {
          const err = e as Error & { code?: number };
          sendJson(res, err.code === 413 ? 413 : 500, { error: err.code === 413 ? err.message : `export failed: ${err.message}` });
        }
      },
    },
    {
      kind: 'exact',
      path: '/v1/sandbox/mgmt/session/import',
      handler: async (req, res) => {
        if (!mgmtGate(req, res)) return;
        let body: Record<string, unknown>;
        try {
          body = (await readBody(req)) as Record<string, unknown>;
        } catch (e) {
          sendJson(res, 400, { error: `bad request: ${(e as Error).message}` });
          return;
        }
        try {
          const outcome = await importHome(home(), body);
          let agentRestarted = false;
          if (outcome.applied && body.restart !== false && handle) {
            // the dsh restart = dispose + lazy re-create on the next turn
            await handle.dispose().catch(() => {});
            handle = undefined;
            agentRestarted = true;
          }
          sendJson(res, 200, {
            ...outcome,
            agent_restarted: agentRestarted,
            session: null,
          });
        } catch (e) {
          const err = e as Error & { code?: number };
          const status = err.code === 400 ? 400 : err.code === 413 ? 413 : 500;
          sendJson(res, status, { error: status === 500 ? `import write failed: ${err.message}` : err.message });
        }
      },
    },
  ];

  for (const route of routes) {
    ctx.effect(() => ctx.webServer.register(route), `agentkeys-bridge: ${route.path}`);
  }
  // Bind-first (#589): the webserver listens on activation; the agent is created
  // lazily on the first /v1/chat, so the port answers within the veFaaS budget.
  void ensureAgent();

  ctx.effect(() => async () => {
    if (handle) await handle.dispose();
    handle = undefined;
  }, 'agentkeys-bridge: teardown');
}
