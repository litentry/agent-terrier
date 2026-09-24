/**
 * @module @agentkeys/dsh-suite/bridge — the in-process AgentKeys sandbox bridge
 * (#613): serves the byte-compatible HTTP contract the FIVE existing consumers
 * speak (daemon chat loop, broker update handler, parent-control, ESP32
 * firmware, dev tooling — spec §3.2), driving a dsh agent instead of Hermes.
 *
 * The surface: `/v1/chat` (SSE + non-stream), `/healthz`, `/v1/jobs` (GET the
 * registry, POST to register — #669 schedule entries), `/v1/context/apply`
 * (#428/#390/#662: persona + skills + knowledge, written under the runtime
 * cwd AND registered as dsh system-prompt sections so the next model step
 * reads them), `/v1/context/files` (the #390 view leg), `/v1/agent/restart`
 * (the explicit re-source: persona and skills re-read, the conversation
 * continues), `/v1/session/reset` (typed sessions: end open sessions), and
 * the `/v1/sandbox/mgmt/*` checkpoint surface (#577/#594) — bind-first on
 * :8090. Every route but
 * `/healthz` and the mgmt surface is gated on the per-delegate in-pod bearer
 * (`AGENTKEYS_BRIDGE_TOKEN`, #715 — fail-closed when unset); the mgmt surface
 * keeps its own `AGENTKEYS_SANDBOX_MGMT_TOKEN`.
 *
 * Typed sessions (owner decision 2026-09-23): a `/v1/chat` body that names a
 * `session` runs in that session — a throwaway one for `none` / `event`, the
 * open one for its `thread` / `conversation` key (bridge-sessions.ts). A body
 * without one runs in the legacy resident session, kept for the direct
 * callers that carry no feed (the ESP32 client, the broker's bridge proxy).
 *
 * Byte-exactness of the wire lives in bridge-frames.ts + bridge-stream.ts
 * (pure, unit-tested). NO default export (dsh postmortem 0001).
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { SessionId } from '@deepseek-ai/dsh-session';
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import type { AgentHandle } from '@deepseek-ai/dsh-agent';
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver';
import { chatReply, encodeFrame, healthzBody } from './bridge-frames.js';
import { exportHome, homeBytes, importHome, settleQuiet } from './bridge-mgmt.js';
import {
  endMatching,
  expireIdle,
  MAX_LIVE_SESSIONS,
  newSessionId,
  parseChatSession,
  parseResetBody,
  planTurn,
  readIndex,
  removeSessionDirs,
  retire,
  touch,
  writeIndex,
} from './bridge-sessions.js';
import type { ChatSessionSpec, ResetSpec, SessionIndex } from './bridge-sessions.js';
import { TurnStreamer } from './bridge-stream.js';
import { DEFAULT_HIDDEN_TOOLS } from './mapping.js';

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
  /** #715 in-pod bearer override (default: env AGENTKEYS_BRIDGE_TOKEN) gating
   *  every NON-mgmt route but /healthz. Empty/absent = those routes answer 401
   *  not-armed (fail closed): a sandbox the broker did not arm serves no chat. */
  bridgeToken?: string;
  /** Typed sessions: how often idle `thread` / `conversation` sessions are
   *  ended when no turn arrives (ms). */
  sessionSweepMs?: number;
}

export const Config: z<Config> = z.object({
  cwd: z.string().default('/opt/agentkeys'),
  engine: z.string().default('dsh'),
  provider: z.string().default('gate'),
  model: z.string().default(process.env.LLM_ENDPOINT_ID ?? '(unset)'),
  homeDir: z.string().default(process.env.DSH_HOME ?? '/root/.dsh'),
  mgmtToken: z.string(),
  bridgeToken: z.string(),
  sessionSweepMs: z.number().default(60_000),
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

/** Take the tools this deployment switches off out of an agent's view
 *  (`remember`: OpenViking runs without an extraction model here, #726). The
 *  guard denies them too — a tool registered after setup stays visible but
 *  refused. dsh's restrict() rejects a name no plugin registered yet, so each
 *  name is masked on its own. */
export function hideTools(agentCtx: Context): void {
  const tools = (agentCtx as unknown as { tools?: { restrict(filter: { deny: string[] }): () => void } }).tools;
  if (!tools) return;
  for (const name of DEFAULT_HIDDEN_TOOLS) {
    try {
      tools.restrict({ deny: [name] });
    } catch {
      /* not registered (yet) — the guard's deny covers it */
    }
  }
}

/** A context file / skill / knowledge name the bridge will write: one path
 *  segment, no traversal, no hidden files. */
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** The dsh system-prompt section names + orders the bridge owns. The
 *  deployment persona slot (`deployment:persona`, order 0) stays the
 *  profile's; ours render right after it (persona) and with the tool
 *  guidance band (skills, knowledge) — unique names, so a re-apply never
 *  collides with a base-layer registration. */
const SECTION_PERSONA = { name: 'agentkeys:persona', order: 1 };
const SECTION_SKILLS = { name: 'agentkeys:skills', order: 110 };
const SECTION_KNOWLEDGE = { name: 'agentkeys:knowledge', order: 120 };

interface ContextStore {
  /** `<cwd>/SOUL.md` */
  soul?: string;
  /** `<cwd>/AGENTS.md` (owner-editable) */
  agents?: string;
  /** `<cwd>/skills/<name>` */
  skills: Record<string, string>;
  /** `<cwd>/knowledge/<name>` */
  knowledge: Record<string, string>;
}

/** One registered background/scheduled job (#669: the daemon's schedule
 *  entries register here so the device `jobs` command lists them). */
export interface RegisteredJob {
  id: string;
  cron?: string;
  label?: string;
  status?: string;
  [key: string]: unknown;
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

const BASE64 = /^[A-Za-z0-9+/\s]*={0,2}\s*$/;

function decodeB64(value: unknown, what: string): string {
  if (typeof value !== 'string') throw Object.assign(new Error(`${what} must be a base64 string`), { code: 400 });
  // Node decodes leniently (drops invalid characters) — a garbage body would
  // silently become garbage bytes, so validate the alphabet first.
  if (!BASE64.test(value)) throw Object.assign(new Error(`${what} is not valid base64`), { code: 400 });
  return Buffer.from(value, 'base64').toString('utf8');
}

function readDirDocs(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  let names: string[] = [];
  try {
    names = readdirSync(dir);
  } catch {
    return out;
  }
  for (const n of names) {
    if (!SAFE_NAME.test(n)) continue;
    try {
      const p = join(dir, n);
      if (statSync(p).isFile()) out[n] = readFileSync(p, 'utf8');
    } catch {
      /* unreadable entry — skipped */
    }
  }
  return out;
}

function readOptional(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

/** Load whatever an earlier apply persisted under `cwd` (a bridge restart
 *  re-registers the sections from disk). */
function loadContext(cwd: string): ContextStore {
  return {
    soul: readOptional(join(cwd, 'SOUL.md')),
    agents: readOptional(join(cwd, 'AGENTS.md')),
    skills: readDirDocs(join(cwd, 'skills')),
    knowledge: readDirDocs(join(cwd, 'knowledge')),
  };
}

/** The rendered prompt sections (persona · skills · knowledge). Empty text
 *  = the section contributes nothing (dsh drops empty sections). */
export function renderContextSections(store: ContextStore): { persona: string; skills: string; knowledge: string } {
  const persona = (store.soul ?? '').trim();
  const skillNames = Object.keys(store.skills).sort();
  const skills = skillNames.length
    ? ['# Skills', ...skillNames.map((n) => `## ${n}\n\n${store.skills[n].trim()}`)].join('\n\n')
    : '';
  const knowledgeNames = Object.keys(store.knowledge).sort();
  const knowledge = knowledgeNames.length
    ? ['# Knowledge', ...knowledgeNames.map((n) => `## ${n}\n\n${store.knowledge[n].trim()}`)].join('\n\n')
    : '';
  return { persona, skills, knowledge };
}

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
  const cwd = () => config.cwd ?? '/opt/agentkeys';
  // The applied context (persona / skills / knowledge) + the registered
  // system-prompt section disposers (re-registered on every apply).
  let context: ContextStore = loadContext(cwd());
  const sectionDisposers: Array<() => void> = [];
  // #669 — the registered background/scheduled jobs (`POST /v1/jobs`).
  let jobs: RegisteredJob[] = [];

  /** Push the current context into dsh's system prompt (when the service is
   *  up — the #631 test harness has none, and the files alone still serve
   *  the view leg). Sections are re-registered wholesale: dispose, then add. */
  function registerContextSections(): boolean {
    const service = (ctx as { get?: (name: string) => unknown }).get?.('systemPrompt') as
      | { section(s: { name: string; order: number; text: string }): () => void }
      | undefined;
    for (const off of sectionDisposers.splice(0)) {
      try {
        off();
      } catch {
        /* already disposed */
      }
    }
    if (!service) return false;
    const rendered = renderContextSections(context);
    const pairs: Array<[{ name: string; order: number }, string]> = [
      [SECTION_PERSONA, rendered.persona],
      [SECTION_SKILLS, rendered.skills],
      [SECTION_KNOWLEDGE, rendered.knowledge],
    ];
    for (const [meta, text] of pairs) {
      if (!text) continue;
      try {
        sectionDisposers.push(service.section({ ...meta, text }));
      } catch (e) {
        console.error(`agentkeys-bridge: system-prompt section ${meta.name} failed: ${(e as Error).message}`);
      }
    }
    return true;
  }
  registerContextSections();
  // One turn at a time (the resident single-session bridge, like hermes): a
  // second /v1/chat waits behind the first.
  let turnLock: Promise<unknown> = Promise.resolve();

  /** The dsh session-persistence collision family: a persisted log exists for
   *  our FIXED session id — the #616 hand-off/checkpoint-restore lands the
   *  previous instance's log. It surfaces at CREATE only in a narrow race;
   *  the common thrower is the lazy persistence BIND on the first turn WRITE
   *  (`adoptLivePrefix`: a fresh session's seed cannot cover the imported
   *  prefix → "id collision"), measured live on agent-i 2026-08-26. dsh's
   *  contract for every spelling is "load/resume it instead of creating". */
  const SESSION_COLLISION = /persisted log|id collision|load\/resume it instead/i;
  /** dsh-session-persistence `prepare()` on an id with no stored log. */
  const SESSION_NOT_FOUND = /session ".*" not found/i;

  function agentOpts() {
    const selection = currentSelection(ctx, config);
    return { ...(selection ? { agentOptions: selection } : {}), setup: hideTools };
  }

  /** Resume the bridge session's persisted log; undefined when none exists.
   *  The caller must hold no live session for the id — `prepare()` waits for
   *  retirement, so dispose before resuming. */
  async function resumeAgent(): Promise<AgentHandle | undefined> {
    try {
      return await ctx.agents.resume({
        resumeSessionId: SessionId(SESSION_ID),
        ...agentOpts(),
      });
    } catch (e) {
      if (SESSION_NOT_FOUND.test(String((e as Error).message ?? e))) return undefined;
      throw e;
    }
  }

  async function createOrResumeAgent(): Promise<AgentHandle> {
    // RESUME-FIRST: the bridge session id is fixed, so a persisted log is
    // always ours to continue. create() does NOT probe the stored log — the
    // persistence layer binds lazily at the first write and only THEN
    // collides, killing the turn — so create-first turns an imported log
    // into a poisoned session instead of the previous conversation.
    const resumed = await resumeAgent();
    if (resumed) {
      console.error(
        'agentkeys-bridge: resumed the persisted bridge session (#616 hand-off)',
      );
      return resumed;
    }
    try {
      return await ctx.agents.create({
        sessionId: SessionId(SESSION_ID),
        meta: { cwd: config.cwd ?? '/opt/agentkeys' },
        ...agentOpts(),
      });
    } catch (e) {
      if (!SESSION_COLLISION.test(String((e as Error).message ?? e))) throw e;
      // The create-time guard: a log landed between the resume probe and
      // create (the import races the lazy first-turn ensure).
      console.error(
        'agentkeys-bridge: persisted session log landed during create — resuming it (#616 hand-off)',
      );
      const raced = await resumeAgent();
      if (raced) return raced;
      throw e;
    }
  }

  async function ensureAgent(): Promise<AgentHandle | undefined> {
    if (handle) return handle;
    if (starting) return undefined;
    starting = true;
    try {
      handle = await createOrResumeAgent();
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

  /** Run one turn; if it dies on the session-collision family (the
   *  create-before-import ordering: the live session was created BEFORE the
   *  #616 import landed the old log), dispose the live handle, re-ensure —
   *  which resumes the persisted log — and retry ONCE. */
  async function runTurnRecovering(
    text: string,
    onFrame?: (frame: string) => void,
  ): Promise<TurnStreamer> {
    try {
      return await runTurn(text, onFrame);
    } catch (e) {
      if (!SESSION_COLLISION.test(String((e as Error).message ?? e))) throw e;
      console.error(
        'agentkeys-bridge: turn hit a session-log collision — disposing the live session and resuming the persisted one (#616)',
      );
      if (handle) await handle.dispose().catch(() => {});
      handle = undefined;
      await ensureAgent();
      return await runTurn(text, onFrame);
    }
  }

  /** Run one turn (serialized): submit the text, project session events into
   *  frames as the agent works, resolve when the agent is idle. Returns the
   *  streamer holding the accumulated reply + usage. */
  async function runTurn(text: string, onFrame?: (frame: string) => void): Promise<TurnStreamer> {
    const agent = handle;
    if (!agent) throw new Error('acp_starting');
    const run = turnLock.then(() => runTurnOn(agent, SESSION_ID, text, onFrame));
    turnLock = run.catch(() => undefined);
    return run;
  }

  /** Submit one turn to `agent`, project its session events into frames and
   *  resolve when it is idle. `context` (a typed session's background, new
   *  sessions only) enters first as a plugin-sourced message: model input,
   *  never recorded by the memory plugin as something a person said. */
  async function runTurnOn(
    agent: AgentHandle,
    sessionId: string,
    text: string,
    onFrame?: (frame: string) => void,
    context?: string,
  ): Promise<TurnStreamer> {
    const streamer = new TurnStreamer();
    const off = ctx.on('session/event', (s: Session, e: SessionEvent) => {
      if (String(s.id) !== sessionId) return;
      for (const frame of streamer.push(e)) if (onFrame) onFrame(encodeFrame(frame));
    });
    try {
      if (context) {
        agent.agent.inject(
          createUserMessage({
            content: [{ type: 'text', text: context }],
            source: { kind: 'plugin', plugin: 'agentkeys-bridge' },
          }),
        );
      }
      agent.agent.followup(
        createUserMessage({ content: [{ type: 'text', text }], source: { kind: 'user' } }),
      );
      await agent.agent.whenIdle();
      for (const frame of streamer.finish()) if (onFrame) onFrame(encodeFrame(frame));
    } finally {
      off();
    }
    return streamer;
  }

  // ── typed sessions (owner decision 2026-09-23) ──────────────────────────
  /** Live typed sessions: dsh session id → handle + last use. */
  const live = new Map<string, { handle: AgentHandle; usedAt: number }>();
  /** The index, cached; re-read after a home import. */
  let sessionIndex: SessionIndex | undefined;

  async function loadIndex(): Promise<SessionIndex> {
    if (!sessionIndex) sessionIndex = await readIndex(home());
    return sessionIndex;
  }

  async function saveIndex(next: SessionIndex): Promise<void> {
    sessionIndex = next;
    await writeIndex(home(), next);
  }

  async function disposeLive(ids: Iterable<string>): Promise<void> {
    for (const id of [...ids]) {
      const entry = live.get(id);
      live.delete(id);
      if (entry) await entry.handle.dispose().catch(() => {});
    }
  }

  /** End sessions: dispose their live handles (the memory plugin commits each
   *  OpenViking session) and retire their logs — the newest few stay. */
  async function endSessions(ids: readonly string[]): Promise<void> {
    if (ids.length === 0) return;
    await disposeLive(ids);
    const { index, toDelete } = retire(await loadIndex(), ids);
    await saveIndex(index);
    for (const id of toDelete) await removeSessionDirs(home(), id);
  }

  /** Hold at most MAX_LIVE_SESSIONS in memory: the least recently used goes
   *  (it stays open in the index and resumes on its next turn). */
  async function evictBeyondLiveCap(keep: string): Promise<void> {
    while (live.size > MAX_LIVE_SESSIONS) {
      let oldest: string | undefined;
      let oldestAt = Number.POSITIVE_INFINITY;
      for (const [id, entry] of live) {
        if (id !== keep && entry.usedAt < oldestAt) {
          oldest = id;
          oldestAt = entry.usedAt;
        }
      }
      if (!oldest) return;
      await disposeLive([oldest]);
    }
  }

  /** The live handle for a typed session: a new one, or its log resumed (a
   *  log that is gone — a sandbox that came up without it — starts fresh). */
  async function ensureTyped(sessionId: string, fresh: boolean): Promise<{ handle: AgentHandle; created: boolean }> {
    const current = live.get(sessionId);
    if (current) {
      current.usedAt = Date.now();
      return { handle: current.handle, created: false };
    }
    let resumed: AgentHandle | undefined;
    if (!fresh) {
      try {
        resumed = await ctx.agents.resume({ resumeSessionId: SessionId(sessionId), ...agentOpts() });
      } catch (e) {
        if (!SESSION_NOT_FOUND.test(String((e as Error).message ?? e))) throw e;
      }
    }
    const agent =
      resumed ??
      (await ctx.agents.create({
        sessionId: SessionId(sessionId),
        meta: { cwd: config.cwd ?? '/opt/agentkeys' },
        ...agentOpts(),
      }));
    live.set(sessionId, { handle: agent, usedAt: Date.now() });
    await evictBeyondLiveCap(sessionId);
    return { handle: agent, created: resumed === undefined };
  }

  /** One typed-session turn, serialized with every other turn. */
  async function runTypedTurn(
    spec: ChatSessionSpec,
    text: string,
    onFrame?: (frame: string) => void,
  ): Promise<{ streamer: TurnStreamer; sessionId: string; fresh: boolean }> {
    const run = turnLock.then(async () => {
      const now = Date.now();
      const swept = expireIdle(await loadIndex(), now);
      if (swept.ended.length > 0) {
        await saveIndex(swept.index);
        await endSessions(swept.ended);
      }
      const plan = planTurn(await loadIndex(), spec, now, () =>
        newSessionId(spec.window, now, randomBytes(4).toString('hex')),
      );
      await saveIndex(plan.index);
      await endSessions(plan.ended);
      try {
        const { handle: agent, created } = await ensureTyped(plan.sessionId, plan.fresh);
        const streamer = await runTurnOn(agent, plan.sessionId, text, onFrame, created ? spec.context : undefined);
        if (!plan.throwaway) await saveIndex(touch(await loadIndex(), plan.sessionId, Date.now()));
        return { streamer, sessionId: plan.sessionId, fresh: created };
      } finally {
        if (plan.throwaway) await endSessions([plan.sessionId]);
      }
    });
    turnLock = run.catch(() => undefined);
    return run;
  }

  /** Idle sessions end on time even when no turn arrives. */
  async function sweepIdle(): Promise<number> {
    const run = turnLock.then(async () => {
      const swept = expireIdle(await loadIndex(), Date.now());
      if (swept.ended.length === 0) return 0;
      await saveIndex(swept.index);
      await endSessions(swept.ended);
      console.error(`agentkeys-bridge: ended ${swept.ended.length} idle session(s)`);
      return swept.ended.length;
    });
    turnLock = run.catch(() => undefined);
    return run;
  }

  /** End the open sessions a reset covers. An app-wide reset also starts the
   *  legacy resident session over (its log goes; the next ensure creates). */
  async function resetSessions(reset: ResetSpec): Promise<{ ended: number; legacyReset: boolean }> {
    const run = turnLock.then(async () => {
      const { index, ended } = endMatching(await loadIndex(), reset);
      await saveIndex(index);
      await endSessions(ended);
      if (reset.scope !== 'app') return { ended: ended.length, legacyReset: false };
      if (handle) {
        await handle.dispose().catch(() => {});
        handle = undefined;
      }
      await removeSessionDirs(home(), SESSION_ID);
      return { ended: ended.length, legacyReset: true };
    });
    turnLock = run.catch(() => undefined);
    const outcome = await run;
    if (outcome.legacyReset) void ensureAgent();
    return outcome;
  }

  /** Constant-time bearer compare (never early-exits on a prefix). */
  function bearerMatches(req: IncomingMessage, expected: string): boolean {
    const presented = String(req.headers.authorization ?? '').replace(/^Bearer /, '');
    const a = Buffer.from(presented);
    const b = Buffer.from(expected);
    return a.length === b.length && a.every((x, i) => x === b[i]);
  }

  /** #577 fail-closed mgmt auth: unset ⇒ 404 not-armed; wrong ⇒ 403. Never
   *  falls through to the bridge token. Constant-time compare. */
  function mgmtGate(req: IncomingMessage, res: ServerResponse): boolean {
    const expected = config.mgmtToken ?? process.env.AGENTKEYS_SANDBOX_MGMT_TOKEN ?? '';
    if (!expected) {
      sendJson(res, 404, { error: 'mgmt surface not armed (no AGENTKEYS_SANDBOX_MGMT_TOKEN)' });
      return false;
    }
    if (!bearerMatches(req, expected)) {
      sendJson(res, 403, { error: 'mgmt bearer missing or invalid' });
      return false;
    }
    return true;
  }

  /** #715 fail-closed in-pod auth for every non-mgmt route but /healthz:
   *  unset ⇒ 401 not-armed (a sandbox the broker did not arm serves no chat —
   *  measured 2026-09-22, an instance name alone let anyone chat as the
   *  operator, inject a persona and read the context); wrong ⇒ 401. The
   *  callers are the in-pod daemon (chat loop / scheduler / app runtime) and
   *  the broker on the console's behalf — both hold AGENTKEYS_BRIDGE_TOKEN.
   *  Deliberately a DIFFERENT credential from the mgmt bearer. */
  function bridgeGate(req: IncomingMessage, res: ServerResponse): boolean {
    const expected = config.bridgeToken ?? process.env.AGENTKEYS_BRIDGE_TOKEN ?? '';
    if (!expected) {
      sendJson(res, 401, { error: 'bridge not armed (no AGENTKEYS_BRIDGE_TOKEN) — the broker injects it at create' });
      return false;
    }
    if (!bearerMatches(req, expected)) {
      sendJson(res, 401, { error: 'bridge bearer missing or invalid' });
      return false;
    }
    return true;
  }

  const home = () => config.homeDir ?? process.env.DSH_HOME ?? '/root/.dsh';

  /** Dispose the live session and ensure it again — the explicit re-source
   *  verb (persona / skills re-read). It does NOT start a new conversation:
   *  the ensure RESUMES the persisted log (#616 resume-first). */
  async function restartAgent(): Promise<boolean> {
    const hadTyped = live.size > 0;
    const typed = turnLock.then(() => disposeLive(live.keys()));
    turnLock = typed.catch(() => undefined);
    await typed;
    if (!handle) return hadTyped;
    await handle.dispose().catch(() => {});
    handle = undefined;
    void ensureAgent();
    return true;
  }

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
        if (!bridgeGate(req, res)) return;
        let body: { text?: unknown; query?: unknown; stream?: unknown; session?: unknown };
        let spec: ChatSessionSpec | undefined;
        try {
          body = (await readBody(req)) as typeof body;
          spec = parseChatSession(body.session);
        } catch (e) {
          sendJson(res, 400, { error: `bad request: ${(e as Error).message}` });
          return;
        }
        const text = String(body.text ?? body.query ?? '');
        if (spec) {
          const typed = spec;
          if (body.stream) {
            res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
            try {
              await runTypedTurn(typed, text, (frame) => res.write(frame));
            } catch (e) {
              res.write(encodeFrame({ type: 'error', error: `agent error: ${(e as Error).message}` }));
            }
            res.end();
            return;
          }
          try {
            const { streamer, sessionId, fresh } = await runTypedTurn(typed, text);
            const failure = streamer.errored();
            if (failure !== undefined) {
              sendJson(res, 502, { error: failure });
              return;
            }
            const { reply, totalTokens } = streamer.reply();
            sendJson(res, 200, { ...chatReply(reply, totalTokens), session: { id: sessionId, window: typed.window, fresh } });
          } catch (e) {
            sendJson(res, 502, { error: `agent error: ${(e as Error).message}` });
          }
          return;
        }
        if (!(await ensureAgent())) {
          sendJson(res, 503, { error: 'acp_starting: the agent is still initializing — retry shortly' });
          return;
        }
        const wantStream = Boolean(body.stream);
        if (wantStream) {
          res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
          try {
            await runTurnRecovering(text, (frame) => res.write(frame));
          } catch (e) {
            res.write(encodeFrame({ type: 'error', error: `agent error: ${(e as Error).message}` }));
          }
          res.end();
          return;
        }
        try {
          const streamer = await runTurnRecovering(text);
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
      path: '/v1/session/reset',
      handler: async (req, res) => {
        if (!bridgeGate(req, res)) return;
        if (String(req.method ?? '').toUpperCase() !== 'POST') {
          sendJson(res, 405, { error: 'POST only — a reset ends sessions' });
          return;
        }
        let reset: ResetSpec;
        try {
          reset = parseResetBody(await readBody(req));
        } catch (e) {
          sendJson(res, 400, { error: `bad request: ${(e as Error).message}` });
          return;
        }
        try {
          const outcome = await resetSessions(reset);
          sendJson(res, 200, { ok: true, scope: reset.scope, ended: outcome.ended, legacy_reset: outcome.legacyReset });
        } catch (e) {
          sendJson(res, 500, { error: `session reset failed: ${(e as Error).message}` });
        }
      },
    },
    {
      kind: 'exact',
      path: '/v1/jobs',
      handler: async (req, res) => {
        if (!bridgeGate(req, res)) return;
        if (req.method === 'POST') {
          let body: { jobs?: unknown };
          try {
            body = (await readBody(req)) as typeof body;
          } catch (e) {
            sendJson(res, 400, { error: `bad request: ${(e as Error).message}` });
            return;
          }
          if (!Array.isArray(body.jobs)) {
            sendJson(res, 400, { error: 'jobs must be an array' });
            return;
          }
          const next: RegisteredJob[] = [];
          for (const j of body.jobs as unknown[]) {
            if (!j || typeof j !== 'object' || typeof (j as RegisteredJob).id !== 'string') {
              sendJson(res, 400, { error: 'each job needs a string id' });
              return;
            }
            next.push(j as RegisteredJob);
          }
          jobs = next;
          sendJson(res, 200, { ok: true, jobs });
          return;
        }
        sendJson(res, 200, { jobs });
      },
    },
    {
      kind: 'exact',
      path: '/v1/agent/restart',
      handler: async (req, res) => {
        if (!bridgeGate(req, res)) return;
        const restarted = await restartAgent();
        sendJson(res, 200, { restarted, ok: true });
      },
    },
    {
      kind: 'exact',
      path: '/v1/context/files',
      handler: (req, res) => {
        if (!bridgeGate(req, res)) return;
        const root = cwd();
        const file = (id: string, name: string, content: string | undefined, editable: boolean) => ({
          id,
          path: join(root, name),
          editable,
          present: content !== undefined,
          ...(content !== undefined ? { content, sha256: sha256Hex(content) } : {}),
        });
        sendJson(res, 200, {
          files: [file('soul', 'SOUL.md', context.soul, true), file('agents', 'AGENTS.md', context.agents, true)],
          skills: Object.keys(context.skills).sort(),
          knowledge: Object.keys(context.knowledge).sort(),
          cwd: root,
        });
      },
    },
    {
      kind: 'exact',
      path: '/v1/context/apply',
      handler: async (req, res) => {
        if (!bridgeGate(req, res)) return;
        let body: { files?: unknown; skills?: unknown; knowledge?: unknown; restart?: unknown };
        try {
          body = (await readBody(req)) as typeof body;
        } catch (e) {
          sendJson(res, 400, { error: `bad request: ${(e as Error).message}` });
          return;
        }
        const files = body.files as Record<string, unknown> | undefined;
        const skills = body.skills as Record<string, unknown> | undefined;
        const knowledge = body.knowledge as Record<string, unknown> | undefined;
        const isDoc = (v: unknown) => v && typeof v === 'object' && !Array.isArray(v);
        if (!isDoc(files) && !isDoc(skills) && !isDoc(knowledge)) {
          sendJson(res, 400, { error: 'files and/or skills/knowledge required (objects of name → base64 content)' });
          return;
        }
        const root = cwd();
        const filesWritten: string[] = [];
        const skillsWritten: string[] = [];
        const knowledgeWritten: string[] = [];
        try {
          mkdirSync(root, { recursive: true });
          if (isDoc(files)) {
            for (const [key, value] of Object.entries(files as Record<string, unknown>)) {
              const name = key === 'soul' ? 'SOUL.md' : key === 'agents' ? 'AGENTS.md' : undefined;
              if (!name) {
                sendJson(res, 400, { error: `files must be soul and/or agents (got ${key})` });
                return;
              }
              const text = decodeB64(value, `files.${key}`);
              writeFileSync(join(root, name), text, 'utf8');
              if (key === 'soul') context.soul = text;
              else context.agents = text;
              filesWritten.push(name);
            }
          }
          const writeDocs = (docs: Record<string, unknown> | undefined, dir: string, into: Record<string, string>, written: string[]) => {
            if (!isDoc(docs)) return;
            mkdirSync(join(root, dir), { recursive: true });
            for (const [name, value] of Object.entries(docs as Record<string, unknown>)) {
              if (!SAFE_NAME.test(name)) {
                throw Object.assign(new Error(`${dir} name "${name}" is not a plain file name`), { code: 400 });
              }
              const text = decodeB64(value, `${dir}.${name}`);
              writeFileSync(join(root, dir, name), text, 'utf8');
              into[name] = text;
              written.push(name);
            }
          };
          writeDocs(skills, 'skills', context.skills, skillsWritten);
          writeDocs(knowledge, 'knowledge', context.knowledge, knowledgeWritten);
        } catch (e) {
          const err = e as Error & { code?: number };
          sendJson(res, err.code === 400 ? 400 : 500, { error: err.code === 400 ? err.message : `context write failed: ${err.message}` });
          return;
        }
        const promptRegistered = registerContextSections();
        const restarted = body.restart === true ? await restartAgent() : false;
        sendJson(res, 200, {
          ok: true,
          files_written: filesWritten,
          skills_written: skillsWritten,
          knowledge_written: knowledgeWritten,
          prompt_registered: promptRegistered,
          restarted,
        });
      },
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
          open_sessions: (await loadIndex()).open.length,
          live_sessions: live.size,
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
          let agentRestarted = false;
          // Dispose BEFORE any byte lands (the hook runs after validation +
          // the newer-wins gate, so a rejected snapshot never restarts the
          // agent): the live session's retirement flush must complete against
          // the UNCHANGED log — overwriting it mid-flush aborts the retirement
          // and orphans the persistence owner, wedging every later ensure into
          // a permanent acp_starting (measured live, 2026-09-01). Then wait
          // for the flush to go quiet before the writes.
          const outcome = await importHome(home(), body, async (targets) => {
            if (body.restart !== false && handle) {
              await handle.dispose().catch(() => {});
              handle = undefined;
              agentRestarted = true;
            }
            if (body.restart !== false && live.size > 0) {
              await disposeLive(live.keys());
              agentRestarted = true;
            }
            await settleQuiet(targets);
          });
          sessionIndex = undefined;
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
  // Bind-first (#589): the webserver listens on activation and the agent session
  // is created in the BACKGROUND (not awaited), so the port answers within the
  // veFaaS budget; /healthz reads 503 `starting` until it exists. A session
  // import disposes it and the next /v1/chat re-creates it.
  void ensureAgent();

  const sweepTimer = setInterval(() => void sweepIdle().catch(() => {}), config.sessionSweepMs ?? 60_000);
  sweepTimer.unref?.();
  ctx.effect(() => () => clearInterval(sweepTimer), 'agentkeys-bridge: idle-session sweep');

  ctx.effect(() => async () => {
    await disposeLive(live.keys());
    if (handle) await handle.dispose();
    handle = undefined;
  }, 'agentkeys-bridge: teardown');
}
