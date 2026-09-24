import { afterEach, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Context } from '@deepseek-ai/cordis';
import WebServer from '@deepseek-ai/dsh-host-webserver';
import * as bridgePlugin from '../src/bridge.js';
import {
  emptyIndex,
  endMatching,
  ENDED_LOGS_KEPT,
  expireIdle,
  newSessionId,
  openKey,
  parseChatSession,
  parseResetBody,
  planTurn,
  readIndex,
  removeSessionDirs,
  retire,
  SESSION_INDEX_FILE,
  writeIndex,
} from '../src/bridge-sessions.js';
import type { ChatSessionSpec, SessionIndex } from '../src/bridge-sessions.js';
import { DEFAULT_HIDDEN_TOOLS } from '../src/mapping.js';

const MIN = 60_000;

// The daemon ↔ bridge contract has ONE shape (agentkeys-protocol
// session_window.rs); the Rust side reads this same fixture.
const FIXTURE = new URL('../../../e2e/fixtures/bridge-protocol/session_contract.json', import.meta.url);

describe('the shared session contract', () => {
  it('parses every chat-session and reset shape the Rust owner serializes', async () => {
    const fixture = JSON.parse(await fs.readFile(FIXTURE, 'utf8')) as Record<string, unknown>;
    expect(parseChatSession(fixture.thread_chat_session)).toEqual({
      window: 'thread',
      scope: 'ch-family-weixin',
      party: 'contact-grandma',
      idleMinutes: 30,
      context: "Earlier in this thread (restored from the feed):\n[them 18:02] What's for dinner?",
    });
    expect(parseChatSession(fixture.event_chat_session)).toMatchObject({ window: 'event', scope: 'ch-kitchen-screen' });
    expect(parseChatSession(fixture.schedule_chat_session)).toEqual({ window: 'none', scope: 'schedule:morning-plan' });
    expect(parseResetBody(fixture.app_reset)).toEqual({ scope: 'app' });
    expect(parseResetBody(fixture.thread_reset)).toEqual({ scope: 'thread', channel: 'ch-family-weixin', party: 'contact-grandma' });
    expect(fixture.reset_marker_body).toBe('{"session_reset":"app"}');
  });

  it('refuses a malformed session or reset body', () => {
    expect(parseChatSession(undefined)).toBeUndefined();
    expect(() => parseChatSession({ window: 'forever', scope: 'x' })).toThrow(/window/);
    expect(() => parseChatSession({ window: 'thread', scope: '' })).toThrow(/scope/);
    expect(() => parseChatSession({ window: 'thread', scope: 'x', idle_minutes: 0 })).toThrow(/idle_minutes/);
    expect(() => parseChatSession({ window: 'thread', scope: 'x', lifetime: 1 })).toThrow(/not a known field/);
    expect(() => parseResetBody({ scope: 'everything' })).toThrow(/scope/);
    expect(() => parseResetBody({ scope: 'feed' })).toThrow(/channel/);
    expect(() => parseResetBody({ scope: 'thread', channel: 'c' })).toThrow(/party/);
  });
});

describe('session planning (pure)', () => {
  const thread: ChatSessionSpec = { window: 'thread', scope: 'ch-family', party: 'grandma', idleMinutes: 30 };
  let counter = 0;
  const mint = () => `ak-test-${++counter}`;

  it('a throwaway window gets a fresh session every turn and keeps nothing', () => {
    const plan = planTurn(emptyIndex(), { window: 'event', scope: 'ch-screen' }, 0, mint);
    expect(plan).toMatchObject({ fresh: true, throwaway: true, ended: [] });
    expect(plan.index.open).toEqual([]);
    expect(openKey({ window: 'none', scope: 'schedule:plan' })).toBeUndefined();
  });

  it('a thread opens once, resumes inside its idle limit, and starts over after it', () => {
    const first = planTurn(emptyIndex(), thread, 0, mint);
    expect(first).toMatchObject({ fresh: true, throwaway: false, ended: [] });
    const again = planTurn(first.index, thread, 29 * MIN, mint);
    expect(again).toMatchObject({ sessionId: first.sessionId, fresh: false });
    const later = planTurn(again.index, thread, 29 * MIN + 31 * MIN, mint);
    expect(later.fresh).toBe(true);
    expect(later.sessionId).not.toBe(first.sessionId);
    expect(later.ended).toEqual([first.sessionId]);
    expect(later.index.open).toHaveLength(1);
  });

  it('threads are per sender; a conversation is one per feed', () => {
    const grandma = planTurn(emptyIndex(), thread, 0, mint);
    const grandpa = planTurn(grandma.index, { ...thread, party: 'grandpa' }, 0, mint);
    expect(grandpa.sessionId).not.toBe(grandma.sessionId);
    const chat = planTurn(grandpa.index, { window: 'conversation', scope: 'ch-opchat', party: 'ignored' }, 0, mint);
    const chatAgain = planTurn(chat.index, { window: 'conversation', scope: 'ch-opchat', party: 'someone-else' }, MIN, mint);
    expect(chatAgain.sessionId).toBe(chat.sessionId);
    expect(chat.index.open.find((o) => o.id === chat.sessionId)?.idleMinutes).toBe(24 * 60);
  });

  it('a reset ends exactly what it covers', () => {
    let index: SessionIndex = emptyIndex();
    const ids: Record<string, string> = {};
    for (const [name, spec] of Object.entries({
      grandma: thread,
      grandpa: { ...thread, party: 'grandpa' },
      screen: { window: 'conversation', scope: 'ch-screen' } as ChatSessionSpec,
    })) {
      const plan = planTurn(index, spec, 0, mint);
      index = plan.index;
      ids[name] = plan.sessionId;
    }
    expect(endMatching(index, { scope: 'thread', channel: 'ch-family', party: 'grandma' }).ended).toEqual([ids.grandma]);
    expect(endMatching(index, { scope: 'feed', channel: 'ch-family' }).ended.sort()).toEqual([ids.grandma, ids.grandpa].sort());
    const all = endMatching(index, { scope: 'app' });
    expect(all.ended).toHaveLength(3);
    expect(all.index.open).toEqual([]);
  });

  it('idle sessions expire; ended logs are kept up to the retention and no further', () => {
    const open = planTurn(emptyIndex(), thread, 0, mint);
    expect(expireIdle(open.index, 30 * MIN).ended).toEqual([]);
    expect(expireIdle(open.index, 31 * MIN).ended).toEqual([open.sessionId]);
    let index = emptyIndex();
    const all: string[] = [];
    for (let i = 0; i < ENDED_LOGS_KEPT + 3; i++) {
      const id = `ak-none-${i}`;
      all.push(id);
      const retired = retire(index, [id]);
      index = retired.index;
      if (i < ENDED_LOGS_KEPT) expect(retired.toDelete).toEqual([]);
      else expect(retired.toDelete).toEqual([all[i - ENDED_LOGS_KEPT]]);
    }
    expect(index.ended).toEqual(all.slice(3));
  });

  it('session ids are one plain path segment', () => {
    expect(newSessionId('thread', Date.UTC(2026, 8, 23, 21, 30, 0), 'a1b2c3d4')).toBe('ak-thread-20260923T213000Z-a1b2c3d4');
    expect(newSessionId('none', 0, '../../x')).toMatch(/^ak-none-[0-9TZ]+-x$/);
  });
});

describe('the index in the runtime home', () => {
  it('round-trips, and a missing or malformed file reads as empty', async () => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'ak-index-'));
    expect(await readIndex(home)).toEqual(emptyIndex());
    const plan = planTurn(emptyIndex(), { window: 'conversation', scope: 'ch' }, 5, () => 'ak-conversation-1');
    await writeIndex(home, plan.index);
    expect(await readIndex(home)).toEqual(plan.index);
    await fs.writeFile(path.join(home, SESSION_INDEX_FILE), '{"version":1,"open":[{"id":"../../etc"}],"ended":["ok-id","../x"]}');
    expect(await readIndex(home)).toEqual({ version: 1, open: [], ended: ['ok-id'] });
    await fs.writeFile(path.join(home, SESSION_INDEX_FILE), 'not json');
    expect(await readIndex(home)).toEqual(emptyIndex());
  });

  it('removes only directories named exactly the session id, never inside node_modules', async () => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'ak-sweep-'));
    const gone = path.join(home, 'sessions', '--opt-agentkeys--', 'ak-none-1');
    const kept = path.join(home, 'sessions', '--opt-agentkeys--', 'ak-none-10');
    const nm = path.join(home, 'node_modules', 'ak-none-1');
    for (const dir of [gone, kept, nm]) await fs.mkdir(dir, { recursive: true });
    expect(await removeSessionDirs(home, 'ak-none-1')).toEqual(['sessions/--opt-agentkeys--/ak-none-1']);
    await expect(fs.stat(gone)).rejects.toThrow();
    expect((await fs.stat(kept)).isDirectory()).toBe(true);
    expect((await fs.stat(nm)).isDirectory()).toBe(true);
    expect(await removeSessionDirs(home, '../x')).toEqual([]);
  });
});

// ── the bridge over real HTTP, with a fake that holds many sessions ──────────

function fakeManyAgents(ctx: Context) {
  const created: string[] = [];
  const resumed: string[] = [];
  const disposed: string[] = [];
  const injected: Array<{ sessionId: string; text: string }> = [];
  const followups: Array<{ sessionId: string; text: string }> = [];
  const restricted: string[] = [];
  const persisted = new Set<string>();
  const textOf = (message: { content: Array<{ text?: string }> }) => message.content[0]?.text ?? '';
  const agentCtx = {
    tools: {
      restrict(filter: { deny: string[] }) {
        restricted.push(...filter.deny);
        return () => {};
      },
    },
  };
  const mkHandle = (sessionId: string) => ({
    agent: {
      options: { model: 'mock-model' },
      session: { id: sessionId },
      inject(message: { content: Array<{ text?: string }> }) {
        injected.push({ sessionId, text: textOf(message) });
      },
      followup(message: { content: Array<{ text?: string }> }) {
        followups.push({ sessionId, text: textOf(message) });
        persisted.add(sessionId);
      },
      async whenIdle() {
        const emit = (type: string, data: unknown) =>
          ctx.emit(ctx as never, 'session/event', { id: sessionId } as never, { type, data } as never);
        emit('assistant/chunk', { chunk: { type: 'text-delta', text: `reply from ${sessionId}` } });
        emit('turn/end', { usage: { total_tokens: 3 } });
      },
    },
    dispose: async () => {
      disposed.push(sessionId);
    },
  });
  return {
    service: {
      async create(options: { sessionId: unknown; setup?: (c: unknown) => unknown }) {
        const id = String(options.sessionId);
        created.push(id);
        await options.setup?.(agentCtx);
        return mkHandle(id);
      },
      async resume(options: { resumeSessionId: unknown }) {
        const id = String(options.resumeSessionId);
        if (!persisted.has(id)) throw new Error(`session "${id}" not found`);
        resumed.push(id);
        return mkHandle(id);
      },
    },
    created,
    resumed,
    disposed,
    injected,
    followups,
    restricted,
    persisted,
  };
}

let ctx: Context | undefined;
afterEach(async () => {
  if (ctx) await ctx.fiber.dispose();
  ctx = undefined;
});

const AUTH = { authorization: 'Bearer sbt1_test', 'content-type': 'application/json' };

async function boot() {
  ctx = new Context();
  const fake = fakeManyAgents(ctx);
  ctx.provide('agents', fake.service);
  ctx.provide('sessions', {});
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'ak-typed-'));
  await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0 });
  await ctx.plugin(bridgePlugin, { cwd: '/tmp', engine: 'dsh', model: 'mock-model', bridgeToken: 'sbt1_test', homeDir: home });
  await new Promise((r) => setTimeout(r, 20)); // the legacy session is created at activation
  const base = `http://127.0.0.1:${ctx.webServer.port}`;
  const chat = async (text: string, session?: Record<string, unknown>) => {
    const res = await fetch(`${base}/v1/chat`, {
      method: 'POST',
      headers: AUTH,
      body: JSON.stringify({ text, stream: false, ...(session ? { session } : {}) }),
    });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  const reset = async (body: Record<string, unknown>) => {
    const res = await fetch(`${base}/v1/session/reset`, { method: 'POST', headers: AUTH, body: JSON.stringify(body) });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  return { base, fake, home, chat, reset };
}

describe('typed sessions through the bridge (real HTTP)', () => {
  it('a thread keeps one session: context only when it is created, the same session on the next turn', async () => {
    const { fake, chat, home } = await boot();
    const spec = { window: 'thread', scope: 'ch-family', party: 'grandma', idle_minutes: 30, context: 'Earlier: noodles.' };
    const first = await chat("what's for dinner?", spec);
    expect(first.status).toBe(200);
    const session = first.body.session as { id: string; window: string; fresh: boolean };
    expect(session).toMatchObject({ window: 'thread', fresh: true });
    expect(session.id).toMatch(/^ak-thread-/);
    expect(first.body.reply).toBe(`reply from ${session.id}`);
    expect(fake.injected).toEqual([{ sessionId: session.id, text: 'Earlier: noodles.' }]);
    const second = await chat('and dessert?', { ...spec, context: 'should be ignored' });
    expect((second.body.session as { id: string; fresh: boolean })).toMatchObject({ id: session.id, fresh: false });
    expect(fake.injected).toHaveLength(1);
    expect(fake.followups.map((f) => f.sessionId)).toEqual([session.id, session.id]);
    const index = await readIndex(home);
    expect(index.open.map((o) => o.id)).toEqual([session.id]);
  });

  it('a card tap and a clock tick each run in a throwaway session that ends with the turn', async () => {
    const { fake, chat, home } = await boot();
    const tap = await chat('[command] swap dish', { window: 'event', scope: 'ch-screen', context: 'The card: Dinner plan' });
    const tick = await chat('[clock] morning plan', { window: 'none', scope: 'schedule:morning-plan' });
    const tapId = (tap.body.session as { id: string }).id;
    const tickId = (tick.body.session as { id: string }).id;
    expect(tapId).toMatch(/^ak-event-/);
    expect(tickId).toMatch(/^ak-none-/);
    expect(fake.disposed).toEqual(expect.arrayContaining([tapId, tickId]));
    expect(fake.injected).toEqual([{ sessionId: tapId, text: 'The card: Dinner plan' }]);
    const index = await readIndex(home);
    expect(index.open).toEqual([]);
    expect(index.ended).toEqual([tapId, tickId]);
  });

  it('a body without a session still runs in the legacy resident session', async () => {
    const { fake, chat } = await boot();
    const legacy = await chat('hello from the ESP32');
    expect(legacy.status).toBe(200);
    expect(legacy.body.session).toBeUndefined();
    expect(fake.followups.at(-1)?.sessionId).toBe('agentkeys-bridge-session');
  });

  it('a thread reset ends only that thread; an app reset ends every session and starts the legacy one over', async () => {
    const { fake, chat, reset, home } = await boot();
    const grandma = await chat('hi', { window: 'thread', scope: 'ch-family', party: 'grandma', idle_minutes: 30 });
    const owner = await chat('hi', { window: 'conversation', scope: 'ch-opchat', idle_minutes: 1440 });
    const grandmaId = (grandma.body.session as { id: string }).id;
    const ownerId = (owner.body.session as { id: string }).id;
    const legacyDir = path.join(home, 'sessions', '--tmp--', 'agentkeys-bridge-session');
    await fs.mkdir(legacyDir, { recursive: true });

    expect((await reset({ scope: 'bogus' })).status).toBe(400);
    const one = await reset({ scope: 'thread', channel: 'ch-family', party: 'grandma' });
    expect(one.body).toMatchObject({ ok: true, ended: 1, legacy_reset: false });
    expect(fake.disposed).toContain(grandmaId);
    expect((await readIndex(home)).open.map((o) => o.id)).toEqual([ownerId]);

    const createdBefore = fake.created.length;
    const all = await reset({ scope: 'app' });
    expect(all.body).toMatchObject({ ok: true, ended: 1, legacy_reset: true });
    expect(fake.disposed).toEqual(expect.arrayContaining([ownerId, 'agentkeys-bridge-session']));
    await expect(fs.stat(legacyDir)).rejects.toThrow();
    await new Promise((r) => setTimeout(r, 20));
    expect(fake.created.slice(createdBefore)).toContain('agentkeys-bridge-session');
    // the next turn in the owner's chat opens a NEW conversation
    const next = await chat('fresh start', { window: 'conversation', scope: 'ch-opchat', idle_minutes: 1440 });
    expect((next.body.session as { id: string; fresh: boolean })).toMatchObject({ fresh: true });
    expect((next.body.session as { id: string }).id).not.toBe(ownerId);
  });

  it('a session whose log is on disk but not live resumes instead of starting over', async () => {
    const { fake, chat, home, base } = await boot();
    const first = await chat('hi', { window: 'conversation', scope: 'ch-opchat', idle_minutes: 1440 });
    const id = (first.body.session as { id: string }).id;
    // a restart disposes live sessions (persona / skills re-read)
    const restarted = await fetch(`${base}/v1/agent/restart`, { method: 'POST', headers: AUTH });
    expect(restarted.status).toBe(200);
    expect(fake.disposed).toContain(id);
    const again = await chat('still there?', { window: 'conversation', scope: 'ch-opchat', idle_minutes: 1440, context: 'rebuilt window' });
    expect((again.body.session as { id: string; fresh: boolean })).toMatchObject({ id, fresh: false });
    expect(fake.resumed).toContain(id);
    expect(fake.injected).toEqual([]);
    expect((await readIndex(home)).open).toHaveLength(1);
  });

  it('every agent is set up with the hidden tools masked', async () => {
    const { fake, chat } = await boot();
    await chat('hi', { window: 'none', scope: 'schedule:x' });
    expect(fake.restricted).toEqual(expect.arrayContaining([...DEFAULT_HIDDEN_TOOLS]));
  });

  it('refuses a malformed session with 400 and a GET reset with 405', async () => {
    const { chat, base } = await boot();
    expect((await chat('hi', { window: 'forever', scope: 'x' })).status).toBe(400);
    expect((await fetch(`${base}/v1/session/reset`, { headers: AUTH })).status).toBe(405);
    expect((await fetch(`${base}/v1/session/reset`, { method: 'POST', body: '{"scope":"app"}' })).status).toBe(401);
  });
});
