import { afterEach, describe, expect, it } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import WebServer from '@deepseek-ai/dsh-host-webserver';
import * as bridgePlugin from '../src/bridge.js';

// A controllable fake `agents` service: create() hands back a handle whose
// followup() lets the test emit session/event frames, and whenIdle() resolves
// when the test says the turn is done. This drives the REAL plugin + REAL
// webserver over REAL HTTP without a live LLM.
function fakeAgents(ctx: Context, sessionId: string) {
  let resolveIdle: (() => void) | undefined;
  let signalFollowup: (() => void) | undefined;
  const followupCalled = () => new Promise<void>((r) => (signalFollowup = r));
  const createCalls: unknown[] = [];
  const agent = {
    options: { model: 'mock-model' },
    session: { id: sessionId },
    followup() {
      signalFollowup?.();
    },
    whenIdle: () => new Promise<void>((r) => (resolveIdle = r)),
  };
  const emit = (type: string, data: unknown) => {
    ctx.emit(ctx as never, 'session/event', { id: sessionId } as never, { type, data } as never);
  };
  const releaseIdle = () => resolveIdle?.();
  const resumeCalls: unknown[] = [];
  const disposeCalls: unknown[] = [];
  // Real dsh-session-persistence semantics (measured live, 2026-08-26):
  // create() does NOT probe the stored log — persistence binds lazily at the
  // first WRITE, and a fresh session over an imported log dies THERE with the
  // bind-time "id collision" (adoptLivePrefix). resume() prepares the stored
  // log as the session's own history, or throws `session "<id>" not found`.
  // createCollides models the narrow guard-1 race: create itself refuses AND
  // the log is on disk from that moment.
  const modes = { createCollides: false, persistedLog: false };
  const BIND_COLLISION_MSG =
    'session "agentkeys-bridge-session" already has a persisted log on disk that does not match this live session (id collision)';
  const CREATE_GUARD_MSG =
    'session "agentkeys-bridge-session" already has a persisted log on disk; load/resume it instead of creating';
  const mkHandle = (resumed: boolean) => ({
    agent: {
      ...agent,
      followup() {
        if (!resumed && modes.persistedLog) throw new Error(BIND_COLLISION_MSG);
        signalFollowup?.();
      },
    },
    dispose: async () => {
      disposeCalls.push(resumed ? 'resumed' : 'created');
    },
  });
  return {
    service: {
      async create(options: unknown) {
        createCalls.push(options);
        if (modes.createCollides) {
          modes.persistedLog = true;
          throw new Error(CREATE_GUARD_MSG);
        }
        return mkHandle(false);
      },
      async resume(options: unknown) {
        resumeCalls.push(options);
        if (!modes.persistedLog)
          throw new Error('session "agentkeys-bridge-session" not found');
        return mkHandle(true);
      },
      get() {
        return agent;
      },
    },
    emit,
    releaseIdle,
    followupCalled,
    createCalls,
    resumeCalls,
    disposeCalls,
    modes,
  };
}

let ctx: Context | undefined;
afterEach(async () => {
  if (ctx) await ctx.fiber.dispose();
  ctx = undefined;
});

// #715 — the in-pod bearer every non-healthz route demands (fail-closed).
const BRIDGE_TOKEN = 'sbt1_test';
const AUTH = { authorization: `Bearer ${BRIDGE_TOKEN}` };

async function boot(opts?: {
  defaultModel?: { provider: string; model: string };
  preMode?: (fake: ReturnType<typeof fakeAgents>) => void;
  /** Boot WITHOUT a bridge token (the not-armed posture). */
  unarmed?: boolean;
}) {
  ctx = new Context();
  const fake = fakeAgents(ctx, 'agentkeys-bridge-session');
  opts?.preMode?.(fake);
  ctx.provide('agents', fake.service);
  ctx.provide('sessions', {});
  if (opts?.defaultModel) {
    const selection = opts.defaultModel;
    ctx.provide('agentDefaultModel', { currentSelection: () => selection });
  }
  await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0 });
  await ctx.plugin(bridgePlugin, { cwd: '/tmp', engine: 'dsh', model: 'mock-model', ...(opts?.unarmed ? {} : { bridgeToken: BRIDGE_TOKEN }) });
  const base = `http://127.0.0.1:${ctx.webServer.port}`;
  return { base, fake };
}

describe('agentkeys bridge (real HTTP through the webServer seam)', () => {
  it('healthz reports ready once the agent is created, with the byte-exact body', async () => {
    const { base } = await boot();
    // ensureAgent runs on activation; give it a tick
    await new Promise((r) => setTimeout(r, 20));
    const res = await fetch(`${base}/healthz`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ ok: true, engine: 'dsh', model: 'mock-model', phase: 'ready' });
  });

  it('v1/jobs returns the object shape {jobs:[...]} (the daemon parse bug guard)', async () => {
    const { base } = await boot();
    const res = await fetch(`${base}/v1/jobs`, { headers: AUTH });
    expect(await res.json()).toEqual({ jobs: [] });
  });

  // NOTE: the token/tool/done frame projection over a full turn is proven
  // byte-exactly by the TurnStreamer unit tests against synthetic events (the
  // real session/event bus is scope-routed by a live Session, which a fake
  // cannot faithfully drive); the live agent path verifies in the #615 image.

  it('the agent is created WITH the shared default provider/model when the service is up (#631)', async () => {
    const { fake } = await boot({ defaultModel: { provider: 'gate', model: 'ep-test' } });
    await new Promise((r) => setTimeout(r, 20));
    expect(fake.createCalls[0]).toMatchObject({ agentOptions: { provider: 'gate', model: 'ep-test' } });
  });

  it('falls back to its own config provider/model when no agentDefaultModel service exists (#631)', async () => {
    const { fake } = await boot();
    await new Promise((r) => setTimeout(r, 20));
    expect(fake.createCalls[0]).toMatchObject({ agentOptions: { provider: 'gate', model: 'mock-model' } });
  });

  // #715 — the in-pod bearer gate: every route but /healthz (and the mgmt
  // surface, which keeps its own token) is fail-closed.
  it('refuses a bearer-less or wrong-bearer call on every gated route with 401 (#715)', async () => {
    const { base } = await boot();
    await new Promise((r) => setTimeout(r, 20));
    for (const [path, init] of [
      ['/v1/chat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"text":"x"}' }],
      ['/v1/jobs', {}],
      ['/v1/agent/restart', { method: 'POST' }],
      ['/v1/context/files', {}],
      ['/v1/context/apply', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"skills":{}}' }],
    ] as const) {
      const missing = await fetch(`${base}${path}`, init as RequestInit);
      expect(missing.status, `${path} without bearer`).toBe(401);
      const wrong = await fetch(`${base}${path}`, {
        ...(init as RequestInit),
        headers: { ...((init as RequestInit).headers ?? {}), authorization: 'Bearer sbt1_wrong' },
      });
      expect(wrong.status, `${path} wrong bearer`).toBe(401);
    }
    // /healthz stays open: veFaaS readiness + the console's reachability probe.
    expect((await fetch(`${base}/healthz`)).status).toBe(200);
  });

  it('answers 401 not-armed on the gated routes when no bridge token is configured (#715 fail-closed)', async () => {
    const { base } = await boot({ unarmed: true });
    await new Promise((r) => setTimeout(r, 20));
    const res = await fetch(`${base}/v1/jobs`, { headers: AUTH });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toMatch(/not armed/);
    expect((await fetch(`${base}/healthz`)).status).toBe(200);
  });

  it('a turn that ends in error surfaces as 502, never a 200 empty reply (#631)', async () => {
    const { base, fake } = await boot();
    await new Promise((r) => setTimeout(r, 20)); // agent created at activation
    const followedUp = fake.followupCalled();
    const pending = fetch(`${base}/v1/chat`, {
      method: 'POST',
      headers: { ...AUTH, 'content-type': 'application/json' },
      body: JSON.stringify({ text: 'hi' }),
    });
    await followedUp;
    fake.emit('turn/end', {
      turn: 1,
      reason: { kind: 'error', error: { message: 'no provider/model', code: 'UNKNOWN' } },
    });
    fake.releaseIdle();
    const res = await pending;
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: 'agent error: no provider/model' });
  });

  it('#646: a persisted log at boot is RESUMED — create is never attempted', async () => {
    const { fake } = await boot({ preMode: (f) => (f.modes.persistedLog = true) });
    await new Promise((r) => setTimeout(r, 30));
    expect(fake.createCalls.length).toBe(0);
    expect(fake.resumeCalls.length).toBeGreaterThan(0);
    const opts = fake.resumeCalls[0] as { resumeSessionId?: unknown };
    expect(String(opts.resumeSessionId)).toContain('agentkeys-bridge-session');
  });

  it('#646: no persisted log — the resume probe falls through to create', async () => {
    const { fake } = await boot();
    await new Promise((r) => setTimeout(r, 30));
    expect(fake.resumeCalls.length).toBeGreaterThan(0);
    expect(fake.createCalls.length).toBe(1);
  });

  it('#646: the create-time guard race (log lands mid-create) resumes the raced log', async () => {
    const { fake } = await boot({ preMode: (f) => (f.modes.createCollides = true) });
    await new Promise((r) => setTimeout(r, 30));
    expect(fake.createCalls.length).toBe(1);
    // probe (not found) → create (guard) → raced resume (succeeds)
    expect(fake.resumeCalls.length).toBeGreaterThanOrEqual(2);
  });

  it('#646: a BIND-time collision mid-turn (import landed after create) disposes, resumes, retries once', async () => {
    const { base, fake } = await boot();
    await new Promise((r) => setTimeout(r, 20));
    // the #616 import lands the previous instance's log AFTER the live create:
    // the next turn's first write hits the lazy persistence bind and collides
    fake.modes.persistedLog = true;
    const turn = fetch(`${base}/v1/chat`, {
      method: 'POST',
      headers: { ...AUTH, 'content-type': 'application/json' },
      body: JSON.stringify({ text: 'hello', stream: false }),
    });
    // the retry's followup fires on the RESUMED handle; then finish the turn
    await fake.followupCalled();
    fake.emit('assistant/chunk', { text: 'back' });
    fake.emit('turn/end', { usage: { total_tokens: 5 } });
    fake.releaseIdle();
    const res = await turn;
    expect(res.status).toBe(200);
    expect(fake.disposeCalls).toContain('created');
    expect(fake.resumeCalls.length).toBeGreaterThan(0);
  });

  it('v1/chat rejects a bad body with 400', async () => {
    const { base } = await boot();
    const res = await fetch(`${base}/v1/chat`, {
      method: 'POST',
      headers: { ...AUTH, 'content-type': 'application/json' },
      body: 'not json',
    });
    expect(res.status).toBe(400);
  });
});
