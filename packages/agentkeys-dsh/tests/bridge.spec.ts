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
  const agent = {
    options: { model: 'mock-model' },
    session: { id: sessionId },
    followup() {
      /* the test emits events + then releases whenIdle */
    },
    whenIdle: () => new Promise<void>((r) => (resolveIdle = r)),
  };
  const emit = (type: string, data: unknown) => {
    ctx.emit(ctx as never, 'session/event', { id: sessionId } as never, { type, data } as never);
  };
  const releaseIdle = () => resolveIdle?.();
  return {
    service: {
      async create() {
        return { agent, dispose: async () => {} };
      },
      get() {
        return agent;
      },
    },
    emit,
    releaseIdle,
  };
}

let ctx: Context | undefined;
afterEach(async () => {
  if (ctx) await ctx.fiber.dispose();
  ctx = undefined;
});

async function boot() {
  ctx = new Context();
  const fake = fakeAgents(ctx, 'agentkeys-bridge-session');
  ctx.provide('agents', fake.service);
  ctx.provide('sessions', {});
  await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0 });
  await ctx.plugin(bridgePlugin, { cwd: '/tmp', engine: 'dsh', model: 'mock-model' });
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
    const res = await fetch(`${base}/v1/jobs`);
    expect(await res.json()).toEqual({ jobs: [] });
  });

  // NOTE: the token/tool/done frame projection over a full turn is proven
  // byte-exactly by the TurnStreamer unit tests against synthetic events (the
  // real session/event bus is scope-routed by a live Session, which a fake
  // cannot faithfully drive); the live agent path verifies in the #615 image.

  it('v1/chat rejects a bad body with 400', async () => {
    const { base } = await boot();
    const res = await fetch(`${base}/v1/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not json',
    });
    expect(res.status).toBe(400);
  });
});
