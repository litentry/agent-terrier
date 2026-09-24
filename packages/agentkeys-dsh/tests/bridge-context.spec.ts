import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Context } from '@deepseek-ai/cordis';
import WebServer from '@deepseek-ai/dsh-host-webserver';
import * as bridgePlugin from '../src/bridge.js';
import * as sessionsPlugin from '../src/sessions.js';
import { renderContextSections } from '../src/bridge.js';

// #662/#669 — the bridge's context + jobs surface: persona / skills /
// knowledge land under the runtime cwd AND as dsh system-prompt sections; the
// schedule entries register; restart disposes the live session.

// #715 — the in-pod bearer every gated route demands.
const BRIDGE_TOKEN = 'sbt1_test';
const AUTH = { authorization: `Bearer ${BRIDGE_TOKEN}` };

function fakeAgents() {
  const disposeCalls: string[] = [];
  const handle = {
    agent: {
      options: { model: 'mock-model' },
      followup() {},
      whenIdle: () => Promise.resolve(),
    },
    dispose: async () => {
      disposeCalls.push('disposed');
    },
  };
  return {
    service: {
      async create() {
        return handle;
      },
      async resume() {
        throw new Error('session "agentkeys-bridge-session" not found');
      },
    },
    disposeCalls,
  };
}

function fakeSystemPrompt() {
  const sections: Array<{ name: string; order: number; text: string }> = [];
  return {
    sections,
    service: {
      section(s: { name: string; order: number; text: string }) {
        sections.push(s);
        return () => {
          const i = sections.indexOf(s);
          if (i >= 0) sections.splice(i, 1);
        };
      },
    },
  };
}

let ctx: Context | undefined;
afterEach(async () => {
  if (ctx) await ctx.fiber.dispose();
  ctx = undefined;
});

async function boot(withPrompt: boolean) {
  ctx = new Context();
  const cwd = mkdtempSync(join(tmpdir(), 'ak-bridge-ctx-'));
  const agents = fakeAgents();
  const prompt = fakeSystemPrompt();
  ctx.provide('agents', agents.service);
  ctx.provide('sessions', {});
  if (withPrompt) ctx.provide('systemPrompt', prompt.service);
  await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0 });
  await ctx.plugin(sessionsPlugin, {});
  await ctx.plugin(bridgePlugin, { cwd, engine: 'dsh', model: 'mock-model', bridgeToken: BRIDGE_TOKEN });
  await new Promise((r) => setTimeout(r, 20));
  return { base: `http://127.0.0.1:${ctx.webServer.port}`, cwd, agents, prompt };
}

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

describe('bridge context + jobs surface', () => {
  it('renders persona / skills / knowledge sections deterministically', () => {
    const r = renderContextSections({
      soul: '# Soul\nBe kind.\n',
      skills: { 'plan.md': 'Plan meals.', 'diary.md': 'Log meals.' },
      knowledge: {},
    });
    expect(r.persona).toBe('# Soul\nBe kind.');
    expect(r.skills).toBe('# Skills\n\n## diary.md\n\nLog meals.\n\n## plan.md\n\nPlan meals.');
    expect(r.knowledge).toBe('');
  });

  it('context/apply writes the files, registers prompt sections, and the view lists them', async () => {
    const { base, cwd, prompt } = await boot(true);
    const res = await fetch(`${base}/v1/context/apply`, {
      method: 'POST',
      headers: { ...AUTH, 'content-type': 'application/json' },
      body: JSON.stringify({
        files: { soul: b64('# Chef\nCook well.') },
        skills: { 'perception.md': b64('Look at the photo.'), 'plan.md': b64('Plan.') },
        knowledge: { 'nutrition.md': b64('Protein matters.') },
        restart: false,
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({
      ok: true,
      files_written: ['SOUL.md'],
      skills_written: ['perception.md', 'plan.md'],
      knowledge_written: ['nutrition.md'],
      prompt_registered: true,
      restarted: false,
    });
    expect(readFileSync(join(cwd, 'SOUL.md'), 'utf8')).toBe('# Chef\nCook well.');
    expect(existsSync(join(cwd, 'skills', 'plan.md'))).toBe(true);
    const names = prompt.sections.map((s) => s.name).sort();
    expect(names).toEqual(['agentkeys:knowledge', 'agentkeys:persona', 'agentkeys:skills']);
    expect(prompt.sections.find((s) => s.name === 'agentkeys:persona')?.text).toBe('# Chef\nCook well.');

    // A second apply REPLACES the sections (no duplicate-name throw).
    const again = await fetch(`${base}/v1/context/apply`, {
      method: 'POST',
      headers: { ...AUTH, 'content-type': 'application/json' },
      body: JSON.stringify({ files: { soul: b64('# Chef v2') } }),
    });
    expect(again.status).toBe(200);
    expect(prompt.sections.filter((s) => s.name === 'agentkeys:persona')).toHaveLength(1);
    expect(prompt.sections.find((s) => s.name === 'agentkeys:persona')?.text).toBe('# Chef v2');

    const view = await (await fetch(`${base}/v1/context/files`, { headers: AUTH })).json();
    expect(view.files[0]).toMatchObject({ id: 'soul', present: true, content: '# Chef v2', editable: true });
    expect(view.files[1]).toMatchObject({ id: 'agents', present: false });
    expect(view.skills).toEqual(['perception.md', 'plan.md']);
    expect(view.knowledge).toEqual(['nutrition.md']);
  });

  it('refuses an empty apply, a traversal name, and bad base64 (400)', async () => {
    const { base } = await boot(false);
    const post = (payload: unknown) =>
      fetch(`${base}/v1/context/apply`, { method: 'POST', headers: { ...AUTH, 'content-type': 'application/json' }, body: JSON.stringify(payload) });
    expect((await post({})).status).toBe(400);
    expect((await post({ skills: { '../evil.md': b64('x') } })).status).toBe(400);
    expect((await post({ files: { config: b64('x') } })).status).toBe(400);
    expect((await post({ skills: { 'a.md': '!!!not-base64!!!' } })).status).toBe(400);
  });

  it('without a systemPrompt service the files still land (prompt_registered false)', async () => {
    const { base } = await boot(false);
    const res = await fetch(`${base}/v1/context/apply`, {
      method: 'POST',
      headers: { ...AUTH, 'content-type': 'application/json' },
      body: JSON.stringify({ skills: { 'x.md': b64('x') } }),
    });
    expect(await res.json()).toMatchObject({ ok: true, skills_written: ['x.md'], prompt_registered: false });
  });

  it('jobs register and list; restart disposes the live session', async () => {
    const { base, agents } = await boot(false);
    const reg = await fetch(`${base}/v1/jobs`, {
      method: 'POST',
      headers: { ...AUTH, 'content-type': 'application/json' },
      body: JSON.stringify({ jobs: [{ id: 'schedule-0-morning', cron: '0 7 * * *', label: 'Morning plan', status: 'armed' }] }),
    });
    expect(reg.status).toBe(200);
    const list = await (await fetch(`${base}/v1/jobs`, { headers: AUTH })).json();
    expect(list.jobs).toHaveLength(1);
    expect(list.jobs[0]).toMatchObject({ id: 'schedule-0-morning', status: 'armed' });
    const bad = await fetch(`${base}/v1/jobs`, { method: 'POST', headers: { ...AUTH, 'content-type': 'application/json' }, body: JSON.stringify({ jobs: [{ cron: 'x' }] }) });
    expect(bad.status).toBe(400);

    const restart = await fetch(`${base}/v1/agent/restart`, { method: 'POST', headers: AUTH });
    expect(await restart.json()).toMatchObject({ restarted: true, ok: true });
    expect(agents.disposeCalls).toEqual(['disposed']);
  });
});
