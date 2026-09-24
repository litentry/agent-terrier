import { createServer, type Server } from 'node:http';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import ToolRuntime, { defineContentToolFixture } from '@deepseek-ai/dsh-tools';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import * as presetsPlugin from '../src/presets.js';
import { applyRestrictions, deniedTools } from '../src/presets.js';

const view = (...services: string[]) => new Set(services.map((s) => s.toLowerCase()));
const NAMES = ['read', 'web_search', 'web_fetch', 'bash', 'schedule_create', 'publish_to_slot', 'propose_to_owner', 'mcp__openviking__remember', 'mcp__openviking__search', 'made_up'];

describe('deniedTools (pure)', () => {
  it('hides hidden, ungranted-class, ungranted-verb and unmapped tools; keeps baseline and granted ones', () => {
    expect(deniedTools(NAMES, view('tool:web', 'channel-pub:kitchen-display'), true, {})).toEqual([
      'bash', 'schedule_create', 'propose_to_owner', 'mcp__openviking__remember', 'made_up',
    ]);
    expect(deniedTools(NAMES, view('tool:web', 'tool:code', 'tool:schedule', 'channel-pub:x', 'proposal:app-chef'), true, {})).toEqual([
      'mcp__openviking__remember', 'made_up',
    ]);
  });
  it('fails closed while the grant view is unavailable: every classed and advertised tool is hidden', () => {
    expect(deniedTools(NAMES, view('tool:web'), false, {})).toEqual([
      'web_search', 'web_fetch', 'bash', 'schedule_create', 'publish_to_slot', 'propose_to_owner', 'mcp__openviking__remember', 'made_up',
    ]);
  });
  it('honors the mapping overrides', () => {
    expect(deniedTools(['my_fetch', 'read'], view(), true, { toolClasses: { web: ['my_fetch'] }, baseline: ['read'] })).toEqual(['my_fetch']);
  });
});

describe('applyRestrictions (pure over a scope)', () => {
  it('restricts one name at a time, contains the names dsh refuses, and returns the disposers', () => {
    const calls: string[][] = [];
    const scope = {
      restrict(filter: { deny: string[] }) {
        calls.push(filter.deny);
        if (filter.deny[0] === 'not_registered') throw new Error('unknown tool');
        return () => calls.push(['lifted', ...filter.deny]);
      },
    };
    const out = applyRestrictions(scope, ['bash', 'not_registered', 'made_up']);
    expect(out.applied).toEqual(['bash', 'made_up']);
    expect(out.refused).toEqual(['not_registered']);
    expect(out.disposers).toHaveLength(2);
    for (const off of out.disposers) off();
    expect(calls).toEqual([['bash'], ['not_registered'], ['made_up'], ['lifted', 'bash'], ['lifted', 'made_up']]);
  });
});

// ── the plugin, through the real tool runtime with a fake agent event ────────
let server: Server;
let grantsUrl: string;
let granted: string[] = [];
beforeAll(async () => {
  server = createServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ services: granted }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no addr');
  grantsUrl = `http://127.0.0.1:${addr.port}/v1/sandbox/self/grants`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

let ctx: Context | undefined;
afterEach(async () => {
  if (ctx) await ctx.fiber.dispose();
  ctx = undefined;
  granted = [];
  vi.restoreAllMocks();
});

const fixture = (name: string) => defineContentToolFixture({ name, description: name, parameters: {}, execute: async () => [{ type: 'text', text: name }] });

async function until(cond: () => boolean, ms = 2_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`condition not met within ${ms} ms`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe('agentkeys presets (the grant view compiled into the agent’s tool view)', () => {
  it('on agent/created the ungranted tools leave the agent scope’s schema; a granted class stays; tools/change re-projects', async () => {
    granted = ['tool:web', 'channel-pub:kitchen-display'];
    ctx = new Context();
    await ctx.plugin(SystemPrompt);
    await ctx.plugin(ToolRuntime);
    ctx.provide('agents', {});
    for (const n of ['read', 'web_search', 'bash', 'publish_to_slot', 'propose_to_owner', 'mcp__openviking__remember']) {
      ctx.effect(() => ctx!.tools.register(fixture(n)));
    }
    await ctx.plugin(presetsPlugin, { grantsUrl, ttlMs: 30, refreshMs: 60_000 });
    // A fake agent whose scope records the restrictions dsh would apply
    // (the plugin reads only `agent.ctx.tools.restrict`).
    const restricted: string[] = [];
    const lifted: string[] = [];
    const scope = {
      restrict(filter: { deny: string[] }) {
        for (const n of filter.deny) restricted.push(n);
        return () => lifted.push(...filter.deny);
      },
    };
    const agent = { ctx: { tools: scope } } as never;
    // cordis emit: (thisArg, name, ...payload) — the same call shape the bridge test uses.
    ctx.emit(ctx as never, 'agent/created', { agent } as never);
    await until(() => restricted.length >= 3);
    expect(restricted).toEqual(expect.arrayContaining(['bash', 'propose_to_owner', 'mcp__openviking__remember']));
    expect(restricted).not.toContain('read');
    expect(restricted).not.toContain('web_search');
    expect(restricted).not.toContain('publish_to_slot');
    // A grant lands (the view changes) + tools/change: the projection is re-done and bash is lifted.
    const before = restricted.length;
    granted = ['tool:web', 'tool:code', 'channel-pub:kitchen-display'];
    await new Promise((r) => setTimeout(r, 40)); // > ttlMs
    ctx.emit(ctx as never, 'tools/change');
    await until(() => restricted.length > before);
    expect(lifted).toEqual(expect.arrayContaining(['bash']));
    expect(restricted.slice(before)).not.toContain('bash');
    // disposal lifts everything
    ctx.emit(ctx as never, 'agent/disposed', { agent } as never);
    expect(lifted.length).toBeGreaterThanOrEqual(restricted.length);
  });
});
