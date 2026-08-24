import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import ToolRuntime, { defineContentToolFixture, type ToolExecutionInput } from '@deepseek-ai/dsh-tools';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import * as guardPlugin from '../src/guard.js';
import { recordApprovedCall } from '../src/grants.js';

let server: Server;
let grantsUrl: string;
let granted: string[] = ['tool:web'];

beforeAll(async () => {
  server = createServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ services: granted, unresolved_service_ids: [] }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no addr');
  grantsUrl = `http://127.0.0.1:${addr.port}/v1/sandbox/self/grants`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

async function setup(config: Record<string, unknown> = {}) {
  const ctx = new Context();
  await ctx.plugin(SystemPrompt);
  await ctx.plugin(ToolRuntime);
  await ctx.plugin(guardPlugin, { grantsUrl, ttlMs: 30, ...config });
  for (const name of ['web_fetch', 'bash', 'read', 'made_up_tool']) {
    ctx.tools.register(
      defineContentToolFixture({
        name,
        description: `fixture ${name}`,
        parameters: {},
        execute: async () => [{ type: 'text', text: `${name} ran` }],
      }),
    );
  }
  return ctx;
}

let n = 0;
const exec = (name: string): ToolExecutionInput =>
  ({
    callId: `call-${n++}`,
    name,
    arguments: {},
    signal: new AbortController().signal,
  }) as unknown as ToolExecutionInput;

describe('agentkeys guard (real dsh pipeline)', () => {
  it('allows baseline and granted-class tools', async () => {
    const ctx = await setup();
    expect((await ctx.tools.execute(exec('read'))).isError).toBe(false);
    expect((await ctx.tools.execute(exec('web_fetch'))).isError).toBe(false);
  });

  it('denies unmapped tools with the deny-by-absence reason', async () => {
    const ctx = await setup();
    const result = await ctx.tools.execute(exec('made_up_tool'));
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('deny by absence');
  });

  it('an ungranted class asks — and with no approval service composed, fails closed', async () => {
    const ctx = await setup();
    const result = await ctx.tools.execute(exec('bash'));
    expect(result.isError).toBe(true);
  });

  it('MONOTONIC: a rogue prepend allow listener cannot bypass the guard', async () => {
    const ctx = await setup();
    await ctx.tools.execute(exec('read')); // warm the grant cache via the normal path
    ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }) as const, true);
    const unmapped = await ctx.tools.execute(exec('made_up_tool'));
    expect(unmapped.isError).toBe(true);
    const ungranted = await ctx.tools.execute(exec('bash'));
    expect(ungranted.isError).toBe(true);
    // granted class still passes through the rogue path (guard allows it)
    const grantedCall = await ctx.tools.execute(exec('web_fetch'));
    expect(grantedCall.isError).toBe(false);
  });

  it('an allowed-once ledger entry lets exactly one approved call through the backstop', async () => {
    const ctx = await setup();
    await ctx.tools.execute(exec('read'));
    ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }) as const, true);
    const input = exec('bash');
    recordApprovedCall(String(input.callId));
    const first = await ctx.tools.execute(input);
    expect(first.isError).toBe(false);
    const second = await ctx.tools.execute(exec('bash'));
    expect(second.isError).toBe(true);
  });

  it('fails closed when the grants endpoint is down', async () => {
    const ctx = await setup({ grantsUrl: 'http://127.0.0.1:1/nope', ttlMs: 30 });
    const result = await ctx.tools.execute(exec('web_fetch'));
    expect(result.isError).toBe(true);
    expect((await ctx.tools.execute(exec('read'))).isError).toBe(false);
  });
});
