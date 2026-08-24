import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import { ApprovalService } from '@deepseek-ai/dsh-user-approval';
import type { ApprovalOutcome, ApprovalRequest } from '@deepseek-ai/dsh-user-approval';
import * as answererPlugin from '../src/answerer.js';
import { consumeApprovedCall } from '../src/grants.js';

let server: Server;
let grantsUrl: string;

beforeAll(async () => {
  server = createServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ services: ['tool:web'] }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no addr');
  grantsUrl = `http://127.0.0.1:${addr.port}/grants`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe('agentkeys answerer (waterfall dispatch)', () => {
  it('answers allowed-once for a granted class and records the ledger entry', async () => {
    const ctx = new Context();
    await ctx.plugin(ApprovalService);
    await ctx.plugin(answererPlugin, { grantsUrl, ttlMs: 30, proposeCommand: '' });
    const req = { agent: {} as never, toolName: 'web_fetch', callId: 'approve-1' } as unknown as ApprovalRequest;
    const outcome: ApprovalOutcome = await (ctx as never as {
      waterfall: (name: string, req: ApprovalRequest, next: () => Promise<ApprovalOutcome>) => Promise<ApprovalOutcome>;
    }).waterfall('approval/request', req, async () => 'unavailable');
    expect(outcome).toBe('allowed-once');
    expect(consumeApprovedCall('approve-1')).toBe(true);
    expect(consumeApprovedCall('approve-1')).toBe(false);
  });

  it('rejects an ungranted class', async () => {
    const ctx = new Context();
    await ctx.plugin(ApprovalService);
    await ctx.plugin(answererPlugin, { grantsUrl, ttlMs: 30, proposeCommand: '' });
    const req = { agent: {} as never, toolName: 'bash', callId: 'approve-2' } as unknown as ApprovalRequest;
    const outcome: ApprovalOutcome = await (ctx as never as {
      waterfall: (name: string, req: ApprovalRequest, next: () => Promise<ApprovalOutcome>) => Promise<ApprovalOutcome>;
    }).waterfall('approval/request', req, async () => 'unavailable');
    expect(outcome).toBe('rejected');
    expect(consumeApprovedCall('approve-2')).toBe(false);
  });
});
