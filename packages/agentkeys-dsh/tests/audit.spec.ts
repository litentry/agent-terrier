import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import ToolRuntime, { defineContentToolFixture, type ToolExecutionInput } from '@deepseek-ai/dsh-tools';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import * as auditPlugin from '../src/audit.js';
import { approvalRow, toolResultRow } from '../src/audit.js';

let server: Server;
let auditUrl: string;
const rows: Array<Record<string, unknown>> = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      rows.push(JSON.parse(raw) as Record<string, unknown>);
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no addr');
  auditUrl = `http://127.0.0.1:${addr.port}/v1/sandbox/self/audit`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe('audit tee', () => {
  it('tees a real pipeline tool result as op_kind 110', async () => {
    const ctx = new Context();
    await ctx.plugin(SystemPrompt);
    await ctx.plugin(ToolRuntime);
    // a sessions service stub: the tee only subscribes to events
    ctx.provide('sessions', {});
    await ctx.plugin(auditPlugin, { auditUrl });
    ctx.tools.register(
      defineContentToolFixture({
        name: 'read',
        description: 'fixture',
        parameters: {},
        execute: async () => [{ type: 'text', text: 'ok' }],
      }),
    );
    const result = await ctx.tools.execute({
      callId: 'audit-1',
      name: 'read',
      arguments: {},
      signal: new AbortController().signal,
    } as unknown as ToolExecutionInput);
    expect(result.isError).toBe(false);
    await vi.waitFor(() => {
      expect(rows.length).toBeGreaterThanOrEqual(1);
    });
    const row = rows.at(-1)!;
    expect(row.op_kind).toBe(110);
    expect((row.op_body as Record<string, unknown>).tool).toBe('read');
    expect(row.result).toBe(0);
  });

  it('pure mappers shape the two op kinds', () => {
    const tr = toolResultRow(
      { name: 'bash', callId: 'c9' } as never,
      { isError: true } as never,
    );
    expect(tr).toMatchObject({ op_kind: 110, result: 1, op_body: { tool: 'bash', is_error: true } });
    const ar = approvalRow({ type: 'approval/decided', data: { id: 'x', outcome: 'allowed-once', toolName: 'web_fetch' } } as never);
    expect(ar).toMatchObject({ op_kind: 111, result: 0, op_body: { tool: 'web_fetch', outcome: 'allowed-once' } });
    expect(approvalRow({ type: 'tool/call', data: {} } as never)).toBeUndefined();
  });
});
