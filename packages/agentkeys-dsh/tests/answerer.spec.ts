import { createServer, type Server } from 'node:http';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import { ApprovalService } from '@deepseek-ai/dsh-user-approval';
import type { ApprovalOutcome, ApprovalRequest } from '@deepseek-ai/dsh-user-approval';
import * as answererPlugin from '../src/answerer.js';
import { maybePropose, PROPOSE_THROTTLE_MS, proposeKey, ProposeThrottle } from '../src/answerer.js';
import { consumeApprovedCall } from '../src/grants.js';

// ── the daemon's grant view (`tool:web` only) ────────────────────────────────
let server: Server;
let grantsUrl: string;

// ── the daemon's proposal sink (`POST /v1/sandbox/self/propose`) ─────────────
// Records every ask; answers per `askMode` — the receipt, or the daemon's
// refusal (a cap-mint 403 relayed as 502 with the reason).
type Ask = { method: string; path: string; authorization: string; body: { text: string; key: string } };
let askServer: Server;
let askUrl: string;
let askMode: 'receipt' | 'refuse' = 'receipt';
const asks: Ask[] = [];

async function listen(s: Server): Promise<number> {
  await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
  const addr = s.address();
  if (addr === null || typeof addr === 'string') throw new Error('no addr');
  return addr.port;
}

beforeAll(async () => {
  server = createServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ services: ['tool:web'] }));
  });
  grantsUrl = `http://127.0.0.1:${await listen(server)}/grants`;

  askServer = createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk: Buffer) => {
      raw += chunk.toString('utf8');
    });
    req.on('end', () => {
      asks.push({
        method: req.method ?? '',
        path: req.url ?? '',
        authorization: String(req.headers.authorization ?? ''),
        body: JSON.parse(raw) as Ask['body'],
      });
      res.setHeader('content-type', 'application/json');
      if (askMode === 'refuse') {
        res.statusCode = 502;
        res.end(JSON.stringify({ error: 'propose: cap-mint: HTTP 403 service_not_in_scope proposal:app-chef' }));
        return;
      }
      res.end(
        JSON.stringify({ outcome: 'proposed', namespace: 'app-chef', key: 'grant-request-tool-code', kind: 'knowledge', content_hash: 'h', s3_key: 's' }),
      );
    });
  });
  askUrl = `http://127.0.0.1:${await listen(askServer)}/v1/sandbox/self/propose`;
});
afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await new Promise<void>((resolve) => askServer.close(() => resolve()));
});
afterEach(() => {
  asks.length = 0;
  askMode = 'receipt';
  vi.restoreAllMocks();
});

const waterfall = (ctx: Context, req: ApprovalRequest): Promise<ApprovalOutcome> =>
  (ctx as never as {
    waterfall: (name: string, req: ApprovalRequest, next: () => Promise<ApprovalOutcome>) => Promise<ApprovalOutcome>;
  }).waterfall('approval/request', req, async () => 'unavailable');

async function until(cond: () => boolean, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`condition not met within ${ms} ms`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

async function closedPortUrl(): Promise<string> {
  const probe = createServer();
  const port = await listen(probe);
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return `http://127.0.0.1:${port}/v1/sandbox/self/propose`;
}

describe('agentkeys answerer (waterfall dispatch)', () => {
  it('answers allowed-once for a granted class and records the ledger entry', async () => {
    const ctx = new Context();
    await ctx.plugin(ApprovalService);
    await ctx.plugin(answererPlugin, { grantsUrl, ttlMs: 30, proposeUrl: '' });
    const req = { agent: {} as never, toolName: 'web_fetch', callId: 'approve-1' } as unknown as ApprovalRequest;
    expect(await waterfall(ctx, req)).toBe('allowed-once');
    expect(consumeApprovedCall('approve-1')).toBe(true);
    expect(consumeApprovedCall('approve-1')).toBe(false);
  });

  it('rejects an ungranted class', async () => {
    const ctx = new Context();
    await ctx.plugin(ApprovalService);
    await ctx.plugin(answererPlugin, { grantsUrl, ttlMs: 30, proposeUrl: '' });
    const req = { agent: {} as never, toolName: 'bash', callId: 'approve-2' } as unknown as ApprovalRequest;
    expect(await waterfall(ctx, req)).toBe('rejected');
    expect(consumeApprovedCall('approve-2')).toBe(false);
  });

  it('an ungranted deny files the runtime ask at the daemon; an empty proposeUrl disables it', async () => {
    const ctx = new Context();
    await ctx.plugin(ApprovalService);
    await ctx.plugin(answererPlugin, { grantsUrl, ttlMs: 30, proposeUrl: askUrl, bridgeToken: 'sbt1_test' });
    const req = { agent: {} as never, toolName: 'bash', callId: 'approve-3' } as unknown as ApprovalRequest;
    expect(await waterfall(ctx, req)).toBe('rejected');
    await until(() => asks.length === 1, 2_000);
    expect(asks[0].method).toBe('POST');
    expect(asks[0].path).toBe('/v1/sandbox/self/propose');
    expect(asks[0].authorization).toBe('Bearer sbt1_test');
    expect(asks[0].body.key).toBe('grant-request-tool-code');
    expect(asks[0].body.text).toContain('# Grant request: tool:code');
    expect(asks[0].body.text).toContain('"bash"');

    // A granted class never asks.
    const granted = { agent: {} as never, toolName: 'web_search', callId: 'approve-4' } as unknown as ApprovalRequest;
    expect(await waterfall(ctx, granted)).toBe('allowed-once');

    // Disabled: the deny stands alone, nothing is filed.
    const off = new Context();
    await off.plugin(ApprovalService);
    await off.plugin(answererPlugin, { grantsUrl, ttlMs: 30, proposeUrl: '' });
    expect(await waterfall(off, { agent: {} as never, toolName: 'schedule_create', callId: 'approve-5' } as unknown as ApprovalRequest)).toBe('rejected');
    await new Promise((r) => setTimeout(r, 100));
    expect(asks).toHaveLength(1);
  });
});

describe('the runtime ask (#573 inbox through the daemon self surface)', () => {
  it('files one ask per class per window, with the bridge bearer and a stable key', async () => {
    const throttle = new ProposeThrottle();
    const cfg = { proposeUrl: askUrl, bridgeToken: 'sbt1_test' };
    const t0 = 1_000_000;
    expect(await maybePropose(cfg, 'tool:code', 'bash', throttle, t0)).toBe('filed');
    expect(asks).toHaveLength(1);
    expect(asks[0].authorization).toBe('Bearer sbt1_test');
    expect(asks[0].body).toEqual({ text: expect.stringContaining('# Grant request: tool:code'), key: 'grant-request-tool-code' });
    // The same class inside the window is throttled — the owner already holds the ask.
    expect(await maybePropose(cfg, 'tool:code', 'terminal_open', throttle, t0 + 60_000)).toBe('throttled');
    expect(asks).toHaveLength(1);
    // Another class is its own ask; the same class asks again once the window elapsed.
    expect(await maybePropose(cfg, 'tool:schedule', 'schedule_create', throttle, t0 + 60_000)).toBe('filed');
    expect(await maybePropose(cfg, 'tool:code', 'terminal_open', throttle, t0 + PROPOSE_THROTTLE_MS)).toBe('filed');
    expect(asks.map((a) => a.body.key)).toEqual(['grant-request-tool-code', 'grant-request-tool-schedule', 'grant-request-tool-code']);
    expect(proposeKey('tool:web')).toBe('grant-request-tool-web');
  });

  it('a refused or unreachable daemon is LOUD and releases the throttle so the next deny retries', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const throttle = new ProposeThrottle();
    askMode = 'refuse';
    expect(await maybePropose({ proposeUrl: askUrl }, 'tool:web', 'web_search', throttle, 5_000_000)).toBe('failed');
    expect(error).toHaveBeenCalledTimes(1);
    const refused = String(error.mock.calls[0][0]);
    expect(refused).toContain('runtime ask for tool:web');
    expect(refused).toContain('did NOT reach the owner');
    expect(refused).toContain('HTTP 502');
    expect(refused).toContain('service_not_in_scope proposal:app-chef');
    // Released: the very next deny retries instead of waiting out the window.
    askMode = 'receipt';
    expect(await maybePropose({ proposeUrl: askUrl }, 'tool:web', 'web_search', throttle, 5_000_001)).toBe('filed');
    expect(asks).toHaveLength(2);

    // Nothing listening (the daemon is down): the same loud line, the reason from the transport.
    const closed = await closedPortUrl();
    expect(await maybePropose({ proposeUrl: closed }, 'tool:code', 'bash', throttle, 6_000_000)).toBe('failed');
    expect(error).toHaveBeenCalledTimes(2);
    expect(String(error.mock.calls[1][0])).toContain('did NOT reach the owner');
    expect(String(error.mock.calls[1][0])).toContain(closed);
    expect(await maybePropose({ proposeUrl: closed }, 'tool:code', 'bash', throttle, 6_000_001)).toBe('failed');
    expect(error).toHaveBeenCalledTimes(3);
  });
});
