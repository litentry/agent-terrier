import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import ToolRuntime, { type ToolExecutionInput } from '@deepseek-ai/dsh-tools';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import * as guardPlugin from '../src/guard.js';
import * as actionsPlugin from '../src/actions.js';
import { callBody, missingRequired, parseAdvertised, toolParameters, toReceipt, whenRegistered } from '../src/actions.js';
import { DaemonClient, DaemonError, reasonOf } from '../src/daemon-client.js';
import { advertisedGrantPrefix, PROPOSE_ACTION, PUBLISH_ACTION } from '../src/mapping.js';

// ── the shared contract (the daemon's Rust test reads the SAME document) ─────
const FIXTURE = new URL('../../../e2e/fixtures/bridge-protocol/actions_contract.json', import.meta.url);
type Fixture = {
  advertised: { pub_slots: string[]; own_namespace: string; response: { actions: unknown[] } };
  publish_request: Record<string, string>;
  propose_request: Record<string, string>;
  publish_receipt: Record<string, unknown>;
  propose_receipt: Record<string, unknown>;
};
const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as Fixture;

// ── a fake daemon: the advertisement, the grant view, the two verb sinks ─────
type Hit = { method: string; path: string; authorization: string; body: Record<string, unknown> };
const hits: Hit[] = [];
let granted: string[] = [];
let advertiseMode: 'fixture' | 'not-a-sandbox' | 'garbage' = 'fixture';
let verbMode: 'receipt' | 'refuse' = 'receipt';
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c: Buffer) => {
      raw += c.toString('utf8');
    });
    req.on('end', () => {
      const path = req.url ?? '';
      const json = (code: number, body: unknown) => {
        res.statusCode = code;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(body));
      };
      if (req.method === 'GET' && path === '/v1/sandbox/self/grants') return json(200, { services: granted });
      if (req.method === 'GET' && path === '/v1/sandbox/self/actions') {
        if (advertiseMode === 'not-a-sandbox') return json(404, { error: 'not a sandbox delegate daemon (no AGENTKEYS_ACTOR_OMNI identity)' });
        if (advertiseMode === 'garbage') return json(200, { actions: [{ name: 'Bad Name' }] });
        return json(200, fixture.advertised.response);
      }
      if (req.method === 'POST' && (path === '/v1/sandbox/self/publish' || path === '/v1/sandbox/self/propose')) {
        hits.push({ method: 'POST', path, authorization: String(req.headers.authorization ?? ''), body: JSON.parse(raw || '{}') as Record<string, unknown> });
        if (verbMode === 'refuse') return json(502, { error: 'publish: cap-mint: HTTP 403 service_not_in_scope channel-pub:family-chat is not granted to this delegate' });
        return json(200, path.endsWith('/publish') ? fixture.publish_receipt : fixture.propose_receipt);
      }
      json(404, { error: `unexpected ${req.method} ${path}` });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no addr');
  baseUrl = `http://127.0.0.1:${addr.port}`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

let ctx: Context | undefined;
afterEach(async () => {
  if (ctx) await ctx.fiber.dispose();
  ctx = undefined;
  hits.length = 0;
  advertiseMode = 'fixture';
  verbMode = 'receipt';
  granted = [];
});

async function boot(withGuard = true): Promise<Context> {
  ctx = new Context();
  await ctx.plugin(SystemPrompt);
  await ctx.plugin(ToolRuntime);
  if (withGuard) await ctx.plugin(guardPlugin, { grantsUrl: `${baseUrl}/v1/sandbox/self/grants`, ttlMs: 30 });
  await ctx.plugin(actionsPlugin, { daemonUrl: baseUrl, bridgeToken: 'sbt1_test', timeoutMs: 10_000, retryMs: 20, maxWaitMs: 2_000 });
  await whenRegistered();
  return ctx;
}

let n = 0;
const call = (name: string, args: Record<string, unknown>): ToolExecutionInput =>
  ({ callId: `call-${n++}`, name, arguments: args, signal: new AbortController().signal }) as unknown as ToolExecutionInput;

const publishSpec = () => parseAdvertised(fixture.advertised.response)[0];
const proposeSpec = () => parseAdvertised(fixture.advertised.response)[1];

describe('the advertisement (pure)', () => {
  it('parses the shared fixture into the two verbs with their grant families and parameters', () => {
    const actions = parseAdvertised(fixture.advertised.response);
    expect(actions.map((a) => a.name)).toEqual([PUBLISH_ACTION, PROPOSE_ACTION]);
    expect(actions[0].route).toBe('/v1/sandbox/self/publish');
    expect(actions[0].requires_grant_prefix).toBe('channel-pub:');
    expect(actions[1].requires_grant_prefix).toBe('proposal:');
    const params = toolParameters(actions[0]);
    expect(params.slot).toEqual({ type: 'string', required: true, description: expect.stringContaining('kitchen_screen, family_chat, opchat') });
    expect(params.kind.enum).toEqual(['text', 'image', 'audio-clip', 'frame', 'command', 'doc']);
    expect(params.body.required).toBe(true);
    expect(params.correlation.required).toBeUndefined();
    expect(toolParameters(actions[1]).kind.enum).toEqual(['knowledge', 'skill']);
  });

  it('refuses a malformed advertisement wholesale', () => {
    expect(() => parseAdvertised({ actions: [{ name: 'Bad Name' }] })).toThrow(/not a tool name/);
    expect(() => parseAdvertised({ actions: [{ name: 'ok', description: 'd', route: 'nope', requires_grant_prefix: 'x:', parameters: [] }] })).toThrow(/daemon path/);
    expect(() => parseAdvertised({ actions: [{ name: 'ok', description: 'd', route: '/v1/x', requires_grant_prefix: 'x', parameters: [] }] })).toThrow(/grant family/);
    expect(() => parseAdvertised({})).toThrow(/actions array/);
  });

  it('builds the call body from the declared parameters only, dropping blank optionals', () => {
    expect(callBody(publishSpec(), { ...fixture.publish_request, content_type: '  ', made_up: 'x' })).toEqual(fixture.publish_request);
    expect(callBody(proposeSpec(), fixture.propose_request)).toEqual(fixture.propose_request);
    expect(missingRequired(publishSpec(), { slot: 'kitchen_screen', body: '' })).toEqual(['body']);
    expect(missingRequired(proposeSpec(), { text: 'x' })).toEqual([]);
  });

  it('normalizes a reply into a receipt that always renders a summary', () => {
    expect(toReceipt(publishSpec(), fixture.publish_receipt)).toEqual(fixture.publish_receipt);
    expect(toReceipt(publishSpec(), { outcome: 'published' })).toEqual({ outcome: 'published', summary: 'published: publish_to_slot' });
    expect(toReceipt(publishSpec(), 'garbage')).toEqual({ outcome: 'done', summary: 'done: publish_to_slot' });
  });

  it('the daemon client turns a refusal into the daemon’s own reason', async () => {
    const client = new DaemonClient({ baseUrl, bridgeToken: 'sbt1_test' });
    expect(client.url('/v1/x')).toBe(`${baseUrl}/v1/x`);
    expect(client.url('http://elsewhere/v1/y')).toBe('http://elsewhere/v1/y');
    expect(client.headers(true)).toEqual({ 'content-type': 'application/json', authorization: 'Bearer sbt1_test' });
    verbMode = 'refuse';
    await expect(client.postJson('/v1/sandbox/self/publish', { slot: 's', body: 'b' })).rejects.toMatchObject({ status: 502, reason: expect.stringContaining('service_not_in_scope') });
    expect(reasonOf('{"error":"e"}')).toBe('e');
    expect(reasonOf('plain text')).toBe('plain text');
    await expect(client.getJson('/nowhere')).rejects.toBeInstanceOf(DaemonError);
  });
});

describe(`${PUBLISH_ACTION} + ${PROPOSE_ACTION} — through the real dsh tool runtime`, () => {
  it('registers the advertised verbs and runs a publish as ONE bearer-gated POST with the contract body', async () => {
    granted = ['channel-pub:kitchen-display', 'proposal:app-chef'];
    const c = await boot();
    expect(advertisedGrantPrefix(PUBLISH_ACTION)).toBe('channel-pub:');
    const result = await c.tools.execute(call(PUBLISH_ACTION, fixture.publish_request));
    expect(result.isError).toBe(false);
    expect(result.value).toEqual(fixture.publish_receipt);
    expect(JSON.stringify(result.content)).toContain(String(fixture.publish_receipt.summary));
    expect(hits).toHaveLength(1);
    expect(hits[0]).toEqual({ method: 'POST', path: '/v1/sandbox/self/publish', authorization: 'Bearer sbt1_test', body: fixture.publish_request });
  });

  it('runs a proposal the same way', async () => {
    granted = ['proposal:family'];
    const c = await boot();
    const result = await c.tools.execute(call(PROPOSE_ACTION, fixture.propose_request));
    expect(result.isError).toBe(false);
    expect(result.value).toEqual(fixture.propose_receipt);
    expect(hits[0]).toEqual({ method: 'POST', path: '/v1/sandbox/self/propose', authorization: 'Bearer sbt1_test', body: fixture.propose_request });
  });

  it('a refused feed reaches the model as an error carrying the daemon’s reason', async () => {
    granted = ['channel-pub:kitchen-display'];
    verbMode = 'refuse';
    const c = await boot();
    const result = await c.tools.execute(call(PUBLISH_ACTION, { slot: 'family_chat', body: 'hello' }));
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('channel-pub:family-chat is not granted');
    expect(JSON.stringify(result)).toContain('daemon HTTP 502');
  });

  it('a missing required argument never reaches the daemon', async () => {
    granted = ['channel-pub:kitchen-display'];
    const c = await boot();
    const result = await c.tools.execute(call(PUBLISH_ACTION, { slot: 'kitchen_screen', body: '   ' }));
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('body is required');
    expect(hits).toHaveLength(0);
  });

  it('the guard denies a verb whose grant family the delegate does not hold — nothing is posted', async () => {
    granted = ['tool:web', 'channel-sub:kitchen-display'];
    const c = await boot();
    const result = await c.tools.execute(call(PUBLISH_ACTION, fixture.publish_request));
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('channel-pub:<…> grant');
    expect(hits).toHaveLength(0);
  });

  it('a daemon that is not a sandbox delegate advertises nothing — no verbs, no error', async () => {
    advertiseMode = 'not-a-sandbox';
    const c = await boot(false);
    const result = await c.tools.execute(call(PUBLISH_ACTION, fixture.publish_request));
    expect(result.isError).toBe(true);
    expect(hits).toHaveLength(0);
  });
});
