import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import ToolRuntime, { type ToolExecutionInput } from '@deepseek-ai/dsh-tools';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import * as guardPlugin from '../src/guard.js';
import * as publishPlugin from '../src/publish.js';
import { boundPubSlots, parseReceipt, publishArgv, PUBLISH_TOOL_NAME, stderrTail } from '../src/publish.js';

// ── stand-ins for `agentkeys-daemon --publish-once` ──────────────────────────
// The real daemon needs the spawn's chat env contract + a broker; the tool's
// job ends at handing it the helper's exact argv + the body on stdin and
// relaying the receipt (or the refusal). bash only — no python on the path.
const dir = mkdtempSync(join(tmpdir(), 'agentkeys-publish-'));
const argvFile = join(dir, 'argv.txt');
const bodyFile = join(dir, 'body.txt');
const okDaemon = join(dir, 'daemon-ok.sh');
const refusingDaemon = join(dir, 'daemon-refused.sh');
const slowDaemon = join(dir, 'daemon-slow.sh');
const noReceiptDaemon = join(dir, 'daemon-silent.sh');

function script(path: string, body: string): void {
  writeFileSync(path, `#!/usr/bin/env bash\n${body}\n`);
  chmodSync(path, 0o755);
}
script(
  okDaemon,
  `printf '%s\\n' "$@" > '${argvFile}'
cat > '${bodyFile}'
slot=$3; kind=$5; corr=\${7:-publish-1}
printf '{\\n  "outcome": "published",\\n  "slot": "%s",\\n  "channel_id": "chan-%s",\\n  "kind": "%s",\\n  "bytes": %s,\\n  "correlation": "%s",\\n  "body_ref": null\\n}\\n' "$slot" "$slot" "$kind" "$(wc -c < '${bodyFile}' | tr -d ' ')" "$corr"`,
);
script(
  refusingDaemon,
  `cat > /dev/null
echo 'WARN publish-once: cap-mint refused' >&2
echo 'Error: publish-once: cap mint refused: channel-pub:family-chat is not granted to this delegate' >&2
exit 1`,
);
script(slowDaemon, `cat > /dev/null\nsleep 5`);
script(noReceiptDaemon, `cat > /dev/null\necho 'nothing structured'`);
afterAll(() => rmSync(dir, { recursive: true, force: true }));

// ── the daemon's grant view (the guard's source) ─────────────────────────────
let server: Server;
let grantsUrl: string;
let granted: string[] = [];
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

let ctx: Context | undefined;
afterEach(async () => {
  if (ctx) await ctx.fiber.dispose();
  ctx = undefined;
});

async function boot(config: Record<string, unknown> = {}, withGuard = false): Promise<Context> {
  ctx = new Context();
  await ctx.plugin(SystemPrompt);
  await ctx.plugin(ToolRuntime);
  if (withGuard) await ctx.plugin(guardPlugin, { grantsUrl, ttlMs: 30 });
  await ctx.plugin(publishPlugin, { daemonCommand: okDaemon, timeoutMs: 10_000, ...config });
  return ctx;
}

let n = 0;
const call = (args: Record<string, unknown>): ToolExecutionInput =>
  ({
    callId: `call-${n++}`,
    name: PUBLISH_TOOL_NAME,
    arguments: args,
    signal: new AbortController().signal,
  }) as unknown as ToolExecutionInput;

describe('publish_to_slot — pure pieces', () => {
  it('argv mirrors the publish-to-slot helper, optional flags only when given', () => {
    expect(publishArgv({ slot: ' kitchen_screen ', kind: 'doc', body: 'x' })).toEqual([
      '--publish-once', '--publish-slot', 'kitchen_screen', '--publish-kind', 'doc',
    ]);
    expect(publishArgv({ slot: 'family_chat', body: 'hi', correlation: 'evt-1', content_type: 'text/plain' })).toEqual([
      '--publish-once', '--publish-slot', 'family_chat', '--publish-kind', 'text', '--publish-correlation', 'evt-1', '--publish-content-type', 'text/plain',
    ]);
  });
  it('lists the pub-capable bound slots plus opchat, and only opchat on a broken env', () => {
    const env = {
      AGENTKEYS_BOUND_CHANNELS: JSON.stringify([
        { slot: 'kitchen_screen', kind: 'display', direction: 'pub', channel_id: 'kitchen-display' },
        { slot: 'family_chat', kind: 'messaging', direction: 'duplex', channel_id: 'weixin-chef' },
        { slot: 'doorway_camera', kind: 'camera', direction: 'sub', channel_id: 'cam-1' },
      ]),
    };
    expect(boundPubSlots(env)).toEqual(['kitchen_screen', 'family_chat', 'opchat']);
    expect(boundPubSlots({})).toEqual(['opchat']);
    expect(boundPubSlots({ AGENTKEYS_BOUND_CHANNELS: '{not json' })).toEqual(['opchat']);
  });
  it('parses the daemon receipt and rejects anything else', () => {
    expect(parseReceipt('{\n "outcome": "published", "slot": "s", "channel_id": "c", "kind": "doc", "bytes": 12, "correlation": "k", "body_ref": null }')).toEqual({
      outcome: 'published', slot: 's', channel_id: 'c', kind: 'doc', bytes: 12, correlation: 'k',
    });
    expect(parseReceipt('nothing')).toBeNull();
    expect(parseReceipt('{"slot": 1}')).toBeNull();
  });
  it('keeps the last stderr lines on one line (the refusal reason)', () => {
    expect(stderrTail('a\n\nb\n c \n')).toBe('a | b | c');
  });
});

describe(`${PUBLISH_TOOL_NAME} — through the real dsh tool runtime`, () => {
  it('hands the daemon the helper’s argv + the body on stdin and relays the receipt', async () => {
    const c = await boot();
    const result = await c.tools.execute(call({ slot: 'kitchen_screen', kind: 'doc', body: '{"card":1}', correlation: 'evt-9' }));
    expect(result.isError).toBe(false);
    expect(result.value).toEqual({
      outcome: 'published', slot: 'kitchen_screen', channel_id: 'chan-kitchen_screen', kind: 'doc', bytes: 10, correlation: 'evt-9',
    });
    expect(readFileSync(argvFile, 'utf8').trim().split('\n')).toEqual([
      '--publish-once', '--publish-slot', 'kitchen_screen', '--publish-kind', 'doc', '--publish-correlation', 'evt-9',
    ]);
    expect(readFileSync(bodyFile, 'utf8')).toBe('{"card":1}');
    expect(JSON.stringify(result.content)).toContain('published: doc → kitchen_screen');
  });

  it('a refused feed reaches the model as an error carrying the daemon’s reason', async () => {
    const c = await boot({ daemonCommand: refusingDaemon });
    const result = await c.tools.execute(call({ slot: 'family_chat', body: 'hello' }));
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('channel-pub:family-chat is not granted');
  });

  it('an empty body, a silent daemon, and a hung daemon all fail loudly', async () => {
    const c = await boot({ daemonCommand: slowDaemon, timeoutMs: 300 });
    expect(JSON.stringify(await c.tools.execute(call({ slot: 'opchat', body: '   ' })))).toContain('body is empty');
    expect(JSON.stringify(await c.tools.execute(call({ slot: 'opchat', body: 'x' })))).toContain('did not finish within 300 ms');
    await c.fiber.dispose();
    const d = await boot({ daemonCommand: noReceiptDaemon });
    expect(JSON.stringify(await d.tools.execute(call({ slot: 'opchat', body: 'x' })))).toContain('no receipt on stdout');
  });

  it('under the guard: any channel-pub grant allows it, a sheet without one denies it', async () => {
    granted = ['tool:web', 'channel-pub:kitchen-display'];
    const allowed = await boot({}, true);
    expect((await allowed.tools.execute(call({ slot: 'kitchen_screen', kind: 'doc', body: '{"card":1}' }))).isError).toBe(false);
    await allowed.fiber.dispose();

    granted = ['tool:web', 'tool:schedule', 'channel-sub:kitchen-display'];
    const denied = await boot({}, true);
    const result = await denied.tools.execute(call({ slot: 'kitchen_screen', kind: 'doc', body: '{"card":1}' }));
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('channel-pub:<feed> grant');
  });
});
