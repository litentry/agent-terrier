import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import ToolRuntime, { type ToolExecutionInput } from '@deepseek-ai/dsh-tools';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import * as guardPlugin from '../src/guard.js';
import * as proposePlugin from '../src/propose.js';
import { defaultProposalNamespace, parseProposalReceipt, proposeArgv, PROPOSE_TOOL_NAME } from '../src/propose.js';

// ── stand-ins for `agentkeys-daemon --propose-once` ──────────────────────────
// The real daemon needs the spawn's chat env contract + a broker; the tool's
// job ends at handing it the helper's exact argv + the text on stdin and
// relaying the receipt (or the refusal). bash only — no python on the path.
const dir = mkdtempSync(join(tmpdir(), 'agentkeys-propose-'));
const argvFile = join(dir, 'argv.txt');
const bodyFile = join(dir, 'body.txt');
const okDaemon = join(dir, 'daemon-ok.sh');
const refusingDaemon = join(dir, 'daemon-refused.sh');

function script(path: string, body: string): void {
  writeFileSync(path, `#!/usr/bin/env bash\n${body}\n`);
  chmodSync(path, 0o755);
}
script(
  okDaemon,
  `printf '%s\\n' "$@" > '${argvFile}'
cat > '${bodyFile}'
ns=app-chef; key=proposal-1; kind=knowledge
while [ $# -gt 0 ]; do case "$1" in --propose-ns) ns=$2; shift 2;; --propose-key) key=$2; shift 2;; --propose-kind) kind=$2; shift 2;; *) shift;; esac; done
printf '{\\n  "outcome": "proposed",\\n  "namespace": "%s",\\n  "key": "%s",\\n  "kind": "%s",\\n  "content_hash": "abc123",\\n  "s3_key": "bots/o/inbox/d/%s"\\n}\\n' "$ns" "$key" "$kind" "$key"`,
);
script(
  refusingDaemon,
  `cat > /dev/null
echo 'Error: propose-once: cap mint refused: proposal:family is not granted to this delegate (service_not_in_scope)' >&2
exit 1`,
);
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
  await ctx.plugin(proposePlugin, { daemonCommand: okDaemon, timeoutMs: 10_000, ...config });
  return ctx;
}

let n = 0;
const call = (args: Record<string, unknown>): ToolExecutionInput =>
  ({
    callId: `call-${n++}`,
    name: PROPOSE_TOOL_NAME,
    arguments: args,
    signal: new AbortController().signal,
  }) as unknown as ToolExecutionInput;

describe('propose_to_owner — pure pieces', () => {
  it('argv mirrors the propose-to-owner helper, optional flags only when given', () => {
    expect(proposeArgv({ text: 'x' })).toEqual(['--propose-once']);
    expect(proposeArgv({ text: 'x', namespace: ' family ', key: 'pantry-habits', kind: 'knowledge' })).toEqual([
      '--propose-once', '--propose-ns', 'family', '--propose-key', 'pantry-habits', '--propose-kind', 'knowledge',
    ]);
  });
  it('the default namespace is the first of the spawn env list', () => {
    expect(defaultProposalNamespace({ AGENTKEYS_MEMORY_NAMESPACES: 'app-chef,family,personal' })).toBe('app-chef');
    expect(defaultProposalNamespace({})).toBe('');
  });
  it('parses the daemon receipt and rejects anything else', () => {
    expect(parseProposalReceipt('{\n "outcome": "proposed", "namespace": "family", "key": "k", "kind": "knowledge", "content_hash": "h", "s3_key": "s" }')).toEqual({
      outcome: 'proposed', namespace: 'family', key: 'k', kind: 'knowledge', content_hash: 'h',
    });
    expect(parseProposalReceipt('nothing')).toBeNull();
    expect(parseProposalReceipt('{"namespace": 1}')).toBeNull();
  });
});

describe(`${PROPOSE_TOOL_NAME} — through the real dsh tool runtime`, () => {
  it('hands the daemon the helper’s argv + the text on stdin and relays the receipt', async () => {
    const c = await boot();
    const result = await c.tools.execute(call({ text: 'The family avoids gluten.', namespace: 'family', key: 'food-rules' }));
    expect(result.isError).toBe(false);
    expect(result.value).toEqual({ outcome: 'proposed', namespace: 'family', key: 'food-rules', kind: 'knowledge', content_hash: 'abc123' });
    expect(readFileSync(argvFile, 'utf8').trim().split('\n')).toEqual(['--propose-once', '--propose-ns', 'family', '--propose-key', 'food-rules']);
    expect(readFileSync(bodyFile, 'utf8')).toBe('The family avoids gluten.');
    expect(JSON.stringify(result.content)).toContain('proposed: knowledge → family/food-rules');
  });

  it('a refused namespace reaches the model as an error carrying the daemon’s reason', async () => {
    const c = await boot({ daemonCommand: refusingDaemon });
    const result = await c.tools.execute(call({ text: 'hello', namespace: 'family' }));
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('proposal:family is not granted');
  });

  it('an empty text fails loudly', async () => {
    const c = await boot();
    expect(JSON.stringify(await c.tools.execute(call({ text: '   ' })))).toContain('text is empty');
  });

  it('under the guard: any proposal grant allows it, a sheet without one denies it', async () => {
    granted = ['tool:web', 'proposal:app-chef'];
    const allowed = await boot({}, true);
    expect((await allowed.tools.execute(call({ text: 'keep this' }))).isError).toBe(false);
    await allowed.fiber.dispose();

    granted = ['tool:web', 'knowledge:family', 'channel-pub:kitchen-display'];
    const denied = await boot({}, true);
    const result = await denied.tools.execute(call({ text: 'keep this' }));
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain('proposal:<ns> grant');
  });
});
