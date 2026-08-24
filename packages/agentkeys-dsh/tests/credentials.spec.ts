import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import { credentialRef } from '@deepseek-ai/dsh-credentials';
import AgentKeysCredentialProvider from '../src/credentials.js';

let server: Server;
let credentialUrl: string;
const seen: Array<{ service: string; auth: string | undefined }> = [];
let mode: 'ok' | 'denied' | 'envelope' = 'ok';

beforeAll(async () => {
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const body = JSON.parse(raw) as { service: string };
      seen.push({ service: body.service, auth: req.headers.authorization });
      res.setHeader('content-type', 'application/json');
      if (mode === 'denied') {
        res.statusCode = 403;
        res.end(JSON.stringify({ error: 'data plane refused: service_not_in_scope' }));
      } else if (mode === 'envelope') {
        res.statusCode = 501;
        res.end(JSON.stringify({ error: 'cred_envelope_requires_kek_release' }));
      } else {
        res.end(
          JSON.stringify({
            ok: true,
            service: body.service,
            value_b64: Buffer.from('sk-live-secret').toString('base64'),
            source: 'agentkeys-vault',
          }),
        );
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no addr');
  credentialUrl = `http://127.0.0.1:${addr.port}/v1/sandbox/self/credential`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

async function provider() {
  const ctx = new Context();
  await ctx.plugin(AgentKeysCredentialProvider, {
    credentialUrl,
    bridgeToken: 'brtok',
    refs: { OPENROUTER_API_KEY: 'openrouter' },
  });
  return ctx.credentials;
}

describe('AgentKeys credential provider (dsh seam)', () => {
  it('resolves a mapped ref through the daemon, per operation, with the bearer', async () => {
    mode = 'ok';
    const creds = await provider();
    const resolved = await creds.resolve(credentialRef('OPENROUTER_API_KEY'));
    expect(resolved).toEqual({ value: 'sk-live-secret', source: 'agentkeys-vault' });
    expect(seen.at(-1)).toEqual({ service: 'openrouter', auth: 'Bearer brtok' });
    await creds.resolve(credentialRef('OPENROUTER_API_KEY'));
    expect(seen.length).toBeGreaterThanOrEqual(2); // per-operation, no caching
  });

  it('unmapped refs are unconfigured; denied/envelope resolve as absent', async () => {
    const creds = await provider();
    expect(await creds.resolve(credentialRef('UNKNOWN_KEY'))).toBeUndefined();
    expect((await creds.describe(credentialRef('UNKNOWN_KEY'))).configured).toBe(false);
    expect((await creds.describe(credentialRef('OPENROUTER_API_KEY'))).configured).toBe(true);
    mode = 'denied';
    expect(await creds.resolve(credentialRef('OPENROUTER_API_KEY'))).toBeUndefined();
    mode = 'envelope';
    expect(await creds.resolve(credentialRef('OPENROUTER_API_KEY'))).toBeUndefined();
    mode = 'ok';
  });

  it('an unmapped ref falls through to the process env (#631: the gate ARK_API_KEY transport)', async () => {
    const name = 'AGENTKEYS_TEST_ENV_FALLTHROUGH_631';
    process.env[name] = 'env-held-key';
    try {
      const creds = await provider();
      const before = seen.length;
      expect(await creds.resolve(credentialRef(name))).toEqual({ value: 'env-held-key', source: 'launch-env' });
      expect((await creds.describe(credentialRef(name))).configured).toBe(true);
      expect(seen.length).toBe(before); // env fallthrough never touches the daemon
    } finally {
      delete process.env[name];
    }
    const creds = await provider();
    expect(await creds.resolve(credentialRef(name))).toBeUndefined();
  });

  it('rejects delegate-side writes', async () => {
    const creds = await provider();
    await expect(creds.set(credentialRef('OPENROUTER_API_KEY'), 'x')).rejects.toThrow(/master ceremony/);
    await expect(creds.unset(credentialRef('OPENROUTER_API_KEY'))).rejects.toThrow(/master ceremony/);
  });
});
