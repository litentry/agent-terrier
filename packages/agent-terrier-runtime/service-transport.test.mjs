import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import http from 'node:http';
import { Duplex } from 'node:stream';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createTransportServer, validateTargets } from './service-transport.mjs';
import { listener, stop } from './test-support.mjs';

test('service transport forwards concurrent authenticated streams and denies target escape and redirects', { timeout: 10_000 }, async () => {
  const proof = randomBytes(32).toString('hex');
  let requests = 0;
  let unexpected = 0;
  const forbidden = await listener((_request, response) => { unexpected++; response.end('must not be reached'); });
  const source = await listener(async (request, response) => {
    requests++;
    assert.equal(request.headers.authorization, `Bearer ${proof}`);
    if (request.url === '/v1/redirect') { response.writeHead(307, { location: forbidden.origin }); response.end(); return; }
    assert.equal(request.url, '/v1/echo');
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.write('begin:');
    response.end(Buffer.concat(chunks));
  });
  const child = spawn(process.execPath, [fileURLToPath(new URL('./service-transport.mjs', import.meta.url)),
    'client', '--services', '["model","unconfigured"]'], { env: {}, stdio: ['pipe', 'pipe', 'pipe'] });
  const transport = createTransportServer({ model: source.origin + '/v1' });
  transport.attach(Duplex.from({ readable: child.stdout, writable: child.stdin }));
  let diagnostics = '';
  child.stderr.on('data', (chunk) => { diagnostics += chunk; });
  try {
    const readiness = await new Promise((resolve, reject) => {
      let buffer = '';
      child.once('exit', () => reject(new Error('Transport client exited')));
      child.stderr.on('data', (chunk) => {
        buffer += chunk;
        if (buffer.includes('\n')) {
          try { resolve(JSON.parse(buffer)); } catch { reject(new Error('Invalid readiness')); }
        }
      });
    });
    const endpoint = `http://127.0.0.1:${readiness.ports.model}/v1`;
    await Promise.all(Array.from({ length: 8 }, async (_, index) => {
      const response = await fetch(endpoint + '/echo', { method: 'POST', headers: { authorization: `Bearer ${proof}` },
        body: String(index), redirect: 'error', signal: AbortSignal.timeout(3_000) });
      assert.equal(response.status, 200);
      assert.equal(await response.text(), `begin:${index}`);
    }));
    const baseline = requests;
    const unconfigured = await fetch(`http://127.0.0.1:${readiness.ports.unconfigured}/v1/echo`, {
      headers: { authorization: `Bearer ${proof}` }, redirect: 'error' });
    assert.equal(unconfigured.status, 403); await unconfigured.body.cancel();
    assert.equal(requests, baseline);
    const escapeStatus = await new Promise((resolve, reject) => {
      const request = http.request(endpoint, { method: 'POST', path: '/v1/%2e%2e/admin', headers: { authorization: `Bearer ${proof}` } }, (response) => {
        response.resume(); response.on('end', () => resolve(response.statusCode));
      });
      request.on('error', reject); request.end('must not escape');
    });
    assert.equal(escapeStatus, 400);
    assert.equal(requests, baseline);
    const redirect = await fetch(endpoint + '/redirect', { headers: { authorization: `Bearer ${proof}` }, redirect: 'error' });
    assert.equal(redirect.status, 502); await redirect.body.cancel();
    assert.equal(unexpected, 0);
    const oversized = await fetch(endpoint + '/echo', { method: 'POST', headers: { authorization: `Bearer ${proof}` },
      body: 'x'.repeat(1024 * 1024 + 1), redirect: 'error' });
    assert.equal(oversized.status, 413); await oversized.body.cancel();
    assert.equal(requests, baseline + 1);
    transport.close();
    const exited = await once(child, 'exit');
    assert.equal(exited[0], 0);
  } catch (error) {
    throw new Error(`Transport client diagnostics: ${diagnostics}`, { cause: error });
  } finally {
    transport.close();
    await stop(child);
    await Promise.all([source.server, forbidden.server].map((server) => new Promise((resolve) => {
      server.close(resolve); server.closeAllConnections();
    })));
  }
});

test('service transport only accepts explicitly named loopback targets', () => {
  for (const values of [{}, { model: 'https://example.invalid/v1' }, { model: 'http://127.0.0.1/v1?token=synthetic' },
    { model: 'http://user:synthetic@127.0.0.1/v1' }, { model: 'http://192.0.2.1/v1' }, { '../escape': 'http://127.0.0.1' }]) {
    assert.throws(() => validateTargets(values));
  }
  assert.equal(validateTargets({ model: 'http://127.0.0.1:1234/v1' }).size, 1);
});
