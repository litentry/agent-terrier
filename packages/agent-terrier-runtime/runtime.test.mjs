import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { chmod, lstat, mkdtemp, readdir, realpath, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { listener, freePort, stop, environment, launch, ready, chat } from './test-support.mjs';

test('runtime persists turns, rejects wrong proofs and denies ungranted tool effects', { timeout: 30_000 }, async () => {
  const state = await realpath(await mkdtemp(path.join(os.tmpdir(), 'terrier-runtime-test-')));
  const bridgeToken = randomBytes(32).toString('hex');
  const modelToken = randomBytes(32).toString('hex');
  const modelRequests = [];
  let effects = 0;
  let granted = false;
  const daemon = await listener(async (request, response) => {
    assert.equal(request.headers.authorization, `Bearer ${bridgeToken}`);
    response.setHeader('content-type', 'application/json');
    if (request.url === '/v1/sandbox/self/actions') {
      response.end(JSON.stringify({ actions: [{ name: 'record_value', description: 'Record a synthetic value.',
        route: '/record', requires_grant_prefix: 'record:', parameters: [], receipt_fields: ['recorded'] }] }));
    } else if (request.url === '/v1/sandbox/self/grants') {
      response.end(JSON.stringify({ services: granted ? ['record:example'] : [] }));
    } else if (request.url === '/record' && request.method === 'POST') {
      effects++;
      response.end(JSON.stringify({ recorded: true }));
    } else {
      response.writeHead(404); response.end('{}');
    }
  });
  const model = await listener(async (request, response) => {
    assert.equal(request.url, '/v1/chat/completions');
    assert.equal(request.headers.authorization, `Bearer ${modelToken}`);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    assert.equal(body.model, 'local-test-model');
    modelRequests.push(body);
    const message = body.messages.at(-1);
    const invoke = message.role === 'user' && message.content === 'invoke action';
    const delta = invoke ? { tool_calls: [{ index: 0, id: `call_${modelRequests.length}`, type: 'function',
      function: { name: 'record_value', arguments: '{}' } }] } : { content: 'Local fixture reply.' };
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    for (const [payload, finish] of [[{ role: 'assistant' }, null], [delta, null], [{}, invoke ? 'tool_calls' : 'stop']]) {
      response.write(`data: ${JSON.stringify({ id: 'local-completion', object: 'chat.completion.chunk', model: body.model,
        choices: [{ index: 0, delta: payload, finish_reason: finish }] })}\n\n`);
    }
    response.end('data: [DONE]\n\n');
  });
  const values = environment(state, model.origin, modelToken, bridgeToken);
  const port = await freePort();
  let runtime;
  try {
    runtime = launch(state, port, daemon.origin, values);
    await ready(runtime);
    assert.equal((await chat(port, 'wrong-proof', 'must not reach model')).status, 401);
    assert.equal(modelRequests.length, 0);
    const marker = `persist-${randomBytes(6).toString('hex')}`;
    const first = await chat(port, bridgeToken, marker);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.ok(JSON.stringify(first.body).includes('Local fixture reply.'));
    const denied = await chat(port, bridgeToken, 'invoke action');
    assert.equal(denied.status, 200, JSON.stringify(denied.body));
    assert.equal(effects, 0);
    const deniedResult = modelRequests.at(-1).messages.at(-1);
    assert.equal(deniedResult.role, 'tool');
    assert.match(JSON.stringify(deniedResult.content), /needs a record:.*grant and this delegate holds none/);
    const unauthorized = await fetch(`http://127.0.0.1:${port}/v1/context/apply`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ persona: 'unauthorized' }) });
    assert.equal(unauthorized.status, 401);
    await unauthorized.body.cancel();
    assert.deepEqual(await readdir(path.join(state, 'work')), []);
    await stop(runtime.child);
    granted = true;
    runtime = launch(state, port, daemon.origin, values);
    await ready(runtime);
    const resumed = await chat(port, bridgeToken, 'invoke action');
    assert.equal(resumed.status, 200, JSON.stringify(resumed.body));
    assert.equal(effects, 1, 'The same advertised action must execute with its grant');
    assert.ok(JSON.stringify(modelRequests.at(-1).messages).includes(marker), 'A restarted runtime must restore prior conversation');
    assert.equal((await lstat(path.join(state, 'state'))).mode & 0o077, 0);
    assert.equal(runtime.output().includes(modelToken), false);
    assert.equal(runtime.output().includes(bridgeToken), false);
  } finally {
    if (runtime) await stop(runtime.child);
    await Promise.all([daemon.server, model.server].map((server) => new Promise((resolve) => {
      server.close(resolve); server.closeAllConnections();
    })));
    await rm(state, { recursive: true, force: true });
  }
});

test('runtime refuses missing model proof, external endpoints, loose directories and linked ancestors', { timeout: 15_000 }, async () => {
  const state = await realpath(await mkdtemp(path.join(os.tmpdir(), 'terrier-runtime-negative-')));
  try {
    const port = await freePort();
    const defaults = environment(state, 'http://127.0.0.1:1', randomBytes(32).toString('hex'), randomBytes(32).toString('hex'));
    const cases = [
      { values: { ...defaults, AGENTKEYS_MODEL_API_KEY: '' }, message: /Missing or invalid AGENTKEYS_MODEL_API_KEY/ },
      { values: { ...defaults, AGENTKEYS_MODEL_BASE_URL: 'https://example.invalid/v1' }, message: /local HTTP/ },
    ];
    for (const scenario of cases) {
      const runtime = launch(state, port, 'http://127.0.0.1:1', scenario.values);
      const [code] = await once(runtime.child, 'exit');
      assert.equal(code, 1); assert.match(runtime.output(), scenario.message);
      assert.deepEqual(await readdir(state), []);
    }
    await symlink(state, path.join(state, 'alias'));
    const linked = launch(state, port, 'http://127.0.0.1:1', defaults, path.join(state, 'alias', 'must-not-exist'));
    assert.equal((await once(linked.child, 'exit'))[0], 1);
    assert.match(linked.output(), /must not contain links/);
    assert.deepEqual(await readdir(state), ['alias']);
    await chmod(state, 0o755);
    const loose = launch(state, port, 'http://127.0.0.1:1', defaults, state);
    assert.equal((await once(loose.child, 'exit'))[0], 1);
    assert.match(loose.output(), /private and owned/);
  } finally {
    await rm(state, { recursive: true, force: true });
  }
});
