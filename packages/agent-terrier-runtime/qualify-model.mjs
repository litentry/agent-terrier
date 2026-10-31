import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { MODEL_ID } from '@agentkeys/dsh-suite/runtime-config';
import { listener, freePort, stop, environment, launch, ready, chat } from './test-support.mjs';

const { values } = parseArgs({ options: { 'model-endpoint': { type: 'string' } } });
const endpoint = new URL(values['model-endpoint']);
assert.equal(endpoint.protocol, 'http:');
assert.ok(['127.0.0.1', 'host.docker.internal'].includes(endpoint.hostname));
assert.equal(endpoint.pathname, '/v1');
const recipe = JSON.parse(await readFile(new URL('../../presets/local-models.json', import.meta.url), 'utf8'));
const state = await realpath(await mkdtemp(path.join(os.tmpdir(), 'terrier-runtime-real-model-')));
const bridgeToken = randomBytes(32).toString('hex');
const modelToken = randomBytes(32).toString('hex');
const daemon = await listener((request, response) => {
  assert.equal(request.headers.authorization, `Bearer ${bridgeToken}`);
  response.writeHead(404, { 'content-type': 'application/json' });
  response.end('{}');
});
const runtimeEnvironment = environment(state, endpoint.origin, modelToken, bridgeToken);
runtimeEnvironment[MODEL_ID] = recipe.chat.model;
const port = await freePort();
let runtime;
const started = performance.now();
try {
  runtime = launch(state, port, daemon.origin, runtimeEnvironment);
  await ready(runtime);
  assert.equal((await chat(port, 'wrong-proof', 'must not run')).status, 401);
  const word = `terrier${randomBytes(4).toString('hex')}`;
  const first = await chat(port, bridgeToken, `The test word for this conversation is ${word}. Reply with exactly that word. /no_think`, 60_000);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.ok(first.body.reply.includes(word), 'The real model did not return the supplied test word');
  await stop(runtime.child);
  runtime = launch(state, port, daemon.origin, runtimeEnvironment);
  await ready(runtime);
  const resumed = await chat(port, bridgeToken, 'What is the test word from the first message? Reply with exactly that word. /no_think', 60_000);
  assert.equal(resumed.status, 200, JSON.stringify(resumed.body));
  assert.ok(resumed.body.reply.includes(word), 'The restarted real agent did not recover its conversation');
  assert.equal(runtime.output().includes(modelToken), false);
  assert.equal(runtime.output().includes(bridgeToken), false);
  console.log(JSON.stringify({ real_model: recipe.chat.model, chat: true, restart_recall: true,
    wrong_bridge_proof: '401', tool_authority: 'not qualified by this probe',
    seconds: Math.round(performance.now() - started) / 1_000 }));
} finally {
  if (runtime) await stop(runtime.child);
  await new Promise((resolve) => { daemon.server.close(resolve); daemon.server.closeAllConnections(); });
  await rm(state, { recursive: true, force: true });
}
