import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { chmod, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { chat, freePort, listener, ready, stop, streamCompletion } from './test-support.mjs';

const runtimeScript = fileURLToPath(new URL('./start.mjs', import.meta.url));
const profile = JSON.parse(await readFile(new URL('../../crates/agentkeys-core/chain-profiles/anvil.json', import.meta.url)));

function configuration(origin) {
  const environment = {};
  for (const name of ['BROKER_URL', 'SIGNER_URL', 'CHANNEL_WORKER_URL', 'WORKER_CRED_URL', 'WORKER_MEMORY_URL', 'WORKER_CONFIG_URL']) {
    environment[`AGENTKEYS_${name}`] = origin;
  }
  for (const name of ['SESSION_JWT', 'BRIDGE_TOKEN', 'SANDBOX_MGMT_TOKEN', 'MODEL_API_KEY', 'ACTOR_OMNI', 'OPERATOR_OMNI']) {
    environment[`AGENTKEYS_${name}`] = randomBytes(32).toString('hex');
  }
  Object.assign(environment, { AGENTKEYS_CHAT_CHANNEL_ID: 'opchat-fixture', AGENTKEYS_MODEL_ID: 'local-test-model',
    AGENTKEYS_MODEL_BASE_URL: `${origin}/v1` });
  return { version: 1, chain_profile: { ...profile, rpc: { ...profile.rpc, http: origin } }, environment };
}

async function launch(state, config, overrides = {}) {
  const daemonPort = overrides.daemonPort || await freePort();
  const agentPort = await freePort();
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => ['PATH', 'TMPDIR', 'LANG', 'LC_ALL'].includes(name)));
  Object.assign(environment, { NODE_OPTIONS: '--require=/must-not-inherit', AGENTKEYS_CHAIN: 'must-not-inherit' });
  const child = spawn(process.env.AGENT_TERRIER_TEST_RUNTIME_BINARY || 'agent-terrier-runtime',
    ['--state-dir', state, '--runtime-script', overrides.runtimeScript || runtimeScript,
      '--daemon-binary', process.env.AGENT_TERRIER_TEST_DAEMON_BINARY || 'agentkeys-daemon',
      '--daemon-port', String(daemonPort), '--agent-port', String(agentPort)],
    { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', (data) => { output += data; });
  child.stdin.on('error', () => {});
  const exited = once(child, 'exit');
  child.stdin.write(overrides.raw ?? `${JSON.stringify(config)}\n`);
  return { child, exited, daemonPort, agentPort, output: () => output };
}

async function closed(runtime) {
  for (const port of [runtime.daemonPort, runtime.agentPort]) {
    await assert.rejects(fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(500) }));
  }
}

async function assertNoSecrets(directory, secrets) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) await assertNoSecrets(filename, secrets);
    else if (entry.isFile()) {
      const bytes = await readFile(filename);
      for (const secret of secrets) assert.equal(bytes.includes(Buffer.from(secret)), false, 'Runtime persisted a bootstrap credential');
    }
  }
}

test('managed processes preserve sessions and stop together on controller EOF and signals', { timeout: 30_000 }, async () => {
  const state = await realpath(await mkdtemp(path.join(os.tmpdir(), 'terrier-managed-')));
  const requests = [];
  let config;
  const model = await listener(async (request, response) => {
    if (request.url !== '/v1/chat/completions') { response.writeHead(503); response.end('{}'); return; }
    assert.equal(request.headers.authorization, `Bearer ${config.environment.AGENTKEYS_MODEL_API_KEY}`);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    requests.push(body);
    streamCompletion(response, body.model, { content: 'Managed fixture reply.' });
  });
  config = configuration(model.origin);
  const checkedScript = path.join(state, 'check-environment.mjs');
  await writeFile(checkedScript, `for (const name of ['AGENTKEYS_SESSION_JWT', 'AGENTKEYS_SIGNER_URL',
    'AGENTKEYS_BROKER_URL', 'AGENTKEYS_CHAIN_PROFILE_FILE', 'NODE_OPTIONS']) {
      if (name in process.env) throw new Error('Unexpected agent environment');
    }
    await import(${JSON.stringify(runtimeScript)});\n`, { mode: 0o600 });
  let runtime;
  try {
    runtime = await launch(state, config, { runtimeScript: checkedScript });
    await ready(runtime);
    assert.match(runtime.output(), /local-agent-processes/);
    assert.equal((await chat(runtime.agentPort, 'wrong-proof', 'denied')).status, 401);
    assert.equal(requests.length, 0);
    const marker = `remember-${randomBytes(8).toString('hex')}`;
    assert.equal((await chat(runtime.agentPort, config.environment.AGENTKEYS_BRIDGE_TOKEN, marker)).status, 200);
    const duplicate = await launch(state, config);
    assert.equal((await duplicate.exited)[0], 1);
    await closed(duplicate);
    runtime.child.stdin.end();
    assert.equal((await runtime.exited)[0], 0);
    await closed(runtime);
    runtime = await launch(state, config, { runtimeScript: checkedScript });
    await ready(runtime);
    assert.equal((await chat(runtime.agentPort, config.environment.AGENTKEYS_BRIDGE_TOKEN, 'recall')).status, 200);
    assert.ok(JSON.stringify(requests.at(-1).messages).includes(marker));
    const secrets = ['SESSION_JWT', 'BRIDGE_TOKEN', 'SANDBOX_MGMT_TOKEN', 'MODEL_API_KEY'].map((name) => config.environment[`AGENTKEYS_${name}`]);
    for (const secret of secrets) assert.equal(runtime.output().includes(secret), false);
    runtime.child.kill('SIGTERM');
    assert.equal((await runtime.exited)[0], 0);
    await closed(runtime);
    await assertNoSecrets(state, secrets);
  } finally {
    if (runtime) await stop(runtime.child);
    await new Promise((resolve) => { model.server.close(resolve); model.server.closeAllConnections(); });
    await rm(state, { recursive: true, force: true });
  }
});

test('managed startup refuses malformed input, unsafe state and unavailable children without surviving listeners', { timeout: 30_000 }, async () => {
  const state = await realpath(await mkdtemp(path.join(os.tmpdir(), 'terrier-managed-denial-')));
  const config = configuration('http://127.0.0.1:1');
  const children = [];
  try {
    for (const raw of ['{invalid}\n', `${'x'.repeat(65 * 1024)}\n`,
      `${JSON.stringify({ ...config, version: 2 })}\n`,
      `${JSON.stringify({ ...config, environment: { ...config.environment, NODE_OPTIONS: '--require=arbitrary-code' } })}\n`]) {
      const runtime = await launch(state, config, { raw }); children.push(runtime);
      assert.equal((await runtime.exited)[0], 1);
      await closed(runtime);
      assert.deepEqual(await readdir(state), []);
    }
    await symlink(state, path.join(state, 'alias'));
    const linked = await launch(path.join(state, 'alias'), config); children.push(linked);
    assert.equal((await linked.exited)[0], 1); await closed(linked);
    assert.deepEqual(await readdir(state), ['alias']);
    await chmod(state, 0o755);
    const loose = await launch(state, config); children.push(loose);
    assert.equal((await loose.exited)[0], 1); await closed(loose);
    await chmod(state, 0o700);
    const unavailable = await launch(state, config, { runtimeScript: path.join(state, 'missing.mjs') }); children.push(unavailable);
    assert.equal((await unavailable.exited)[0], 1); await closed(unavailable);
    const trailing = await launch(state, config, { raw: `${JSON.stringify(config)}\nsecond-frame\n` }); children.push(trailing);
    assert.equal((await trailing.exited)[0], 1); await closed(trailing);
    const occupied = await listener((_request, response) => response.end('foreign'));
    try {
      const collision = await launch(state, config, { daemonPort: occupied.server.address().port }); children.push(collision);
      assert.equal((await collision.exited)[0], 1);
      assert.equal(await (await fetch(occupied.origin)).text(), 'foreign');
      await assert.rejects(fetch(`http://127.0.0.1:${collision.agentPort}/healthz`));
    } finally { await new Promise((resolve) => occupied.server.close(resolve)); }
  } finally {
    for (const runtime of children) await stop(runtime.child);
    await rm(state, { recursive: true, force: true });
  }
});
