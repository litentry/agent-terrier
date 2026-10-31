import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { freePort, stop } from './test-support.mjs';

test('packaged daemon starts without a host mount and preserves management authorization', { timeout: 15_000 }, async () => {
  const state = await realpath(await mkdtemp(path.join(os.tmpdir(), 'terrier-daemon-image-')));
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const bridgeToken = randomBytes(32).toString('hex');
  const environment = Object.fromEntries(Object.entries(process.env)
    .filter(([name]) => ['PATH', 'TMPDIR', 'LANG', 'LC_ALL'].includes(name)));
  Object.assign(environment, { HOME: state, AGENTKEYS_CHAIN: 'anvil', AGENTKEYS_ACTOR_OMNI: randomBytes(32).toString('hex'),
    AGENTKEYS_OPERATOR_OMNI: randomBytes(32).toString('hex'), AGENTKEYS_BRIDGE_TOKEN: bridgeToken });
  const child = spawn(process.env.AGENT_TERRIER_TEST_DAEMON_BINARY || 'agentkeys-daemon',
    ['--ui-bridge', '--ui-bridge-bind', `127.0.0.1:${port}`, '--broker-url', 'http://127.0.0.1:1',
      '--signer-url', 'http://127.0.0.1:1'], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  let spawnError;
  child.on('error', (error) => { spawnError = error; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', (data) => { output += data; });
  try {
    let healthy = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (spawnError) throw new Error('Packaged daemon executable could not start');
      assert.equal(child.exitCode, null, 'Packaged daemon exited before readiness');
      try {
        const response = await fetch(`${origin}/healthz`, { signal: AbortSignal.timeout(500), redirect: 'error' });
        const health = await response.json();
        if (response.ok && health.ok === true && health.surface === 'ui-bridge') { healthy = true; break; }
      } catch {}
      await delay(50);
    }
    assert.equal(healthy, true, 'Packaged daemon did not become ready');
    for (const token of [null, 'wrong-proof']) {
      const response = await fetch(`${origin}/v1/sandbox/self/actions`,
        { headers: token ? { authorization: `Bearer ${token}` } : {}, redirect: 'error' });
      assert.equal(response.status, 401);
      await response.body.cancel();
    }
    const response = await fetch(`${origin}/v1/sandbox/self/actions`,
      { headers: { authorization: `Bearer ${bridgeToken}` }, redirect: 'error' });
    assert.equal(response.status, 200);
    assert.ok(Array.isArray((await response.json()).actions));
    assert.equal(output.includes(bridgeToken), false, 'Daemon output exposed its management proof');
  } finally {
    if (!spawnError) await stop(child);
    await rm(state, { recursive: true, force: true });
  }
});
