import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const entrypoint = fileURLToPath(new URL('./start.mjs', import.meta.url));

export async function listener(handler) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}

export async function freePort() {
  const { server } = await listener((_request, response) => response.end());
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

export async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, 'exit');
  child.kill('SIGTERM');
  const deadline = setTimeout(() => child.kill('SIGKILL'), 5_000);
  try { await exited; } finally { clearTimeout(deadline); }
}

export function environment(state, modelOrigin, modelToken, bridgeToken) {
  const values = Object.fromEntries(Object.entries(process.env).filter(([name]) => ['PATH', 'TMPDIR', 'LANG', 'LC_ALL'].includes(name)));
  return { ...values, HOME: state, AGENTKEYS_MODEL_BASE_URL: `${modelOrigin}/v1`, AGENTKEYS_MODEL_API_KEY: modelToken,
    AGENTKEYS_MODEL_ID: 'local-test-model', AGENTKEYS_BRIDGE_TOKEN: bridgeToken };
}

export function launch(state, port, daemonOrigin, values, stateDirectory = path.join(state, 'state')) {
  const child = spawn(process.execPath, [entrypoint, '--state-dir', stateDirectory, '--work-dir', path.join(state, 'work'),
    '--port', String(port), '--daemon-url', daemonOrigin], { env: values, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', (data) => { output += data; });
  return { child, output: () => output };
}

export async function ready(runtime) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (runtime.output().includes('"ready":true')) return;
    assert.equal(runtime.child.exitCode, null, runtime.output());
    await delay(50);
  }
  assert.fail(`Runtime did not become ready: ${runtime.output()}`);
}

export async function chat(port, token, text, requestTimeout = 10_000) {
  const response = await fetch(`http://127.0.0.1:${port}/v1/chat`, { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ text }), signal: AbortSignal.timeout(requestTimeout), redirect: 'error' });
  return { status: response.status, body: await response.json() };
}

