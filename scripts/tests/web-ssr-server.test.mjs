import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createWebServer } from '../web-ssr-server.mjs';

test('serves public assets and SSR without exposing sibling files or symlink targets', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'terrier-web-test-'));
  const clientDirectory = join(directory, 'client');
  await mkdir(clientDirectory);
  await writeFile(join(clientDirectory, 'public.txt'), 'public asset');
  await writeFile(join(directory, 'private.txt'), 'synthetic-private-canary');
  await symlink(join(directory, 'private.txt'), join(clientDirectory, 'linked.txt'));
  const server = createWebServer({ clientDirectory, fetchHandler: () => new Response('page') });
  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = `http://127.0.0.1:${server.address().port}`;
    assert.equal(await (await fetch(`${origin}/public.txt`)).text(), 'public asset');
    assert.equal(await (await fetch(`${origin}/`)).text(), 'page');
    for (const path of ['/linked.txt', '/%2e%2e%2fprivate.txt']) {
      assert.equal(await (await fetch(origin + path)).text(), 'page');
    }
    assert.equal(await (await fetch(`${origin}/public.txt`, { method: 'HEAD' })).text(), '');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true });
  }
});
