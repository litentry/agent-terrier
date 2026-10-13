import { afterEach, expect, it, vi } from 'vitest';
import { DaemonBackend } from '../client/daemon';

afterEach(() => vi.unstubAllGlobals());

it('shares concurrent reads and fetches again after completion', async () => {
  let finishRead!: (response: Response) => void;
  const fetchRequest = vi.fn().mockReturnValueOnce(new Promise((resolve) => { finishRead = resolve; }))
    .mockImplementation(async () => new Response(JSON.stringify({ categories: [] })));
  vi.stubGlobal('fetch', fetchRequest);
  const client = new DaemonBackend('http://daemon.example.test');
  const first = client.listMemoryCategories();
  const second = client.listMemoryCategories();
  expect(fetchRequest).toHaveBeenCalledTimes(1);
  finishRead(new Response(JSON.stringify({ categories: [] })));
  expect(await Promise.all([first, second])).toEqual([{ ok: true, data: [] }, { ok: true, data: [] }]);
  await client.listMemoryCategories();
  expect(fetchRequest).toHaveBeenCalledTimes(2);
});

it('does not reuse an earlier read after a write completes', async () => {
  let finishOldRead!: (response: Response) => void;
  const fetchRequest = vi.fn().mockReturnValueOnce(new Promise((resolve) => { finishOldRead = resolve; }))
    .mockImplementation(async () => new Response(JSON.stringify({ categories: [], ok: true })));
  vi.stubGlobal('fetch', fetchRequest);
  const client = new DaemonBackend('http://daemon.example.test');
  const oldRead = client.listMemoryCategories();
  await client.logout();
  const newRead = client.listMemoryCategories();
  expect(fetchRequest).toHaveBeenCalledTimes(3);
  finishOldRead(new Response(JSON.stringify({ categories: [] })));
  await Promise.all([oldRead, newRead]);
});
