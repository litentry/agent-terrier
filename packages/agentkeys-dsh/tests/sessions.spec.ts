import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import * as sessionsPlugin from '../src/sessions.js';
import { SERVICE, SessionStore } from '../src/sessions.js';
import { readIndex } from '../src/bridge-sessions.js';
import type { ChatSessionSpec } from '../src/bridge-sessions.js';

const homes: string[] = [];
async function scratchHome(): Promise<string> {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'ak-sessions-'));
  homes.push(home);
  return home;
}
afterEach(async () => {
  for (const h of homes.splice(0)) await fs.rm(h, { recursive: true, force: true });
});

const thread = (party: string, idle = 30): ChatSessionSpec => ({ window: 'thread', scope: 'ch-family', party, idle_minutes: idle });
const tap: ChatSessionSpec = { window: 'event', scope: 'ch-kitchen', context: 'The card' };

describe('SessionStore (the typed-session policy service)', () => {
  it('plans a thread, keeps it across turns, and ends it after silence — listeners hear it before the log retires', async () => {
    const store = new SessionStore(await scratchHome());
    const heard: Array<{ ids: readonly string[]; reason: string }> = [];
    store.onEnded((e) => {
      heard.push({ ids: e.ids, reason: e.reason });
    });
    const t0 = 1_000_000_000;
    const first = await store.plan(thread('grandma'), t0);
    expect(first.fresh).toBe(true);
    expect(first.throwaway).toBe(false);
    await store.touch(first.sessionId, t0 + 1_000);
    const second = await store.plan(thread('grandma'), t0 + 60_000);
    expect(second.sessionId).toBe(first.sessionId);
    expect(second.fresh).toBe(false);
    expect((await readIndex(store.home)).open.map((o) => o.id)).toEqual([first.sessionId]);
    // 30 minutes of silence: the sweep ends it, the listener runs, the index closes it.
    expect(await store.expire(t0 + 60_000 + 31 * 60_000)).toEqual([first.sessionId]);
    expect(heard).toEqual([{ ids: [first.sessionId], reason: 'idle' }]);
    const index = await readIndex(store.home);
    expect(index.open).toEqual([]);
    expect(index.ended).toEqual([first.sessionId]);
    expect(await store.expire(t0 + 99 * 60_000)).toEqual([]);
  });

  it('a throwaway window ends with its reply; a reset ends only what its scope covers', async () => {
    const store = new SessionStore(await scratchHome());
    const reasons: string[] = [];
    store.onEnded((e) => {
      reasons.push(`${e.reason}:${e.ids.length}`);
    });
    const t0 = 2_000_000_000;
    const tapped = await store.plan(tap, t0);
    expect(tapped.throwaway).toBe(true);
    await store.discard(tapped.sessionId);
    const grandma = await store.plan(thread('grandma'), t0);
    const owner = await store.plan({ window: 'conversation', scope: 'opchat-chef' }, t0);
    expect(await store.reset({ scope: 'thread', channel: 'ch-family', party: 'grandma' })).toEqual([grandma.sessionId]);
    expect((await readIndex(store.home)).open.map((o) => o.id)).toEqual([owner.sessionId]);
    expect(await store.reset({ scope: 'app' })).toEqual([owner.sessionId]);
    expect(reasons).toEqual(['throwaway:1', 'reset:1', 'reset:1']);
    expect((await readIndex(store.home)).open).toEqual([]);
  });

  it('invalidate() re-reads the index from disk (a home import replaced it)', async () => {
    const home = await scratchHome();
    const store = new SessionStore(home);
    await store.plan(thread('grandma'), 3_000_000_000);
    const other = new SessionStore(home);
    expect((await other.load()).open).toHaveLength(1);
    await other.reset({ scope: 'app' });
    expect((await store.load()).open).toHaveLength(1); // stale cache
    store.invalidate();
    expect((await store.load()).open).toHaveLength(0);
  });

  it('mounts as the agentkeysSessions service', async () => {
    const ctx = new Context();
    try {
      await ctx.plugin(sessionsPlugin, { homeDir: await scratchHome() });
      const store = (ctx as unknown as Record<string, unknown>)[SERVICE];
      expect(store).toBeInstanceOf(SessionStore);
    } finally {
      await ctx.fiber.dispose();
    }
  });
});
