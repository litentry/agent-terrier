/**
 * @module @agentkeys/dsh-suite/sessions — typed-session POLICY as a service
 * (plan docs/plan/dsh-plugin-abstraction.md PR 2; owner decision 2026-09-23,
 * PR #725). The bridge is transport: it receives `/v1/chat` bodies and holds
 * the live agent handles. THIS plugin owns what a session window means once a
 * body names one — the index in `DSH_HOME` (`agentkeys-sessions.json`), idle
 * expiry, the reset scopes, retention of ended logs (the newest few stay),
 * and the ONE hook the rest of the suite needs: `onEnded`, fired BEFORE a
 * session's logs retire, so the bridge disposes its live handle (the memory
 * plugin commits that OpenViking session on dispose) and, with #726, the
 * extraction / cleanup policy per window has one place to attach.
 *
 * The pure vocabulary (windows, `planTurn`, the index shape, the shared
 * fixture) stays in bridge-sessions.ts; the wire is unchanged (`session` on
 * `/v1/chat`, `POST /v1/session/reset`). Provided as the cordis service
 * `agentkeysSessions`; the bridge injects it. NO default export (dsh
 * postmortem 0001).
 */
import { randomBytes } from 'node:crypto';
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import {
  endMatching,
  expireIdle,
  newSessionId,
  planTurn,
  readIndex,
  removeSessionDirs,
  retire,
  touch,
  writeIndex,
} from './bridge-sessions.js';
import type { ChatSessionSpec, ResetSpec, SessionIndex, TurnPlan } from './bridge-sessions.js';

export const name = 'agentkeys-sessions';
/** The cordis service name the bridge (and #726's cleanup) inject. */
export const SERVICE = 'agentkeysSessions';

export interface Config {
  /** The runtime home the index and the session logs live in (DSH_HOME —
   *  the same home the bridge's mgmt surface snapshots). */
  homeDir?: string;
}

export const Config: z<Config> = z.object({
  homeDir: z.string().default(process.env.DSH_HOME ?? '/root/.dsh'),
});

/** Why a session ended: silence, a reset marker, a throwaway window after its
 *  reply, or a newer session replacing it for the same key. */
export type EndReason = 'idle' | 'reset' | 'throwaway' | 'replaced';

export interface EndedEvent {
  ids: readonly string[];
  reason: EndReason;
}

export type EndedListener = (event: EndedEvent) => void | Promise<void>;

export class SessionStore {
  private index: SessionIndex | undefined;
  private readonly listeners = new Set<EndedListener>();

  constructor(readonly home: string) {}

  /** Hear sessions end — BEFORE their logs retire. Returns the unsubscribe. */
  onEnded(listener: EndedListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Forget the cached index (after a home import replaced the files). */
  invalidate(): void {
    this.index = undefined;
  }

  async load(): Promise<SessionIndex> {
    if (!this.index) this.index = await readIndex(this.home);
    return this.index;
  }

  private async save(next: SessionIndex): Promise<void> {
    this.index = next;
    await writeIndex(this.home, next);
  }

  /** End the open sessions whose idle window elapsed. Returns their ids. */
  async expire(nowMs: number): Promise<string[]> {
    const swept = expireIdle(await this.load(), nowMs);
    if (swept.ended.length === 0) return [];
    await this.save(swept.index);
    await this.end(swept.ended, 'idle');
    return swept.ended;
  }

  /** The session a turn runs in (new or open), per the window policy; a
   *  session the plan replaced is ended first. */
  async plan(spec: ChatSessionSpec, nowMs: number): Promise<TurnPlan> {
    const plan = planTurn(await this.load(), spec, nowMs, () =>
      newSessionId(spec.window, nowMs, randomBytes(4).toString('hex')),
    );
    await this.save(plan.index);
    if (plan.ended.length > 0) await this.end(plan.ended, 'replaced');
    return plan;
  }

  /** Mark an open session used (its idle clock restarts). */
  async touch(sessionId: string, nowMs: number): Promise<void> {
    await this.save(touch(await this.load(), sessionId, nowMs));
  }

  /** A throwaway (`none` / `event`) session after its reply. */
  async discard(sessionId: string): Promise<void> {
    await this.end([sessionId], 'throwaway');
  }

  /** End the open sessions a reset marker covers. Returns their ids. */
  async reset(spec: ResetSpec): Promise<string[]> {
    const { index, ended } = endMatching(await this.load(), spec);
    await this.save(index);
    await this.end(ended, 'reset');
    return ended;
  }

  /** Remove a session's logs outright (the legacy resident session on an
   *  app-wide reset — it is not in the index). */
  async removeLogs(sessionId: string): Promise<string[]> {
    return removeSessionDirs(this.home, sessionId);
  }

  /** End sessions: the listeners first (the bridge disposes the live handle,
   *  which is what commits the OpenViking session), then the index retires
   *  them and the oldest ended logs beyond the retention are deleted. */
  async end(ids: readonly string[], reason: EndReason): Promise<void> {
    if (ids.length === 0) return;
    for (const listener of this.listeners) await listener({ ids, reason });
    const { index, toDelete } = retire(await this.load(), ids);
    await this.save(index);
    for (const id of toDelete) await removeSessionDirs(this.home, id);
  }
}

export function apply(ctx: Context, config: Config): void {
  const store = new SessionStore(config.homeDir ?? process.env.DSH_HOME ?? '/root/.dsh');
  (ctx as unknown as { provide(name: string, value: unknown): void }).provide(SERVICE, store);
}
