/**
 * @module @agentkeys/dsh-suite/bridge-sessions — typed sessions on the bridge
 * (owner decision 2026-09-23).
 *
 * The daemon names the session every turn runs in (the `session` field of a
 * `/v1/chat` body; one owner: agentkeys-protocol `session_window.rs`, shared
 * fixture e2e/fixtures/bridge-protocol/session_contract.json):
 *  - `none` / `event`: a throwaway dsh session, ended with its turn;
 *  - `thread` / `conversation`: one dsh session per key, resumed turn to turn,
 *    ended by `idle_minutes` of silence or a reset.
 * Ending = dispose (the OpenViking memory plugin commits the matching
 * OpenViking session) + the log retired, keeping only the newest few. The
 * index lives in the runtime home, so a checkpoint and a #577 hand-off carry
 * it with the logs.
 *
 * Pure planning functions + small fs helpers; bridge.ts does the dsh calls.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';

export type SessionWindow = 'none' | 'event' | 'thread' | 'conversation';
export type ResetScope = 'app' | 'feed' | 'thread';

const WINDOWS: readonly SessionWindow[] = ['none', 'event', 'thread', 'conversation'];
const RESET_SCOPES: readonly ResetScope[] = ['app', 'feed', 'thread'];

/** The `session` field of a `/v1/chat` body. */
export interface ChatSessionSpec {
  window: SessionWindow;
  /** The feed's channel id, or `schedule:<label>`. */
  scope: string;
  /** `thread` only: whose thread. */
  party?: string;
  /** `thread` / `conversation`: minutes of silence that end the session. */
  idleMinutes?: number;
  /** Background for a NEW session only. */
  context?: string;
}

/** The `/v1/session/reset` body. */
export interface ResetSpec {
  scope: ResetScope;
  channel?: string;
  party?: string;
}

/** One open `thread` / `conversation` session. */
export interface OpenSession {
  key: string;
  /** The dsh session id. */
  id: string;
  window: 'thread' | 'conversation';
  scope: string;
  party: string;
  idleMinutes: number;
  createdAt: number;
  lastActiveAt: number;
}

export interface SessionIndex {
  version: 1;
  open: OpenSession[];
  /** Ended dsh session ids whose logs are still in the home, oldest first. */
  ended: string[];
}

/** The index file, relative to the runtime home. */
export const SESSION_INDEX_FILE = 'agentkeys-sessions.json';
/** Ended session logs kept for inspection; older ones are deleted. */
export const ENDED_LOGS_KEPT = 20;
/** Open sessions held live in memory; the least recently used beyond this
 *  is disposed (it stays open in the index and resumes on its next turn). */
export const MAX_LIVE_SESSIONS = 8;
/** The idle limit an open session gets when the daemon names none. */
const FALLBACK_IDLE_MINUTES: Record<'thread' | 'conversation', number> = { thread: 30, conversation: 24 * 60 };

const SESSION_ID_RE = /^[A-Za-z0-9._-]{1,120}$/;

function badRequest(message: string): Error {
  return Object.assign(new Error(message), { code: 400 });
}

function optionalString(value: unknown, what: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') throw badRequest(`${what} must be a string`);
  return value;
}

function onlyKeys(raw: Record<string, unknown>, allowed: readonly string[], what: string): void {
  for (const key of Object.keys(raw)) {
    if (!allowed.includes(key)) throw badRequest(`${what}.${key} is not a known field`);
  }
}

/** Parse the `session` field of a `/v1/chat` body. `undefined` = absent (the
 *  legacy resident session); a malformed field throws a 400. */
export function parseChatSession(raw: unknown): ChatSessionSpec | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw badRequest('session must be an object');
  const r = raw as Record<string, unknown>;
  onlyKeys(r, ['window', 'scope', 'party', 'idle_minutes', 'context'], 'session');
  if (!WINDOWS.includes(r.window as SessionWindow)) {
    throw badRequest(`session.window must be one of ${WINDOWS.join(', ')}`);
  }
  if (typeof r.scope !== 'string' || !r.scope.trim()) throw badRequest('session.scope must be a non-empty string');
  const idle = r.idle_minutes;
  if (idle !== undefined && idle !== null && (typeof idle !== 'number' || !Number.isInteger(idle) || idle < 1)) {
    throw badRequest('session.idle_minutes must be a positive integer');
  }
  const spec: ChatSessionSpec = { window: r.window as SessionWindow, scope: r.scope };
  const party = optionalString(r.party, 'session.party');
  if (party) spec.party = party;
  if (typeof idle === 'number') spec.idleMinutes = idle;
  const context = optionalString(r.context, 'session.context');
  if (context && context.trim()) spec.context = context;
  return spec;
}

/** Parse a `/v1/session/reset` body (throws a 400 on a malformed one). */
export function parseResetBody(raw: unknown): ResetSpec {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw badRequest('reset body must be an object');
  const r = raw as Record<string, unknown>;
  onlyKeys(r, ['scope', 'channel', 'party'], 'reset');
  if (!RESET_SCOPES.includes(r.scope as ResetScope)) {
    throw badRequest(`reset.scope must be one of ${RESET_SCOPES.join(', ')}`);
  }
  const spec: ResetSpec = { scope: r.scope as ResetScope };
  const channel = optionalString(r.channel, 'reset.channel');
  const party = optionalString(r.party, 'reset.party');
  if ((spec.scope === 'feed' || spec.scope === 'thread') && !channel) {
    throw badRequest(`a ${spec.scope} reset names its channel`);
  }
  if (spec.scope === 'thread' && !party) throw badRequest('a thread reset names its party');
  if (channel) spec.channel = channel;
  if (party) spec.party = party;
  return spec;
}

/** The index key of an open session (`undefined` for a throwaway window). */
export function openKey(spec: ChatSessionSpec): string | undefined {
  if (spec.window !== 'thread' && spec.window !== 'conversation') return undefined;
  return `${spec.window}|${spec.scope}|${spec.window === 'thread' ? (spec.party ?? '') : ''}`;
}

/** A fresh dsh session id: `ak-<window>-<utc stamp>-<random>` — one plain path
 *  segment (dsh's JSONL backend keeps it verbatim as the log's directory). */
export function newSessionId(window: SessionWindow, nowMs: number, random: string): string {
  const stamp = new Date(nowMs).toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return `ak-${window}-${stamp}-${random.replace(/[^A-Za-z0-9]/g, '').slice(0, 8) || '0'}`;
}

export function emptyIndex(): SessionIndex {
  return { version: 1, open: [], ended: [] };
}

export function isExpired(open: OpenSession, nowMs: number): boolean {
  return nowMs - open.lastActiveAt > open.idleMinutes * 60_000;
}

/** Where one turn runs. */
export interface TurnPlan {
  index: SessionIndex;
  sessionId: string;
  /** A new dsh session (the context, if any, applies). */
  fresh: boolean;
  /** Ended with this turn (`none` / `event`). */
  throwaway: boolean;
  /** Open sessions this plan ended (an expired one under the same key). */
  ended: string[];
}

/** Decide which dsh session a turn runs in (pure). */
export function planTurn(index: SessionIndex, spec: ChatSessionSpec, nowMs: number, mintId: () => string): TurnPlan {
  const key = openKey(spec);
  if (!key) {
    return { index, sessionId: mintId(), fresh: true, throwaway: true, ended: [] };
  }
  const existing = index.open.find((o) => o.key === key);
  if (existing && !isExpired(existing, nowMs)) {
    const touched = { ...existing, lastActiveAt: nowMs };
    return {
      index: { ...index, open: index.open.map((o) => (o.key === key ? touched : o)) },
      sessionId: existing.id,
      fresh: false,
      throwaway: false,
      ended: [],
    };
  }
  const window = spec.window as 'thread' | 'conversation';
  const opened: OpenSession = {
    key,
    id: mintId(),
    window,
    scope: spec.scope,
    party: window === 'thread' ? (spec.party ?? '') : '',
    idleMinutes: spec.idleMinutes ?? FALLBACK_IDLE_MINUTES[window],
    createdAt: nowMs,
    lastActiveAt: nowMs,
  };
  return {
    index: { ...index, open: [...index.open.filter((o) => o.key !== key), opened] },
    sessionId: opened.id,
    fresh: true,
    throwaway: false,
    ended: existing ? [existing.id] : [],
  };
}

/** Mark a session active now (after its turn). */
export function touch(index: SessionIndex, sessionId: string, nowMs: number): SessionIndex {
  return { ...index, open: index.open.map((o) => (o.id === sessionId ? { ...o, lastActiveAt: nowMs } : o)) };
}

/** End the open sessions a reset covers (pure). */
export function endMatching(index: SessionIndex, reset: ResetSpec): { index: SessionIndex; ended: string[] } {
  const covered = (o: OpenSession): boolean => {
    switch (reset.scope) {
      case 'app':
        return true;
      case 'feed':
        return o.scope === reset.channel;
      case 'thread':
        return o.window === 'thread' && o.scope === reset.channel && o.party === reset.party;
    }
  };
  const ended = index.open.filter(covered).map((o) => o.id);
  return { index: { ...index, open: index.open.filter((o) => !covered(o)) }, ended };
}

/** End the open sessions silent past their idle limit (pure). */
export function expireIdle(index: SessionIndex, nowMs: number): { index: SessionIndex; ended: string[] } {
  const ended = index.open.filter((o) => isExpired(o, nowMs)).map((o) => o.id);
  return { index: { ...index, open: index.open.filter((o) => !isExpired(o, nowMs)) }, ended };
}

/** Record ended sessions; returns the logs past the retention to delete. */
export function retire(index: SessionIndex, ids: readonly string[]): { index: SessionIndex; toDelete: string[] } {
  const ended = [...index.ended.filter((id) => !ids.includes(id)), ...ids];
  const overflow = Math.max(0, ended.length - ENDED_LOGS_KEPT);
  return { index: { ...index, ended: ended.slice(overflow) }, toDelete: ended.slice(0, overflow) };
}

function isOpenSession(v: unknown): v is OpenSession {
  const o = v as OpenSession;
  return (
    !!o &&
    typeof o.key === 'string' &&
    typeof o.id === 'string' &&
    SESSION_ID_RE.test(o.id) &&
    (o.window === 'thread' || o.window === 'conversation') &&
    typeof o.scope === 'string' &&
    typeof o.party === 'string' &&
    Number.isFinite(o.idleMinutes) &&
    Number.isFinite(o.createdAt) &&
    Number.isFinite(o.lastActiveAt)
  );
}

/** Read the index from the runtime home; a missing or malformed file reads as
 *  empty (a bad index must never wedge chat — the sessions just start fresh). */
export async function readIndex(home: string): Promise<SessionIndex> {
  try {
    const raw = JSON.parse(await fs.readFile(path.join(home, SESSION_INDEX_FILE), 'utf8')) as Partial<SessionIndex>;
    if (raw?.version !== 1) return emptyIndex();
    return {
      version: 1,
      open: Array.isArray(raw.open) ? raw.open.filter(isOpenSession) : [],
      ended: Array.isArray(raw.ended) ? raw.ended.filter((id): id is string => typeof id === 'string' && SESSION_ID_RE.test(id)) : [],
    };
  } catch {
    return emptyIndex();
  }
}

/** Write the index atomically (.tmp + rename). */
export async function writeIndex(home: string, index: SessionIndex): Promise<void> {
  await fs.mkdir(home, { recursive: true });
  const target = path.join(home, SESSION_INDEX_FILE);
  const tmp = `${target}.tmp`;
  await fs.writeFile(tmp, `${JSON.stringify(index)}\n`, 'utf8');
  await fs.rename(tmp, target);
}

/** Remove every directory named exactly `id` under the runtime home — dsh's
 *  JSONL backend keeps one directory per session (`<root>/<project>/<id>/`).
 *  Never walks node_modules; bounded depth. Returns the removed paths,
 *  relative to the home. */
export async function removeSessionDirs(home: string, id: string, maxDepth = 5): Promise<string[]> {
  if (!SESSION_ID_RE.test(id)) return [];
  const removed: string[] = [];
  const walk = async (dir: string, rel: string, depth: number): Promise<void> => {
    if (depth > maxDepth) return;
    let entries: import('node:fs').Dirent[];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name === 'node_modules') continue;
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;
      const child = path.join(dir, entry.name);
      if (entry.name === id) {
        await fs.rm(child, { recursive: true, force: true });
        removed.push(childRel);
      } else {
        await walk(child, childRel, depth + 1);
      }
    }
  };
  await walk(home, '', 0);
  return removed;
}
