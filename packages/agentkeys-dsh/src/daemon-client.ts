/**
 * @module @agentkeys/dsh-suite/daemon-client — the ONE way suite code reaches
 * the co-located `agentkeys-daemon` (plan docs/plan/dsh-plugin-abstraction.md
 * PR 1, spec §3.2 "bridge token"): every request carries the per-delegate
 * in-pod bearer (`AGENTKEYS_BRIDGE_TOKEN`, #715), a bounded timeout, and turns
 * a non-2xx reply into a `DaemonError` whose `reason` is the daemon's own
 * `error` line — the cap-mint refusal the model must see — never a bare
 * status. Grants, credentials, audit, the advertised actions and the
 * answerer's runtime ask all go through here; nothing in this package forks
 * a process or reads a receipt off stdout any more.
 *
 * Plain module — no plugin, no default export (dsh postmortem 0001).
 */

export const DEFAULT_DAEMON_URL = 'http://127.0.0.1:3114';

export interface DaemonClientOptions {
  /** The daemon base (scheme + host + port). Default: the in-pod daemon. */
  baseUrl?: string;
  /** The in-pod bearer; default: env AGENTKEYS_BRIDGE_TOKEN. Empty = no header
   *  (the daemon then answers 401 — fail-closed on its side, #715). */
  bridgeToken?: string;
}

export class DaemonError extends Error {
  constructor(
    public readonly status: number,
    public readonly reason: string,
    public readonly url: string,
  ) {
    super(`HTTP ${status} ${reason}`.trim());
    this.name = 'DaemonError';
  }
}

/** The daemon's `error` field when the body is its JSON refusal, else the
 *  body head — one line the caller can relay (pure). */
export function reasonOf(text: string): string {
  try {
    const parsed = JSON.parse(text) as { error?: unknown };
    if (parsed && typeof parsed.error === 'string' && parsed.error.length > 0) return parsed.error;
  } catch {
    // not JSON — the head of the body is the reason
  }
  return text.slice(0, 400).trim();
}

const ABSOLUTE = /^https?:\/\//i;

export class DaemonClient {
  readonly baseUrl: string;
  private readonly token: string;

  constructor(opts: DaemonClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? DEFAULT_DAEMON_URL).replace(/\/+$/, '');
    this.token = opts.bridgeToken ?? process.env.AGENTKEYS_BRIDGE_TOKEN ?? '';
  }

  /** The absolute URL for a daemon path; an absolute URL passes through (the
   *  per-plugin `*Url` overrides the smoke + tests inject). */
  url(pathOrUrl: string): string {
    if (ABSOLUTE.test(pathOrUrl)) return pathOrUrl;
    return `${this.baseUrl}${pathOrUrl.startsWith('/') ? '' : '/'}${pathOrUrl}`;
  }

  headers(withBody: boolean): Record<string, string> {
    const h: Record<string, string> = {};
    if (withBody) h['content-type'] = 'application/json';
    if (this.token) h.authorization = `Bearer ${this.token}`;
    return h;
  }

  async getJson<T>(pathOrUrl: string, opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<T> {
    return this.request<T>(this.url(pathOrUrl), { method: 'GET', headers: this.headers(false) }, opts);
  }

  async postJson<T>(pathOrUrl: string, body: unknown, opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<T> {
    return this.request<T>(
      this.url(pathOrUrl),
      { method: 'POST', headers: this.headers(true), body: JSON.stringify(body) },
      opts,
    );
  }

  private async request<T>(
    url: string,
    init: { method: string; headers: Record<string, string>; body?: string },
    opts: { timeoutMs?: number; signal?: AbortSignal },
  ): Promise<T> {
    const timeout = AbortSignal.timeout(opts.timeoutMs ?? 30_000);
    const any = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any;
    const signal = opts.signal && any ? any([timeout, opts.signal]) : timeout;
    const res = await fetch(url, { ...init, signal });
    const text = await res.text();
    if (!res.ok) throw new DaemonError(res.status, reasonOf(text), url);
    return (text.length > 0 ? JSON.parse(text) : {}) as T;
  }
}
