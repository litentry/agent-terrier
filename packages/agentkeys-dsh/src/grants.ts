/**
 * The delegate's grant view — fetched from the co-located daemon's
 * `GET /v1/sandbox/self/grants` (#611), which is the ONE Rust-owned resolution
 * of on-chain scope state (D1: the chain stays the only authority; this is a
 * read-through cache, never a policy source).
 *
 * Fail-closed: while the view is unavailable (daemon down, fetch failing) the
 * guard treats every grant-classed tool as ungranted.
 */
import { DaemonClient, DEFAULT_DAEMON_URL } from './daemon-client.js';

export interface GrantView {
  readonly services: ReadonlySet<string>;
  readonly fetchedAt: number;
  readonly available: boolean;
}

export interface GrantsConfig {
  readonly grantsUrl?: string;
  readonly bridgeToken?: string;
  readonly ttlMs?: number;
}

export const DEFAULT_GRANTS_URL = `${DEFAULT_DAEMON_URL}/v1/sandbox/self/grants`;
const DEFAULT_TTL_MS = 60_000;
const UNAVAILABLE_RETRY_MS = 5_000;

const EMPTY: GrantView = { services: new Set(), fetchedAt: 0, available: false };

export class GrantsCache {
  private view: GrantView = EMPTY;
  private inflight: Promise<void> | undefined;
  private readonly client: DaemonClient;
  constructor(private readonly config: GrantsConfig = {}) {
    this.client = new DaemonClient({ bridgeToken: config.bridgeToken });
  }

  /** Synchronous read for the monotonic guard (guards must be sync). */
  current(): GrantView {
    return this.view;
  }

  /** Await freshness (TTL-bounded); never throws — failure leaves an
   *  unavailable view, which callers treat as deny. */
  async ensureFresh(now = Date.now()): Promise<GrantView> {
    const ttl = this.config.ttlMs ?? DEFAULT_TTL_MS;
    const age = now - this.view.fetchedAt;
    const stale = this.view.available ? age > ttl : age > UNAVAILABLE_RETRY_MS || this.view.fetchedAt === 0;
    if (stale) {
      this.inflight ??= this.refresh().finally(() => {
        this.inflight = undefined;
      });
      await this.inflight;
    }
    return this.view;
  }

  /** Force a refetch (used after a deny, so a just-granted service is seen
   *  without waiting out the TTL). Never throws. */
  async refresh(): Promise<void> {
    const url = this.config.grantsUrl ?? DEFAULT_GRANTS_URL;
    try {
      const body = await this.client.getJson<{ services?: unknown }>(url, { timeoutMs: 10_000 });
      const services = Array.isArray(body.services)
        ? body.services.filter((s): s is string => typeof s === 'string')
        : [];
      this.view = {
        services: new Set(services.map((s) => s.toLowerCase())),
        fetchedAt: Date.now(),
        available: true,
      };
    } catch {
      this.view = { services: this.view.services, fetchedAt: Date.now(), available: false };
    }
  }
}

/** One-shot approval ledger shared between the answerer (writer) and the
 *  guard (consumer): an `allowed-once` outcome authorizes exactly ONE
 *  execution of exactly ONE callId. Module-level on purpose — both plugins
 *  ship in this package and run in one process. */
const APPROVED_CALLS = new Map<string, number>();
const APPROVAL_TTL_MS = 5 * 60_000;

export function recordApprovedCall(callId: string, now = Date.now()): void {
  for (const [id, at] of APPROVED_CALLS) if (now - at > APPROVAL_TTL_MS) APPROVED_CALLS.delete(id);
  APPROVED_CALLS.set(callId, now);
}

export function consumeApprovedCall(callId: string | undefined, now = Date.now()): boolean {
  if (!callId) return false;
  const at = APPROVED_CALLS.get(callId);
  if (at === undefined || now - at > APPROVAL_TTL_MS) return false;
  APPROVED_CALLS.delete(callId);
  return true;
}
