'use client';

import { EmptyBackend } from './empty';
import type { ConnectionStatus } from './types';

// Lazy, client-only load of the WASM master-plane core (agentkeys-web-core),
// memoized per broker URL. The dynamic import keeps the wasm glue out of the
// server bundle; init() fetches the .wasm from /wasm/ (served from public/,
// written by dev.sh's build_wasm). Keying by URL means a second CoreBackend with
// a different broker gets its own instance; on failure the entry is evicted so
// the next call retries (a transient load/broker failure must not poison it).
type LoadedCore = import('@/lib/wasm/agentkeys-web-core/agentkeys_web_core').WebCore;
const coreByUrl = new Map<string, Promise<LoadedCore>>();
function loadCore(brokerUrl: string): Promise<LoadedCore> {
  let p = coreByUrl.get(brokerUrl);
  if (!p) {
    p = (async () => {
      const wasm = await import('@/lib/wasm/agentkeys-web-core/agentkeys_web_core.js');
      await wasm.default('/wasm/agentkeys_web_core_bg.wasm');
      return new wasm.WebCore(brokerUrl);
    })();
    coreByUrl.set(brokerUrl, p);
    void p.catch(() => coreByUrl.delete(brokerUrl));
  }
  return p;
}

/**
 * CoreBackend — the phone-first host (browser → WASM core → broker DIRECTLY, no
 * daemon). X1 of docs/plan/web-flow/wire-real-paths.md: it loads the
 * `agentkeys-web-core` WASM module and exposes the broker calls (cap-mint,
 * pairing) the onboarding/pairing slices use.
 *
 * The `AgentKeysClient` READ endpoints (actors, audit, memory, …) are wired in
 * the later W-phases, so they inherit EmptyBackend's disconnected behaviour for
 * now (the UI shows honest empty states); `status()` exercises the full path
 * (load WASM + probe the broker) and reports what happened.
 */
export class CoreBackend extends EmptyBackend {
  private brokerUrl: string;

  constructor(brokerUrl: string) {
    super();
    this.brokerUrl = brokerUrl.replace(/\/+$/, '');
  }

  async status(): Promise<ConnectionStatus> {
    try {
      await loadCore(this.brokerUrl);
    } catch (e) {
      return {
        kind: 'disconnected',
        reason: 'no-backend-configured',
        detail: `WASM core failed to load: ${String(e)}`,
      };
    }
    try {
      const r = await fetch(`${this.brokerUrl}/healthz`, { cache: 'no-store' });
      return {
        kind: 'disconnected',
        reason: r.ok ? 'no-backend-configured' : 'unreachable',
        detail: r.ok
          ? `WASM core loaded; broker ${this.brokerUrl} reachable. The AgentKeysClient read endpoints wire in later W-phases (wire-real-paths.md).`
          : `WASM core loaded; broker /healthz → ${r.status}.`,
      };
    } catch (e) {
      return {
        kind: 'disconnected',
        reason: 'unreachable',
        detail: `broker ${this.brokerUrl} unreachable: ${String(e)}`,
      };
    }
  }

  // ── Broker calls in the browser (X1). Beyond the AgentKeysClient interface;
  //    the onboarding/pairing slices call these directly via the CoreBackend.
  //    `req.service` for memory MUST be namespace-qualified — `memory:<ns>`
  //    (use `memoryService(ns)` from lib/constants); a bare `memory` fails
  //    cap-mint with `service_not_in_scope` (arch.md §896). The agent's *read*
  //    is query-aware: the worker stores per-namespace (`memory:<ns>.enc`) and
  //    the configured engine (OpenViking / deterministic) ranks the
  //    gate-bounded lines per turn, never widening past scope (#177).
  async capMemoryPut(bearer: string, req: unknown): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).capMemoryPut(bearer, req);
  }
  async capMemoryGet(bearer: string, req: unknown): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).capMemoryGet(bearer, req);
  }
  async pairingClaim(bearer: string, req: unknown): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).pairingClaim(bearer, req);
  }
  async pendingBindings(bearer: string): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).pendingBindings(bearer);
  }
  async ackBinding(bearer: string, requestId: string): Promise<unknown> {
    return (await loadCore(this.brokerUrl)).ackBinding(bearer, requestId);
  }
}
