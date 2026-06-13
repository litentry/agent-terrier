'use client';

// Lazy, client-only, memoized load of the agentkeys-web-core wasm MODULE —
// shared by CoreBackend (which wraps it in a per-broker-URL WebCore) and
// DaemonBackend's plant path (#275 tier-3: module-level route/body builders).
// The dynamic import keeps the wasm glue out of the server bundle; init()
// fetches the .wasm from /wasm/ (served from public/, written by dev.sh's
// build_wasm). On failure the memo is evicted so the next call retries (a
// transient load failure must not poison the page).
type WasmModule = typeof import('@/lib/wasm/agentkeys-web-core/agentkeys_web_core.js');

let modulePromise: Promise<WasmModule> | null = null;

export function loadWasmModule(): Promise<WasmModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const wasm = await import('@/lib/wasm/agentkeys-web-core/agentkeys_web_core.js');
      await wasm.default('/wasm/agentkeys_web_core_bg.wasm');
      return wasm;
    })();
    void modulePromise.catch(() => {
      modulePromise = null;
    });
  }
  return modulePromise;
}
