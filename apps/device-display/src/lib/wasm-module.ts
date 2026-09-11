// Lazy, client-only, memoized load of the agentkeys-web-core wasm MODULE (the
// same pkg parent-control consumes; dev.sh build_wasm / CI copy it into
// src/wasm + public/wasm). On failure the memo is evicted so the next call
// retries — a transient load failure must not poison the page.
type WasmModule = typeof import('../wasm/agentkeys-web-core/agentkeys_web_core.js');

let modulePromise: Promise<WasmModule> | null = null;

export function loadWasmModule(): Promise<WasmModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const wasm = await import('../wasm/agentkeys-web-core/agentkeys_web_core.js');
      await wasm.default('/wasm/agentkeys_web_core_bg.wasm');
      return wasm;
    })();
    void modulePromise.catch(() => {
      modulePromise = null;
    });
  }
  return modulePromise;
}
