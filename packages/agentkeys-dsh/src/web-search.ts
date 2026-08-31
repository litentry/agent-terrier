/**
 * @module @agentkeys/dsh-suite/web-search — the gate-backed SEARCH PROVIDER
 * (#653) for dsh's own `web_search` tool.
 *
 * dsh ships the model-facing tool in `@deepseek-ai/dsh-tool-web` and routes it
 * through the `ctx.web` capability seam (`@deepseek-ai/dsh-web`), which is a
 * PROVIDER REGISTRY — registering a second global `web_search` tool is refused
 * at boot ("already registered", the 2026-08-31 pod crashloop). So this plugin
 * plugs the seam instead: it registers the `agentkeys-gate` search provider,
 * which POSTs the gate's `/v1/search` relay (SearXNG behind the gate, engine
 * set gate-pinned — Bing by deployment default) with the injected
 * `ARK_BASE_URL`+`ARK_API_KEY` pair (#572 rule: base + key travel together).
 * Selection: dsh-base PINS `web.config.searchProvider: deepseek-official`
 * (config beats the DSH_WEB_SEARCH_PROVIDER env), so the profile's
 * cordis.patch.yml overrides that entry's config to `agentkeys-gate` — the
 * registration here only matters together with that selection patch. The
 * tool stays `tool:web`-classed for the #611 guard (mapping.ts).
 * NO default export (dsh postmortem 0001).
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';

export const name = 'agentkeys-web-search';
export const inject = ['web'];

export interface Config {
  /** Full search endpoint. Default: `${ARK_BASE_URL}/search` (the gate base). */
  searchUrl?: string;
  /** Bearer for the gate. Default: env ARK_API_KEY (the gk_ relay key). */
  apiKey?: string;
  maxResults?: number;
  timeoutMs?: number;
}

export const Config: z<Config> = z.object({
  searchUrl: z.string(),
  apiKey: z.string(),
  maxResults: z.number().default(5),
  timeoutMs: z.number().default(25000),
});

/** The gate search endpoint from the injected model-path pair. Empty = the
 *  spawn carries no gate base (unprovisioned) — the provider then reports
 *  unavailable and the seam surfaces its structured error, never a crash. */
export function searchEndpoint(env: Record<string, string | undefined>): string {
  const base = (env.ARK_BASE_URL ?? '').trim().replace(/\/+$/, '');
  return base ? `${base}/search` : '';
}

/** One source row in the seam's search result. */
interface WebSearchSource {
  url: string;
  title?: string;
  snippet?: string;
}
/** The seam's search result shape (`dsh-web`): optional provider answer +
 *  source list. `truncated` is REQUIRED — the tool's output schema declares it
 *  `required: true` and copies it verbatim, so an absent field lands as
 *  `undefined` and fails the lossless-JSON output validation (measured in the
 *  local twin). The seam's own capSources flips it to true when it trims. */
interface WebSearchResult {
  content?: string;
  sources: WebSearchSource[];
  truncated: boolean;
}

/** Map the gate's compact `/v1/search` body to the seam's result shape.
 *  Pure (unit-tested). */
export function toSeamResult(body: unknown): WebSearchResult {
  const b = (body ?? {}) as {
    results?: Array<{ title?: unknown; url?: unknown; snippet?: unknown }>;
    answers?: unknown[];
  };
  const sources: WebSearchSource[] = Array.isArray(b.results)
    ? b.results
        .filter((r) => typeof r?.url === 'string' && r.url.length > 0)
        .map((r) => ({
          url: String(r.url),
          ...(typeof r.title === 'string' && r.title.length > 0 ? { title: r.title } : {}),
          ...(typeof r.snippet === 'string' && r.snippet.length > 0 ? { snippet: r.snippet } : {}),
        }))
    : [];
  const answers = Array.isArray(b.answers) ? b.answers.filter((a) => typeof a === 'string' && a.length > 0) : [];
  return {
    ...(answers.length > 0 ? { content: answers.join('\n') } : {}),
    sources,
    truncated: false,
  };
}

/** The `ctx.web` seam surface this plugin consumes (typed locally — the suite
 *  does not depend on `@deepseek-ai/dsh-web`; the host provides the service). */
interface WebSeam {
  registerSearchProvider(provider: {
    id: string;
    available(): boolean;
    search(request: { query: string; maxResults?: number }, signal?: AbortSignal): Promise<WebSearchResult>;
  }): unknown;
}

export function apply(ctx: Context, config: Config): void {
  const endpoint = (config.searchUrl ?? '').trim() || searchEndpoint(process.env);
  const apiKey = (config.apiKey ?? '').trim() || (process.env.ARK_API_KEY ?? '').trim();
  const maxResults = config.maxResults ?? 5;
  const timeoutMs = config.timeoutMs ?? 25000;

  (ctx as unknown as { web: WebSeam }).web.registerSearchProvider({
    id: 'agentkeys-gate',
    available: () => Boolean(endpoint && apiKey),
    search: async (
      request: { query: string; maxResults?: number },
      signal?: AbortSignal,
    ): Promise<WebSearchResult> => {
      const q = String(request.query ?? '').trim();
      if (!q) throw new Error('web_search: empty query');
      const count = Math.min(Math.max(Math.trunc(request.maxResults ?? maxResults), 1), 10);
      const timeout = AbortSignal.timeout(timeoutMs);
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({ q, count }),
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      });
      if (!resp.ok) {
        const detail = (await resp.text().catch(() => '')).slice(0, 300);
        throw new Error(
          `agentkeys-gate search failed: HTTP ${resp.status}${detail ? ` — ${detail}` : ''}`,
        );
      }
      return toSeamResult(await resp.json());
    },
  });
}
