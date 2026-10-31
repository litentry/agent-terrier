/** Optional relay-backed provider for the existing web-search tool. */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { API_KEY, BASE_URL } from './generated/model-runtime.js';

export const name = 'agentkeys-web-search';
export const inject = ['web'];

export interface Config {
  /** An explicit endpoint and credential must be configured together. */
  searchUrl?: string;
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
  const base = (env[BASE_URL] ?? '').trim().replace(/\/+$/, '');
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

export function searchConfiguration(config: Config, environment: Record<string, string | undefined>) {
  const explicit = Boolean(config.searchUrl?.trim() || config.apiKey?.trim());
  const endpoint = explicit ? (config.searchUrl ?? '').trim() : searchEndpoint(environment);
  const apiKey = explicit ? (config.apiKey ?? '').trim() : (environment[API_KEY] ?? '').trim();
  if (Boolean(endpoint) !== Boolean(apiKey)) throw new Error('search endpoint and credential must be supplied together');
  if (endpoint) {
    let parsed: URL;
    try { parsed = new URL(endpoint); } catch { throw new Error('invalid search endpoint'); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new Error('invalid search endpoint');
    }
    if (/[\x00-\x20\x7f]/.test(apiKey)) throw new Error('invalid search credential');
  }
  return { endpoint, apiKey };
}

export function apply(ctx: Context, config: Config): void {
  const { endpoint, apiKey } = searchConfiguration(config, process.env);
  const maxResults = config.maxResults ?? 5;
  const timeoutMs = config.timeoutMs ?? 25000;

  (ctx as unknown as { web: WebSeam }).web.registerSearchProvider({
    id: 'agentkeys-gate',
    available: () => Boolean(endpoint && apiKey),
    search: async (
      request: { query: string; maxResults?: number },
      signal?: AbortSignal,
    ): Promise<WebSearchResult> => {
      if (!endpoint || !apiKey) throw new Error('web_search is not configured');
      const q = String(request.query ?? '').trim();
      if (!q) throw new Error('web_search: empty query');
      const count = Math.min(Math.max(Math.trunc(request.maxResults ?? maxResults), 1), 10);
      const timeout = AbortSignal.timeout(timeoutMs);
      const resp = await fetch(endpoint, {
        method: 'POST',
        redirect: 'error',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({ q, count }),
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      });
      if (!resp.ok) {
        throw new Error(`agentkeys-gate search failed: HTTP ${resp.status}`);
      }
      return toSeamResult(await resp.json());
    },
  });
}
