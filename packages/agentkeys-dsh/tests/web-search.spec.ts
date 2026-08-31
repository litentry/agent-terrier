import { afterEach, describe, expect, it, vi } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import * as webSearch from '../src/web-search.js';

// The plugin registers through the REAL ctx.web seam contract; a fake web
// service captures the provider so available()/search() run under test.
function fakeWeb() {
  const providers: any[] = [];
  return {
    service: {
      registerSearchProvider(provider: unknown) {
        providers.push(provider);
        return () => {};
      },
    },
    providers,
  };
}

let ctx: Context | undefined;
afterEach(async () => {
  vi.unstubAllGlobals();
  if (ctx) await ctx.fiber.dispose();
  ctx = undefined;
});

async function boot(config: Record<string, unknown> = {}) {
  ctx = new Context();
  const web = fakeWeb();
  ctx.provide('web', web.service);
  await ctx.plugin(webSearch, {
    searchUrl: 'http://gate.test/v1/search',
    apiKey: 'gk_test',
    ...config,
  });
  expect(web.providers.length).toBe(1);
  return web.providers[0];
}

const GATE_BODY = {
  engine: 'bing',
  results: [
    { title: 'Weather in Hangzhou', url: 'https://a.example/w', snippet: 'Sunny, 31°C.' },
    { title: '', url: 'https://b.example/7d', snippet: '' },
    { title: 'no url — dropped' },
  ],
  answers: ['31°C and sunny'],
};

describe('web_search provider (#653 — the ctx.web seam, never a second tool)', () => {
  it('registers the agentkeys-gate provider, available with the pair present', async () => {
    const provider = await boot();
    expect(provider.id).toBe('agentkeys-gate');
    expect(provider.available()).toBe(true);
  });

  it('reports unavailable (never crashes) when the spawn carries no gate pair', async () => {
    const provider = await boot({ searchUrl: '', apiKey: '' });
    expect(provider.available()).toBe(false);
  });

  it('POSTs the gate leg with the gk_ bearer and maps to the seam result shape', async () => {
    const provider = await boot();
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(GATE_BODY), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const result = await provider.search({ query: 'hangzhou weather', maxResults: 3 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://gate.test/v1/search');
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer gk_test');
    expect(JSON.parse(String(init.body))).toEqual({ q: 'hangzhou weather', count: 3 });
    expect(result.content).toBe('31°C and sunny');
    expect(result.sources).toEqual([
      { url: 'https://a.example/w', title: 'Weather in Hangzhou', snippet: 'Sunny, 31°C.' },
      { url: 'https://b.example/7d' },
    ]);
    // REQUIRED by the tool's output schema — absent ⇒ undefined ⇒ the
    // lossless-JSON output validation rejects the whole call (measured).
    expect(result.truncated).toBe(false);
  });

  it('surfaces a gate error status as a loud provider error', async () => {
    const provider = await boot();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('{"error":"budget exceeded"}', { status: 429 })),
    );
    await expect(provider.search({ query: 'x' })).rejects.toThrow(/HTTP 429/);
  });

  it('toSeamResult: empty answers → no content field; alien shapes → empty sources', () => {
    expect(webSearch.toSeamResult({ results: [], answers: [] })).toEqual({ sources: [], truncated: false });
    expect(webSearch.toSeamResult({ results: 'nope' })).toEqual({ sources: [], truncated: false });
    expect(webSearch.toSeamResult(null)).toEqual({ sources: [], truncated: false });
  });

  it('searchEndpoint derives from ARK_BASE_URL and is empty-safe', () => {
    expect(webSearch.searchEndpoint({ ARK_BASE_URL: 'https://gate.z/v1/' })).toBe(
      'https://gate.z/v1/search',
    );
    expect(webSearch.searchEndpoint({})).toBe('');
  });
});
