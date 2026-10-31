import { afterEach, describe, expect, it, vi } from 'vitest';
import { Context } from '@deepseek-ai/cordis';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import * as webSearch from '../src/web-search.js';
import { API_KEY, BASE_URL } from '../src/generated/model-runtime.js';

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
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(provider.search({ query: 'test' })).rejects.toThrow('not configured');
    expect(fetchMock).not.toHaveBeenCalled();
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
    expect(init.redirect).toBe('error');
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
      vi.fn(async () => new Response('{"error":"synthetic-private-detail"}', { status: 429 })),
    );
    await expect(provider.search({ query: 'x' })).rejects.toThrow(/HTTP 429/);
    await expect(provider.search({ query: 'x' })).rejects.not.toThrow(/synthetic-private-detail/);
  });

  it('toSeamResult: empty answers → no content field; alien shapes → empty sources', () => {
    expect(webSearch.toSeamResult({ results: [], answers: [] })).toEqual({ sources: [], truncated: false });
    expect(webSearch.toSeamResult({ results: 'nope' })).toEqual({ sources: [], truncated: false });
    expect(webSearch.toSeamResult(null)).toEqual({ sources: [], truncated: false });
  });

  it('searchEndpoint derives from the shared model base and is empty-safe', () => {
    expect(webSearch.searchEndpoint({ [BASE_URL]: 'http://localhost:8077/v1/' })).toBe(
      'http://localhost:8077/v1/search',
    );
    expect(webSearch.searchEndpoint({})).toBe('');
  });

  it('never combines a partial explicit endpoint with an inherited credential', () => {
    const environment = { [BASE_URL]: 'http://localhost:8077/v1', [API_KEY]: 'synthetic-key' };
    expect(webSearch.searchConfiguration({}, environment)).toEqual({
      endpoint: 'http://localhost:8077/v1/search', apiKey: 'synthetic-key',
    });
    for (const config of [{ searchUrl: 'http://other.example/search' }, { apiKey: 'explicit-key' }]) {
      expect(() => webSearch.searchConfiguration(config, environment)).toThrow('supplied together');
    }
    for (const endpoint of ['file:///tmp/search', 'http://synthetic-key@localhost/search', 'http://localhost/search?key=synthetic-key']) {
      expect(() => webSearch.searchConfiguration({ searchUrl: endpoint, apiKey: 'synthetic-key' }, {})).toThrow('invalid search endpoint');
    }
  });

  it('refuses a real redirect without delivering the credential to its target', async () => {
    let targetCalls = 0;
    const target = createServer((_request, response) => { targetCalls++; response.end('{}'); });
    const redirect = createServer((_request, response) => {
      response.writeHead(307, { location: `http://127.0.0.1:${(target.address() as AddressInfo).port}/capture` });
      response.end();
    });
    try {
      await new Promise<void>((resolve) => target.listen(0, '127.0.0.1', resolve));
      await new Promise<void>((resolve) => redirect.listen(0, '127.0.0.1', resolve));
      const provider = await boot({ searchUrl: `http://127.0.0.1:${(redirect.address() as AddressInfo).port}/search` });
      await expect(provider.search({ query: 'test' })).rejects.toThrow();
      expect(targetCalls).toBe(0);
    } finally {
      for (const server of [redirect, target]) {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    }
  });
});
