import { describe, it, expect, afterEach, vi } from "vitest";
import { chromium, type Browser } from "playwright";
import { runOpenRouterScraper } from "../../src/scrapers/openrouter.js";
import { makePhantomMockSite } from "../fixtures/openrouter/mock-site.js";

const TEST_BASE_URL = "http://localhost:19997";
const PHANTOM_KEY = "sk-or-v1-FAKE00000000000";

function captureEmittedEvents(): {
  getEvents: () => Array<Record<string, unknown>>;
  restore: () => void;
} {
  const captured: Array<Record<string, unknown>> = [];
  const originalWrite = process.stdout.write.bind(process.stdout);

  const replacement = (
    chunk: Uint8Array | string,
    encodingOrCb?: BufferEncoding | ((err?: Error | null) => void),
    cb?: (err?: Error | null) => void
  ): boolean => {
    const text = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf-8");
    for (const line of text.split("\n").filter((l) => l.length > 0)) {
      try {
        captured.push(JSON.parse(line) as Record<string, unknown>);
      } catch {
        // non-JSON line — ignore
      }
    }
    if (typeof encodingOrCb === "function") {
      return originalWrite(chunk, encodingOrCb);
    }
    if (encodingOrCb !== undefined && cb !== undefined) {
      return originalWrite(chunk, encodingOrCb, cb);
    }
    if (encodingOrCb !== undefined) {
      return originalWrite(chunk, encodingOrCb);
    }
    return originalWrite(chunk);
  };

  process.stdout.write = replacement as typeof process.stdout.write;

  return {
    getEvents: () => captured,
    restore: () => {
      process.stdout.write = originalWrite;
    },
  };
}

function make401FetchFn(): typeof fetch {
  return async (_input, init) => {
    const authHeader = (init?.headers as Record<string, string>)?.["Authorization"] ?? "";
    if (authHeader.includes("FAKE")) {
      return { status: 401, ok: false } as Response;
    }
    return { status: 200, ok: true } as Response;
  };
}

describe("scraper", () => {
  const browsers: Browser[] = [];

  afterEach(async () => {
    for (const browser of browsers) {
      await browser.close();
    }
    browsers.length = 0;
    vi.restoreAllMocks();
  });

  it("phantom_key_caught", async () => {
    const browser = await chromium.launch({ headless: true });
    browsers.push(browser);

    const setupPhantomSite = makePhantomMockSite(PHANTOM_KEY);
    const originalNewPage = browser.newPage.bind(browser);
    browser.newPage = async (...args) => {
      const page = await originalNewPage(...args);
      await setupPhantomSite(page, TEST_BASE_URL);
      return page;
    };

    const mockEmailFetcher = vi.fn().mockResolvedValue("123456");

    const phantomFetchFn = make401FetchFn();
    const mockVerifier = vi.fn().mockImplementation(
      async (verifyOpts: { service: string; key: string }) => {
        const { verify } = await import("../../src/lib/verify.js");
        return verify({ service: verifyOpts.service, key: verifyOpts.key, fetchFn: phantomFetchFn });
      }
    );

    const { getEvents, restore } = captureEmittedEvents();

    try {
      await expect(
        runOpenRouterScraper({
          browser,
          emailFetcher: mockEmailFetcher,
          verifier: mockVerifier,
          signupUrl: `${TEST_BASE_URL}/auth`,
        })
      ).rejects.toThrow("store_failed");
    } finally {
      restore();
    }

    const events = getEvents();

    const successEvent = events.find((e) => e["type"] === "success");
    expect(successEvent).toBeUndefined();

    const errorEvent = events.find((e) => e["type"] === "error");
    expect(errorEvent).toBeDefined();
    expect(errorEvent?.["code"]).toBe("store_failed");
    expect(String(errorEvent?.["details"])).toContain("phantom");

    expect(mockVerifier).toHaveBeenCalledWith({
      service: "openrouter",
      key: PHANTOM_KEY,
    });
  });
});
