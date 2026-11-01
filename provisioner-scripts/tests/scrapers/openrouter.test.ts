import { describe, it, expect, afterEach, vi } from "vitest";
import { chromium, type Browser, type Page } from "playwright";
import { runOpenRouterScraper } from "../../src/scrapers/openrouter.js";
import { setupMockSite } from "../fixtures/openrouter/mock-site.js";
import type { VerifyResult } from "../../src/lib/verify.js";

const TEST_BASE_URL = "http://localhost:19999";

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

function patchBrowserWithRoutes(
  browser: Browser,
  setupFn: (page: Page) => Promise<void>
): void {
  const originalNewPage = browser.newPage.bind(browser);
  browser.newPage = async (...args) => {
    const newPage = await originalNewPage(...args);
    await setupFn(newPage);
    return newPage;
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

  it("happy_path", async () => {
    const browser = await chromium.launch({ headless: true });
    browsers.push(browser);

    patchBrowserWithRoutes(browser, (page) => setupMockSite(page, TEST_BASE_URL));

    const mockEmailFetcher = vi.fn().mockResolvedValue("123456");
    const mockVerifier = vi.fn().mockResolvedValue({ valid: true } as VerifyResult);

    const { getEvents, restore } = captureEmittedEvents();
    try {
      await runOpenRouterScraper({
        browser,
        emailFetcher: mockEmailFetcher,
        verifier: mockVerifier,
        signupUrl: `${TEST_BASE_URL}/auth`,
      });
    } finally {
      restore();
    }

    const events = getEvents();
    const successEvent = events.find((e) => e["type"] === "success");
    expect(successEvent).toBeDefined();
    expect(successEvent?.["api_key"]).toBe("sk-or-v1-testvalid123456789");
    expect(mockEmailFetcher).toHaveBeenCalledTimes(1);
    expect(mockVerifier).toHaveBeenCalledWith({
      service: "openrouter",
      key: "sk-or-v1-testvalid123456789",
    });
  });

  it("selector_timeout", async () => {
    const browser = await chromium.launch({ headless: true });
    browsers.push(browser);

    // Serve a page without email input — triggers selector timeout
    patchBrowserWithRoutes(browser, async (page) => {
      await page.route(`${TEST_BASE_URL}/**`, (route) => {
        void route.fulfill({
          status: 200,
          contentType: "text/html",
          body: "<html><body><h1>No form here</h1></body></html>",
        });
      });
    });

    const mockEmailFetcher = vi.fn().mockResolvedValue("123456");
    const mockVerifier = vi.fn().mockResolvedValue({ valid: true } as VerifyResult);

    const { getEvents, restore } = captureEmittedEvents();
    try {
      await expect(
        runOpenRouterScraper({
          browser,
          emailFetcher: mockEmailFetcher,
          verifier: mockVerifier,
          signupUrl: `${TEST_BASE_URL}/auth`,
          selectorTimeoutMs: 1000,
        })
      ).rejects.toThrow("selector_timeout");
    } finally {
      restore();
    }

    const events = getEvents();
    const tripwireEvent = events.find((e) => e["type"] === "tripwire");
    expect(tripwireEvent).toBeDefined();
    expect(tripwireEvent?.["kind"]).toBe("selector_timeout");
  });

  it("verification_failure", async () => {
    const browser = await chromium.launch({ headless: true });
    browsers.push(browser);

    patchBrowserWithRoutes(browser, (page) => setupMockSite(page, TEST_BASE_URL));

    const mockEmailFetcher = vi.fn().mockResolvedValue("123456");
    const mockVerifier = vi.fn().mockResolvedValue({
      valid: false,
      reason: "phantom",
    } as VerifyResult);

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
    const errorEvent = events.find((e) => e["type"] === "error");
    expect(errorEvent).toBeDefined();
    expect(errorEvent?.["code"]).toBe("store_failed");
  });
});
