import { describe, it, expect, afterEach, vi } from "vitest";
import { chromium, type Browser } from "playwright";
import { signupEmailOtp } from "../../src/patterns/signup_email_otp.js";
import { setupMockSite } from "../fixtures/openrouter/mock-site.js";

const TEST_BASE_URL = "http://localhost:19998";

describe("patterns", () => {
  const browsers: Browser[] = [];

  afterEach(async () => {
    for (const browser of browsers) {
      await browser.close();
    }
    browsers.length = 0;
    vi.restoreAllMocks();
  });

  it("signup_email_otp_happy", async () => {
    const browser = await chromium.launch({ headless: true });
    browsers.push(browser);

    const page = await browser.newPage();
    await setupMockSite(page, TEST_BASE_URL);

    const mockEmailFetcher = vi.fn().mockResolvedValue("123456");

    const apiKey = await signupEmailOtp({
      page,
      signupUrl: `${TEST_BASE_URL}/auth`,
      emailSelector: 'input[name="email"]',
      submitButtonSelector: 'button[type="submit"]',
      otpSelector: 'input[name="otp"]',
      verifyButtonSelector: 'button[type="submit"]',
      postVerifyNavUrl: `${TEST_BASE_URL}/keys`,
      createKeyButtonSelector: 'button#create-key-btn, button:has-text("Create Key")',
      keyRevealSelector: 'span[data-testid="new-api-key"]',
      emailFetcher: mockEmailFetcher,
      emailAddress: "test@example.com",
      emailFromRegex: /noreply@example\.com/,
      emailSubjectRegex: /verify/i,
      emailCodeRegex: /(\d{6})/,
      emailTimeoutMs: 5000,
    });

    expect(apiKey).toBe("sk-or-v1-testvalid123456789");
    expect(mockEmailFetcher).toHaveBeenCalledTimes(1);
  });

  it("signup_email_otp_selector_timeout", async () => {
    const browser = await chromium.launch({ headless: true });
    browsers.push(browser);

    const page = await browser.newPage();
    // Serve a page without email input — missing the email selector
    await page.route(`${TEST_BASE_URL}/**`, (route) => {
      void route.fulfill({
        status: 200,
        contentType: "text/html",
        body: "<html><body><h1>No form here</h1></body></html>",
      });
    });

    const mockEmailFetcher = vi.fn().mockResolvedValue("123456");

    await expect(
      signupEmailOtp({
        page,
        signupUrl: `${TEST_BASE_URL}/auth`,
        emailSelector: 'input[name="email"]',
        submitButtonSelector: 'button[type="submit"]',
        otpSelector: 'input[name="otp"]',
        verifyButtonSelector: 'button[type="submit"]',
        postVerifyNavUrl: `${TEST_BASE_URL}/keys`,
        createKeyButtonSelector: 'button#create-key-btn',
        keyRevealSelector: 'span[data-testid="new-api-key"]',
        emailFetcher: mockEmailFetcher,
        emailAddress: "test@example.com",
        emailFromRegex: /noreply@example\.com/,
        emailSubjectRegex: /verify/i,
        emailCodeRegex: /(\d{6})/,
        emailTimeoutMs: 5000,
        selectorTimeoutMs: 1000,
      })
    ).rejects.toThrow();
  });
});
