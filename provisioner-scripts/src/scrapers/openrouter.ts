import type { Browser } from "playwright";
import { emit } from "../types.js";
import type { VerifyResult } from "../lib/verify.js";
import { signupEmailOtp } from "../patterns/signup_email_otp.js";

export interface OpenRouterScraperOpts {
  browser: Browser;
  emailFetcher: (
    from: RegExp,
    subject: RegExp,
    codeRegex: RegExp,
    timeoutMs: number
  ) => Promise<string>;
  verifier: (opts: { service: string; key: string }) => Promise<VerifyResult>;
  signupUrl?: string;
  selectorTimeoutMs?: number;
}

class ScraperAbortError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScraperAbortError";
  }
}

const EMAIL_SELECTOR = 'input[name="email"]';
const SUBMIT_BUTTON_SELECTOR = 'button[type="submit"]';
const OTP_SELECTOR = 'input[name="otp"]';
const VERIFY_BUTTON_SELECTOR = 'button[type="submit"]';
const CREATE_KEY_BUTTON_SELECTOR = 'button#create-key-btn, button:has-text("Create Key")';
const KEY_REVEAL_SELECTOR = 'span[data-testid="new-api-key"]';

const EMAIL_FROM_REGEX = /noreply@openrouter\.ai/;
const EMAIL_SUBJECT_REGEX = /openrouter/i;
const EMAIL_CODE_REGEX = /(\d{6})/;
const EMAIL_TIMEOUT_MS = 60_000;

const OPENROUTER_EMAIL = process.env["AGENTKEYS_EMAIL_USER"] ?? "user@example.com";

export async function runOpenRouterScraper(opts: OpenRouterScraperOpts): Promise<void> {
  const signupUrl =
    opts.signupUrl ?? process.env["OPENROUTER_SIGNUP_URL"] ?? "https://openrouter.ai/auth";

  const baseUrl = new URL(signupUrl).origin;
  const startedAt = Date.now();
  const page = await opts.browser.newPage();

  try {
    emit({ type: "progress", step: "navigating_to_signup" });
    emit({ type: "progress", step: "filling_email" });

    let apiKey: string;
    try {
      apiKey = await signupEmailOtp({
        page,
        signupUrl,
        emailSelector: EMAIL_SELECTOR,
        submitButtonSelector: SUBMIT_BUTTON_SELECTOR,
        otpSelector: OTP_SELECTOR,
        verifyButtonSelector: VERIFY_BUTTON_SELECTOR,
        postVerifyNavUrl: `${baseUrl}/keys`,
        createKeyButtonSelector: CREATE_KEY_BUTTON_SELECTOR,
        keyRevealSelector: KEY_REVEAL_SELECTOR,
        emailFetcher: opts.emailFetcher,
        emailAddress: OPENROUTER_EMAIL,
        emailFromRegex: EMAIL_FROM_REGEX,
        emailSubjectRegex: EMAIL_SUBJECT_REGEX,
        emailCodeRegex: EMAIL_CODE_REGEX,
        emailTimeoutMs: EMAIL_TIMEOUT_MS,
        selectorTimeoutMs: opts.selectorTimeoutMs,
      });
    } catch (err) {
      const elapsedMs = Date.now() - startedAt;
      const errMessage = err instanceof Error ? err.message : String(err);
      if (errMessage.includes("Timeout") || errMessage.includes("timeout")) {
        emit({
          type: "tripwire",
          kind: "selector_timeout",
          step: "signup_flow",
          elapsed_ms: elapsedMs,
        });
        throw new ScraperAbortError("selector_timeout:signup_flow");
      }
      emit({
        type: "tripwire",
        kind: "email_timeout",
        step: "fetch_otp",
        elapsed_ms: elapsedMs,
      });
      throw new ScraperAbortError(`signup_flow_error:${errMessage}`);
    }

    emit({ type: "progress", step: "verifying_key" });
    const verifyResult = await opts.verifier({ service: "openrouter", key: apiKey });

    if (verifyResult.valid) {
      emit({ type: "success", api_key: apiKey });
    } else {
      emit({
        type: "error",
        code: "store_failed",
        details: `key verification failed: ${verifyResult.reason}`,
      });
      throw new ScraperAbortError(`store_failed:${verifyResult.reason}`);
    }
  } finally {
    await page.close();
  }
}

export default async function main(): Promise<void> {
  const { chromium } = await import("playwright");
  const { fetchVerificationCode } = await import("../lib/email.js");
  const { verify } = await import("../lib/verify.js");

  const browser = await chromium.launch({ headless: true });
  try {
    await runOpenRouterScraper({
      browser,
      emailFetcher: (from, subject, codeRegex, timeoutMs) =>
        fetchVerificationCode({ from, subject, codeRegex, timeoutMs }),
      verifier: verify,
    });
  } catch (err) {
    if (err instanceof ScraperAbortError) {
      process.exit(1);
    }
    throw err;
  } finally {
    await browser.close();
  }
}
