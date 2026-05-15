// KNOWN BROKEN — DOM drift on openrouter signup page.
// Tracked: https://github.com/litentry/agentKeys/issues/83 (label: provision-fix)
// Symptom: `agentkeys provision openrouter` exits with
//   `trip_wire_fired ... kind:"SelectorTimeout" step:"signup_flow"`.
// Root cause: openrouter changed the signup-page DOM since selectors below
// were last verified. The auto-provision pipeline upstream (mint-oidc-jwt
// + AssumeRoleWithWebIdentity + env-injection) still works — only the
// scraper's selectors are stale. Re-record via the
// `agentkeys-record-scraper` skill to refresh.
import { fileURLToPath } from "url";
import type { Browser } from "playwright";
import { emit, type ProvisionEvent } from "../types.js";
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

// IMAP login — must be the canonical Gmail address (plus-addressing aliases
// are not valid IMAP logins).
const IMAP_LOGIN_EMAIL = process.env["AGENTKEYS_EMAIL_USER"] ?? "user@example.com";
// What we type into the service's signup form. Defaults to the IMAP login but
// can be overridden (e.g. plus-addressed `you+or-<ts>@gmail.com`) so returning
// users can mint a fresh account per run while reusing one real inbox.
const SIGNUP_EMAIL = process.env["AGENTKEYS_SIGNUP_EMAIL"] ?? IMAP_LOGIN_EMAIL;

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
        emailAddress: SIGNUP_EMAIL,
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

// Emit a terminal event and wait for stdout to flush before exiting. Using a
// bare `process.exit` can drop buffered writes to the parent's pipe — which is
// exactly how the orchestrator ends up reporting "subprocess ended without
// terminal event" when something upstream of the scraper's try/catch throws.
function emitAndExit(event: ProvisionEvent, exitCode: number): void {
  process.stdout.write(JSON.stringify(event) + "\n", () => process.exit(exitCode));
}

export default async function main(): Promise<void> {
  try {
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
    } finally {
      await browser.close();
    }
  } catch (err) {
    if (err instanceof ScraperAbortError) {
      // Tripwire / expected-error path: the scraper already emitted a terminal
      // event (tripwire or error) before throwing. Just propagate the exit.
      emitAndExit(
        { type: "error", code: "internal", details: `abort: ${err.message}` },
        1,
      );
      return;
    }
    // Unhandled path: a throw that escaped the scraper's try/catch — e.g.
    // Playwright browser-launch failure, IMAP connection refused, dynamic
    // import failure, unhandled rejection in the pattern. Without this
    // catch-all the orchestrator sees a naked process exit and reports
    // "subprocess ended without terminal event" with no cause.
    const msg = err instanceof Error ? (err.stack ?? err.message) : String(err);
    emitAndExit({ type: "error", code: "internal", details: `unhandled: ${msg}` }, 2);
  }
}

// Entry-point guard. Invoke main() only when this file is the direct script
// target (e.g. `npx tsx src/scrapers/openrouter.ts`). When the module is
// imported by test files that only use named exports like
// `runOpenRouterScraper`, main() must NOT run — otherwise tests would launch
// a real browser and hit real OpenRouter. Without this block, the provisioner
// subprocess just loads the module, reaches EOF, and exits 0 with no events —
// exactly the "exit_code: Some(0) / events_emitted: 0" failure mode.
const isEntry = fileURLToPath(import.meta.url) === process.argv[1];
if (isEntry) {
  void main();
}
