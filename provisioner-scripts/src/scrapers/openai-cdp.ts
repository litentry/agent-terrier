// Production scraper — OpenAI signup → API-key mint.
//
// Contract:
//   stdout: newline-delimited JSON events, terminal {"type":"success","api_key":"sk-proj-..."}
//           or {"type":"error","code":"...","details":"..."}
//   stderr: timestamped progress logs
//   exit:   0 on success, 1 on failure
//
// Shell / direct:
//   node --import tsx/esm src/scrapers/openai-cdp.ts | jq -r 'select(.type=="success") | .api_key'
//
// Prereq: Chrome listening on CDP_URL (default http://localhost:9222).
//
// Required env:
//   AGENTKEYS_SIGNUP_EMAIL         fresh local-part
//   AGENTKEYS_SIGNUP_PASSWORD      strong password
//   AGENTKEYS_EMAIL_BACKEND        "gmail" | "ses-s3" | "mock-inbox" (default gmail)
//   (+ backend-specific vars: see src/lib/email.ts)
//
// Optional env:
//   CDP_URL                        default http://localhost:9222
//
// Flow length: ~90s (signup → password page → OTP email → /about-you profile
// → OAuth callback → keys page → instant-mint click → key extracted).

import { chromium, type Browser, type Page } from "playwright";
import { fetchAndAnalyzeSesEmail } from "../lib/email-analyzer.js";
import {
  clickFirstVisible,
  clickOuterCreate,
  humanType,
  jitterDelay,
} from "../lib/playwright-patterns.js";

const CDP_URL = process.env.CDP_URL ?? "http://localhost:9222";
const SIGNUP_EMAIL = process.env.AGENTKEYS_SIGNUP_EMAIL ?? "";
const SIGNUP_PASSWORD = process.env.AGENTKEYS_SIGNUP_PASSWORD ?? "";

// Start at platform; it redirects to auth.openai.com with a fresh session
// token. Navigating directly to /create-account breaks the session flow.
const SIGNUP_URL = "https://platform.openai.com/signup";
const KEYS_URL = "https://platform.openai.com/api-keys";

const FROM_REGEX = /@openai\.com|noreply|no-reply/i;
const SUBJECT_REGEX = /verify|verification|sign[-\s]?in|log[-\s]?in|code|one[-\s]?time|otp/i;
// AGENTKEYS_SES_BUCKET is set by scripts/stage6-demo-env.sh. The scraper
// uses the ses-s3 backend + full analyzeEmail pipeline so HTML-only content
// (like CSS hex colors near "141415") doesn't false-positive as the OTP.
const SES_BUCKET = process.env.AGENTKEYS_SES_BUCKET ?? "";

type Event =
  | { type: "progress"; step: string }
  | { type: "success"; api_key: string }
  | { type: "error"; code: string; details: string };

function emit(e: Event): void {
  process.stdout.write(JSON.stringify(e) + "\n");
}
const progress = (step: string): void => emit({ type: "progress", step });
const log = (msg: string): void => {
  process.stderr.write(`[openai] ${new Date().toISOString().slice(11, 19)} ${msg}\n`);
};

// Service-specific: OpenAI's /about-you post-verify profile form requires
// a name that LOOKS human (no digits) plus an age. Clicking "Finish creating
// account" without filling both (or with an invalid name like "Bot 7061")
// returns "Hmm, that doesn't look right." Name+age are the only required
// fields; birthday is hidden and computed from age via React.
async function completeOpenAIPostVerifyProfile(page: Page): Promise<boolean> {
  const NAME_SEL =
    'input[autocomplete="name"], input[id*="name" i][type="text"]:not([name*="company" i])';
  const AGE_SEL = 'input[id*="age" i][inputmode="numeric"], input[placeholder="Age"], input[name="age"]';

  const nameVisible = await page
    .locator(NAME_SEL)
    .first()
    .isVisible({ timeout: 2_000 })
    .catch(() => false);
  if (!nameVisible) return false;

  const firsts = ["Alex", "Jamie", "Taylor", "Morgan", "Casey", "Jordan", "Riley", "Avery"];
  const lasts = ["Parker", "Reed", "Hayes", "Bennett", "Foster", "Cole", "Quinn", "Shaw"];
  const pick = (arr: string[]): string => arr[Math.floor(Math.random() * arr.length)]!;
  await humanType(page, NAME_SEL, `${pick(firsts)} ${pick(lasts)}`);
  await jitterDelay(200, 500);

  const ageVisible = await page
    .locator(AGE_SEL)
    .first()
    .isVisible({ timeout: 500 })
    .catch(() => false);
  if (ageVisible) {
    await humanType(page, AGE_SEL, "28");
    // React-controlled hidden birthday field recomputes from age on input.
    // Give the reactive cycle a beat + Tab blur before submit.
    await jitterDelay(600, 1_000);
    await page.keyboard.press("Tab").catch(() => {});
    await jitterDelay(200, 400);
  }

  const clicked = await clickFirstVisible(page, [
    'button:text-is("Finish creating account")',
    'button:has-text("Finish")',
    'button:text-is("Continue")',
    'form button[type="submit"]',
  ]);
  if (!clicked) return false;

  await page
    .waitForURL((u) => !/\/about-you|\/create-account|\/email-verification/i.test(u.toString()), {
      timeout: 30_000,
    })
    .catch(() => {});
  return true;
}

// Fill OTP digits using pressSequentially + explicit input/change event
// dispatch. Some variants render as 1 input, some as 6 separate inputs.
async function fillOtp(page: Page, code: string): Promise<void> {
  const OTP_SEL =
    'input[name="code"], input[name="otp"], input[inputmode="numeric"], input[autocomplete="one-time-code"]';
  const inputs = await page.locator(OTP_SEL).all();
  const type = async (el: (typeof inputs)[number], v: string): Promise<void> => {
    await el.click();
    await el.pressSequentially(v, { delay: 80 });
    await el.dispatchEvent("input");
    await el.dispatchEvent("change");
  };
  if (inputs.length === 1) {
    await type(inputs[0]!, code);
  } else if (inputs.length === 6) {
    for (let i = 0; i < 6; i++) await type(inputs[i]!, code[i]!);
  } else {
    throw new Error(`unexpected OTP input count: ${inputs.length}`);
  }
  await jitterDelay(300, 700);
  // Wait for submit button to enable (React form validation may debounce).
  const submitBtn = page.getByRole("button", { name: /verify|submit|continue|confirm/i }).first();
  for (let i = 0; i < 20; i++) {
    if (await submitBtn.isEnabled().catch(() => false)) break;
    await page.waitForTimeout(250);
  }
  if (await submitBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await submitBtn.click({ timeout: 10_000 }).catch(() => {});
  }
}

async function main(): Promise<void> {
  if (!SIGNUP_EMAIL || !SIGNUP_PASSWORD) {
    emit({
      type: "error",
      code: "missing-env",
      details: "AGENTKEYS_SIGNUP_EMAIL and AGENTKEYS_SIGNUP_PASSWORD required",
    });
    process.exit(1);
  }

  progress("cdp-connect");
  log(`connecting to CDP at ${CDP_URL}`);
  const browser: Browser = await chromium.connectOverCDP(CDP_URL);
  const ctx = browser.contexts()[0] ?? (await browser.newContext());
  await ctx.clearCookies().catch(() => {});
  const page: Page = ctx.pages()[0] ?? (await ctx.newPage());

  try {
    progress("goto-signup");
    log("navigating to signup (platform → auth redirect)");
    await page.goto(SIGNUP_URL, { waitUntil: "load", timeout: 30_000 });

    progress("signup-email");
    const EMAIL_SEL = 'input[type="email"], input[name*="email" i]';
    await page.locator(EMAIL_SEL).first().waitFor({ timeout: 15_000 });
    await humanType(page, EMAIL_SEL, SIGNUP_EMAIL);
    await jitterDelay(250, 550);

    // Multi-step: click Continue, wait for password page.
    progress("click-continue-1");
    const clickedEmail = await clickFirstVisible(page, [
      'button:text-is("Continue")',
      'form button[type="submit"]:not(:has-text("Google")):not(:has-text("Apple")):not(:has-text("Microsoft")):not(:has-text("GitHub"))',
    ]);
    if (!clickedEmail) {
      emit({ type: "error", code: "selector-missing", details: "no Continue after email" });
      process.exit(1);
    }

    progress("signup-password");
    const PW_SEL = 'input[type="password"], input[name*="password" i]';
    await page.locator(PW_SEL).first().waitFor({ state: "visible", timeout: 20_000 });
    await humanType(page, PW_SEL, SIGNUP_PASSWORD);
    await jitterDelay(300, 700);

    progress("click-continue-2");
    const clickedPw = await clickFirstVisible(page, [
      'button:text-is("Continue")',
      'form button[type="submit"]:not(:has-text("Google")):not(:has-text("Apple")):not(:has-text("Microsoft")):not(:has-text("GitHub"))',
    ]);
    if (!clickedPw) {
      emit({ type: "error", code: "selector-missing", details: "no Continue after password" });
      process.exit(1);
    }

    progress("fetch-otp-email");
    log("polling SES S3 for OpenAI OTP email (HTML-strip + label-aware)");
    if (!SES_BUCKET) {
      emit({ type: "error", code: "missing-env", details: "AGENTKEYS_SES_BUCKET required (source scripts/stage6-demo-env.sh)" });
      process.exit(1);
    }
    const analysis = await fetchAndAnalyzeSesEmail({
      bucket: SES_BUCKET,
      fromPattern: FROM_REGEX,
      subjectPattern: SUBJECT_REGEX,
      timeoutMs: 120_000,
    });
    if (analysis.verifyType !== "otp") {
      emit({
        type: "error",
        code: "otp-not-found",
        details: `analyzer returned verifyType=${analysis.verifyType} for post-signup email; expected OTP`,
      });
      process.exit(1);
    }
    const otpCode = analysis.code;
    log(`OTP received (label-aware): ${otpCode.slice(0, 2)}****`);

    progress("fill-otp");
    await fillOtp(page, otpCode);

    // Wait for URL to leave /email-verification (OpenAI redirects to /about-you).
    await page
      .waitForURL((u) => !/\/email-verification\b/.test(u.toString()), { timeout: 30_000 })
      .catch(() => {});

    progress("complete-profile");
    log("filling /about-you profile (name + age)");
    const profileDone = await completeOpenAIPostVerifyProfile(page);
    if (!profileDone) {
      log("profile form not present (already logged in?) — continuing");
    }

    // OAuth callback from auth.openai.com → platform.openai.com/auth/callback?code=...
    // Router needs ~3s to settle before keys page renders cleanly.
    if (/\/(auth\/callback|about-you|email-verification|create-account)/i.test(page.url())) {
      await page
        .waitForURL(
          (u) => !/\/(auth\/callback|about-you|email-verification|create-account)/i.test(u.toString()),
          { timeout: 15_000 },
        )
        .catch(() => {});
      await page.waitForTimeout(3_000);
    }

    progress("goto-keys");
    log("navigating to platform keys page");
    await page.goto(KEYS_URL, { waitUntil: "load", timeout: 20_000 });

    progress("click-create");
    log("clicking Create new secret key (instant-mint UI)");
    const clickedCreate = await clickOuterCreate(page);
    if (!clickedCreate) {
      emit({ type: "error", code: "selector-missing", details: "no visible Create Key button on keys page" });
      process.exit(1);
    }

    progress("extract-key");
    // OpenAI instant-mints — the revealed `sk-proj-*` appears immediately on
    // the page, no Name dialog. Extraction matches long-shape keys only so
    // masked table-row previews (`sk-...xyz`) don't false-positive.
    const keyEl = page
      .locator('code:has-text("sk-"), pre:has-text("sk-"), input[value^="sk-"]')
      .first();
    await keyEl.waitFor({ state: "visible", timeout: 15_000 });
    const tag = await keyEl.evaluate((n) => n.tagName.toLowerCase());
    const raw =
      tag === "input"
        ? await keyEl.inputValue()
        : ((await keyEl.textContent()) ?? "");
    const key = raw.trim();
    if (!/^sk-[a-zA-Z0-9_-]{20,}$/.test(key)) {
      emit({ type: "error", code: "key-format", details: `extracted value didn't match sk-*: ${key.slice(0, 40)}` });
      process.exit(1);
    }

    log(`minted key: ${key.slice(0, 10)}****${key.slice(-4)}`);
    emit({ type: "success", api_key: key });
  } finally {
    await page.close().catch(() => {});
    await browser.close().catch(() => {});
  }
  process.exit(0);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  emit({ type: "error", code: "fatal", details: msg });
  log(`FATAL: ${msg}`);
  process.exit(1);
});
