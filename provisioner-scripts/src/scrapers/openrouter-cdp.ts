// Production scraper — OpenRouter signup → API-key mint.
//
// Contract:
//   stdin:  —
//   stdout: newline-delimited JSON events, terminal {"type":"success","api_key":"sk-or-v1-..."}
//           or {"type":"error","code":"...","details":"..."} on failure
//   stderr: timestamped progress logs (for humans reading live)
//   exit:   0 on success, 1 on failure
//
// Shell / direct use:
//   node --import tsx/esm src/scrapers/openrouter-cdp.ts | jq -r 'select(.type=="success") | .api_key'
//
// Rust provisioner use: the daemon's `spawn_and_collect` already consumes
// this JSON-event contract — drops in with no wrapper.
//
// Why CDP-to-real-Chrome and not Playwright-launched Chromium:
//   Cloudflare Turnstile detects --enable-automation (baked into Playwright's
//   bundled Chromium) and refuses to issue tokens. Connecting via CDP to a
//   user-launched real Chrome avoids the flag entirely.
//
// Prereq: Chrome listening on CDP_URL (default http://localhost:9222). The
// `scripts/utils/demo/reset-chrome-for-recording.sh` script in the repo root launches
// the expected throwaway profile. Alternatively:
//   /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
//     --remote-debugging-port=9222 \
//     --user-data-dir=/tmp/agentkeys-chrome-profile &
//
// Required env:
//   AGENTKEYS_SIGNUP_EMAIL         fresh local-part (Clerk rejects plus-alias reuse)
//   AGENTKEYS_SIGNUP_PASSWORD      strong password
//   AGENTKEYS_EMAIL_BACKEND        "gmail" | "ses-s3" | "mock-inbox" (default gmail)
//   (+ backend-specific vars: see src/lib/email.ts)
//
// Optional env:
//   CDP_URL                        default http://localhost:9222

import { chromium, type Browser, type Page } from "playwright";
import { fetchVerificationCode } from "../lib/email.js";
import {
  clickFirstVisible,
  clickOuterCreate,
  dismissCookieBanner,
  humanType,
  jitterDelay,
  probeAndDismissDialog,
} from "../lib/playwright-patterns.js";
import { handleTurnstile } from "../lib/captcha/turnstile.js";

const CDP_URL = process.env.CDP_URL ?? "http://localhost:9222";
// Issue #83: when the CLI injects AGENTKEYS_USER_WALLET (lowercase hex
// 0x-address derived from the OIDC JWT), derive a routable signup email
// of the form `or-${wallet}-${ts}@${MAIL_DOMAIN}` so the SES routing
// Lambda copies the verification email into `bots/${wallet}/inbound/`
// (readable by the operator's PrincipalTag-scoped data-role). Falling
// back to AGENTKEYS_SIGNUP_EMAIL keeps manual / pre-Lambda invocations
// working: in that mode the email backend polls the legacy `inbound/`
// (admin profile creds required).
const USER_WALLET = (process.env.AGENTKEYS_USER_WALLET ?? "").toLowerCase();
const MAIL_DOMAIN = process.env.AGENTKEYS_MAIL_DOMAIN ?? "bots.example.invalid";
const SIGNUP_EMAIL =
  USER_WALLET !== ""
    ? `or-${USER_WALLET}-${Math.floor(Date.now() / 1000)}@${MAIL_DOMAIN}`
    : (process.env.AGENTKEYS_SIGNUP_EMAIL ?? "");
const SIGNUP_PASSWORD = process.env.AGENTKEYS_SIGNUP_PASSWORD ?? "";

const SIGNUP_URL = "https://openrouter.ai/auth";
const KEYS_URL = "https://openrouter.ai/workspaces/default/keys";

// Real sender observed: "OpenRouter <notifications@openrouter.ai>".
const FROM_REGEX = /@openrouter\.ai|clerk/i;
// Subjects observed: "Your sign up link", "Verify your email for OpenRouter".
const SUBJECT_REGEX = /sign[\s-]?up.*link|sign[\s-]?in.*link|magic.*link|verify|verification|confirm/i;
// Clerk magic-link URL shape.
const URL_REGEX = /(https:\/\/[^\s<>"'\)]*(?:clerk|\/verify|ticket=|verification)[^\s<>"'\)]*)/i;

// JSON-line event emitter — contract shared with the Rust provisioner's
// `spawn_and_collect` parser. Progress events are informational; exactly
// one terminal event (success | error) MUST be emitted per run.
type Event =
  | { type: "progress"; step: string }
  | { type: "success"; api_key: string }
  | { type: "error"; code: string; details: string };

function emit(e: Event): void {
  process.stdout.write(JSON.stringify(e) + "\n");
}
const progress = (step: string): void => emit({ type: "progress", step });
const log = (msg: string): void => {
  process.stderr.write(`[openrouter] ${new Date().toISOString().slice(11, 19)} ${msg}\n`);
};

// Service-specific: OpenRouter chains TWO modals after signup that each
// block the keys page:
//   1. Survey: "Where did you first hear about OpenRouter?" — select an
//      option button (we use "Other / Not sure") then click Continue.
//   2. Welcome: "You're all set!" — click Close (X).
// Either or both may render; both may render sequentially.
async function dismissOpenRouterOnboardingModals(
  page: Page,
  detectTimeoutMs = 500,
): Promise<boolean> {
  return probeAndDismissDialog({
    page,
    textRegex:
      /where did you first hear|you'?re all set|welcome to|get started by buying/i,
    detectTimeoutMs,
    maxRounds: 4,
    dismissFn: async (p) => {
      // Decide branch by peeking at dialog textContent.
      const text = await p
        .evaluate(() => {
          const d = Array.from(document.querySelectorAll('[role="dialog"]')).find(
            (el) => !!((el as HTMLElement).offsetWidth || (el as HTMLElement).offsetHeight),
          );
          return (d?.textContent ?? "").toLowerCase();
        })
        .catch(() => "");
      if (text.includes("where did you first hear")) {
        // Survey branch: click "Other / Not sure" then Continue.
        const optionLabels = [
          /^other\s*\/\s*not sure$/i,
          /^other.*not sure$/i,
          /^skip$/i,
          /^not now$/i,
          /^other$/i,
        ];
        for (const lbl of optionLabels) {
          const btn = p.getByRole("button", { name: lbl }).first();
          if (!(await btn.isVisible({ timeout: 300 }).catch(() => false))) continue;
          await btn.click({ timeout: 3_000, force: true }).catch(() => {});
          break;
        }
        await p.waitForTimeout(250);
        await p
          .getByRole("button", { name: /^continue$/i })
          .first()
          .click({ timeout: 5_000, force: true })
          .catch(() => {});
      } else {
        // Welcome banner: click Close (X).
        const closeBtn = p.getByRole("button", { name: /^close$/i }).first();
        if (await closeBtn.isVisible({ timeout: 500 }).catch(() => false)) {
          await closeBtn.click({ timeout: 3_000, force: true }).catch(() => {});
        } else {
          await p.keyboard.press("Escape").catch(() => {});
        }
      }
    },
  });
}

async function main(): Promise<void> {
  if (!SIGNUP_EMAIL || !SIGNUP_PASSWORD) {
    emit({
      type: "error",
      code: "internal",
      details: "AGENTKEYS_SIGNUP_EMAIL and AGENTKEYS_SIGNUP_PASSWORD required",
    });
    process.exit(1);
  }

  progress("cdp-connect");
  log(`connecting to CDP at ${CDP_URL}`);
  const browser: Browser = await chromium.connectOverCDP(CDP_URL);
  const ctx = browser.contexts()[0] ?? (await browser.newContext());
  // Wipe cookies so Clerk doesn't short-circuit us into a stale session.
  await ctx.clearCookies().catch(() => {});
  const page: Page = ctx.pages()[0] ?? (await ctx.newPage());

  try {
    progress("goto-signup");
    log("navigating to signup");
    await page.goto(SIGNUP_URL, { waitUntil: "load", timeout: 30_000 });
    await dismissCookieBanner(page);

    progress("signup-form");
    log(`filling credentials (email=${SIGNUP_EMAIL})`);
    const EMAIL_SEL = 'input[type="email"], input[name*="email" i]';
    const PW_SEL = 'input[type="password"], input[name*="password" i]';
    await page.locator(EMAIL_SEL).first().waitFor({ timeout: 15_000 });
    await humanType(page, EMAIL_SEL, SIGNUP_EMAIL);
    await jitterDelay(250, 550);
    await humanType(page, PW_SEL, SIGNUP_PASSWORD);
    await jitterDelay(300, 700);

    // Check TOS checkbox with label-click fallback (Clerk hides the real
    // input and styles the label as the visible toggle).
    const TOS_SEL =
      'input[type="checkbox"][id*="legal" i], input[type="checkbox"][name*="terms" i], input[type="checkbox"][id*="tos" i]';
    const tos = page.locator(TOS_SEL).first();
    if (await tos.count()) {
      await tos.check({ force: true, timeout: 3_000 }).catch(() => {});
      if (!(await tos.isChecked().catch(() => false))) {
        const id = await tos.evaluate((el: HTMLInputElement) => el.id || "");
        if (id) {
          await page.locator(`label[for="${id}"]`).first().click({ timeout: 2_000 }).catch(() => {});
        }
      }
      await jitterDelay(200, 500);
    }

    progress("click-continue");
    const clickedContinue = await clickFirstVisible(page, [
      'button[data-localization-key="formButtonPrimary"]',
      'button:text-is("Sign up")',
      'button:text-is("Continue")',
      'button:text-is("Register")',
      'form button[type="submit"]:not(:has-text("Google")):not(:has-text("GitHub")):not(:has-text("Apple"))',
    ]);
    if (!clickedContinue) {
      emit({ type: "error", code: "internal", details: "no visible Continue button after fill" });
      process.exit(1);
    }

    progress("turnstile");
    const turnstile = await handleTurnstile(page);
    log(`turnstile: ${turnstile}`);

    progress("fetch-verification-email");
    log(
      `polling email backend for verification email (walletPrefix=${USER_WALLET || "(none, legacy inbound/ poll)"})`,
    );
    const verifyUrl = (
      await fetchVerificationCode({
        from: FROM_REGEX,
        subject: SUBJECT_REGEX,
        codeRegex: URL_REGEX,
        timeoutMs: 120_000,
        // When the CLI injected the wallet, poll `bots/${wallet}/inbound/`
        // (per-wallet prefix the SES routing Lambda copies into). When it
        // didn't, the backend polls `inbound/` directly — admin profile
        // creds required in that mode (manual / pre-Lambda flow).
        walletPrefix: USER_WALLET || undefined,
      })
    )
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">");

    progress("goto-verify-url");
    log("following magic link");
    await page.goto(verifyUrl, { waitUntil: "load", timeout: 30_000 });
    // Clerk magic links land on /sign-up/verify-email-address?__clerk_status=verified.
    // URL still contains "/sign-up" but session IS established. Accept as done.
    await page
      .waitForURL(
        (u) => {
          const s = u.toString();
          return (
            /[?&]__clerk_status=verified|__clerk_created_session=/.test(s) ||
            (!s.includes("/sign-up") && !s.includes("/sign-in"))
          );
        },
        { timeout: 30_000 },
      )
      .catch(() => {});

    progress("goto-keys");
    log("navigating to keys page");
    await page.goto(KEYS_URL, { waitUntil: "load", timeout: 20_000 });

    // OpenRouter's onboarding + welcome modal chain renders 15-40s after
    // keys-page hydration. Short initial probe so fast-loading sessions
    // don't stall; the per-iteration dismiss inside clickOuterCreate catches
    // late-rendering modals.
    await dismissOpenRouterOnboardingModals(page, 1_500);

    progress("click-create");
    log("clicking Create (up to 40s, dismissing onboarding each iter)");
    const clickedCreate = await clickOuterCreate(page, {
      onBeforeIteration: (p) => dismissOpenRouterOnboardingModals(p, 200).then(() => {}),
    });
    if (!clickedCreate) {
      emit({ type: "error", code: "internal", details: "no visible Create Key button on keys page" });
      process.exit(1);
    }

    // Defensive re-dismiss in case the onboarding modal popped up over the
    // freshly-opened Create Key form dialog.
    await dismissOpenRouterOnboardingModals(page, 500);

    progress("fill-key-name");
    const NAME_SEL =
      'input#name, input[id*="name" i]:not([type="email"]):not([type="password"])';
    await page.locator(NAME_SEL).first().waitFor({ state: "visible", timeout: 10_000 }).catch(() => {});
    const nameInput = page.locator(NAME_SEL).first();
    if (await nameInput.count()) {
      await nameInput.fill("").catch(() => {});
      await humanType(page, NAME_SEL, `agentkeys-${Date.now()}`);
      await jitterDelay(300, 600);
    }

    await dismissOpenRouterOnboardingModals(page, 300);
    progress("click-confirm");
    const clickedConfirm = await clickFirstVisible(page, [
      '[role="dialog"]:has(input#name) button:text-is("Create API Key")',
      '[role="dialog"]:has(input#name) button:text-is("Create")',
      '[role="dialog"]:has(input#name) button:has-text("Create")',
    ]);
    if (!clickedConfirm) {
      emit({ type: "error", code: "internal", details: "no visible Create/Submit in dialog" });
      process.exit(1);
    }

    progress("extract-key");
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
      emit({ type: "error", code: "store_failed", details: `key-format: extracted value didn't match sk-*: ${key.slice(0, 40)}` });
      process.exit(1);
    }

    log(`minted key: ${key.slice(0, 8)}****${key.slice(-4)}`);
    emit({ type: "success", api_key: key });
  } finally {
    await page.close().catch(() => {});
    await browser.close().catch(() => {});
  }
  process.exit(0);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  emit({ type: "error", code: "internal", details: `fatal: ${msg}` });
  log(`FATAL: ${msg}`);
  process.exit(1);
});
