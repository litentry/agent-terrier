import * as path from "node:path";
import type { Page } from "playwright";
import {
  finalizeManifest,
  logAction,
  snap,
  type Manifest,
  type SessionCtx,
} from "./artifacts.js";
import { dumpEmailToRecording, pollFreshRawEmail } from "../lib/email-analyzer.js";
import { handleTurnstile } from "../lib/captcha/turnstile.js";
import { handleHCaptcha } from "../lib/captcha/hcaptcha.js";
import { escalateAndThrow } from "../lib/human-assist.js";
import {
  clickFirstVisible,
  clickOuterCreate,
  dismissCookieBanner,
  humanType,
  jitterDelay,
} from "../lib/playwright-patterns.js";

export interface FlowCtx {
  session: SessionCtx;
  manifest: Manifest;
  page: Page;
  signupEmail: string;
  signupPassword: string;
  signupUrl: string;
  loginUrl?: string;
  keysPath: string;
  bucket: string;
}

const MAGIC_LINK_TEXT_SELECTOR = 'text=/verification link|use the link|sign up link|magic link/i';
const OTP_SELECTOR = 'input[name="code"], input[inputmode="numeric"], input[autocomplete="one-time-code"]';

// clickFirstVisible, jitterDelay, humanType, dismissCookieBanner,
// clickOuterCreate moved to ../lib/playwright-patterns.ts (shared with
// production scrapers). Recorder-specific wrappers below still reference
// them via the named imports at the top of this file.

// OpenRouter's onboarding modal ("Where did you first hear...") may pop up
// after the keys page hydrates AND can re-open mid-form-fill if dismissed
// late. This helper is idempotent — call it whenever a layered Radix modal
// might be intercepting clicks.
// Probe the page DOM directly — Playwright's locator filter+waitFor sometimes
// fails to detect Radix modals that are mid-mount. Returns true if we found
// (and dismissed via DOM removal as a hard fallback) at least one onboarding
// modal during the polling window.
async function dismissOnboardingModalDom(page: Page, detectTimeoutMs = 500): Promise<boolean> {
  const start = Date.now();
  let dismissed = false;
  while (Date.now() - start < detectTimeoutMs + 100) {
    const found = await page.evaluate(() => {
      const dialogs = Array.from(document.querySelectorAll('[role="dialog"]'));
      const result = { surveyOpen: false, welcomeOpen: false };
      for (const d of dialogs) {
        const t = (d.textContent || "").toLowerCase();
        const visible = !!((d as HTMLElement).offsetWidth || (d as HTMLElement).offsetHeight);
        if (!visible) continue;
        if (t.includes("where did you first hear")) result.surveyOpen = true;
        if (t.includes("you're all set") || t.includes("youre all set") || t.includes("get started by buying")) result.welcomeOpen = true;
      }
      return result;
    });

    if (!found.surveyOpen && !found.welcomeOpen) {
      if (dismissed) return true;
      // Modal not visible; short wait then re-poll, until detect timeout.
      if (Date.now() - start >= detectTimeoutMs) return false;
      await page.waitForTimeout(200);
      continue;
    }

    dismissed = true;

    if (found.surveyOpen) {
      // Click "Other / Not sure" then Continue
      for (const lbl of [/^other\s*\/\s*not sure$/i, /^skip$/i, /^not now$/i, /^other$/i]) {
        const btn = page.getByRole("button", { name: lbl }).first();
        if (await btn.isVisible().catch(() => false)) {
          await btn.click({ timeout: 3_000, force: true }).catch(() => {});
          break;
        }
      }
      await page.waitForTimeout(300);
      await page
        .getByRole("button", { name: /^continue$/i })
        .first()
        .click({ timeout: 3_000, force: true })
        .catch(() => {});
      await page.waitForTimeout(700);
    }

    if (found.welcomeOpen) {
      // Click Close (X) on the welcome banner.
      await page
        .getByRole("button", { name: /^close$/i })
        .first()
        .click({ timeout: 3_000, force: true })
        .catch(() => {});
      await page.waitForTimeout(700);
    }
  }
  return dismissed;
}

// `dismissCookieBanner` now imported from ../lib/playwright-patterns.js
// The legacy `dismissOnboardingModal` (locator-based variant) was removed —
// `dismissOnboardingModalDom` above is the active, DOM-probe-based dismisser.

async function detectAlreadyLoggedIn(page: Page): Promise<boolean> {
  const url = page.url();
  if (/\/(dashboard|home|keys|workspaces|account)/.test(url)) return true;
  const signOutVisible = await page
    .getByRole("button", { name: /sign out|log out|logout/i })
    .first()
    .isVisible({ timeout: 1_500 })
    .catch(() => false);
  return signOutVisible;
}

async function trySignOut(page: Page): Promise<void> {
  const accountMenu = page
    .getByRole("button", { name: /account|profile|menu/i })
    .first();
  await accountMenu.click({ timeout: 2_000 }).catch(() => {});
  await page
    .getByRole("menuitem", { name: /sign out|log out|logout/i })
    .first()
    .click({ timeout: 2_000 })
    .catch(async () => {
      await page
        .getByRole("button", { name: /sign out|log out|logout/i })
        .first()
        .click({ timeout: 2_000 })
        .catch(() => {});
    });
  await page.waitForTimeout(1_000);
}

export async function runSignupFlow(ctx: FlowCtx): Promise<void> {
  const { page, session, manifest } = ctx;

  await snap(page, "pre-signup-open", session, manifest);
  logAction(session.outDir, { kind: "goto", url: ctx.signupUrl });
  await page.goto(ctx.signupUrl, { waitUntil: "load", timeout: 30_000 });

  // Cookie consent banner (ElevenLabs, many EU-compliant sites): click away
  // before it blocks form interactions. No-op if no banner shows.
  await dismissCookieBanner(page);

  if (await detectAlreadyLoggedIn(page)) {
    await snap(page, "already-logged-in-pre-signup", session, manifest);
    await trySignOut(page);
    await page.goto(ctx.signupUrl, { waitUntil: "load", timeout: 30_000 });
    await dismissCookieBanner(page);
    await snap(page, "post-logout", session, manifest);
  }

  await snap(page, "signup-form", session, manifest);
  manifest.detectedSelectors.signupUrl = ctx.signupUrl;

  const EMAIL_SEL = 'input[type="email"], input[name*="email" i], input[id*="email" i]';
  await page.locator(EMAIL_SEL).first().waitFor({ timeout: 15_000 });
  await humanType(page, EMAIL_SEL, ctx.signupEmail);
  manifest.detectedSelectors.emailField = EMAIL_SEL;
  await jitterDelay(250, 550);

  const PW_SEL = 'input[type="password"], input[name*="password" i]';
  // Multi-step signup detection (OpenAI Auth0, Auth0-style flows): if password
  // input isn't on the same page as email, advance with Continue and wait.
  const pwImmediate = await page
    .locator(PW_SEL)
    .first()
    .isVisible({ timeout: 1_500 })
    .catch(() => false);
  if (!pwImmediate) {
    await clickFirstVisible(page, [
      'button:text-is("Continue")',
      'button[type="submit"]:not(:has-text("Google")):not(:has-text("Apple")):not(:has-text("Microsoft")):not(:has-text("GitHub"))',
    ]);
    await jitterDelay(500, 900);
    await page.locator(PW_SEL).first().waitFor({ timeout: 20_000 });
    await snap(page, "password-step", session, manifest);
  }
  await humanType(page, PW_SEL, ctx.signupPassword);
  manifest.detectedSelectors.passwordField = PW_SEL;
  await jitterDelay(300, 700);

  // Password-confirm field (Brave, many services): fill with same password.
  const PW_CONFIRM_SEL =
    'input[type="password"][name*="verif" i], input[type="password"][name*="confirm" i], input[type="password"][id*="verif" i], input[type="password"][id*="confirm" i], input[type="password"]:nth-of-type(2)';
  const pwConfirm = page.locator(PW_CONFIRM_SEL).first();
  if (await pwConfirm.count()) {
    await humanType(page, PW_CONFIRM_SEL, ctx.signupPassword);
    await jitterDelay(250, 500);
  }

  // "Full name" field (Brave): some services require it to enable submit.
  const FULLNAME_SEL =
    'input[type="text"][id="name"], input[type="text"][name="name"], input[type="text"][id*="fullname" i], input[type="text"][placeholder*="full name" i]';
  const fullnameInput = page.locator(FULLNAME_SEL).first();
  if (await fullnameInput.count()) {
    await humanType(page, FULLNAME_SEL, `AgentKeys Bot ${Date.now().toString().slice(-4)}`);
    await jitterDelay(250, 500);
  }

  // Company field (Brave, optional on most forms — fill defensively).
  const COMPANY_SEL =
    'input[type="text"][id*="company" i], input[type="text"][name*="company" i], input[type="text"][placeholder*="company" i]';
  const companyInput = page.locator(COMPANY_SEL).first();
  if (await companyInput.count()) {
    await humanType(page, COMPANY_SEL, "AgentKeys Recording");
    await jitterDelay(250, 500);
  }

  const TOS_SEL = 'input[type="checkbox"][id*="legal" i], input[type="checkbox"][name*="terms" i], input[type="checkbox"][id*="tos" i]';
  const tosCheckbox = page.locator(TOS_SEL).first();
  if (await tosCheckbox.count()) {
    // Try direct check first; many custom-styled checkboxes hide the input
    // behind a label. If still unchecked after that, click the label.
    await tosCheckbox.check({ force: true, timeout: 3_000 }).catch(() => {});
    const isChecked = await tosCheckbox.isChecked().catch(() => false);
    if (!isChecked) {
      // Click the label associated with the checkbox via for= attr, OR the
      // parent label, OR the first clickable ancestor.
      const labelFor = await tosCheckbox.evaluate((el: HTMLInputElement) => el.id || "");
      if (labelFor) {
        await page.locator(`label[for="${labelFor}"]`).first().click({ timeout: 2_000 }).catch(() => {});
      }
      // Still not checked? Click parent label.
      if (!(await tosCheckbox.isChecked().catch(() => false))) {
        await tosCheckbox.evaluateHandle((el: HTMLInputElement) => {
          const lbl = el.closest("label");
          if (lbl) (lbl as HTMLLabelElement).click();
        }).catch(() => {});
      }
    }
    manifest.detectedSelectors.tosCheckbox = TOS_SEL;
    await jitterDelay(200, 500);
  }

  // Clerk renders TWO `data-localization-key="formButtonPrimary"` buttons on
  // some pages: a template/SSR placeholder with aria-hidden="true", and the
  // real visible one. `.first()` grabs the aria-hidden dup and the click
  // times out on invisible. Iterate and pick the first VISIBLE candidate.
  // Text-based selectors FIRST — avoids the blanket `button[type="submit"]`
  // that would match cookie-banner closes, Google-sign-up buttons, etc.
  // Exclude the "Sign up with Google" OAuth button (text contains "Google").
  const clickedContinue = await clickFirstVisible(page, [
    'button[data-localization-key="formButtonPrimary"]',
    'button:text-is("Sign up")',
    'button:text-is("Register")',
    'button:text-is("Continue")',
    'button:text-is("Create account")',
    'button:has-text("Create account")',
    'form button[type="submit"]:not([aria-label="Open AI Assistant"]):not([aria-label="Close"]):not(:has-text("Google")):not(:has-text("GitHub")):not(:has-text("Apple"))',
  ]);
  if (!clickedContinue) {
    escalateAndThrow({
      reason: "selector-missing",
      hint: "No visible Continue button found after fill. Clerk widget may have changed — inspect via Chrome DevTools.",
      url: page.url(),
      screenshotPath: path.join(session.outDir, "steps"),
      lastActionLog: [],
    });
  }
  manifest.detectedSelectors.continueBtn = clickedContinue;
  await snap(page, "after-continue", session, manifest);

  const turnstileMode = await handleTurnstile(page);
  manifest.outcomes.turnstileMode = turnstileMode;
  await snap(page, "turnstile-resolved", session, manifest, { turnstileMode });

  // hCaptcha (ElevenLabs, Discord-style signups): invoked ON submit. If the
  // fingerprint looks human, invisible hCaptcha passes passively and the
  // token auto-populates. If a challenge shows up, we fall back to
  // human-in-loop or CapSolver (when the account supports hCaptcha).
  const hcaptchaMode = await handleHCaptcha(page, {
    screenshotPathOnEscalate: path.join(session.outDir, "steps"),
  });
  manifest.outcomes.hCaptchaMode = hcaptchaMode;
  await snap(page, "hcaptcha-resolved", session, manifest, { hcaptchaMode });

  await resolveVerification(ctx);
  await completePostVerifyProfile(ctx);

  manifest.outcomes.signupCompleted = true;
  await mintApiKey(ctx);
}

// If the URL is /login|/sign-in after resolveVerification, fill the login
// form with the just-used signup credentials and submit. No-op if not on
// login page.
async function maybeAutoLoginAfterSignup(ctx: FlowCtx): Promise<void> {
  const { page, session, manifest } = ctx;
  if (!/\/(log[-_]?in|sign[-_]?in)\b/i.test(page.url())) return;

  await snap(page, "post-signup-login-form", session, manifest);

  const emailSel = 'input[type="email"], input[name*="email" i], input[id*="email" i]';
  const pwSel = 'input[type="password"]';
  const emailInput = page.locator(emailSel).first();
  if (await emailInput.count()) {
    await humanType(page, emailSel, ctx.signupEmail);
    await jitterDelay(200, 500);
  }
  const pwInput = page.locator(pwSel).first();
  if (await pwInput.count()) {
    await humanType(page, pwSel, ctx.signupPassword);
    await jitterDelay(200, 500);
  }

  const loginSubmitAtMs = Date.now();
  await clickFirstVisible(page, [
    'button:text-is("Login")',
    'button:text-is("Log in")',
    'button:text-is("Sign in")',
    'form button[type="submit"]:not([aria-label="Open AI Assistant"]):not([aria-label="Close"])',
  ]);

  await page
    .waitForURL((u) => !/\/(log[-_]?in|sign[-_]?in)\b/i.test(u.toString()), { timeout: 30_000 })
    .catch(() => {});
  await snap(page, "post-signup-login-done", session, manifest);

  // Brave 2FA: after password login, URL lands on /verify-otp and a new email
  // arrives with a 6-digit code. Poll S3 and fill it in before mintApiKey
  // re-navigates to the keys page.
  if (/\/(verify-otp|otp|2fa|mfa)\b/i.test(page.url())) {
    await resolvePostLoginOtp(ctx, loginSubmitAtMs);
  }
}

async function resolvePostLoginOtp(ctx: FlowCtx, startedAtMs: number): Promise<void> {
  const { page, session, manifest } = ctx;
  await snap(page, "post-login-otp-page", session, manifest);
  logAction(session.outDir, { kind: "poll-s3-email", bucket: ctx.bucket, startedAt: new Date(startedAtMs).toISOString(), phase: "post-login-otp" });

  // Filter to login/verify-coded emails so we don't pick up welcome emails
  // that arrive between registration and the actual OTP.
  const { key, rawMime } = await pollFreshRawEmail({
    bucket: ctx.bucket,
    startedAtMs,
    timeoutMs: 120_000,
    subjectPattern: /login|sign[-\s]?in|verify|verification|one[-\s]?time|otp|code|2fa|mfa/i,
  });
  logAction(session.outDir, { kind: "email-matched", key, phase: "post-login-otp" });

  const analysis = dumpEmailToRecording(
    path.join(session.outDir, "emails"),
    key,
    rawMime
  );

  // The analyzer prefers magic-link when it sees a verification-flavored URL
  // in the body. But Brave's "Brave Search API login attempt" email contains
  // BOTH a 6-digit OTP AND helper URLs — so it gets misclassified. Fall
  // back to direct OTP extraction from the raw body so the post-login flow
  // still completes.
  let otpCode: string | undefined =
    analysis.verifyType === "otp" ? analysis.code : undefined;
  if (!otpCode) {
    const stripped = rawMime
      .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/g, " ")
      .replace(/=\r?\n/g, "")
      .replace(/\s+/g, " ");
    const labeled = stripped.match(
      /(?:verification|security|login|sign[-\s]?in|one[-\s]?time|auth(?:entication)?|access)\s*code[^0-9]{0,40}(\d{6})/i,
    );
    const before = stripped.match(/(\d{6})[^0-9]{0,40}(?:is\s+your|to\s+(?:verify|sign|log))/i);
    otpCode = labeled?.[1] ?? before?.[1] ?? stripped.match(/\b(\d{6})\b/)?.[1];
  }
  if (!otpCode) {
    escalateAndThrow({
      reason: "verification-blocked",
      hint: `post-login 2FA email had no extractable 6-digit code (analyzer verifyType=${analysis.verifyType})`,
      url: page.url(),
      screenshotPath: path.join(session.outDir, "steps"),
      lastActionLog: [],
    });
  }
  // Bind for downstream code that previously read analysis.code.
  const analysisOtp = otpCode!;

  // React/Svelte-controlled OTP inputs: `.fill()` sets DOM value but doesn't
  // fire onChange. Use pressSequentially + explicit input/change events.
  // Svelte components often validate on `input` event; React on `change`.
  const inputs = await page.locator(OTP_SELECTOR).all();
  const typeWithEvents = async (el: (typeof inputs)[number], code: string) => {
    await el.click();
    await el.pressSequentially(code, { delay: 80 });
    // Fire input+change to force frameworks to revalidate form state.
    await el.dispatchEvent("input");
    await el.dispatchEvent("change");
  };
  if (inputs.length === 1) {
    await typeWithEvents(inputs[0], analysisOtp);
  } else if (inputs.length === 6) {
    for (let i = 0; i < 6; i++) {
      await typeWithEvents(inputs[i], analysisOtp[i]);
    }
  } else {
    escalateAndThrow({
      reason: "verification-blocked",
      hint: `unexpected post-login OTP input count: ${inputs.length}`,
      url: page.url(),
      screenshotPath: path.join(session.outDir, "steps"),
      lastActionLog: [],
    });
  }
  await jitterDelay(300, 700);
  const submitBtn = page.getByRole("button", { name: /verify|submit|continue|confirm/i }).first();
  // Wait for button to become enabled (React validation may take a tick).
  await submitBtn.waitFor({ state: "visible", timeout: 5_000 }).catch(() => {});
  for (let i = 0; i < 20; i++) {
    if (await submitBtn.isEnabled().catch(() => false)) break;
    await page.waitForTimeout(250);
  }
  if (await submitBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await submitBtn.click({ timeout: 10_000 });
  }
  await page
    .waitForURL((u) => !/\/(verify-otp|otp|2fa|mfa)\b/i.test(u.toString()), { timeout: 30_000 })
    .catch(() => {});
  manifest.outcomes.postLoginOtp = true;
  await snap(page, "post-login-otp-done", session, manifest);
}

export async function runLoginFlow(ctx: FlowCtx): Promise<void> {
  const { page, session, manifest } = ctx;
  const url = ctx.loginUrl ?? ctx.signupUrl;

  await snap(page, "pre-login-open", session, manifest);
  await page.goto(url, { waitUntil: "load", timeout: 30_000 });

  if (await detectAlreadyLoggedIn(page)) {
    await snap(page, "already-logged-in", session, manifest);
    manifest.outcomes.loginSkipped = true;
    await mintApiKey(ctx);
    return;
  }

  await snap(page, "login-form", session, manifest);

  const LOGIN_EMAIL_SEL = 'input[type="email"], input[name*="email" i]';
  await page.locator(LOGIN_EMAIL_SEL).first().waitFor({ timeout: 15_000 });
  await humanType(page, LOGIN_EMAIL_SEL, ctx.signupEmail);
  manifest.detectedSelectors.emailField = LOGIN_EMAIL_SEL;
  await jitterDelay(250, 550);

  const LOGIN_PW_SEL = 'input[type="password"]';
  const passwordInput = page.locator(LOGIN_PW_SEL).first();
  if (await passwordInput.count()) {
    await humanType(page, LOGIN_PW_SEL, ctx.signupPassword);
    manifest.detectedSelectors.passwordField = LOGIN_PW_SEL;
    await jitterDelay(300, 700);
  }

  const clickedLoginContinue = await clickFirstVisible(page, [
    'button[data-localization-key="formButtonPrimary"]',
    'form button[type="submit"]',
    'button:has-text("Continue")',
    'button:has-text("Sign in")',
    'button:has-text("Log in")',
  ]);
  if (!clickedLoginContinue) {
    escalateAndThrow({
      reason: "selector-missing",
      hint: "No visible login Continue button found after fill.",
      url: page.url(),
      screenshotPath: path.join(session.outDir, "steps"),
      lastActionLog: [],
    });
  }
  manifest.detectedSelectors.continueBtn = clickedLoginContinue;
  await snap(page, "after-continue", session, manifest);

  const turnstileMode = await handleTurnstile(page);
  manifest.outcomes.turnstileMode = turnstileMode;
  await snap(page, "turnstile-resolved", session, manifest, { turnstileMode });

  const needsVerify = await page
    .locator(OTP_SELECTOR)
    .first()
    .isVisible({ timeout: 2_000 })
    .catch(() => false);
  if (needsVerify) {
    await resolveVerification(ctx);
  }

  await page
    .waitForURL((u) => !u.toString().includes("/sign-in") && !u.toString().includes("/log-in"), {
      timeout: 30_000,
    })
    .catch(() => {});
  await snap(page, "post-login", session, manifest);

  manifest.outcomes.loginCompleted = true;
  await mintApiKey(ctx);
}

// Post-email-verification profile page (OpenAI's /about-you, etc.): some
// services gate session-cookie issuance behind a final "Full name + Age"
// form. Fill and submit so the account is fully provisioned before we try
// to mint an API key on the product domain. No-op if no profile fields
// visible.
async function completePostVerifyProfile(ctx: FlowCtx): Promise<void> {
  const { page, session, manifest } = ctx;

  const NAME_SEL =
    'input[autocomplete="name"], input[id*="name" i][type="text"]:not([name*="company" i]), input[placeholder*="full name" i], input[placeholder*="your name" i]';
  const AGE_SEL =
    'input[id*="age" i][inputmode="numeric"], input[placeholder="Age"], input[name="age"]';

  const nameVisible = await page
    .locator(NAME_SEL)
    .first()
    .isVisible({ timeout: 2_000 })
    .catch(() => false);
  const ageVisible = await page
    .locator(AGE_SEL)
    .first()
    .isVisible({ timeout: 500 })
    .catch(() => false);
  if (!nameVisible && !ageVisible) return;

  await snap(page, "post-verify-profile-form", session, manifest);

  if (nameVisible) {
    // OpenAI rejects names containing digits or anything that doesn't look
    // person-name-shaped. Use plausible human-looking names (no numbers).
    const firsts = ["Alex", "Jamie", "Taylor", "Morgan", "Casey", "Jordan", "Riley", "Avery"];
    const lasts = ["Parker", "Reed", "Hayes", "Bennett", "Foster", "Cole", "Quinn", "Shaw"];
    const pick = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)]!;
    await humanType(page, NAME_SEL, `${pick(firsts)} ${pick(lasts)}`);
    await jitterDelay(200, 500);
  }
  if (ageVisible) {
    await humanType(page, AGE_SEL, "28");
    // React-controlled hidden birthday field recomputes from age on input.
    // Give the reactive cycle a beat before clicking submit.
    await jitterDelay(600, 1_000);
    // Blur the age field (Tab) — some forms only compute birthday on blur.
    await page.keyboard.press("Tab").catch(() => {});
    await jitterDelay(200, 400);
  }

  const clicked = await clickFirstVisible(page, [
    'button:text-is("Finish creating account")',
    'button:has-text("Finish")',
    'button:text-is("Continue")',
    'button:has-text("Get started")',
    'form button[type="submit"]',
  ]);
  if (!clicked) return;

  // Wait for the session-cookie redirect away from auth.openai.com's profile
  // page toward the product domain (platform.openai.com/*).
  await page
    .waitForURL((u) => !/\/about-you|\/create-account|\/email-verification/i.test(u.toString()), {
      timeout: 30_000,
    })
    .catch(() => {});
  await snap(page, "post-verify-profile-done", session, manifest);
  manifest.outcomes.postVerifyProfile = true;
}

async function resolveVerification(ctx: FlowCtx): Promise<void> {
  const { page, session, manifest } = ctx;

  // Wait up to 60s for ONE OF: OTP input, magic-link copy, verify-pending URL,
  // or URL-leaves-all-auth. Polling loop because Clerk renders the verify
  // screen 1–5s after submit + Turnstile. Previous naive 3s check fired too
  // early and returned false-false, then wasted 120s polling S3 for an email
  // the user never triggered.
  let otpPresent = false;
  let magicLinkPresent = false;
  let urlAdvanced = false;
  let onVerifyPage = false;
  const waitDeadline = Date.now() + 60_000;
  while (Date.now() < waitDeadline) {
    otpPresent = await page
      .locator(OTP_SELECTOR)
      .first()
      .isVisible({ timeout: 500 })
      .catch(() => false);
    magicLinkPresent = await page
      .locator(MAGIC_LINK_TEXT_SELECTOR)
      .first()
      .isVisible({ timeout: 500 })
      .catch(() => false);
    const url = page.url();
    // `/verify*` = "we sent you an email" pending state (Brave's /verify-account).
    // Treat as verify-pending, not as advanced.
    onVerifyPage = /\/verify(?:[\/?-]|$)/.test(url);
    // Include all auth paths: sign-up/sign-in/register/login/auth/verify. Brave
    // uses /register and /login instead of /sign-up; OpenRouter uses /auth.
    urlAdvanced = !/\/sign-up|\/sign-in|\/auth|\/verify|\/register|\/log[-_]?in/.test(url);
    if (otpPresent || magicLinkPresent || urlAdvanced || onVerifyPage) break;
    await page.waitForTimeout(1_500);
  }

  await snap(page, "verify-screen", session, manifest, {
    otpPresent,
    magicLinkPresent,
    urlAdvanced,
    onVerifyPage,
    finalUrl: page.url(),
  });

  // If URL already advanced past all known auth flows (Clerk sometimes auto-
  // verifies or lands straight on dashboard for SSO), skip email polling.
  if (urlAdvanced && !otpPresent && !magicLinkPresent && !onVerifyPage) {
    manifest.outcomes.verifyType = "skipped";
    return;
  }

  // Not on verify screen AND URL still on sign-up → submit failed or flow
  // genuinely stuck. Escalate rather than burn 120s polling S3.
  if (!otpPresent && !magicLinkPresent && !onVerifyPage) {
    manifest.outcomes.verifyType = "unknown";
    escalateAndThrow({
      reason: "verification-blocked",
      hint: "No verify screen appeared within 60s and URL still on sign-up path. Form submit likely failed (wrong Continue button clicked?).",
      url: page.url(),
      screenshotPath: path.join(session.outDir, "steps"),
      lastActionLog: [],
    });
  }

  const startedAtMs = Date.now();
  const pollStart = new Date(startedAtMs).toISOString();
  logAction(session.outDir, { kind: "poll-s3-email", bucket: ctx.bucket, startedAt: pollStart });

  const { key, rawMime } = await pollFreshRawEmail({
    bucket: ctx.bucket,
    startedAtMs,
    timeoutMs: 120_000,
  });
  logAction(session.outDir, { kind: "email-matched", key });

  const analysis = dumpEmailToRecording(
    path.join(session.outDir, "emails"),
    key,
    rawMime
  );

  manifest.detectedRegexes.emailFrom = analysis.from;
  manifest.detectedRegexes.emailSubject = analysis.subject;

  if (analysis.verifyType === "magic-link") {
    manifest.outcomes.verifyType = "magic-link";
    const urlObj = new URL(analysis.url);
    manifest.detectedRegexes.verifyUrlHost = urlObj.host;
    manifest.detectedRegexes.urlHasHtmlEntities = analysis.urlHasHtmlEntities;
    const decoded = analysis.url
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">");
    logAction(session.outDir, { kind: "goto-verify-url", host: urlObj.host });
    await page.goto(decoded, { waitUntil: "load", timeout: 30_000 });
    // Clerk magic links land on /sign-up/verify-email-address?__clerk_status=verified
    // — the URL still contains "/sign-up" but the session IS established.
    // Treat verified-session query params as advancement so we don't burn
    // 30s waiting for a redirect that never comes (mintApiKey can navigate
    // to the keys URL itself once the session cookie is set).
    const verifyDone = (u: { toString(): string }): boolean => {
      const s = u.toString();
      const verifiedSession = /[?&]__clerk_status=verified|__clerk_created_session=/.test(s);
      const leftAuth = !s.includes("/sign-up") && !s.includes("/sign-in");
      return verifiedSession || leftAuth;
    };
    await page.waitForURL(verifyDone, { timeout: 30_000 }).catch(() => {});
    await snap(page, "post-verify-redirect", session, manifest);
    return;
  }

  if (analysis.verifyType === "otp") {
    manifest.outcomes.verifyType = "otp";
    // React/Svelte-controlled OTP inputs: `.fill()` sets DOM value but doesn't
    // fire onChange, leaving Submit disabled. Use pressSequentially +
    // dispatched input/change events.
    const inputs = await page.locator(OTP_SELECTOR).all();
    const typeWithEvents = async (el: (typeof inputs)[number], code: string) => {
      await el.click();
      await el.pressSequentially(code, { delay: 80 });
      await el.dispatchEvent("input");
      await el.dispatchEvent("change");
    };
    if (inputs.length === 1) {
      await typeWithEvents(inputs[0], analysis.code);
    } else if (inputs.length === 6) {
      for (let i = 0; i < 6; i++) await typeWithEvents(inputs[i], analysis.code[i]);
    } else {
      escalateAndThrow({
        reason: "verification-blocked",
        hint: `unexpected OTP input count: ${inputs.length}`,
        url: page.url(),
        screenshotPath: path.join(session.outDir, "steps"),
        lastActionLog: [],
      });
    }
    await jitterDelay(300, 700);
    const submitBtn = page.getByRole("button", { name: /verify|submit|continue|confirm/i }).first();
    // Wait for button to become enabled (form validation may debounce).
    for (let i = 0; i < 20; i++) {
      if (await submitBtn.isEnabled().catch(() => false)) break;
      await page.waitForTimeout(250);
    }
    if (await submitBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
      await submitBtn.click({ timeout: 10_000 }).catch(() => {});
    }
    await page
      .waitForURL((u) => !/\/(sign-up|sign-in|verify|email-verification)\b/i.test(u.toString()), {
        timeout: 30_000,
      })
      .catch(() => {});
    await snap(page, "post-verify-redirect", session, manifest);
    return;
  }

  manifest.outcomes.verifyType = "unknown";
  escalateAndThrow({
    reason: "verification-blocked",
    hint: `email-analyzer could not classify the verification email: ${analysis.reason}`,
    url: page.url(),
    screenshotPath: path.join(session.outDir, "steps"),
    lastActionLog: [],
  });
}

export async function mintApiKey(ctx: FlowCtx): Promise<void> {
  const { page, session, manifest } = ctx;

  // If we're mid-OAuth callback (e.g. `/auth/callback?code=...`), let the
  // client-side router finish before forcing our own navigation — goto during
  // a callback drops the exchanged session cookie. Wait up to 15s for URL to
  // leave `/auth/callback`, `/about-you`, `/email-verification`.
  if (/\/(auth\/callback|about-you|email-verification|create-account)/i.test(page.url())) {
    await page
      .waitForURL(
        (u) => !/\/(auth\/callback|about-you|email-verification|create-account)/i.test(u.toString()),
        { timeout: 15_000 },
      )
      .catch(() => {});
    // OpenAI: after callback lands on /home (or similar), the onboarding
    // backend may need a few seconds to ensure a default project exists
    // before /api-keys routes render correctly. Without this, the SPA
    // races "Organization already has a default project" errors.
    await page.waitForTimeout(3_000);
  }

  const keysUrl = new URL(ctx.keysPath, page.url()).toString();
  logAction(session.outDir, { kind: "goto-keys", url: keysUrl });
  await page.goto(keysUrl, { waitUntil: "load", timeout: 20_000 });

  // If goto-keys got redirected to a /login page (Brave, etc.), auto-login
  // with the signup credentials we just created, then re-goto keys.
  await maybeAutoLoginAfterSignup(ctx);
  if (/\/(log[-_]?in|sign[-_]?in)\b/i.test(page.url())) {
    // Still stuck on login; escalate.
    escalateAndThrow({
      reason: "auth-challenge",
      hint: "Stuck on /login after navigating to keys. Auto-login either didn't fill or didn't advance. Credentials may not be valid yet, or there's a second auth step.",
      url: page.url(),
      screenshotPath: path.join(session.outDir, "steps"),
      lastActionLog: [],
    });
  }

  // Re-navigate to keys in case auto-login landed us on dashboard root.
  if (!page.url().includes(ctx.keysPath)) {
    await page.goto(keysUrl, { waitUntil: "load", timeout: 20_000 });
  }
  await snap(page, "keys-page", session, manifest);
  manifest.detectedSelectors.keysPath = ctx.keysPath;

  // OpenRouter's modal chain can render 25-60s+ post-hydration — too long
  // to wait synchronously. Strategy: do a very short initial probe (so
  // services where the modal IS already present don't skip it), then race
  // ahead into clickOuterCreate where the per-iteration inline dismiss
  // catches the modal if/when it appears.
  if (await dismissOnboardingModalDom(page, 1_500)) {
    manifest.outcomes.onboardingModalSeen = true;
    await snap(page, "onboarding-dismissed", session, manifest);
  } else {
    manifest.outcomes.onboardingModalSeen = false;
  }

  await snap(page, "keys-empty-state", session, manifest);

  // Outer "Create ... Key" button (empty-state or list-header). If the
  // dialog is already open (stale from a prior failed run), skip this.
  const dlgAlreadyOpen = await page.locator('[role="dialog"]').first().isVisible({ timeout: 500 }).catch(() => false);
  let clickedCreateKey: string | null = "dialog-already-open";
  if (!dlgAlreadyOpen) {
    clickedCreateKey = await clickOuterCreate(page, {
      onBeforeIteration: (p) => dismissOnboardingModalDom(p, 200).then(() => {}),
    });
  }
  if (!clickedCreateKey) {
    escalateAndThrow({
      reason: "selector-missing",
      hint: "No visible Create Key button on the keys page.",
      url: page.url(),
      screenshotPath: path.join(session.outDir, "steps"),
      lastActionLog: [],
    });
  }
  manifest.detectedSelectors.createKeyBtn = clickedCreateKey;
  await snap(page, "create-dialog", session, manifest);

  // Defensive re-dismiss: OpenRouter's onboarding modal sometimes pops up
  // (or re-pops) on top of the freshly-opened Create Key form dialog,
  // intercepting all subsequent name-fill and confirm clicks.
  await dismissOnboardingModalDom(page);

  // OpenAI instant-mint UI: after clicking "Create new secret key" the key
  // reveals immediately without a Name prompt. Detect and skip the
  // name+confirm flow when the count of sk-* elements INCREASED above the
  // baseline (don't be fooled by tutorial text containing example keys).
  const SK_REVEAL_SEL = 'code:has-text("sk-"), pre:has-text("sk-"), input[value^="sk-"]';
  const skRevealCount = await page.locator(SK_REVEAL_SEL).count().catch(() => 0);
  // We don't have an independent baseline here; if a fresh form dialog opened
  // input#name will be visible → instantRevealed should stay false. Treat
  // instant reveal as ONLY when a Name input is NOT also visible.
  const nameInputVisible = await page
    .locator('input#name, input[id*="name" i]:not([type="email"]):not([type="password"])')
    .first()
    .isVisible({ timeout: 500 })
    .catch(() => false);
  const instantRevealed = skRevealCount > 0 && !nameInputVisible;

  if (!instantRevealed) {
    // Traditional flow: wait for Name input dialog, fill, confirm.
    const NAME_SEL =
      'input#name, input[id*="name" i]:not([type="email"]):not([type="password"])';
    await page.locator(NAME_SEL).first().waitFor({ state: "visible", timeout: 10_000 }).catch(() => {});

    // Defensive re-dismiss in case the onboarding modal is now ON TOP of
    // the form dialog (it pops asynchronously after keys-page hydrates and
    // can race ahead of clickOuterCreate's success check).
    await dismissOnboardingModalDom(page);

    const nameInput = page.locator(NAME_SEL).first();
    if (await nameInput.count()) {
      // Clear any partial value left by a prior interrupted humanType
      // (onboarding-modal-induced focus loss).
      await nameInput.fill("").catch(() => {});
      await humanType(page, NAME_SEL, `agentkeys-recording-${Date.now()}`);
      await jitterDelay(300, 600);
    }

    // Scope confirm to the dialog that contains the name input. `:has()`
    // picks only the matching container, not the welcome-banner dialog.
    const formDialog = page.locator('[role="dialog"]:has(input#name)').first();
    await formDialog
      .locator('button:not([disabled])')
      .filter({ hasText: /create/i })
      .first()
      .waitFor({ state: "visible", timeout: 10_000 })
      .catch(() => {});

    // One more defensive dismissal right before the confirm click.
    await dismissOnboardingModalDom(page);
    await jitterDelay(250, 550);
    const clickedConfirm = await clickFirstVisible(page, [
      '[role="dialog"]:has(input#name) button:text-is("Create API Key")',
      '[role="dialog"]:has(input#name) button:text-is("Create")',
      '[role="dialog"]:has(input#name) button:has-text("Create")',
    ]);
    if (!clickedConfirm) {
      escalateAndThrow({
        reason: "selector-missing",
        hint: "No visible Create/Submit button inside the Create Key dialog. Dialog may have extra required fields (credit limit, expiration) blocking submit.",
        url: page.url(),
        screenshotPath: path.join(session.outDir, "steps"),
        lastActionLog: [],
      });
    }
    manifest.detectedSelectors.createKeyBtn = `${clickedCreateKey} → confirm via ${clickedConfirm}`;
  } else {
    manifest.detectedSelectors.createKeyBtn = `${clickedCreateKey} → instant-mint (no Name prompt)`;
  }

  const keyEl = page
    .locator(
      'code:has-text("sk-"), pre:has-text("sk-"), input[value^="sk-"]'
    )
    .first();
  await keyEl.waitFor({ timeout: 15_000 });
  manifest.detectedSelectors.keyReveal =
    'code:has-text("sk-"), pre:has-text("sk-"), input[value^="sk-"]';
  await snap(page, "key-revealed", session, manifest);

  const tag = await keyEl.evaluate((n) => n.tagName.toLowerCase());
  const raw =
    tag === "input"
      ? await keyEl.inputValue()
      : (await keyEl.textContent()) ?? "";
  const key = raw.trim();
  if (!/^sk-[a-zA-Z0-9_-]{20,}$/.test(key)) {
    escalateAndThrow({
      reason: "selector-missing",
      hint: `extracted value doesn't match sk-* format: ${key.slice(0, 40)}`,
      url: page.url(),
      screenshotPath: path.join(session.outDir, "steps"),
      lastActionLog: [],
    });
  }

  manifest.outcomes.apiKeyExtracted = true;
  manifest.outcomes.apiKeyMasked = `${key.slice(0, 8)}****${key.slice(-4)}`;
  logAction(session.outDir, {
    kind: "key-minted",
    masked: manifest.outcomes.apiKeyMasked,
  });
}

export { finalizeManifest };
