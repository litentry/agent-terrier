import type { Page } from "playwright";

export type SignupEmailOtpOpts = {
  page: Page;
  signupUrl: string;
  emailSelector: string;
  submitButtonSelector: string;
  otpSelector: string;
  verifyButtonSelector: string;
  postVerifyNavUrl: string;
  createKeyButtonSelector: string;
  keyRevealSelector: string;
  emailFetcher: (
    from: RegExp,
    subject: RegExp,
    codeRegex: RegExp,
    timeoutMs: number
  ) => Promise<string>;
  emailAddress: string;
  emailFromRegex: RegExp;
  emailSubjectRegex: RegExp;
  emailCodeRegex: RegExp;
  emailTimeoutMs: number;
  selectorTimeoutMs?: number;
};

const DEFAULT_SELECTOR_TIMEOUT_MS = 15_000;

export async function signupEmailOtp(opts: SignupEmailOtpOpts): Promise<string> {
  const selectorTimeoutMs = opts.selectorTimeoutMs ?? DEFAULT_SELECTOR_TIMEOUT_MS;

  await opts.page.goto(opts.signupUrl, { waitUntil: "domcontentloaded" });

  await opts.page.waitForSelector(opts.emailSelector, { timeout: selectorTimeoutMs });
  await opts.page.fill(opts.emailSelector, opts.emailAddress);
  await opts.page.click(opts.submitButtonSelector);

  const otpCode = await opts.emailFetcher(
    opts.emailFromRegex,
    opts.emailSubjectRegex,
    opts.emailCodeRegex,
    opts.emailTimeoutMs
  );

  await opts.page.waitForSelector(opts.otpSelector, { timeout: selectorTimeoutMs });
  await opts.page.fill(opts.otpSelector, otpCode);
  await opts.page.click(opts.verifyButtonSelector);

  await opts.page.goto(opts.postVerifyNavUrl, { waitUntil: "domcontentloaded" });

  await opts.page.waitForSelector(opts.createKeyButtonSelector, { timeout: selectorTimeoutMs });
  await opts.page.click(opts.createKeyButtonSelector);

  await opts.page.waitForSelector(opts.keyRevealSelector, { timeout: selectorTimeoutMs });
  const rawText = await opts.page.textContent(opts.keyRevealSelector);
  return (rawText ?? "").trim();
}
