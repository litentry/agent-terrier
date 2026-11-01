import type { Page } from "playwright";
import { escalateAndThrow } from "../human-assist.js";

export type TurnstileMode = "not-present" | "auto-passive" | "auto-click" | "human" | "timeout";

export interface TurnstileOpts {
  detectTimeoutMs?: number;
  autoPassiveWindowMs?: number;
  totalTimeoutMs?: number;
  screenshotPathOnEscalate?: string;
}

// v1: human-only Turnstile handling, matching openrouter-cdp.ts:79-100
// proven pattern. v2 TODO: add Claude-CV path via IPC with the skill host.
//
// Flow:
//   1. Detect iframe/input within detectTimeoutMs (default 3s).
//   2. If not present → not-present (return immediately).
//   3. Poll for response-value population up to autoPassiveWindowMs (10s).
//      If populated without human action → auto-passive.
//   4. If still waiting, log to stderr + wait totalTimeoutMs (180s) for
//      the human to click in the Chrome window.
//   5. If response populates → human mode. Else → escalate.
export async function handleTurnstile(
  page: Page,
  opts: TurnstileOpts = {}
): Promise<TurnstileMode> {
  // Clerk widgets + Turnstile iframe can take 3–7s to attach after form submit
  // on slow networks. 3s was too aggressive; bumping to 8s reduces false
  // "not-present" returns. If genuinely absent the 8s cost is one-time.
  const detectTimeout = opts.detectTimeoutMs ?? 8_000;
  const autoPassiveWindow = opts.autoPassiveWindowMs ?? 10_000;
  const totalTimeout = opts.totalTimeoutMs ?? 180_000;

  const iframeSel = 'iframe[src*="challenges.cloudflare.com"]';
  const inputSel = 'input[name="cf-turnstile-response"]';

  // Turnstile renders its visible widget inside a shadow root that Playwright
  // can't see. The cf-turnstile-response input IS in the DOM (display:none)
  // before any iframe attaches. Use count() as a presence signal — isVisible
  // returns false for the hidden input and misses the iframe attach race.
  const present = await page
    .locator(`${iframeSel}, ${inputSel}`)
    .first()
    .isVisible({ timeout: detectTimeout })
    .catch(() => false);
  const domPresent =
    present || (await page.locator(inputSel).count().catch(() => 0)) > 0;
  if (!domPresent) {
    return "not-present";
  }

  const isResolved = async (): Promise<boolean> => {
    try {
      const val = await page.locator(inputSel).first().inputValue({ timeout: 500 });
      return Boolean(val && val.length > 0);
    } catch {
      return false;
    }
  };

  const start = Date.now();
  while (Date.now() - start < autoPassiveWindow) {
    if (await isResolved()) return "auto-passive";
    await page.waitForTimeout(500);
  }

  // Auto-click attempt: Turnstile's visible checkbox sits at a consistent
  // position inside the cross-origin iframe (~25px from left, vertically
  // centered). We can't pierce the iframe (cross-origin), but we can click
  // at that absolute screen coordinate via the parent page's mouse.
  process.stderr.write(
    "[turnstile] auto-passive window elapsed; attempting mouse-click at iframe checkbox position\n"
  );
  try {
    const box = await page
      .locator(iframeSel)
      .first()
      .boundingBox({ timeout: 2_000 });
    if (box) {
      // Humanized approach to avoid instant teleport.
      const targetX = box.x + 25;
      const targetY = box.y + box.height / 2;
      await page.mouse.move(targetX - 30, targetY + 10, { steps: 8 });
      await page.waitForTimeout(150 + Math.floor(Math.random() * 200));
      await page.mouse.move(targetX, targetY, { steps: 6 });
      await page.waitForTimeout(80 + Math.floor(Math.random() * 120));
      await page.mouse.click(targetX, targetY);
      // Turnstile takes 1-3s to validate after click.
      const clickDeadline = Date.now() + 15_000;
      while (Date.now() < clickDeadline) {
        if (await isResolved()) return "auto-click";
        await page.waitForTimeout(500);
      }
    }
  } catch {
    // iframe bounding box unavailable; fall through to human wait
  }

  process.stderr.write(
    "[turnstile] auto-click did not resolve — please click the checkbox " +
      "in the Chrome window. Waiting up to " +
      Math.round((totalTimeout - (Date.now() - start)) / 1000) +
      "s...\n\x07\n"
  );

  while (Date.now() - start < totalTimeout) {
    if (await isResolved()) return "human";
    await page.waitForTimeout(1_000);
  }

  escalateAndThrow({
    reason: "captcha",
    hint: "Turnstile did not resolve within 180s",
    url: page.url(),
    screenshotPath: opts.screenshotPathOnEscalate ?? "(no screenshot)",
    lastActionLog: [],
  });
}
