// Generic Playwright helpers shared between the workflow-recorder and
// production scrapers. Rule: only truly service-agnostic primitives live
// here. Service-specific text patterns and dismissal flows (e.g. OpenRouter's
// "where did you first hear" onboarding survey) stay in the scraper file.
//
// Every helper here has survived at least one recorder iteration against a
// live service; behavior must stay byte-identical to the recorder embedded
// version so the shared import doesn't regress the recorder.

import type { Locator, Page } from "playwright";

// Random wait between min and max ms. Short enough that the recorder doesn't
// feel sluggish but long enough to avoid "every action in 0ms" bot-signature.
export function jitterDelay(minMs: number, maxMs: number): Promise<void> {
  const ms = Math.floor(minMs + Math.random() * (maxMs - minMs));
  return new Promise((r) => setTimeout(r, ms));
}

// Iterate candidate selectors in priority order. For each, enumerate all
// matches and click the FIRST visible+enabled one. Returns the winning
// selector string, or null if nothing matched.
//
// Essential for Clerk-family pages that render aria-hidden duplicates of
// their primary button — `.first()` would grab the hidden template and the
// click would time out on invisible.
export async function clickFirstVisible(
  page: Page,
  selectors: string[],
): Promise<string | null> {
  for (const sel of selectors) {
    const candidates = await page.locator(sel).all();
    for (const c of candidates) {
      const visible = await c.isVisible().catch(() => false);
      if (!visible) continue;
      // Skip disabled buttons — Playwright's .click() on a disabled element
      // succeeds silently (no throw) but doesn't fire the action. We'd then
      // falsely think we submitted. Check enabled state before attempting.
      const enabled = await c.isEnabled().catch(() => true);
      if (!enabled) continue;
      // Layer 1 humanization: move mouse to element BEFORE clicking. A
      // direct click teleports the cursor which is a fingerprinting signal
      // Turnstile watches for.
      try {
        const box = await c.boundingBox();
        if (box) {
          await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, {
            steps: 10,
          });
          await jitterDelay(120, 280);
        }
        await c.click({ timeout: 5_000 });
        return sel;
      } catch {
        // visible but not clickable (covered by overlay, etc.); try next
      }
    }
  }
  return null;
}

// Human-ish typing: sequential keystrokes with a randomized inter-key delay.
// Replaces `.fill()` which writes instantly (another Turnstile red flag) and
// doesn't fire React/Svelte onChange for controlled inputs. Focuses with a
// mouse-move-then-click so the cursor trail looks natural.
export async function humanType(
  page: Page,
  selector: string,
  value: string,
): Promise<void> {
  const locator = page.locator(selector).first();
  const box = await locator.boundingBox();
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, {
      steps: 8,
    });
    await jitterDelay(60, 180);
  }
  await locator.click({ timeout: 5_000 }).catch(() => {});
  await locator.pressSequentially(value, {
    delay: 60 + Math.floor(Math.random() * 60),
  });
}

// Dismiss a cookie-consent banner if one is present. Common EU-compliant
// text variants. Short per-selector timeout — if none match, no banner is
// shown and the function returns fast.
export async function dismissCookieBanner(page: Page): Promise<void> {
  const texts = [
    "Accept All Cookies",
    "Accept all cookies",
    "Accept cookies",
    "Accept All",
    "Accept",
    "Agree",
    "OK",
    "Got it",
  ];
  for (const t of texts) {
    const candidate = page
      .locator("button")
      .filter({ hasText: new RegExp(`^${t}$`, "i") })
      .first();
    if (await candidate.isVisible({ timeout: 800 }).catch(() => false)) {
      await candidate.click({ timeout: 3_000 }).catch(() => {});
      await page.waitForTimeout(400);
      return;
    }
  }
}

// Generic dialog probe — returns true if a `[role="dialog"]` whose visible
// textContent matches `textRegex` is currently open. Caller composes dismiss
// logic around this primitive (service-specific: click the right button, or
// the right radio, or Escape, etc).
export async function isDialogOpenByText(
  page: Page,
  textRegex: RegExp,
): Promise<boolean> {
  const pattern = textRegex.source;
  const flags = textRegex.flags;
  return await page
    .evaluate(
      ({ pattern, flags }) => {
        const re = new RegExp(pattern, flags);
        const dialogs = Array.from(document.querySelectorAll('[role="dialog"]'));
        return dialogs.some((d) => {
          const t = d.textContent || "";
          const visible = !!(
            (d as HTMLElement).offsetWidth || (d as HTMLElement).offsetHeight
          );
          return visible && re.test(t);
        });
      },
      { pattern, flags },
    )
    .catch(() => false);
}

// Composes `isDialogOpenByText` with a caller-provided `dismissFn`, looping
// for chained modals (some services show 2+ in sequence). Returns true if at
// least one matching dialog was detected and dismissFn was invoked.
export interface ProbeAndDismissOpts {
  page: Page;
  textRegex: RegExp;
  dismissFn: (page: Page) => Promise<void>;
  detectTimeoutMs?: number;
  maxRounds?: number;
  settleMs?: number;
}
export async function probeAndDismissDialog(
  opts: ProbeAndDismissOpts,
): Promise<boolean> {
  const { page, textRegex, dismissFn } = opts;
  const detectTimeoutMs = opts.detectTimeoutMs ?? 500;
  const maxRounds = opts.maxRounds ?? 4;
  const settleMs = opts.settleMs ?? 300;
  const start = Date.now();
  let dismissedAny = false;
  for (let i = 0; i < maxRounds; i++) {
    const pollDeadline = i === 0 ? detectTimeoutMs : 500;
    let found = false;
    const pollStart = Date.now();
    while (Date.now() - pollStart < pollDeadline) {
      if (await isDialogOpenByText(page, textRegex)) {
        found = true;
        break;
      }
      if (Date.now() - start >= detectTimeoutMs) break;
      await page.waitForTimeout(200);
    }
    if (!found) break;
    dismissedAny = true;
    await dismissFn(page);
    await page.waitForTimeout(settleMs);
  }
  return dismissedAny;
}

// Click the "Create (API) Key" button that opens the form dialog. Success =
// EITHER a form-dialog with a Name input appears (OpenRouter/Brave/Clerk
// style) OR a fully-revealed `sk-*` value of long-key shape appears on the
// page (OpenAI-style instant-mint UI with no Name prompt).
//
// `onBeforeIteration` is a per-iteration hook where the caller can run
// service-specific cleanup (e.g. dismiss the OpenRouter onboarding modal
// before retrying the Create click).
export interface ClickOuterCreateOpts {
  deadlineMs?: number;
  onBeforeIteration?: (page: Page) => Promise<void>;
}
export async function clickOuterCreate(
  page: Page,
  opts: ClickOuterCreateOpts = {},
): Promise<string | null> {
  // OpenAI's /api-keys SPA takes 10-15s to hydrate on first visit. OpenRouter's
  // onboarding+welcome modal chain can take 25-40s to render after keys-page
  // hydrates. 40s default lets the per-iter dismiss callback catch the modals
  // as they appear and still leaves time to click Create.
  const deadline = Date.now() + (opts.deadlineMs ?? 40_000);
  const preferences = [
    { label: '"Create"', filter: /^Create$/i },
    { label: '"Create Key"', filter: /^Create Key$/i },
    { label: '"Create API Key"', filter: /^Create API Key$/i },
    { label: '"Create new secret key"', filter: /^Create new secret key$/i },
    { label: '"New secret key"', filter: /^New secret key$/i },
    { label: '"Generate API Key"', filter: /^Generate API Key$/i },
    { label: '"New API Key"', filter: /^New API Key$/i },
    // OpenRouter shipped a UI refresh in 2026-Q2 that shortened the
    // empty-state button from "Create Key" / "New API Key" to bare
    // "New Key" — verified live via chrome-devtools-mcp snapshot
    // 2026-05-15 (uid=1_61 "New Key" on /workspaces/default/keys).
    { label: '"New Key"', filter: /^New Key$/i },
    // Looser fallbacks — match variations with leading/trailing whitespace
    // or icon text nodes that break anchored filters.
    { label: 'substring "Create new secret key"', filter: /Create new secret key/i },
    { label: 'substring "Create secret key"', filter: /Create secret key/i },
    { label: 'substring "New Key"', filter: /New Key/i },
  ];

  const NAME_INPUT_SEL =
    'input#name, input[id*="name" i]:not([type="email"]):not([type="password"])';
  const longKeyCount = async () =>
    page
      .evaluate(() => {
        let n = 0;
        const re = /sk-[A-Za-z0-9_-]{20,}/;
        document.querySelectorAll("code, pre, input").forEach((el) => {
          const v = (el as HTMLInputElement).value ?? el.textContent ?? "";
          if (re.test(v)) n++;
        });
        return n;
      })
      .catch(() => 0);
  const baselineKeyCount = await longKeyCount();
  const clickWorked = async (timeoutMs: number): Promise<boolean> => {
    const dialogPromise = page
      .locator(NAME_INPUT_SEL)
      .first()
      .waitFor({ state: "visible", timeout: timeoutMs })
      .then(() => true)
      .catch(() => false);
    const keyDeadline = Date.now() + timeoutMs;
    while (Date.now() < keyDeadline) {
      if (await Promise.race([dialogPromise, Promise.resolve(false)])) return true;
      const c = await longKeyCount();
      if (c > baselineKeyCount) return true;
      await page.waitForTimeout(250);
    }
    return await dialogPromise;
  };

  while (Date.now() < deadline) {
    // Per-iteration hook: caller dismisses any service-specific modal that
    // may be covering the Create button. The recorder wraps its onboarding
    // dismiss here; each production scraper passes its service-specific dismiss.
    if (opts.onBeforeIteration) {
      try {
        await opts.onBeforeIteration(page);
      } catch {
        // callback failures never break clickOuterCreate
      }
    }

    const testid = page.locator('[data-testid="create-key-btn"]').first();
    if (
      (await testid.isVisible().catch(() => false)) &&
      (await testid.isEnabled().catch(() => true))
    ) {
      await testid.click({ timeout: 5_000 });
      if (await clickWorked(5_000)) {
        return '[data-testid="create-key-btn"]';
      }
    }
    for (const pref of preferences) {
      const candidates = await page
        .locator("button")
        .filter({ hasText: pref.filter })
        .all();
      for (const c of candidates) {
        const visible = await c.isVisible().catch(() => false);
        const enabled = await c.isEnabled().catch(() => true);
        if (!visible || !enabled) continue;
        try {
          const box = await c.boundingBox();
          if (box) {
            await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, {
              steps: 8,
            });
            await jitterDelay(100, 220);
          }
          // force:true bypasses overlay-intercept errors when an onboarding
          // modal is mid-fade-in over our target button.
          await c.click({ timeout: 5_000, force: true });
          // Form-dialog OR key-reveal within 10s → click was meaningful.
          if (await clickWorked(10_000)) {
            return `button:has-text(${pref.label})`;
          }
        } catch {
          // next candidate / preference
        }
      }
    }
    await page.waitForTimeout(500);
  }
  return null;
}

// Re-export so callers don't need to reach for playwright types separately.
export type { Locator, Page };
