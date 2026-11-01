import type { Page } from "playwright";
import { escalateAndThrow } from "../human-assist.js";

export type HCaptchaMode = "not-present" | "auto-passive" | "capsolver" | "human" | "timeout";

export interface HCaptchaOpts {
  detectTimeoutMs?: number;
  autoPassiveWindowMs?: number;
  capsolverTimeoutMs?: number;
  humanFallbackTimeoutMs?: number;
  screenshotPathOnEscalate?: string;
}

// Detects hCaptcha on the page and resolves it via CapSolver when
// CAPSOLVER_API_KEY is set, otherwise waits for the human to solve it in
// the Chrome window. ElevenLabs uses invisible hCaptcha — page JS injects
// the iframe and expects a token in textarea[name="h-captcha-response"].
//
// Flow:
//   1. Detect iframe[src*="hcaptcha.com"] OR textarea[name="h-captcha-response"].
//   2. If not present → not-present.
//   3. Poll for token-populated within autoPassiveWindowMs. If it populates
//      on its own (invisible-mode passes), return auto-passive.
//   4. If CAPSOLVER_API_KEY is set: extract sitekey from iframe URL, submit
//      to CapSolver, poll for token, inject into the textarea, fire
//      input+change events. Return capsolver.
//   5. Else human fallback (like turnstile-handler).
export async function handleHCaptcha(
  page: Page,
  opts: HCaptchaOpts = {}
): Promise<HCaptchaMode> {
  const detectTimeout = opts.detectTimeoutMs ?? 5_000;
  // Invisible hCaptcha fingerprints the browser after submit click and often
  // auto-passes in 5-25s on real Chrome. 30s gives passive a fair shot.
  const autoPassiveWindow = opts.autoPassiveWindowMs ?? 30_000;
  const capsolverTimeout = opts.capsolverTimeoutMs ?? 180_000;
  const humanFallbackTimeout = opts.humanFallbackTimeoutMs ?? 180_000;

  const iframeSel = 'iframe[src*="hcaptcha.com"]';
  const textareaSel = 'textarea[name="h-captcha-response"]';

  const present = await page
    .locator(`${iframeSel}, ${textareaSel}`)
    .first()
    .isVisible({ timeout: detectTimeout })
    .catch(() => false);
  const domPresent =
    present ||
    (await page.locator(textareaSel).count().catch(() => 0)) > 0;
  if (!domPresent) return "not-present";

  const isResolved = async (): Promise<boolean> => {
    try {
      const val = await page.evaluate(() => {
        const tas = Array.from(
          document.querySelectorAll<HTMLTextAreaElement>(
            'textarea[name="h-captcha-response"]',
          ),
        );
        return tas.find((t) => t.value && t.value.length > 20)?.value ?? "";
      });
      return Boolean(val);
    } catch {
      return false;
    }
  };

  const start = Date.now();
  while (Date.now() - start < autoPassiveWindow) {
    if (await isResolved()) return "auto-passive";
    await page.waitForTimeout(500);
  }

  const apiKey = process.env["CAPSOLVER_API_KEY"];
  if (apiKey) {
    const sitekey = await extractSitekey(page);
    if (!sitekey) {
      process.stderr.write("[hcaptcha] capsolver wanted but sitekey not found; falling back to human\n");
    } else {
      process.stderr.write(`[hcaptcha] solving via CapSolver (sitekey=${sitekey.slice(0, 8)}...)\n`);
      const token = await solveHCaptchaViaCapSolver({
        apiKey,
        websiteUrl: page.url(),
        websiteKey: sitekey,
        timeoutMs: capsolverTimeout,
      }).catch((err) => {
        process.stderr.write(`[hcaptcha] CapSolver failed: ${err.message}\n`);
        return null;
      });
      if (token) {
        await page.evaluate((t) => {
          const tas = Array.from(
            document.querySelectorAll<HTMLTextAreaElement>(
              'textarea[name="h-captcha-response"]',
            ),
          );
          for (const ta of tas) {
            ta.value = t;
            ta.dispatchEvent(new Event("input", { bubbles: true }));
            ta.dispatchEvent(new Event("change", { bubbles: true }));
          }
          // Some frontends also watch a global window callback. ElevenLabs
          // registers `window.hcaptchaOnVerify` or similar. Best-effort call.
          const w = window as unknown as {
            hcaptchaOnVerify?: (t: string) => void;
            onHCaptchaSuccess?: (t: string) => void;
          };
          try {
            w.hcaptchaOnVerify?.(t);
            w.onHCaptchaSuccess?.(t);
          } catch {
            /* ignore */
          }
        }, token);
        // Give the framework a moment to revalidate the form.
        await page.waitForTimeout(800);
        if (await isResolved()) return "capsolver";
        // Even if textarea.value check fails, the form may have accepted.
        return "capsolver";
      }
    }
  }

  process.stderr.write(
    "[hcaptcha] CapSolver unavailable or failed — please solve hCaptcha " +
      "in the Chrome window. Waiting up to " +
      Math.round(humanFallbackTimeout / 1000) +
      "s...\n\x07\n",
  );
  const humanDeadline = Date.now() + humanFallbackTimeout;
  while (Date.now() < humanDeadline) {
    if (await isResolved()) return "human";
    await page.waitForTimeout(1_000);
  }

  escalateAndThrow({
    reason: "captcha",
    hint: "hCaptcha did not resolve within fallback window",
    url: page.url(),
    screenshotPath: opts.screenshotPathOnEscalate ?? "(no screenshot)",
    lastActionLog: [],
  });
}

async function extractSitekey(page: Page): Promise<string | undefined> {
  const iframeSrc = await page
    .locator('iframe[src*="hcaptcha.com"]')
    .first()
    .getAttribute("src")
    .catch(() => null);
  if (iframeSrc) {
    const m = iframeSrc.match(/sitekey=([a-f0-9-]{20,})/i);
    if (m) return m[1];
  }
  // Fallback: scan DOM attributes and scripts for data-sitekey or sitekey.
  return page
    .evaluate(() => {
      const attr = document.querySelector("[data-sitekey]")?.getAttribute("data-sitekey");
      if (attr) return attr;
      const html = document.documentElement.outerHTML;
      const m = html.match(/sitekey[=:\s"']+([a-f0-9-]{30,})/i);
      return m ? m[1] : undefined;
    })
    .catch(() => undefined);
}

interface CapSolverOpts {
  apiKey: string;
  websiteUrl: string;
  websiteKey: string;
  timeoutMs: number;
  pollIntervalMs?: number;
}

async function solveHCaptchaViaCapSolver(opts: CapSolverOpts): Promise<string> {
  const pollInterval = opts.pollIntervalMs ?? 3_000;
  const createRes = await fetch("https://api.capsolver.com/createTask", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      clientKey: opts.apiKey,
      task: {
        type: "HCaptchaTaskProxyless",
        websiteURL: opts.websiteUrl,
        websiteKey: opts.websiteKey,
      },
    }),
  });
  const createJson = (await createRes.json()) as {
    errorId?: number;
    errorDescription?: string;
    taskId?: string;
  };
  if (createJson.errorId || !createJson.taskId) {
    throw new Error(`createTask: ${createJson.errorDescription ?? "unknown"}`);
  }
  const taskId = createJson.taskId;

  const deadline = Date.now() + opts.timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, pollInterval));
    const resultRes = await fetch("https://api.capsolver.com/getTaskResult", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clientKey: opts.apiKey, taskId }),
    });
    const resultJson = (await resultRes.json()) as {
      errorId?: number;
      errorDescription?: string;
      status?: "ready" | "processing" | "failed";
      solution?: { gRecaptchaResponse?: string; token?: string };
    };
    if (resultJson.errorId) {
      throw new Error(`getTaskResult: ${resultJson.errorDescription ?? "unknown"}`);
    }
    if (resultJson.status === "ready") {
      const token =
        resultJson.solution?.gRecaptchaResponse ?? resultJson.solution?.token;
      if (!token) throw new Error("getTaskResult ready but no token in solution");
      return token;
    }
  }
  throw new Error(`CapSolver timed out after ${opts.timeoutMs}ms (taskId=${taskId})`);
}
