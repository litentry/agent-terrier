import * as fs from "node:fs";
import * as path from "node:path";
import type { Page } from "playwright";

export interface SessionCtx {
  outDir: string;
  service: string;
  flow: "signup" | "login";
  signupEmail?: string;
  startedAt: string;
}

export interface StepArtifacts {
  index: number;
  label: string;
  ts: string;
  url: string;
  stepDir: string;
  metadata?: Record<string, unknown>;
}

export interface ManifestOutcomes {
  signupCompleted?: boolean;
  loginCompleted?: boolean;
  loginSkipped?: boolean;
  verifyType?: "magic-link" | "otp" | "skipped" | "unknown";
  turnstileMode?: "not-present" | "auto-passive" | "auto-click" | "human" | "timeout";
  hCaptchaMode?: "not-present" | "auto-passive" | "capsolver" | "human" | "timeout";
  onboardingModalSeen?: boolean;
  postLoginOtp?: boolean;
  postVerifyProfile?: boolean;
  apiKeyExtracted?: boolean;
  apiKeyMasked?: string;
}

export interface DetectedRegexes {
  emailFrom?: string;
  emailSubject?: string;
  verifyUrlHost?: string;
  urlHasHtmlEntities?: boolean;
}

export interface DetectedSelectors {
  signupUrl?: string;
  emailField?: string;
  passwordField?: string;
  tosCheckbox?: string;
  continueBtn?: string;
  onboardingDismiss?: string;
  keysPath?: string;
  createKeyBtn?: string;
  keyReveal?: string;
}

export interface Manifest {
  service: string;
  flow: "signup" | "login";
  state: "in-progress" | "completed" | "failed" | "aborted";
  startedAt: string;
  finishedAt?: string;
  signupEmail?: string;
  outcomes: ManifestOutcomes;
  detectedRegexes: DetectedRegexes;
  detectedSelectors: DetectedSelectors;
  steps: StepArtifacts[];
}

function writeAtomic(filePath: string, content: string): void {
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, filePath);
}

function writeManifest(outDir: string, manifest: Manifest, partial: boolean): void {
  const fname = partial ? "manifest.partial.json" : "manifest.json";
  writeAtomic(path.join(outDir, fname), JSON.stringify(manifest, null, 2));
}

export function initManifest(ctx: SessionCtx): Manifest {
  fs.mkdirSync(path.join(ctx.outDir, "steps"), { recursive: true });
  fs.mkdirSync(path.join(ctx.outDir, "emails"), { recursive: true });
  const manifest: Manifest = {
    service: ctx.service,
    flow: ctx.flow,
    state: "in-progress",
    startedAt: ctx.startedAt,
    signupEmail: ctx.signupEmail,
    outcomes: {},
    detectedRegexes: {},
    detectedSelectors: {},
    steps: [],
  };
  writeManifest(ctx.outDir, manifest, true);
  fs.writeFileSync(path.join(ctx.outDir, "steps.jsonl"), "");
  fs.writeFileSync(path.join(ctx.outDir, "action-log.jsonl"), "");
  return manifest;
}

function slug(label: string): string {
  return label.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

interface DigestElement {
  tag: string;
  role: string | null;
  id?: string;
  name?: string;
  type?: string;
  text: string;
}

interface StepDigest {
  url: string;
  title: string;
  visibleText: string;
  interactiveElements: DigestElement[];
  errors: string[];
}

export async function snap(
  page: Page,
  label: string,
  ctx: SessionCtx,
  manifest: Manifest,
  metadata?: Record<string, unknown>
): Promise<StepArtifacts> {
  const index = manifest.steps.length + 1;
  const paddedIdx = String(index).padStart(3, "0");
  const stepDirName = `${paddedIdx}-${slug(label)}`;
  const stepDir = path.join(ctx.outDir, "steps", stepDirName);
  fs.mkdirSync(stepDir, { recursive: true });

  const [, domHtml] = await Promise.all([
    page.screenshot({ path: path.join(stepDir, "screenshot.png"), fullPage: true }).catch(() => null),
    page.content().catch(() => ""),
  ]);

  fs.writeFileSync(path.join(stepDir, "dom.html"), domHtml);

  const url = page.url();
  const title = await page.title().catch(() => "");
  const visibleText = await page
    .locator("body")
    .innerText({ timeout: 1000 })
    .catch(() => "");
  const interactiveElements: DigestElement[] = await page
    .$$eval(
      "input, button, a[role='button'], [role='link'], select, textarea, [role='radio'], [role='checkbox']",
      (nodes: Element[]) =>
        nodes
          .map((n) => {
            const el = n as HTMLElement & { name?: string; value?: string; type?: string };
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return null;
            return {
              tag: el.tagName.toLowerCase(),
              role: el.getAttribute("role"),
              id: el.id || undefined,
              name: el.name || undefined,
              type: el.type || undefined,
              text: (el.innerText || el.value || "").slice(0, 80),
            };
          })
          .filter((x): x is NonNullable<typeof x> => x !== null)
    )
    .catch(() => []);
  const errors = await page
    .locator('[role="alert"], .cl-formFieldError, .cl-alertText')
    .allInnerTexts()
    .catch(() => []);

  const digest: StepDigest = {
    url,
    title,
    visibleText: visibleText.slice(0, 200).replace(/\s+/g, " ").trim(),
    interactiveElements,
    errors,
  };
  fs.writeFileSync(path.join(stepDir, "digest.json"), JSON.stringify(digest, null, 2));

  const step: StepArtifacts = {
    index,
    label,
    ts: new Date().toISOString(),
    url,
    stepDir: stepDirName,
    metadata,
  };

  fs.appendFileSync(path.join(ctx.outDir, "steps.jsonl"), JSON.stringify(step) + "\n");
  manifest.steps.push(step);
  writeManifest(ctx.outDir, manifest, true);

  return step;
}

export function logAction(outDir: string, entry: Record<string, unknown>): void {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
  fs.appendFileSync(path.join(outDir, "action-log.jsonl"), line + "\n");
}

export function finalizeManifest(
  ctx: SessionCtx,
  manifest: Manifest,
  status: "completed" | "failed" | "aborted"
): void {
  manifest.state = status;
  manifest.finishedAt = new Date().toISOString();
  writeManifest(ctx.outDir, manifest, false);
  try {
    fs.unlinkSync(path.join(ctx.outDir, "manifest.partial.json"));
  } catch {}
  writeSummaryMd(ctx.outDir, manifest);
  if (status === "completed") {
    emitDraftScraper(ctx.outDir, manifest);
  }
}

function writeSummaryMd(outDir: string, m: Manifest): void {
  const dr = m.detectedRegexes;
  const ds = m.detectedSelectors;
  const outcomeLines = Object.entries(m.outcomes)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `- ${k}: ${v}`);
  const selectorLines = Object.entries(ds)
    .filter(([, v]) => v)
    .map(([k, v]) => `- ${k}: \`${v}\``);

  const md = [
    `# ${m.service} / ${m.flow} recording — ${m.startedAt}`,
    ``,
    `## Outcomes`,
    ...outcomeLines,
    ``,
    `## Verification email (what a scraper needs)`,
    dr.emailFrom ? `- From: \`${dr.emailFrom}\`` : `- From: (not captured)`,
    dr.emailSubject ? `- Subject: \`${dr.emailSubject}\`` : `- Subject: (not captured)`,
    dr.verifyUrlHost ? `- URL host: \`${dr.verifyUrlHost}\`` : `- URL host: (not captured)`,
    `- URL contains HTML entities: ${dr.urlHasHtmlEntities ? "**yes** — decode `&amp;` before page.goto()" : "no"}`,
    ``,
    `## Key selectors observed`,
    ...selectorLines,
    ``,
    `## Steps recorded`,
    ...m.steps.map((s) => `- \`${s.stepDir}\` (${s.label})`),
    ``,
    `## Next`,
    `- Fill in \`TODO(human):\` markers in \`draft-scraper.ts\` to finish.`,
    `- Drill into per-step \`digest.json\` if a selector looks suspicious.`,
    `- Open \`trace.zip\` in Playwright Trace Viewer for full interaction replay.`,
    ``,
  ].join("\n");

  fs.writeFileSync(path.join(outDir, "summary.md"), md);
}

function regexSourceOrPlaceholder(s: string | undefined, placeholder: string): string {
  if (!s) return placeholder;
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

// Emit a self-contained scraper with inlined helpers. Zero `TODO(human):` in
// the runtime path — the recorder's logic is serialized directly. Generated
// code uses template literals; we build it as a string array joined with
// newlines to avoid nested-backtick escaping hell.
function emitDraftScraper(outDir: string, m: Manifest): void {
  const dr = m.detectedRegexes;
  const ds = m.detectedSelectors;

  const fromRegex = dr.emailFrom
    ? "/" + regexSourceOrPlaceholder(dr.emailFrom.split("<")[1]?.replace(">", "") ?? dr.emailFrom, "openrouter\\.ai|clerk") + "/i"
    : "/@openrouter\\.ai|clerk/i";
  const subjectRegex = dr.emailSubject
    ? "/" + regexSourceOrPlaceholder(dr.emailSubject, "verify|confirm|sign.up|magic") + "/i"
    : "/sign[\\s-]?up.*link|verify|magic.*link|confirm/i";
  const urlRegex = dr.verifyUrlHost
    ? '/(https:\\/\\/[^\\s<>"\'\\)]*' + regexSourceOrPlaceholder(dr.verifyUrlHost, "clerk") + '[^\\s<>"\'\\)]*)/i'
    : '/(https:\\/\\/[^\\s<>"\'\\)]*(?:clerk|\\/verify|ticket=|verification)[^\\s<>"\'\\)]*)/i';

  const signupUrl = ds.signupUrl ?? "";
  const keysPath = ds.keysPath ?? "/keys";

  // Build as array of literal-string lines; no outer template literal → no
  // nested-backtick escaping. Any `${...}` below is a real interpolation we
  // WANT resolved at emit time; the ones that should appear literally in
  // the generated file use backslash escaping.
  const LINE = (s: string) => s;

  const BT = "`"; // backtick for use inside strings without escaping hell
  const DOLLAR = "$";

  const L: string[] = [];
  L.push(LINE("// Auto-generated scraper from recording: " + m.service + " / " + m.flow));
  L.push(LINE("// Started: " + m.startedAt));
  L.push(LINE("// Finished: " + (m.finishedAt ?? "(incomplete)")));
  L.push(LINE("//"));
  L.push(LINE("// Self-contained: helpers inlined, no manual edits required to run."));
  L.push(LINE("// Prereqs: AGENTKEYS_SIGNUP_EMAIL + AGENTKEYS_SIGNUP_PASSWORD in env,"));
  L.push(LINE("//          Chrome listening on CDP_URL (default http://localhost:9222)."));
  L.push(LINE(""));
  L.push(LINE('import { chromium, type Browser, type BrowserContext, type Page } from "playwright";'));
  L.push(LINE('import { fetchVerificationCode } from "../../src/lib/email.js";'));
  L.push(LINE(""));
  L.push(LINE('const CDP_URL = process.env.CDP_URL ?? "http://localhost:9222";'));
  L.push(LINE('const SIGNUP_EMAIL = process.env.AGENTKEYS_SIGNUP_EMAIL ?? "";'));
  L.push(LINE('const SIGNUP_PASSWORD = process.env.AGENTKEYS_SIGNUP_PASSWORD ?? "";'));
  L.push(LINE(""));
  L.push(LINE("// === Detected at recording time ==="));
  L.push(LINE('const SIGNUP_URL = "' + signupUrl + '";'));
  L.push(LINE('const KEYS_PATH = "' + keysPath + '";'));
  L.push(LINE("const FROM_REGEX = " + fromRegex + ";"));
  L.push(LINE("const SUBJECT_REGEX = " + subjectRegex + ";"));
  L.push(LINE("const URL_REGEX = " + urlRegex + ";"));
  L.push(LINE(""));
  L.push(LINE("const log = (msg: string) => process.stderr.write(" + BT + "[scraper] " + DOLLAR + "{new Date().toISOString().slice(11, 19)} " + DOLLAR + "{msg}\\n" + BT + ");"));
  L.push(LINE(""));
  L.push(LINE("// === Inlined helpers (from workflow-recorder/flows.ts) ==="));
  L.push(LINE(""));
  L.push(LINE("function jitter(min: number, max: number): Promise<void> {"));
  L.push(LINE("  const ms = Math.floor(min + Math.random() * (max - min));"));
  L.push(LINE("  return new Promise((r) => setTimeout(r, ms));"));
  L.push(LINE("}"));
  L.push(LINE(""));
  L.push(LINE("async function humanType(page: Page, selector: string, value: string): Promise<void> {"));
  L.push(LINE("  const loc = page.locator(selector).first();"));
  L.push(LINE("  const box = await loc.boundingBox();"));
  L.push(LINE("  if (box) {"));
  L.push(LINE("    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 8 });"));
  L.push(LINE("    await jitter(60, 180);"));
  L.push(LINE("  }"));
  L.push(LINE("  await loc.click({ timeout: 5_000 }).catch(() => {});"));
  L.push(LINE("  await loc.pressSequentially(value, { delay: 60 + Math.floor(Math.random() * 60) });"));
  L.push(LINE("}"));
  L.push(LINE(""));
  L.push(LINE("async function clickFirstVisible(page: Page, selectors: string[]): Promise<string | null> {"));
  L.push(LINE("  for (const sel of selectors) {"));
  L.push(LINE("    const candidates = await page.locator(sel).all();"));
  L.push(LINE("    for (const c of candidates) {"));
  L.push(LINE("      if (!(await c.isVisible().catch(() => false))) continue;"));
  L.push(LINE("      if (!(await c.isEnabled().catch(() => true))) continue;"));
  L.push(LINE("      try {"));
  L.push(LINE("        const box = await c.boundingBox();"));
  L.push(LINE("        if (box) {"));
  L.push(LINE("          await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 10 });"));
  L.push(LINE("          await jitter(120, 280);"));
  L.push(LINE("        }"));
  L.push(LINE("        await c.click({ timeout: 5_000 });"));
  L.push(LINE("        return sel;"));
  L.push(LINE("      } catch { /* next candidate */ }"));
  L.push(LINE("    }"));
  L.push(LINE("  }"));
  L.push(LINE("  return null;"));
  L.push(LINE("}"));
  L.push(LINE(""));
  L.push(LINE("async function dismissCookieBanner(page: Page): Promise<void> {"));
  L.push(LINE('  const texts = ["Accept All Cookies", "Accept cookies", "Accept All", "Accept", "Agree", "OK", "Got it"];'));
  L.push(LINE("  for (const t of texts) {"));
  L.push(LINE("    const c = page.locator(\"button\").filter({ hasText: new RegExp(" + BT + "^" + DOLLAR + "{t}" + DOLLAR + "{\"\"}" + BT + ", \"i\") }).first();"));
  L.push(LINE("    if (await c.isVisible({ timeout: 800 }).catch(() => false)) {"));
  L.push(LINE("      await c.click({ timeout: 3_000 }).catch(() => {});"));
  L.push(LINE("      await page.waitForTimeout(400);"));
  L.push(LINE("      return;"));
  L.push(LINE("    }"));
  L.push(LINE("  }"));
  L.push(LINE("}"));
  L.push(LINE(""));
  L.push(LINE("async function handleTurnstile(page: Page): Promise<string> {"));
  L.push(LINE('  const iframeSel = \'iframe[src*="challenges.cloudflare.com"]\';'));
  L.push(LINE('  const inputSel = \'input[name="cf-turnstile-response"]\';'));
  L.push(LINE("  const present = await page.locator(" + BT + DOLLAR + "{iframeSel}, " + DOLLAR + "{inputSel}" + BT + ").first().isVisible({ timeout: 8_000 }).catch(() => false);"));
  L.push(LINE('  if (!present) return "not-present";'));
  L.push(LINE("  const isResolved = async () => {"));
  L.push(LINE("    try {"));
  L.push(LINE("      const val = await page.locator(inputSel).first().inputValue({ timeout: 500 });"));
  L.push(LINE("      return Boolean(val && val.length > 0);"));
  L.push(LINE("    } catch { return false; }"));
  L.push(LINE("  };"));
  L.push(LINE("  const start = Date.now();"));
  L.push(LINE("  while (Date.now() - start < 10_000) {"));
  L.push(LINE('    if (await isResolved()) return "auto-passive";'));
  L.push(LINE("    await page.waitForTimeout(500);"));
  L.push(LINE("  }"));
  L.push(LINE("  try {"));
  L.push(LINE("    const box = await page.locator(iframeSel).first().boundingBox({ timeout: 2_000 });"));
  L.push(LINE("    if (box) {"));
  L.push(LINE("      const x = box.x + 25, y = box.y + box.height / 2;"));
  L.push(LINE("      await page.mouse.move(x - 30, y + 10, { steps: 8 });"));
  L.push(LINE("      await page.waitForTimeout(150);"));
  L.push(LINE("      await page.mouse.move(x, y, { steps: 6 });"));
  L.push(LINE("      await page.waitForTimeout(80);"));
  L.push(LINE("      await page.mouse.click(x, y);"));
  L.push(LINE("      const clickEnd = Date.now() + 15_000;"));
  L.push(LINE("      while (Date.now() < clickEnd) {"));
  L.push(LINE('        if (await isResolved()) return "auto-click";'));
  L.push(LINE("        await page.waitForTimeout(500);"));
  L.push(LINE("      }"));
  L.push(LINE("    }"));
  L.push(LINE("  } catch { /* fall through to human */ }"));
  L.push(LINE('  process.stderr.write("[scraper] Turnstile detected — click checkbox in Chrome within 180s\\n\\x07\\n");'));
  L.push(LINE("  while (Date.now() - start < 180_000) {"));
  L.push(LINE('    if (await isResolved()) return "human";'));
  L.push(LINE("    await page.waitForTimeout(1_000);"));
  L.push(LINE("  }"));
  L.push(LINE('  throw new Error("Turnstile did not resolve within 180s");'));
  L.push(LINE("}"));
  L.push(LINE(""));
  L.push(LINE("async function openCreateKeyDialog(page: Page): Promise<void> {"));
  L.push(LINE('  const nameInputSel = \'input#name, input[id*="name" i]:not([type="email"]):not([type="password"])\';'));
  L.push(LINE("  const deadline = Date.now() + 15_000;"));
  L.push(LINE("  // Priority: welcome-banner 'Create API Key' link FIRST — it opens the"));
  L.push(LINE("  // form dialog directly AND dismisses the banner overlay whose portal"));
  L.push(LINE("  // would otherwise intercept clicks on the empty-state 'Create' button."));
  L.push(LINE("  // Fall back to outer 'Create'/'Create Key'. Use force:true to bypass"));
  L.push(LINE("  // the portal-root pointer-event interceptor if normal click fails."));
  L.push(LINE("  while (Date.now() < deadline) {"));
  L.push(LINE("    for (const filter of [/^Create API Key$/i, /^Create Key$/i, /^Create$/i]) {"));
  L.push(LINE('      const candidates = await page.locator("button").filter({ hasText: filter }).all();'));
  L.push(LINE("      for (const c of candidates) {"));
  L.push(LINE("        if (!(await c.isVisible().catch(() => false))) continue;"));
  L.push(LINE("        if (!(await c.isEnabled().catch(() => true))) continue;"));
  L.push(LINE("        for (const force of [false, true]) {"));
  L.push(LINE("          try {"));
  L.push(LINE("            if (!force) {"));
  L.push(LINE("              const box = await c.boundingBox();"));
  L.push(LINE("              if (box) {"));
  L.push(LINE("                await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 8 });"));
  L.push(LINE("                await jitter(100, 220);"));
  L.push(LINE("              }"));
  L.push(LINE("            }"));
  L.push(LINE("            await c.click({ timeout: 3_000, force });"));
  L.push(LINE("            if (await page.locator(nameInputSel).first().isVisible({ timeout: 5_000 }).catch(() => false)) return;"));
  L.push(LINE("          } catch { /* next force / next candidate */ }"));
  L.push(LINE("        }"));
  L.push(LINE("      }"));
  L.push(LINE("    }"));
  L.push(LINE("    await page.waitForTimeout(500);"));
  L.push(LINE("  }"));
  L.push(LINE('  throw new Error("openCreateKeyDialog: no Create button opened the form dialog after 15s");'));
  L.push(LINE("}"));
  L.push(LINE(""));
  L.push(LINE("// === Main flow ==="));
  L.push(LINE(""));
  L.push(LINE("async function main(): Promise<void> {"));
  L.push(LINE("  if (!SIGNUP_EMAIL || !SIGNUP_PASSWORD) {"));
  L.push(LINE('    throw new Error("AGENTKEYS_SIGNUP_EMAIL + AGENTKEYS_SIGNUP_PASSWORD required");'));
  L.push(LINE("  }"));
  L.push(LINE("  log(" + BT + "connecting to CDP " + DOLLAR + "{CDP_URL}" + BT + ");"));
  L.push(LINE("  const browser: Browser = await chromium.connectOverCDP(CDP_URL);"));
  L.push(LINE("  const ctx: BrowserContext = browser.contexts()[0] ?? (await browser.newContext());"));
  L.push(LINE("  await ctx.clearCookies().catch(() => {});"));
  L.push(LINE("  const page: Page = ctx.pages()[0] ?? (await ctx.newPage());"));
  L.push(LINE('  await page.goto("about:blank").catch(() => {});'));
  L.push(LINE(""));
  L.push(LINE('  log("navigating to signup");'));
  L.push(LINE('  await page.goto(SIGNUP_URL, { waitUntil: "networkidle", timeout: 30_000 });'));
  L.push(LINE("  await dismissCookieBanner(page);"));
  L.push(LINE(""));
  L.push(LINE('  log("filling credentials");'));
  L.push(LINE('  await humanType(page, \'input[type="email"], input[name*="email" i], input[id*="email" i]\', SIGNUP_EMAIL);'));
  L.push(LINE("  await jitter(250, 550);"));
  L.push(LINE('  await humanType(page, \'input[type="password"], input[name*="password" i]\', SIGNUP_PASSWORD);'));
  L.push(LINE("  await jitter(300, 700);"));
  L.push(LINE(""));
  L.push(LINE('  // TOS checkbox: try direct check, fall back to label click.'));
  L.push(LINE('  const tosSel = \'input[type="checkbox"][id*="legal" i], input[type="checkbox"][name*="terms" i], input[type="checkbox"][id*="tos" i]\';'));
  L.push(LINE("  const tos = page.locator(tosSel).first();"));
  L.push(LINE("  if (await tos.count()) {"));
  L.push(LINE("    await tos.check({ force: true, timeout: 3_000 }).catch(() => {});"));
  L.push(LINE("    if (!(await tos.isChecked().catch(() => false))) {"));
  L.push(LINE("      const id = await tos.evaluate((el: HTMLInputElement) => el.id || \"\");"));
  L.push(LINE("      if (id) await page.locator(" + BT + "label[for=\"" + DOLLAR + "{id}\"]" + BT + ").first().click({ timeout: 2_000 }).catch(() => {});"));
  L.push(LINE("    }"));
  L.push(LINE("    await jitter(200, 500);"));
  L.push(LINE("  }"));
  L.push(LINE(""));
  L.push(LINE('  log("clicking continue");'));
  L.push(LINE("  await clickFirstVisible(page, ["));
  L.push(LINE('    \'button[data-localization-key="formButtonPrimary"]\','));
  L.push(LINE('    \'button:text-is("Continue")\','));
  L.push(LINE('    \'button:text-is("Sign up")\','));
  L.push(LINE('    \'button:text-is("Register")\','));
  L.push(LINE('    \'button:text-is("Create account")\','));
  L.push(LINE('    \'form button[type="submit"]:not([aria-label="Open AI Assistant"]):not([aria-label="Close"]):not(:has-text("Google")):not(:has-text("GitHub")):not(:has-text("Apple"))\','));
  L.push(LINE("  ]);"));
  L.push(LINE(""));
  L.push(LINE('  log("handling Turnstile (if present)");'));
  L.push(LINE("  const turnstileMode = await handleTurnstile(page);"));
  L.push(LINE("  log(" + BT + "turnstile: " + DOLLAR + "{turnstileMode}" + BT + ");"));
  L.push(LINE(""));
  L.push(LINE('  log("fetching verification email");'));
  L.push(LINE("  const verifyUrlRaw = await fetchVerificationCode({"));
  L.push(LINE("    from: FROM_REGEX, subject: SUBJECT_REGEX, codeRegex: URL_REGEX, timeoutMs: 90_000,"));
  L.push(LINE("  });"));
  L.push(LINE('  const verifyUrl = verifyUrlRaw.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");'));
  L.push(LINE("  log(" + BT + "got verify URL: " + DOLLAR + "{verifyUrl.slice(0, 80)}..." + BT + ");"));
  L.push(LINE('  await page.goto(verifyUrl, { waitUntil: "networkidle", timeout: 30_000 });'));
  L.push(LINE('  await page.waitForURL((u) => !u.toString().includes("/sign-up"), { timeout: 30_000 }).catch(() => {});'));
  L.push(LINE(""));
  L.push(LINE('  log("navigating to keys page");'));
  L.push(LINE("  const keysUrl = new URL(KEYS_PATH, page.url()).toString();"));
  L.push(LINE('  await page.goto(keysUrl, { waitUntil: "networkidle", timeout: 20_000 });'));
  L.push(LINE(""));
  L.push(LINE("  // Dismiss onboarding modal if present (OpenRouter: 'Where did you first hear')."));
  L.push(LINE("  // Retry in a loop until the modal's header text is gone — single-shot clicks"));
  L.push(LINE("  // silently fail when portal overlays intercept or elements lag rendering."));
  L.push(LINE('  const onboardHeader = page.locator("text=/where did you first hear|welcome|get started/i").first();'));
  L.push(LINE("  if (await onboardHeader.isVisible({ timeout: 3_000 }).catch(() => false)) {"));
  L.push(LINE('    log("dismissing onboarding modal");'));
  L.push(LINE("    const dismissDeadline = Date.now() + 15_000;"));
  L.push(LINE("    while (Date.now() < dismissDeadline) {"));
  L.push(LINE("      // Select a radio option — try multiple strategies."));
  L.push(LINE("      const radio = page.getByRole(\"radio\", { name: /other.*not sure|skip|not now/i }).or(page.getByLabel(/other.*not sure/i)).or(page.getByText(/^other.*not sure$/i)).first();"));
  L.push(LINE("      await radio.click({ timeout: 2_000, force: true }).catch(() => {});"));
  L.push(LINE("      await jitter(200, 400);"));
  L.push(LINE("      // Click Continue — force:true bypasses portal overlay hit-testing."));
  L.push(LINE("      const cont = page.getByRole(\"button\", { name: /^continue$/i }).or(page.locator(\"button\").filter({ hasText: /^Continue$/i })).first();"));
  L.push(LINE("      await cont.click({ timeout: 2_000, force: true }).catch(() => {});"));
  L.push(LINE("      await page.waitForTimeout(800);"));
  L.push(LINE("      if (!(await onboardHeader.isVisible({ timeout: 500 }).catch(() => false))) break;"));
  L.push(LINE("    }"));
  L.push(LINE("  }"));
  L.push(LINE(""));
  L.push(LINE('  log("opening create-key dialog");'));
  L.push(LINE("  await openCreateKeyDialog(page);"));
  L.push(LINE(""));
  L.push(LINE('  log("filling key name + confirming");'));
  L.push(LINE("  await humanType(page, "));
  L.push(LINE('    \'[role="dialog"] input#name, [role="dialog"] input[id*="name" i]:not([type="email"]):not([type="password"])\','));
  L.push(LINE("    " + BT + "scraper-" + DOLLAR + "{Date.now()}" + BT));
  L.push(LINE("  );"));
  L.push(LINE("  await jitter(400, 700);"));
  L.push(LINE("  await clickFirstVisible(page, ["));
  L.push(LINE('    \'[role="dialog"]:has(input#name) button:text-is("Create API Key")\','));
  L.push(LINE('    \'[role="dialog"]:has(input#name) button:text-is("Create")\','));
  L.push(LINE('    \'[role="dialog"]:has(input#name) button:has-text("Create")\','));
  L.push(LINE("  ]);"));
  L.push(LINE(""));
  L.push(LINE('  log("waiting for key reveal");'));
  L.push(LINE('  const keyEl = page.locator(\'code:has-text("sk-"), pre:has-text("sk-"), input[value^="sk-"]\').first();'));
  L.push(LINE("  await keyEl.waitFor({ timeout: 15_000 });"));
  L.push(LINE("  const tag = await keyEl.evaluate((n) => n.tagName.toLowerCase());"));
  L.push(LINE('  const raw = tag === "input" ? await keyEl.inputValue() : ((await keyEl.textContent()) ?? "");'));
  L.push(LINE("  const key = raw.trim();"));
  L.push(LINE("  if (!/^sk-[a-zA-Z0-9_-]{20,}$/.test(key)) {"));
  L.push(LINE("    throw new Error(" + BT + "extracted value doesn't match sk-* format: " + DOLLAR + "{key.slice(0, 40)}" + BT + ");"));
  L.push(LINE("  }"));
  L.push(LINE("  log(" + BT + "extracted: " + DOLLAR + "{key.slice(0, 8)}****" + DOLLAR + "{key.slice(-4)}" + BT + ");"));
  L.push(LINE('  process.stdout.write(key + "\\n");'));
  L.push(LINE(""));
  L.push(LINE("  // Close the tab so the revealed key isn't left visible in Chrome."));
  L.push(LINE("  // browser.close() in CDP mode only disconnects us — it doesn't close"));
  L.push(LINE("  // tabs (user owns Chrome). page.close() is the right primitive."));
  L.push(LINE("  await page.close().catch(() => {});"));
  L.push(LINE("  await browser.close().catch(() => {}); // disconnects WebSocket"));
  L.push(LINE("  process.exit(0);"));
  L.push(LINE("}"));
  L.push(LINE(""));
  L.push(LINE("main().catch((err) => {"));
  L.push(LINE("  const msg = err?.message ?? String(err);"));
  L.push(LINE("  process.stderr.write(" + BT + "[scraper] FATAL: " + DOLLAR + "{msg}\\n" + BT + ");"));
  L.push(LINE("  if (err?.stack) process.stderr.write(err.stack + \"\\n\");"));
  L.push(LINE("  process.exit(1);"));
  L.push(LINE("});"));
  L.push(LINE(""));

  fs.writeFileSync(path.join(outDir, "draft-scraper.ts"), L.join("\n"));
}
