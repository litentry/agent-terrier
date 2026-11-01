#!/usr/bin/env -S node --import tsx/esm
import * as fs from "node:fs";
import * as path from "node:path";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright";
import { initManifest, type SessionCtx } from "./artifacts.js";
import { finalizeManifest, runLoginFlow, runSignupFlow, type FlowCtx } from "./flows.js";
import { resolveLoginCreds } from "./credential-resolver.js";

interface CliArgs {
  service: string;
  flow: "signup" | "login";
  signupUrl: string;
  loginUrl?: string;
  emailDomain: string;
  keysPath: string;
  outputDir?: string;
  loginEmail?: string;
  loginPassword?: string;
}

function parseArgs(argv: string[]): CliArgs {
  const args: Partial<CliArgs> = { keysPath: "/keys" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`flag ${a} requires a value`);
      return v;
    };
    switch (a) {
      case "--service": args.service = next(); break;
      case "--flow": {
        const v = next();
        if (v !== "signup" && v !== "login") throw new Error(`--flow must be signup|login, got ${v}`);
        args.flow = v;
        break;
      }
      case "--signup-url": args.signupUrl = next(); break;
      case "--login-url": args.loginUrl = next(); break;
      case "--email-domain": args.emailDomain = next(); break;
      case "--keys-path": args.keysPath = next(); break;
      case "--output-dir": args.outputDir = next(); break;
      case "--login-email": args.loginEmail = next(); break;
      case "--login-password": args.loginPassword = next(); break;
      case "-h":
      case "--help":
        process.stdout.write(usageText());
        process.exit(0);
        break;
      default:
        throw new Error(`unknown flag: ${a}`);
    }
  }
  if (!args.service) throw new Error("--service is required");
  if (!args.flow) throw new Error("--flow is required (signup|login)");
  if (!args.signupUrl) throw new Error("--signup-url is required");
  if (!args.emailDomain) throw new Error("--email-domain is required");
  return args as CliArgs;
}

function usageText(): string {
  return [
    "record-service — capture signup/login flow into provisioner-scripts/recordings/",
    "",
    "Usage:",
    "  npx tsx src/workflow-recorder/record-service.ts \\",
    "    --service <slug> --flow signup|login \\",
    "    --signup-url <url> [--login-url <url>] \\",
    "    --email-domain <domain> [--keys-path /keys] \\",
    "    [--output-dir <dir>] \\",
    "    [--login-email <email> --login-password <pw>]",
    "",
    "Env:",
    "  CDP_URL                        default http://localhost:9222",
    "  AGENTKEYS_SES_BUCKET           required",
    "  AWS_REGION                     default us-east-1",
    "  AGENTKEYS_SIGNUP_PASSWORD      required for signup flow",
    "  AGENTKEYS_LOGIN_EMAIL/PASSWORD fallback for login flow",
    "",
  ].join("\n");
}

function defaultOutputDir(repoRoot: string, service: string, flow: string): string {
  const ts = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  return path.join(repoRoot, "provisioner-scripts", "recordings", `${service}-${flow}-${ts}`);
}

// Walk up looking for `.git` (the TRUE repo root). Earlier version returned
// the first dir with `package.json`, which matched provisioner-scripts/ and
// doubled the path on output (provisioner-scripts/provisioner-scripts/...).
function findRepoRoot(startDir: string): string {
  let dir = startDir;
  while (dir !== "/") {
    if (fs.existsSync(path.join(dir, ".git"))) return dir;
    dir = path.dirname(dir);
  }
  // Fallback: first package.json if no .git found (unlikely in this repo).
  dir = startDir;
  while (dir !== "/") {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    dir = path.dirname(dir);
  }
  return process.cwd();
}

async function withTimeout<T>(label: string, ms: number, fn: () => Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      fn(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`timeout after ${ms}ms at: ${label}`)),
          ms
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function writeAssistRequest(outDir: string, payload: Record<string, unknown>): void {
  try {
    fs.writeFileSync(
      path.join(outDir, "assist-request.json"),
      JSON.stringify({ ts: new Date().toISOString(), ...payload }, null, 2)
    );
  } catch {
    // best-effort
  }
}

const log = (msg: string) =>
  process.stderr.write(`[recorder] ${new Date().toISOString().slice(11, 19)} ${msg}\n`);

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const repoRoot = findRepoRoot(process.cwd());
  const outDir = args.outputDir ?? defaultOutputDir(repoRoot, args.service, args.flow);
  fs.mkdirSync(outDir, { recursive: true });

  const signupEmail =
    args.flow === "signup"
      ? `bot-${Date.now()}@${args.emailDomain}`
      : resolveLoginCreds({
          service: args.service,
          recordingsRoot: path.join(repoRoot, "provisioner-scripts", "recordings"),
          emailFlag: args.loginEmail,
          passwordFlag: args.loginPassword,
        }).email;

  const signupPassword =
    args.flow === "signup"
      ? process.env["AGENTKEYS_SIGNUP_PASSWORD"] ??
        (() => {
          throw new Error("AGENTKEYS_SIGNUP_PASSWORD required for signup flow");
        })()
      : resolveLoginCreds({
          service: args.service,
          recordingsRoot: path.join(repoRoot, "provisioner-scripts", "recordings"),
          emailFlag: args.loginEmail,
          passwordFlag: args.loginPassword,
        }).password;

  const bucket = process.env["AGENTKEYS_SES_BUCKET"];
  if (!bucket) throw new Error("AGENTKEYS_SES_BUCKET env var required");

  const session: SessionCtx = {
    outDir,
    service: args.service,
    flow: args.flow,
    signupEmail,
    startedAt: new Date().toISOString(),
  };

  const manifest = initManifest(session);
  log(`recording → ${outDir}`);
  log(`service=${args.service} flow=${args.flow} signupEmail=${signupEmail}`);

  const cdpUrl = process.env["CDP_URL"] ?? "http://localhost:9222";
  log(`connecting to CDP at ${cdpUrl}`);
  let browser: Browser;
  try {
    browser = await withTimeout("chromium.connectOverCDP", 15_000, () =>
      chromium.connectOverCDP(cdpUrl)
    );
  } catch (err) {
    writeAssistRequest(outDir, {
      reason: "cdp-connect-timeout",
      cdpUrl,
      hint: "Chrome not running on this port, or firewall blocked. Relaunch Chrome with --remote-debugging-port=9222.",
      error: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
  log(`CDP connected; contexts=${browser.contexts().length}`);

  const existingContext = browser.contexts()[0];
  const ctx: BrowserContext = existingContext ?? (await browser.newContext());
  log(`using ${existingContext ? "existing" : "new"} context; pages=${ctx.pages().length}`);

  // Defensive: prior crashed run may have left tracing on for this context.
  // Stop first, ignore errors. Then start fresh.
  await ctx.tracing.stop().catch(() => {});
  log("starting tracing (screenshots + snapshots + sources)");
  try {
    await withTimeout("tracing.start", 15_000, () =>
      ctx.tracing.start({
        screenshots: true,
        snapshots: true,
        sources: true,
        title: `${args.service}-${args.flow}`,
      })
    );
  } catch (err) {
    writeAssistRequest(outDir, {
      reason: "tracing-start-timeout",
      hint: "tracing.start hung. Try: close all Chrome tabs except about:blank, or restart Chrome with --remote-debugging-port=9222.",
      error: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
  log("tracing started");

  // Clean slate: close all existing pages (they may have stale dialogs /
  // logged-in state from prior failed runs), clear ALL cookies in this
  // throwaway profile, and open one fresh tab on about:blank.
  // (Per-domain clearing left Clerk's subdomain session cookies intact and
  // auto-redirected /auth → dashboard. Full wipe is safe because the Chrome
  // profile at /tmp/agentkeys-chrome-profile is recording-only.)
  log(`cleaning slate (${ctx.pages().length} stale pages, wiping all cookies)`);
  try {
    await ctx.clearCookies();
    await ctx.clearPermissions().catch(() => {});
  } catch (err) {
    log(`cookie clear failed (non-fatal): ${err instanceof Error ? err.message : err}`);
  }

  // Close extras, keep one page for the fresh run.
  const existingPages = ctx.pages();
  for (let i = 1; i < existingPages.length; i++) {
    await existingPages[i].close().catch(() => {});
  }

  let page: Page =
    ctx.pages()[0] ?? (await withTimeout("ctx.newPage", 10_000, () => ctx.newPage()));
  // Reset the page to about:blank — if it had a modal/dialog open, this
  // discards it. Cheaper than closing-and-recreating.
  await page.goto("about:blank").catch(() => {});
  log(`page ready (${ctx.pages().length} pages in context, cookies cleared for ${new URL(args.signupUrl).hostname})`);

  const flowCtx: FlowCtx = {
    session,
    manifest,
    page,
    signupEmail,
    signupPassword,
    signupUrl: args.signupUrl,
    loginUrl: args.loginUrl,
    keysPath: args.keysPath,
    bucket,
  };

  let status: "completed" | "failed" | "aborted" = "failed";
  try {
    if (args.flow === "signup") {
      await runSignupFlow(flowCtx);
    } else {
      await runLoginFlow(flowCtx);
    }
    status = "completed";
    log("flow completed successfully");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`FATAL: ${msg}`);
    status = "failed";
  } finally {
    try {
      await ctx.tracing.stop({ path: path.join(outDir, "trace.zip") });
    } catch (err) {
      log(`tracing.stop failed: ${err instanceof Error ? err.message : err}`);
    }
    finalizeManifest(session, manifest, status);
    log(`finalized manifest (state=${status}) at ${outDir}/manifest.json`);
    log(`summary → ${outDir}/summary.md`);
    if (status === "completed") {
      log(`draft scraper → ${outDir}/draft-scraper.ts`);
    }
  }

  if (status !== "completed") process.exit(1);
}

main().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[recorder] FATAL (outside flow): ${msg}\n`);
  if (err instanceof Error && err.stack) process.stderr.write(err.stack + "\n");
  process.exit(1);
});
