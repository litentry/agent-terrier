import * as fs from "node:fs";

export type AssistReason =
  | "captcha"
  | "unknown-modal"
  | "selector-missing"
  | "verification-blocked"
  | "auth-challenge"
  | "other";

export interface AssistContext {
  reason: AssistReason;
  hint: string;
  url: string;
  screenshotPath: string;
  lastActionLog: string[];
}

const ESCALATION_LOG_PATH =
  process.env["AGENTKEYS_ESCALATION_LOG"] ?? "/tmp/agentkeys-escalations.jsonl";

// v1 helper: appends one JSONL line to the escalation log, then throws an
// Error. Scrapers call this at every spot where the recording's observed
// shape might have drifted (captcha, unknown modal, selector missing,
// auth challenge, etc.). v2 will replace the body with a HumanAssist
// provider dispatch (stdin prompt, desktop notification, Slack message)
// and the interface stays identical — zero code change in callers.
export function escalateAndThrow(ctx: AssistContext): never {
  const entry = { ...ctx, ts: new Date().toISOString() };
  try {
    fs.appendFileSync(ESCALATION_LOG_PATH, JSON.stringify(entry) + "\n");
  } catch {
    // best-effort: if we can't write the log, still throw so the caller
    // learns about the escalation through the exception path.
  }
  throw new Error(
    `[${ctx.reason}] ${ctx.hint} at ${ctx.url} (screenshot: ${ctx.screenshotPath})`
  );
}

// v2 (not implemented yet): HumanAssist interface for richer channels.
// Define here so callers can reference the type when they're ready.
export type AssistResult =
  | { action: "resolved"; continue: true; skipStep?: boolean; note?: string }
  | { action: "aborted"; reason: string }
  | { action: "timeout" };

export interface HumanAssist {
  requestAssistance(ctx: AssistContext & { timeoutMs: number }): Promise<AssistResult>;
}
