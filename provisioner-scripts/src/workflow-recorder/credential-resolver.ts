import * as fs from "node:fs";
import * as path from "node:path";

export interface ResolvedLoginCreds {
  email: string;
  password: string;
  source: "cli-flags" | "env" | "env+recording" | "recording+env";
}

export interface ResolveOpts {
  service: string;
  recordingsRoot: string;
  emailFlag?: string;
  passwordFlag?: string;
}

// Priority chain:
//   1. CLI flags (--login-email / --login-password)
//   2. env AGENTKEYS_LOGIN_EMAIL / AGENTKEYS_LOGIN_PASSWORD
//   3. fallback: reuse signupEmail from the latest `<service>-signup-*`
//      recording's manifest.json (password must still come from flags or env).
export function resolveLoginCreds(opts: ResolveOpts): ResolvedLoginCreds {
  const envEmail = process.env["AGENTKEYS_LOGIN_EMAIL"];
  const envPassword = process.env["AGENTKEYS_LOGIN_PASSWORD"];

  const email = opts.emailFlag ?? envEmail ?? findLatestRecordingEmail(opts);
  const password = opts.passwordFlag ?? envPassword;

  if (!email) {
    throw new Error(
      `Could not resolve login email for ${opts.service}. ` +
      `Pass --login-email, set AGENTKEYS_LOGIN_EMAIL, or ensure a prior ` +
      `${opts.service}-signup-* recording exists in ${opts.recordingsRoot}.`
    );
  }
  if (!password) {
    throw new Error(
      `Could not resolve login password for ${opts.service}. ` +
      `Pass --login-password or set AGENTKEYS_LOGIN_PASSWORD. ` +
      `(Recordings intentionally do not persist passwords.)`
    );
  }

  const source: ResolvedLoginCreds["source"] = opts.emailFlag && opts.passwordFlag
    ? "cli-flags"
    : (opts.emailFlag ?? envEmail) && (opts.passwordFlag ?? envPassword)
      ? "env"
      : opts.emailFlag
        ? "cli-flags"
        : "env+recording";

  return { email, password, source };
}

function findLatestRecordingEmail(opts: ResolveOpts): string | undefined {
  if (!fs.existsSync(opts.recordingsRoot)) return undefined;
  const prefix = `${opts.service}-signup-`;
  const entries = fs
    .readdirSync(opts.recordingsRoot, { withFileTypes: true })
    .filter((e) => e.isDirectory() && e.name.startsWith(prefix))
    .map((e) => e.name)
    .sort()
    .reverse();

  for (const dirName of entries) {
    const manifestPath = path.join(opts.recordingsRoot, dirName, "manifest.json");
    if (!fs.existsSync(manifestPath)) continue;
    try {
      const raw = fs.readFileSync(manifestPath, "utf8");
      const parsed = JSON.parse(raw) as { signupEmail?: string; state?: string };
      if (parsed.state === "completed" && parsed.signupEmail) {
        return parsed.signupEmail;
      }
    } catch {
      continue;
    }
  }
  return undefined;
}
