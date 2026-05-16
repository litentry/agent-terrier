export type { ImapClientLike } from "./email-backends/gmail-imap.js";

export interface FetchOpts {
  from: RegExp;
  subject: RegExp;
  codeRegex: RegExp;
  timeoutMs: number;
  pollIntervalMs?: number;
  // ses-s3 only: how many ms before poll start a message may be and still
  // count as fresh. Default 60_000. Smaller = stricter rejection of prior-run
  // leftovers; larger = more tolerant to clock skew / S3 delivery latency.
  freshnessGraceMs?: number;
  // ses-s3 only (issue #83): when set, poll `bots/${walletPrefix}/inbound/`
  // instead of the shared `inbound/`. The SES routing Lambda copies
  // per-wallet emails into that prefix so the operator's OIDC-assumed
  // data-role can read them under PrincipalTag scoping. Lowercase hex,
  // typically the value of $AGENTKEYS_USER_WALLET injected by the CLI.
  walletPrefix?: string;
  imapClientFactory?: () => import("./email-backends/gmail-imap.js").ImapClientLike;
}

type EmailBackend = "gmail" | "mock-inbox" | "ses-s3";

function resolveBackend(): EmailBackend {
  const raw = process.env["AGENTKEYS_EMAIL_BACKEND"] ?? "gmail";
  if (raw === "gmail" || raw === "mock-inbox" || raw === "ses-s3") {
    return raw;
  }
  throw new Error(
    `Unknown AGENTKEYS_EMAIL_BACKEND value "${raw}". Accepted values: gmail, mock-inbox, ses-s3`
  );
}

export async function fetchVerificationCode(opts: FetchOpts): Promise<string> {
  const backend = resolveBackend();

  if (backend === "gmail") {
    const { fetchViaGmailImap } = await import("./email-backends/gmail-imap.js");
    return fetchViaGmailImap(opts);
  }

  if (backend === "mock-inbox") {
    const { fetchViaMockInbox } = await import("./email-backends/mock-inbox.js");
    return fetchViaMockInbox(opts);
  }

  if (backend === "ses-s3") {
    const { fetchViaSesS3 } = await import("./email-backends/ses-s3.js");
    return fetchViaSesS3(opts);
  }

  const _exhaustive: never = backend;
  throw new Error(`Unhandled backend: ${String(_exhaustive)}`);
}
