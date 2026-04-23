import type { FetchOpts } from "../email.js";
import { S3Client, ListObjectsV2Command, GetObjectCommand } from "@aws-sdk/client-s3";

export class EmailTimeoutError extends Error {
  readonly code = "EMAIL_TIMEOUT" as const;
  constructor(
    public readonly elapsed_ms: number,
    public readonly scanned: number,
    public readonly reasons: Record<string, number>,
    public readonly samples: Array<{ key: string; from: string; subject: string }>
  ) {
    const reasonsStr = Object.entries(reasons)
      .map(([k, v]) => `${k}=${v}`)
      .join(" ");
    const samplesStr = samples
      .slice(0, 5)
      .map((s) => `  - ${s.key} | from=${s.from.slice(0, 50)} | subject=${s.subject.slice(0, 50)}`)
      .join("\n");
    super(
      `EMAIL_TIMEOUT after ${elapsed_ms}ms — scanned ${scanned} objects | ${reasonsStr}\n` +
      (samples.length > 0 ? `most recent objects:\n${samplesStr}` : "bucket appeared empty during poll")
    );
    this.name = "EmailTimeoutError";
  }
}

const debug = (msg: string) => process.stderr.write(`[ses-s3] ${new Date().toISOString().slice(11, 19)} ${msg}\n`);

function parseEmailHeaders(rawMime: string): { from: string; subject: string; body: string } {
  const lines = rawMime.split(/\r?\n/);
  let from = "";
  let subject = "";
  let bodyStartIndex = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === "") {
      bodyStartIndex = i + 1;
      break;
    }
    const lower = line.toLowerCase();
    if (lower.startsWith("from:")) {
      from = line.slice(5).trim();
    } else if (lower.startsWith("subject:")) {
      subject = line.slice(8).trim();
    }
  }

  const body = bodyStartIndex >= 0 ? lines.slice(bodyStartIndex).join("\n") : "";
  return { from, subject, body };
}

async function streamToString(stream: NodeJS.ReadableStream): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
  }
  return Buffer.concat(chunks).toString("utf-8");
}

// Most transactional providers (Clerk/SendGrid/Postmark) encode HTML bodies in
// quoted-printable. That splits long URLs across lines via "=\n" soft breaks and
// encodes reserved chars (=3D, =2E, =2F, =3A). A naive regex over the raw body
// fails to match verification URLs. Normalizing before regex keeps the backend
// generic across OTP digits and magic-link URLs.
function normalizeQuotedPrintable(body: string): string {
  return body
    .replace(/=\r?\n/g, "")
    .replace(/=3D/gi, "=")
    .replace(/=2E/gi, ".")
    .replace(/=2F/gi, "/")
    .replace(/=3A/gi, ":")
    .replace(/=3F/gi, "?")
    .replace(/=26/gi, "&");
}

export async function fetchViaSesS3(opts: FetchOpts, s3ClientOverride?: S3Client): Promise<string> {
  const bucket = process.env["AGENTKEYS_SES_BUCKET"];
  if (!bucket) {
    throw new Error("AGENTKEYS_SES_BUCKET env var is required for ses-s3 backend");
  }

  // AWS SDK reads AWS_REGION / AWS_DEFAULT_REGION. Fall back to REGION
  // (our runbook's preferred name) so one forgotten AWS_-prefix doesn't
  // stop the whole flow. Explicit config beats SDK's default chain here.
  const region =
    process.env["AWS_REGION"] ??
    process.env["AWS_DEFAULT_REGION"] ??
    process.env["REGION"] ??
    "us-east-1";
  const s3 = s3ClientOverride ?? new S3Client({ region });

  const pollIntervalMs = opts.pollIntervalMs ?? 2000;
  const startedAt = Date.now();
  // The bucket accumulates emails from prior runs. Verification tokens expire
  // in ~10 min, so matching an old email silently fails at page.goto with
  // "link expired". Only consider emails that arrived after the scraper
  // began polling, minus a small grace window for SES→S3 latency + clock skew.
  const freshnessThreshold = new Date(startedAt - (opts.freshnessGraceMs ?? 60_000));
  const seenKeys = new Set<string>();
  const reasons: Record<string, number> = {
    stale: 0,
    from_rejected: 0,
    subject_rejected: 0,
    regex_no_match: 0,
    empty_body: 0,
    matched: 0,
  };
  const samples: Array<{ key: string; from: string; subject: string }> = [];

  debug(`polling s3://${bucket}/inbound/ — from=${opts.from} subject=${opts.subject} code=${opts.codeRegex} timeout=${opts.timeoutMs}ms freshnessThreshold=${freshnessThreshold.toISOString()}`);

  while (true) {
    const elapsed = Date.now() - startedAt;
    if (elapsed >= opts.timeoutMs) {
      throw new EmailTimeoutError(elapsed, seenKeys.size, reasons, samples);
    }

    const listResponse = await s3.send(
      new ListObjectsV2Command({ Bucket: bucket, Prefix: "inbound/" })
    );
    // Freshest-first so we prefer the most recent verification email when
    // more than one arrives (e.g. user clicked "Resend").
    const objects = (listResponse.Contents ?? [])
      .slice()
      .sort((a, b) => (b.LastModified?.getTime() ?? 0) - (a.LastModified?.getTime() ?? 0));

    for (const obj of objects) {
      const key = obj.Key;
      if (!key || seenKeys.has(key)) continue;
      seenKeys.add(key);

      if (obj.LastModified && obj.LastModified < freshnessThreshold) {
        reasons.stale++;
        debug(`skip ${key}: LastModified=${obj.LastModified.toISOString()} is older than freshness threshold (prior-run leftover)`);
        continue;
      }

      const getResponse = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
      if (!getResponse.Body) {
        reasons.empty_body++;
        debug(`skip ${key}: empty body`);
        continue;
      }

      const rawMime = await streamToString(getResponse.Body as NodeJS.ReadableStream);
      const { from, subject, body } = parseEmailHeaders(rawMime);
      samples.push({ key, from, subject });
      if (samples.length > 10) samples.shift();

      const fromOk = opts.from.test(from);
      const subjectOk = opts.subject.test(subject);
      if (!fromOk) {
        reasons.from_rejected++;
        debug(`skip ${key}: from=${JSON.stringify(from)} did not match ${opts.from}`);
        continue;
      }
      if (!subjectOk) {
        reasons.subject_rejected++;
        debug(`skip ${key}: from=${JSON.stringify(from)} OK but subject=${JSON.stringify(subject)} did not match ${opts.subject}`);
        continue;
      }

      const normalizedBody = normalizeQuotedPrintable(body);
      const match = opts.codeRegex.exec(normalizedBody);
      if (match && match[1] !== undefined) {
        reasons.matched++;
        debug(`MATCH ${key}: extracted ${match[1].slice(0, 80)}${match[1].length > 80 ? "..." : ""}`);
        return match[1];
      }
      reasons.regex_no_match++;
      const bodySnippet = normalizedBody.slice(0, 400).replace(/\s+/g, " ");
      debug(`skip ${key}: from+subject matched but codeRegex ${opts.codeRegex} found nothing. body[0..400]=${JSON.stringify(bodySnippet)}`);
    }

    const remainingMs = opts.timeoutMs - (Date.now() - startedAt);
    if (remainingMs <= 0) {
      throw new EmailTimeoutError(Date.now() - startedAt, seenKeys.size, reasons, samples);
    }
    if (seenKeys.size === 0 && elapsed > 10_000 && elapsed % 20_000 < pollIntervalMs) {
      debug(`still waiting — bucket is empty after ${Math.round(elapsed / 1000)}s. Check MX/DNS or SES receipt rule.`);
    }

    await new Promise<void>((resolve) =>
      setTimeout(resolve, Math.min(pollIntervalMs, remainingMs))
    );
  }
}
