import * as fs from "node:fs";
import * as path from "node:path";
import { S3Client, ListObjectsV2Command, GetObjectCommand } from "@aws-sdk/client-s3";

export type EmailAnalysis =
  | {
      verifyType: "magic-link";
      from: string;
      subject: string;
      url: string;
      urlHasHtmlEntities: boolean;
      bodyDigest: string;
    }
  | {
      verifyType: "otp";
      from: string;
      subject: string;
      code: string;
      bodyDigest: string;
    }
  | {
      verifyType: "unknown";
      from: string;
      subject: string;
      reason: string;
      bodyDigest: string;
    };

// Shared URL detector — matches verification-link flavored URLs (Clerk,
// generic /verify, ticket-based, etc.). Kept broad so we catch shapes
// we haven't seen yet and surface them as `unknown` with the raw URL.
const MAGIC_LINK_URL_REGEX = /(https:\/\/[^\s<>"'\)]*(?:clerk|\/verify|ticket=|verification|magic)[^\s<>"'\)]*)/i;
const OTP_REGEX = /\b(\d{6})\b/;

// Strip HTML tags and <style>…</style> blocks so the OTP extractor doesn't
// match 6-digit CSS hex color codes (e.g. #141415) in email stylesheets.
function stripHtmlForText(body: string): string {
  return body
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+/g, " ")
    .trim();
}

// Extract the OTP code from the visible (text) portion of the email. Prefer
// codes that appear near labels ("code", "verification", "one-time", "login"),
// fall back to the first remaining 6-digit sequence. Stripping HTML+CSS is
// essential because email templates commonly embed 6-digit hex color codes
// (e.g. #141415) that would otherwise be picked up as the OTP.
function extractOtpCode(bodyText: string): string | undefined {
  const labeled = bodyText.match(
    /(?:verification|security|login|sign[-\s]?in|one[-\s]?time|auth(?:entication)?|access)\s*code[^0-9]{0,40}(\d{6})/i,
  );
  if (labeled) return labeled[1];
  const before = bodyText.match(/(\d{6})[^0-9]{0,40}(?:is\s+your|to\s+(?:verify|sign|log))/i);
  if (before) return before[1];
  const first = OTP_REGEX.exec(bodyText);
  return first ? first[1] : undefined;
}

export function parseHeaders(rawMime: string): { from: string; subject: string; body: string } {
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
    if (lower.startsWith("from:")) from = line.slice(5).trim();
    else if (lower.startsWith("subject:")) subject = line.slice(8).trim();
  }
  const body = bodyStartIndex >= 0 ? lines.slice(bodyStartIndex).join("\n") : "";
  return { from, subject, body };
}

export function normalizeQP(body: string): string {
  return body
    .replace(/=\r?\n/g, "")
    .replace(/=3D/gi, "=")
    .replace(/=2E/gi, ".")
    .replace(/=2F/gi, "/")
    .replace(/=3A/gi, ":")
    .replace(/=3F/gi, "?")
    .replace(/=26/gi, "&");
}

export function analyzeEmail(rawMime: string): EmailAnalysis {
  const { from, subject, body } = parseHeaders(rawMime);
  const normalized = normalizeQP(body);
  const snippet = normalized.slice(0, 500).replace(/\s+/g, " ").trim();

  // Magic-link takes priority if a recognizable URL is present.
  const urlMatch = MAGIC_LINK_URL_REGEX.exec(normalized);
  if (urlMatch && urlMatch[1]) {
    return {
      verifyType: "magic-link",
      from,
      subject,
      url: urlMatch[1],
      urlHasHtmlEntities: /&(amp|lt|gt|quot|#39|#x27);/.test(urlMatch[1]),
      bodyDigest: snippet,
    };
  }

  // No verification URL — look for 6-digit OTP in the visible text (HTML/CSS
  // stripped) so we don't latch onto CSS hex color codes.
  const plainText = stripHtmlForText(normalized);
  const otpCode = extractOtpCode(plainText);
  if (otpCode) {
    return {
      verifyType: "otp",
      from,
      subject,
      code: otpCode,
      bodyDigest: snippet,
    };
  }

  return {
    verifyType: "unknown",
    from,
    subject,
    reason: "no magic-link URL and no 6-digit code found after QP normalization",
    bodyDigest: snippet,
  };
}

// High-level helper for scrapers: poll S3 for a fresh email matching
// from/subject patterns, then parse it via analyzeEmail (HTML-strip + label-
// aware OTP extract). Returns the structured EmailAnalysis — caller picks
// between verifyType === "magic-link" | "otp" | "unknown".
//
// Only works with the ses-s3 email backend. Gmail-IMAP / mock-inbox callers
// continue using `fetchVerificationCode` from lib/email.ts with a regex.
export async function fetchAndAnalyzeSesEmail(opts: {
  bucket: string;
  region?: string;
  fromPattern: RegExp;
  subjectPattern: RegExp;
  startedAtMs?: number;
  timeoutMs?: number;
}): Promise<EmailAnalysis> {
  const startedAtMs = opts.startedAtMs ?? Date.now();
  const { rawMime } = await pollFreshRawEmail({
    bucket: opts.bucket,
    region: opts.region,
    startedAtMs,
    timeoutMs: opts.timeoutMs ?? 120_000,
    fromPattern: opts.fromPattern,
    subjectPattern: opts.subjectPattern,
  });
  return analyzeEmail(rawMime);
}

async function streamToString(stream: NodeJS.ReadableStream): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
  }
  return Buffer.concat(chunks).toString("utf-8");
}

// Poll S3 for the freshest matching inbound email after `startedAtMs`.
// Returns { key, rawMime } once a fresh object is found, or throws on timeout.
export async function pollFreshRawEmail(opts: {
  bucket: string;
  region?: string;
  startedAtMs: number;
  freshnessGraceMs?: number;
  timeoutMs?: number;
  pollIntervalMs?: number;
  fromPattern?: RegExp;
  subjectPattern?: RegExp;
  s3Override?: S3Client;
}): Promise<{ key: string; rawMime: string }> {
  const region =
    opts.region ??
    process.env["AWS_REGION"] ??
    process.env["AWS_DEFAULT_REGION"] ??
    process.env["REGION"] ??
    "us-east-1";
  const s3 = opts.s3Override ?? new S3Client({ region });
  const threshold = new Date(opts.startedAtMs - (opts.freshnessGraceMs ?? 60_000));
  const timeout = opts.timeoutMs ?? 120_000;
  const interval = opts.pollIntervalMs ?? 2_000;
  const begin = Date.now();
  const seen = new Set<string>();

  while (Date.now() - begin < timeout) {
    const list = await s3.send(new ListObjectsV2Command({ Bucket: opts.bucket, Prefix: "inbound/" }));
    const objs = (list.Contents ?? [])
      .filter((o) => o.Key && !seen.has(o.Key))
      .filter((o) => !o.LastModified || o.LastModified >= threshold)
      .sort((a, b) => (b.LastModified?.getTime() ?? 0) - (a.LastModified?.getTime() ?? 0));

    for (const obj of objs) {
      if (!obj.Key) continue;
      seen.add(obj.Key);
      const resp = await s3.send(new GetObjectCommand({ Bucket: opts.bucket, Key: obj.Key }));
      if (!resp.Body) continue;
      const rawMime = await streamToString(resp.Body as NodeJS.ReadableStream);
      if (opts.fromPattern || opts.subjectPattern) {
        const { from, subject } = parseHeaders(rawMime);
        if (opts.fromPattern && !opts.fromPattern.test(from)) continue;
        if (opts.subjectPattern && !opts.subjectPattern.test(subject)) continue;
      }
      return { key: obj.Key, rawMime };
    }

    await new Promise<void>((resolve) => setTimeout(resolve, interval));
  }

  throw new Error(
    `pollFreshRawEmail: no fresh matching email arrived in s3://${opts.bucket}/inbound/ within ${timeout}ms`
  );
}

// Read a raw .eml from disk, analyze, and dump { raw.eml, normalized.txt,
// analysis.json } into a per-email subdir under recordings/.../emails/.
export function dumpEmailToRecording(
  emailsDir: string,
  key: string,
  rawMime: string
): EmailAnalysis {
  const safeKey = key.replace(/[^a-zA-Z0-9._-]/g, "_");
  const dir = path.join(emailsDir, safeKey);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "raw.eml"), rawMime);
  const { body } = parseHeaders(rawMime);
  fs.writeFileSync(path.join(dir, "normalized.txt"), normalizeQP(body));
  const analysis = analyzeEmail(rawMime);
  fs.writeFileSync(path.join(dir, "analysis.json"), JSON.stringify(analysis, null, 2));
  return analysis;
}
