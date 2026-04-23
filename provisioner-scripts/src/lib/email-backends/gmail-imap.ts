import { parse as parseHtml } from "node-html-parser";
import type { FetchOpts } from "../email.js";

export interface ImapClientLike {
  connect(): Promise<void>;
  close(): Promise<void>;
  mailboxOpen(name: string): Promise<void>;
  search(query: object): Promise<number[]>;
  fetchOne(
    uid: number,
    query: object
  ): Promise<{
    envelope: { from: Array<{ address: string }>; subject: string };
    source: Buffer | string;
  } | null>;
}

interface EmailTimeoutError {
  code: "EMAIL_TIMEOUT";
  elapsed_ms: number;
}

interface EmailNotFoundError {
  code: "EMAIL_NOT_FOUND";
  elapsed_ms: number;
}

async function createDefaultImapClient(): Promise<ImapClientLike> {
  const emailUser = process.env["AGENTKEYS_EMAIL_USER"];
  const emailPassword = process.env["AGENTKEYS_EMAIL_PASSWORD"];
  if (!emailUser) throw new Error("AGENTKEYS_EMAIL_USER env var is required");
  if (!emailPassword) throw new Error("AGENTKEYS_EMAIL_PASSWORD env var is required");

  const host = process.env["AGENTKEYS_EMAIL_HOST"] ?? "imap.gmail.com";
  const port = parseInt(process.env["AGENTKEYS_EMAIL_PORT"] ?? "993", 10);

  const { ImapFlow } = await import("imapflow");

  return new ImapFlow({
    host,
    port,
    secure: true,
    auth: { user: emailUser, pass: emailPassword },
    logger: false,
  }) as unknown as ImapClientLike;
}

function extractTextFromBody(source: Buffer | string): string {
  const raw = typeof source === "string" ? source : source.toString("utf-8");
  if (raw.includes("<html") || raw.includes("<HTML")) {
    const root = parseHtml(raw);
    return root.text;
  }
  return raw;
}

export async function fetchViaGmailImap(opts: FetchOpts & { imapClientFactory?: () => ImapClientLike }): Promise<string> {
  const pollIntervalMs = opts.pollIntervalMs ?? 1500;
  const startedAt = Date.now();

  const client = opts.imapClientFactory
    ? opts.imapClientFactory()
    : await createDefaultImapClient();

  try {
    await client.connect();
    await client.mailboxOpen("INBOX");

    while (true) {
      const elapsed = Date.now() - startedAt;

      if (elapsed >= opts.timeoutMs) {
        const timeoutErr: EmailTimeoutError = { code: "EMAIL_TIMEOUT", elapsed_ms: elapsed };
        throw timeoutErr;
      }

      const uids = await client.search({ all: true });

      let matchedEnvelope = false;

      for (const uid of uids) {
        const msg = await client.fetchOne(uid, { envelope: true, source: true });
        if (!msg) continue;

        const fromAddress = msg.envelope.from[0]?.address ?? "";
        const subjectLine = msg.envelope.subject ?? "";

        if (!opts.from.test(fromAddress) || !opts.subject.test(subjectLine)) {
          continue;
        }

        matchedEnvelope = true;
        const bodyText = extractTextFromBody(msg.source);
        const match = opts.codeRegex.exec(bodyText);

        if (match && match[1] !== undefined) {
          return match[1];
        }
      }

      if (matchedEnvelope) {
        const notFoundErr: EmailNotFoundError = {
          code: "EMAIL_NOT_FOUND",
          elapsed_ms: Date.now() - startedAt,
        };
        throw notFoundErr;
      }

      const remainingMs = opts.timeoutMs - (Date.now() - startedAt);
      if (remainingMs <= 0) {
        const timeoutErr: EmailTimeoutError = {
          code: "EMAIL_TIMEOUT",
          elapsed_ms: Date.now() - startedAt,
        };
        throw timeoutErr;
      }

      await new Promise<void>((resolve) =>
        setTimeout(resolve, Math.min(pollIntervalMs, remainingMs))
      );
    }
  } finally {
    await client.close();
  }
}
