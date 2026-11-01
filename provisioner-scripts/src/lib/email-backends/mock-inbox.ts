import type { FetchOpts } from "../email.js";

interface InboxMessage {
  msg_id: string;
  from: string;
  subject: string | null;
  body: string | null;
  received_at: number;
}

interface EmailTimeoutError {
  code: "EMAIL_TIMEOUT";
  elapsed_ms: number;
}

export async function fetchViaMockInbox(opts: FetchOpts): Promise<string> {
  const backendUrl = process.env["AGENTKEYS_BACKEND_URL"] ?? "http://127.0.0.1:8090";
  const sessionToken = process.env["AGENTKEYS_SESSION_TOKEN"];
  if (!sessionToken) {
    throw new Error("AGENTKEYS_SESSION_TOKEN env var is required for mock-inbox backend");
  }

  const inboxAddress = process.env["AGENTKEYS_SIGNUP_EMAIL"];
  if (!inboxAddress) {
    throw new Error("AGENTKEYS_SIGNUP_EMAIL env var is required for mock-inbox backend");
  }

  const pollIntervalMs = opts.pollIntervalMs ?? 2000;
  const startedAt = Date.now();

  const endpoint = `${backendUrl}/mock/inbox/messages?address=${encodeURIComponent(inboxAddress)}`;

  while (true) {
    const elapsed = Date.now() - startedAt;

    if (elapsed >= opts.timeoutMs) {
      const timeoutErr: EmailTimeoutError = { code: "EMAIL_TIMEOUT", elapsed_ms: elapsed };
      throw timeoutErr;
    }

    const response = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });

    if (!response.ok) {
      throw new Error(`mock-inbox fetch failed: ${response.status} ${response.statusText}`);
    }

    const messages: InboxMessage[] = await response.json() as InboxMessage[];

    for (const msg of messages) {
      const fromAddr = msg.from ?? "";
      const subjectLine = msg.subject ?? "";

      if (!opts.from.test(fromAddr) || !opts.subject.test(subjectLine)) {
        continue;
      }

      const bodyText = msg.body ?? "";
      const match = opts.codeRegex.exec(bodyText);
      if (match && match[1] !== undefined) {
        return match[1];
      }
    }

    const remainingMs = opts.timeoutMs - (Date.now() - startedAt);
    if (remainingMs <= 0) {
      const timeoutErr: EmailTimeoutError = { code: "EMAIL_TIMEOUT", elapsed_ms: Date.now() - startedAt };
      throw timeoutErr;
    }

    await new Promise<void>((resolve) =>
      setTimeout(resolve, Math.min(pollIntervalMs, remainingMs))
    );
  }
}
