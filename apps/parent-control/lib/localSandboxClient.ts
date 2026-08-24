// #631 — the LOCAL dsh test-twin surface. Dev-time only: talks to the
// docker/dsh-sandbox container on this machine through the app's own API
// proxy (/api/dev/local-sandbox/*, server-side fetch → no CORS), never
// through the daemon/broker. The twin speaks the byte-compatible sandbox
// bridge contract, so this page exercises the SAME /v1/chat shape a real
// delegate serves.

export interface SandboxHealth {
  ok: boolean;
  engine: string;
  version: string;
  model: string;
  phase: 'ready' | 'starting' | 'down';
}

export interface SandboxChatReply {
  reply: string;
  trace: unknown[];
  usage: { total_tokens: number };
}

export class LocalSandboxError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

async function parseError(res: Response): Promise<never> {
  let detail = `HTTP ${res.status}`;
  try {
    const body = (await res.json()) as { error?: unknown };
    if (typeof body.error === 'string' && body.error) detail = body.error;
  } catch {
    /* non-JSON error body — keep the status text */
  }
  throw new LocalSandboxError(detail, res.status);
}

export async function sandboxHealthz(fetcher: typeof fetch = fetch): Promise<SandboxHealth> {
  const res = await fetcher('/api/dev/local-sandbox/healthz', { cache: 'no-store' });
  if (!res.ok && res.status !== 503) return parseError(res);
  return (await res.json()) as SandboxHealth;
}

export async function sandboxChat(text: string, fetcher: typeof fetch = fetch): Promise<SandboxChatReply> {
  const res = await fetcher('/api/dev/local-sandbox/chat', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text, stream: false }),
  });
  if (!res.ok) return parseError(res);
  return (await res.json()) as SandboxChatReply;
}
