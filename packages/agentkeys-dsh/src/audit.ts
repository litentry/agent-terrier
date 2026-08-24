/**
 * @module @agentkeys/dsh-suite/audit — the runtime-audit tee (#612).
 *
 * Observes the dsh pipeline's immutable outcomes and the durable session log,
 * and forwards the owner-auditable facts to the co-located daemon
 * (`POST /v1/sandbox/self/audit`), which appends them to the audit worker AS
 * the delegate (op_kinds 110 runtime.tool_result / 111 runtime.approval).
 *
 * Fire-and-forget with a small bounded queue: the tee must NEVER block or fail
 * the loop (tools/result is an emit event with contained failures — we still
 * guard ourselves). On a 404 from the sink (master daemon / not a sandbox) the
 * tee disables itself for the process lifetime.
 *
 * NO default export (dsh postmortem 0001).
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session';
import type { ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools';

export const name = 'agentkeys-audit';
export const inject = ['sessions', 'tools'];

export const OP_KIND_RUNTIME_TOOL_RESULT = 110;
export const OP_KIND_RUNTIME_APPROVAL = 111;

export interface Config {
  auditUrl?: string;
  bridgeToken?: string;
}

export const Config: z<Config> = z.object({
  auditUrl: z.string().default('http://127.0.0.1:3114/v1/sandbox/self/audit'),
  bridgeToken: z.string(),
});

export interface AuditRow {
  op_kind: number;
  op_body: Record<string, unknown>;
  result: number;
  intent_text?: string;
}

/** Pure mappers (exported for tests). */
export function toolResultRow(exec: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>): AuditRow {
  return {
    op_kind: OP_KIND_RUNTIME_TOOL_RESULT,
    op_body: { tool: exec.name, call_id: String(exec.callId), is_error: result.isError },
    result: result.isError ? 1 : 0,
  };
}

export function approvalRow(event: SessionEvent): AuditRow | undefined {
  if (event.type !== 'approval/decided') return undefined;
  const data = event.data as { id?: unknown; outcome?: unknown; toolName?: unknown };
  const outcome = typeof data.outcome === 'string' ? data.outcome : 'unavailable';
  return {
    op_kind: OP_KIND_RUNTIME_APPROVAL,
    op_body: { tool: typeof data.toolName === 'string' ? data.toolName : String(data.id ?? ''), outcome },
    result: outcome === 'allowed-once' ? 0 : 1,
  };
}

const MAX_QUEUE = 64;

export class AuditSink {
  private queue: AuditRow[] = [];
  private draining = false;
  private disabled = false;
  constructor(private readonly config: Config) {}

  push(row: AuditRow): void {
    if (this.disabled) return;
    if (this.queue.length >= MAX_QUEUE) this.queue.shift(); // drop-oldest, never block
    this.queue.push(row);
    void this.drain();
  }

  private async drain(): Promise<void> {
    if (this.draining || this.disabled) return;
    this.draining = true;
    try {
      while (this.queue.length > 0 && !this.disabled) {
        const row = this.queue.shift();
        if (!row) break;
        await this.send(row);
      }
    } finally {
      this.draining = false;
    }
  }

  private async send(row: AuditRow): Promise<void> {
    const url = this.config.auditUrl ?? 'http://127.0.0.1:3114/v1/sandbox/self/audit';
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    const token = this.config.bridgeToken ?? process.env.AGENTKEYS_BRIDGE_TOKEN ?? '';
    if (token) headers.authorization = `Bearer ${token}`;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(row),
        signal: AbortSignal.timeout(15_000),
      });
      if (res.status === 404) this.disabled = true; // not a sandbox daemon — stand down
    } catch {
      // fire-and-forget: a lost row never blocks the loop; the durable session
      // log remains the complete record
    }
  }
}

export function apply(ctx: Context, config: Config): void {
  const sink = new AuditSink(config);
  ctx.on('tools/result', (exec: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>) => {
    sink.push(toolResultRow(exec, result));
  });
  ctx.on('session/event', (_session: Session, event: SessionEvent) => {
    const row = approvalRow(event);
    if (row) sink.push(row);
  });
}
