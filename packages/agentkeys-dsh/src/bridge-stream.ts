/**
 * @module @agentkeys/dsh-suite/bridge-stream — the per-turn state machine that
 * projects dsh session events onto AgentKeys bridge frames (#613).
 *
 * Pure: it takes session events (as the plugin observes them from
 * `session/event`) and yields the frames to emit, accumulating the non-stream
 * `reply` text and the turn's token usage. Testable without a live agent.
 *
 * Mapping (byte-exact with the retired hermes_bridge.py):
 *   assistant/chunk text-delta      -> token{text}
 *   assistant/chunk reasoning-delta -> ONE thinking tool_start per turn
 *   tool/call                       -> tool_start{name,id}
 *   tool/result                     -> tool{name,id,status,args,result} (gated)
 *   assistant/message.usage         -> accumulate total_tokens
 *   turn/end                        -> done{usage}
 *   (a turn error)                  -> error{...}  (mutually exclusive with done)
 */
import {
  type BridgeFrame,
  doneFrame,
  errorFrame,
  shouldEmitToolFrame,
  thinkingFrame,
  tokenFrame,
  toolFrame,
  toolStartFrame,
} from './bridge-frames.js';

interface SessionEventLike {
  type: string;
  data?: unknown;
}

interface ToolCallData {
  callId: unknown;
  name: unknown;
  arguments?: unknown;
}

function textOfContent(content: unknown): string {
  if (!Array.isArray(content)) return '';
  const parts: string[] = [];
  for (const block of content) {
    const b = block as { type?: unknown; text?: unknown; content?: unknown };
    if (b && typeof b.text === 'string') parts.push(b.text);
    else if (b && typeof b.content === 'string') parts.push(b.content);
  }
  return parts.join('');
}

export class TurnStreamer {
  private replyText = '';
  private totalTokens = 0;
  private thinkingEmitted = false;
  private toolNames = new Map<string, string>();
  private done = false;
  private erroredWith: string | undefined;

  /** Feed one session event; returns the frames to emit for it (in order). */
  push(event: SessionEventLike): BridgeFrame[] {
    if (this.done || this.erroredWith !== undefined) return [];
    switch (event.type) {
      case 'assistant/chunk':
        return this.onChunk(event.data);
      case 'tool/call':
        return this.onToolCall(event.data as ToolCallData);
      case 'tool/result':
        return this.onToolResult(event.data);
      case 'assistant/message':
        this.accumulateUsage((event.data as { usage?: unknown }).usage);
        return [];
      default:
        return [];
    }
  }

  private onChunk(data: unknown): BridgeFrame[] {
    const chunk = (data as { chunk?: { type?: string; text?: string; usage?: unknown } }).chunk;
    if (!chunk) return [];
    if (chunk.type === 'text-delta' && typeof chunk.text === 'string' && chunk.text.length > 0) {
      this.replyText += chunk.text;
      return [tokenFrame(chunk.text)];
    }
    if (chunk.type === 'reasoning-delta') {
      if (this.thinkingEmitted) return [];
      this.thinkingEmitted = true;
      return [thinkingFrame()];
    }
    if (chunk.type === 'usage') {
      this.accumulateUsage(chunk.usage);
    }
    return [];
  }

  private onToolCall(data: ToolCallData): BridgeFrame[] {
    const id = String(data.callId ?? '');
    const name = typeof data.name === 'string' ? data.name : 'tool';
    if (id) this.toolNames.set(id, name);
    return [toolStartFrame(name, id)];
  }

  private onToolResult(data: unknown): BridgeFrame[] {
    const d = data as { message?: { content?: unknown; source?: { callId?: unknown } }; error?: { code?: unknown } };
    const callId = String(d.message?.source?.callId ?? '');
    const name = this.toolNames.get(callId) ?? 'tool';
    const resultText = textOfContent(d.message?.content);
    const status = d.error ? 'failed' : 'completed';
    if (!shouldEmitToolFrame(status, resultText)) return [];
    return [toolFrame({ name, id: callId, status, argsText: '', resultText })];
  }

  private accumulateUsage(usage: unknown): void {
    const u = usage as { inputTokens?: unknown; outputTokens?: unknown; total_tokens?: unknown } | undefined;
    if (!u) return;
    if (typeof u.total_tokens === 'number') {
      this.totalTokens += u.total_tokens;
      return;
    }
    const input = typeof u.inputTokens === 'number' ? u.inputTokens : 0;
    const output = typeof u.outputTokens === 'number' ? u.outputTokens : 0;
    this.totalTokens += input + output;
  }

  /** Close the turn cleanly — the terminal `done` frame (once). */
  finish(): BridgeFrame[] {
    if (this.done || this.erroredWith !== undefined) return [];
    this.done = true;
    return [doneFrame(this.totalTokens)];
  }

  /** Close the turn with an error — mutually exclusive with `done`. */
  fail(message: string): BridgeFrame[] {
    if (this.done || this.erroredWith !== undefined) return [];
    this.erroredWith = message;
    return [errorFrame(message)];
  }

  /** The accumulated non-stream reply text and usage (read after the turn). */
  reply(): { reply: string; totalTokens: number } {
    return { reply: this.replyText, totalTokens: this.totalTokens };
  }
}
