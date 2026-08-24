/**
 * @module @agentkeys/dsh-suite/bridge-frames — the byte-exact SSE frame mapping
 * from dsh session events to the AgentKeys sandbox-bridge wire format (#613).
 *
 * The bridge HTTP contract has FIVE consumers, one shipped in ESP32 firmware
 * (docs/spec/delegate-runtime-dsh.md §3.2). The frame shapes here MUST stay
 * byte-identical to the retired hermes_bridge.py: `data: ` + compact JSON +
 * `\n\n`, NO event names, and exactly these `type` strings and fields:
 *   token       {type:"token", text}
 *   tool_start  {type:"tool_start", name, id?}   (+ one {name:"thinking"} per turn)
 *   tool        {type:"tool", name, id, status, args, result}
 *   done        {type:"done", usage:{total_tokens}}
 *   error       {type:"error", error}
 * `error` and `done` are MUTUALLY EXCLUSIVE; usage is reported ONLY on `done`.
 *
 * Pure functions — no dsh imports — so the wire contract is unit-testable and
 * cannot silently drift. The plugin (bridge.ts) subscribes to session/event and
 * feeds those events here.
 */

export type BridgeFrame =
  | { type: 'token'; text: string }
  | { type: 'tool_start'; name: string; id?: string }
  | { type: 'tool'; name: string; id: string; status: string; args: string; result: string }
  | { type: 'done'; usage: { total_tokens: number } }
  | { type: 'error'; error: string };

/** Serialize one frame to its SSE bytes (compact JSON, `data: ` prefix WITH the
 *  space, terminated by a blank line). */
export function encodeFrame(frame: BridgeFrame): string {
  return `data: ${JSON.stringify(frame)}\n\n`;
}

export function tokenFrame(text: string): BridgeFrame {
  return { type: 'token', text };
}

export function thinkingFrame(): BridgeFrame {
  // exactly once per turn, no id — matches hermes_bridge.py:1028
  return { type: 'tool_start', name: 'thinking' };
}

export function toolStartFrame(name: string, id: string): BridgeFrame {
  return { type: 'tool_start', name, id };
}

/** A `tool` completion frame. The hermes bridge SUPPRESSED updates unless the
 *  status was completed/failed OR the result was non-empty; the caller applies
 *  that gate (see shouldEmitToolFrame) and only then builds the frame. */
export function toolFrame(args: {
  name: string;
  id: string;
  status: string;
  argsText: string;
  resultText: string;
}): BridgeFrame {
  return {
    type: 'tool',
    name: args.name,
    id: args.id,
    status: args.status.toLowerCase(),
    args: args.argsText,
    result: args.resultText,
  };
}

/** The hermes suppression rule for interim tool updates. */
export function shouldEmitToolFrame(status: string, resultText: string): boolean {
  const s = status.toLowerCase();
  return s === 'completed' || s === 'failed' || resultText.length > 0;
}

export function doneFrame(totalTokens: number): BridgeFrame {
  return { type: 'done', usage: { total_tokens: Math.max(0, Math.trunc(totalTokens) || 0) } };
}

export function errorFrame(message: string): BridgeFrame {
  return { type: 'error', error: message };
}

/** The non-stream `/v1/chat` reply shape. `trace` is always [] (the streaming
 *  path carries tools; the probe still reads the field). */
export interface ChatReply {
  reply: string;
  trace: never[];
  usage: { total_tokens: number };
}

export function chatReply(reply: string, totalTokens: number): ChatReply {
  return { reply, trace: [], usage: { total_tokens: Math.max(0, Math.trunc(totalTokens) || 0) } };
}

/** The healthz body. `phase` mirrors hermes: ready | starting | down. Status is
 *  200 when ok else 503, with the SAME body either way. */
export interface HealthzBody {
  ok: boolean;
  engine: string;
  version: string;
  model: string;
  phase: 'ready' | 'starting' | 'down';
}

export function healthzBody(args: {
  ready: boolean;
  down: boolean;
  engine: string;
  version: string;
  model: string;
}): HealthzBody {
  const phase: HealthzBody['phase'] = args.ready ? 'ready' : args.down ? 'down' : 'starting';
  return {
    ok: args.ready,
    engine: args.engine,
    version: args.version,
    model: args.model,
    phase,
  };
}
