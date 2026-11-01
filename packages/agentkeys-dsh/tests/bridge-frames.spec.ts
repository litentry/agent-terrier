import { describe, expect, it } from 'vitest';
import {
  chatReply,
  doneFrame,
  encodeFrame,
  errorFrame,
  healthzBody,
  shouldEmitToolFrame,
  thinkingFrame,
  tokenFrame,
  toolFrame,
  toolStartFrame,
} from '../src/bridge-frames.js';
import { TurnStreamer } from '../src/bridge-stream.js';

describe('bridge frames (byte-exact wire contract)', () => {
  it('encodes with the exact `data: ` prefix and blank-line terminator, no event name', () => {
    expect(encodeFrame(tokenFrame('hi'))).toBe('data: {"type":"token","text":"hi"}\n\n');
  });
  it('thinking is a nameless tool_start with no id', () => {
    expect(thinkingFrame()).toEqual({ type: 'tool_start', name: 'thinking' });
    expect(JSON.stringify(thinkingFrame())).not.toContain('"id"');
  });
  it('tool_start carries name + id; tool carries lowercased status', () => {
    expect(toolStartFrame('web_fetch', 'c1')).toEqual({ type: 'tool_start', name: 'web_fetch', id: 'c1' });
    expect(toolFrame({ name: 'bash', id: 'c2', status: 'COMPLETED', argsText: '{}', resultText: 'ok' })).toEqual({
      type: 'tool', name: 'bash', id: 'c2', status: 'completed', args: '{}', result: 'ok',
    });
  });
  it('done reports usage only; usage is clamped to a non-negative int', () => {
    expect(doneFrame(42)).toEqual({ type: 'done', usage: { total_tokens: 42 } });
    expect(doneFrame(-1)).toEqual({ type: 'done', usage: { total_tokens: 0 } });
    expect(doneFrame(3.9)).toEqual({ type: 'done', usage: { total_tokens: 3 } });
  });
  it('error is a distinct terminal frame', () => {
    expect(errorFrame('boom')).toEqual({ type: 'error', error: 'boom' });
  });
  it('interim tool updates are suppressed unless completed/failed or non-empty result', () => {
    expect(shouldEmitToolFrame('running', '')).toBe(false);
    expect(shouldEmitToolFrame('running', 'partial')).toBe(true);
    expect(shouldEmitToolFrame('completed', '')).toBe(true);
    expect(shouldEmitToolFrame('failed', '')).toBe(true);
  });
  it('non-stream reply has an always-empty trace', () => {
    expect(chatReply('hello', 7)).toEqual({ reply: 'hello', trace: [], usage: { total_tokens: 7 } });
  });
  it('healthz phase/status follow ready|starting|down with the SAME body', () => {
    expect(healthzBody({ ready: true, down: false, engine: 'dsh', version: '1', model: 'm' })).toEqual({
      ok: true, engine: 'dsh', version: '1', model: 'm', phase: 'ready',
    });
    expect(healthzBody({ ready: false, down: false, engine: 'dsh', version: '?', model: 'm' }).phase).toBe('starting');
    expect(healthzBody({ ready: false, down: true, engine: 'dsh', version: '?', model: 'm' }).phase).toBe('down');
  });
});

const ev = (type: string, data: unknown) => ({ type, data });

describe('TurnStreamer (session events → frames)', () => {
  it('projects a full turn: text tokens, one thinking, a tool, then done with summed usage', () => {
    const s = new TurnStreamer();
    const frames = [
      ...s.push(ev('assistant/chunk', { chunk: { type: 'reasoning-delta', index: 0, text: 'hmm' } })),
      ...s.push(ev('assistant/chunk', { chunk: { type: 'reasoning-delta', index: 0, text: 'more' } })), // 2nd thinking suppressed
      ...s.push(ev('tool/call', { callId: 'c1', name: 'web_fetch', arguments: '{}' })),
      ...s.push(ev('tool/result', { message: { source: { callId: 'c1' }, content: [{ type: 'text', text: 'body' }] } })),
      ...s.push(ev('assistant/chunk', { chunk: { type: 'text-delta', index: 1, text: 'Hel' } })),
      ...s.push(ev('assistant/chunk', { chunk: { type: 'text-delta', index: 1, text: 'lo' } })),
      ...s.push(ev('assistant/message', { usage: { inputTokens: 10, outputTokens: 5 } })),
      ...s.finish(),
    ];
    expect(frames).toEqual([
      { type: 'tool_start', name: 'thinking' },
      { type: 'tool_start', name: 'web_fetch', id: 'c1' },
      { type: 'tool', name: 'web_fetch', id: 'c1', status: 'completed', args: '', result: 'body' },
      { type: 'token', text: 'Hel' },
      { type: 'token', text: 'lo' },
      { type: 'done', usage: { total_tokens: 15 } },
    ]);
    expect(s.reply()).toEqual({ reply: 'Hello', totalTokens: 15 });
  });

  it('a turn/end with an error reason becomes the error frame (#631: never a silent empty reply)', () => {
    const s = new TurnStreamer();
    s.push(ev('assistant/chunk', { chunk: { type: 'text-delta', index: 0, text: 'partial' } }));
    const frames = s.push(
      ev('turn/end', { turn: 1, reason: { kind: 'error', error: { message: 'no provider/model', code: 'UNKNOWN' } } }),
    );
    expect(frames).toEqual([{ type: 'error', error: 'agent error: no provider/model' }]);
    expect(s.errored()).toBe('agent error: no provider/model');
    expect(s.finish()).toEqual([]); // no done after the turn error
  });

  it('a clean turn/end emits nothing and leaves errored() unset', () => {
    const s = new TurnStreamer();
    expect(s.push(ev('turn/end', { turn: 1, reason: { kind: 'completed' } }))).toEqual([]);
    expect(s.errored()).toBeUndefined();
  });

  it('error and done are mutually exclusive; frames stop after either', () => {
    const s = new TurnStreamer();
    expect(s.fail('agent error: x')).toEqual([{ type: 'error', error: 'agent error: x' }]);
    expect(s.finish()).toEqual([]); // no done after error
    expect(s.push(ev('assistant/chunk', { chunk: { type: 'text-delta', index: 0, text: 'late' } }))).toEqual([]);

    const t = new TurnStreamer();
    expect(t.finish()).toEqual([{ type: 'done', usage: { total_tokens: 0 } }]);
    expect(t.fail('too late')).toEqual([]); // no error after done
  });

  it('a failed tool result is reported with status failed', () => {
    const s = new TurnStreamer();
    s.push(ev('tool/call', { callId: 'c9', name: 'bash' }));
    const frames = s.push(ev('tool/result', { message: { source: { callId: 'c9' }, content: [] }, error: { code: 'E' } }));
    expect(frames).toEqual([{ type: 'tool', name: 'bash', id: 'c9', status: 'failed', args: '', result: '' }]);
  });
});
