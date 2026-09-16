import { describe, expect, it } from 'vitest';
import { parseLifecycle, stageDetail, stageLabel, stageTone } from '../client/lifecycle';

describe('delegate lifecycle', () => {
  it('parses a feed report and labels each stage', () => {
    const lc = parseLifecycle(JSON.stringify({ stage: 'syncing', detail: '2 of 3 namespaces', done: 2, total: 3, mirrored: 0, deleted: 0, ms: 0, errors: [], ts_millis: 1 }))!;
    expect(stageLabel(lc)).toBe('syncing 2/3');
    expect(stageTone(lc.stage)).toBe('warn');
    const ready = parseLifecycle(JSON.stringify({ stage: 'ready', detail: '3 namespace(s)', mirrored: 42, deleted: 1, ms: 1830, errors: [] }))!;
    expect(stageLabel(ready)).toBe('ready · 1.8 s');
    expect(stageTone(ready.stage)).toBe('ok');
    expect(stageDetail(ready)).toBe('3 namespace(s) · 42 lines mirrored · 1 removed');
    const bad = parseLifecycle(JSON.stringify({ stage: 'degraded', detail: 'pull failed: fetch travel: 502', errors: ['fetch travel: 502'] }))!;
    expect(stageLabel(bad)).toBe('degraded');
    expect(stageTone(bad.stage)).toBe('bad');
    expect(stageDetail(bad)).toContain('errors: fetch travel: 502');
  });

  it('rejects text that is not a report', () => {
    expect(parseLifecycle('hello')).toBeNull();
    expect(parseLifecycle('{"detail":"no stage"}')).toBeNull();
  });
});
