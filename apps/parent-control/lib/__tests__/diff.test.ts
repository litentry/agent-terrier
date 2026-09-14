import { describe, expect, it } from 'vitest';
import { decodeBase64Utf8, diffStats, errorJson, lineDiff } from '../client/diff';

describe('line diff', () => {
  it('marks changed lines and keeps the unchanged ones in order', () => {
    const d = lineDiff('a\nb\nc', 'a\nB\nc\nd');
    expect(d.map((l) => `${l.kind}:${l.text}`)).toEqual(['same:a', 'del:b', 'add:B', 'same:c', 'add:d']);
    expect(diffStats(d)).toEqual({ added: 2, removed: 1 });
  });

  it('is empty-safe and identity-safe', () => {
    expect(lineDiff('', '')).toEqual([{ kind: 'same', text: '' }]);
    expect(lineDiff('x\ny', 'x\ny').every((l) => l.kind === 'same')).toBe(true);
  });

  it('falls back to whole-file change past the cap', () => {
    const big = Array.from({ length: 2001 }, (_, i) => `l${i}`).join('\n');
    const d = lineDiff(big, 'one');
    expect(d.filter((l) => l.kind === 'del')).toHaveLength(2001);
    expect(d.filter((l) => l.kind === 'add')).toHaveLength(1);
  });
});

describe('daemon error payloads', () => {
  it('extracts the JSON object from a client error detail', () => {
    expect(errorJson('POST /v1/master/resources/add → 409: {"error":"stale_base","current_content_hash":"abc"}')).toEqual({ error: 'stale_base', current_content_hash: 'abc' });
    expect(errorJson('POST /x → 502: gateway timeout')).toBeNull();
    expect(errorJson(undefined)).toBeNull();
  });

  it('decodes base64 bodies as UTF-8', () => {
    expect(decodeBase64Utf8(btoa(unescape(encodeURIComponent('我的饮食 ok'))))).toBe('我的饮食 ok');
  });
});
