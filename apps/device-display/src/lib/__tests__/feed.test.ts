import { describe, expect, it } from 'vitest';
import { decodeBase64Utf8, initialFeed, reduceFeed } from '../feed';

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

describe('feed reducer', () => {
  it('keeps the LATEST doc, ignores commands and text, advances the cursor', () => {
    const s1 = reduceFeed(
      initialFeed(),
      [
        { event_id: 'e1', kind: 'doc', body: b64('{"card":1,"title":"old"}'), ts_millis: 1 },
        { event_id: 'e2', kind: 'command', body: b64('{"command":"x"}'), ts_millis: 2 },
        { event_id: 'e3', kind: 'doc', body: b64('{"card":1,"title":"新的"}'), ts_millis: 3 },
        { event_id: 'e4', kind: 'text', body: b64('hi'), ts_millis: 4 },
      ],
      'bots/op/channel/kitchen-display/e4',
    );
    expect(s1.latestDocId).toBe('e3');
    expect(s1.latestDocJson).toBe('{"card":1,"title":"新的"}');
    expect(s1.latestDocTs).toBe(3);
    expect(s1.cursor).toBe('bots/op/channel/kitchen-display/e4');
    expect(s1.seen).toBe(4);
    // an empty long-poll keeps everything (cursor '' never overwrites)
    const s2 = reduceFeed(s1, [], '');
    expect(s2).toEqual({ ...s1, seen: 4 });
  });

  it('skips an undecodable body without losing the previous card', () => {
    const s = reduceFeed(
      { ...initialFeed(), latestDocId: 'e0', latestDocJson: '{"card":1}' },
      [{ event_id: 'e9', kind: 'doc', body: '%%%not-base64', ts_millis: 9 }],
      'c9',
    );
    expect(s.latestDocId).toBe('e0');
    expect(s.cursor).toBe('c9');
  });

  it('decodes UTF-8 bodies', () => {
    expect(decodeBase64Utf8(b64('家庭厨师 · 今天'))).toBe('家庭厨师 · 今天');
  });
});
