import { describe, expect, it } from 'vitest';
import { decodeBase64Utf8, initialFeed, isImageContentType, pictureDataUrl, pictureOf, reduceFeed, showsPictureOnly } from '../feed';

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
const SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><circle cx="600" cy="400" r="200" fill="#f6b93b"/></svg>';

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
    expect(s1.lastVisual).toBe('doc');
    expect(s1.latestPicture).toBeNull();
    expect(showsPictureOnly(s1)).toBe(false);
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

describe('the picture (image events) and what the screen shows', () => {
  it('a picture published after the card fills the screen alone; a card after it brings the buttons back', () => {
    // The painter's draft: picture, then card → card mode (picture beside the buttons).
    const draft = reduceFeed(
      initialFeed(),
      [
        { event_id: 'p1', kind: 'image', body: b64(SVG), content_type: 'image/svg+xml', ts_millis: 10 },
        { event_id: 'd1', kind: 'doc', body: b64('{"card":1,"title":"Painter · drawing"}'), ts_millis: 11 },
      ],
      'c1',
    );
    expect(draft.latestPicture?.eventId).toBe('p1');
    expect(draft.latestPicture?.contentType).toBe('image/svg+xml');
    expect(draft.latestDocId).toBe('d1');
    expect(draft.lastVisual).toBe('doc');
    expect(showsPictureOnly(draft)).toBe(false);
    // The finished picture is published LAST → the screen shows only the picture.
    const finished = reduceFeed(
      draft,
      [{ event_id: 'p2', kind: 'image', body: b64(SVG), content_type: 'image/svg+xml', ts_millis: 12 }],
      'c2',
    );
    expect(finished.latestPicture?.eventId).toBe('p2');
    expect(finished.latestDocId).toBe('d1');
    expect(finished.lastVisual).toBe('image');
    expect(showsPictureOnly(finished)).toBe(true);
    expect(pictureDataUrl(finished.latestPicture!)).toBe(`data:image/svg+xml;base64,${b64(SVG)}`);
  });

  it('a picture without a media type is the daemon default; a non-image type or a by-reference body is skipped', () => {
    const jpeg = pictureOf({ event_id: 'p', kind: 'image', body: 'AAAA', ts_millis: 1 });
    expect(jpeg?.contentType).toBe('image/jpeg');
    expect(pictureOf({ event_id: 'p', kind: 'image', body: 'AAAA', content_type: 'text/html' })).toBeNull();
    expect(pictureOf({ event_id: 'p', kind: 'image', body: 'not base64!', content_type: 'image/png' })).toBeNull();
    expect(pictureOf({ event_id: 'p', kind: 'image', body: null, body_ref: 'bots/op/channel/kids-display/blob/1', content_type: 'image/png' })).toBeNull();
    expect(pictureOf({ event_id: 'p', kind: 'doc', body: 'AAAA' })).toBeNull();
    // A skipped picture never flips the visual nor drops the picture on screen.
    const before = reduceFeed(initialFeed(), [{ event_id: 'p1', kind: 'image', body: 'AAAA', content_type: 'image/png' }], 'c1');
    const after = reduceFeed(
      before,
      [
        { event_id: 'd1', kind: 'doc', body: b64('{"card":1,"title":"t"}') },
        { event_id: 'p2', kind: 'image', body: null, body_ref: 'bots/op/channel/kids-display/blob/2', content_type: 'image/png' },
      ],
      'c2',
    );
    expect(after.latestPicture?.eventId).toBe('p1');
    expect(after.lastVisual).toBe('doc');
  });

  it('accepts only image media types', () => {
    expect(isImageContentType('image/svg+xml')).toBe(true);
    expect(isImageContentType(' image/PNG ')).toBe(true);
    expect(isImageContentType('application/vnd.agentkeys.card+json')).toBe(false);
    expect(isImageContentType('image/')).toBe(false);
    expect(isImageContentType('')).toBe(false);
  });
});
