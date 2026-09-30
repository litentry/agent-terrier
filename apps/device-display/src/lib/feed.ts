// The display feed as the device sees it: a long-polled stream of channel
// events carrying two visuals — the card (the LATEST `doc` event; older docs
// are superseded) and the picture (the LATEST `image` event). The screen shows
// whichever the app published LAST, in feed order: a card newer than the
// picture is drawn beside it (that is where the buttons live); a picture newer
// than the card fills the screen alone and stays until the next event (the
// painter's finished picture). `command` / `text` events are somebody else's.
//
// Bodies are base64. A doc's is decoded here and validated by the wasm
// `parseCardJson` (the protocol's parser); a picture's base64 feeds a `data:`
// URL as is — an <img> never runs a script inside an SVG and loads nothing
// external, so the bytes are shown, never interpreted. A picture that rides by
// reference (`body_ref`, above the worker's inline ceiling) is beyond this
// renderer and is skipped; the template contract keeps pictures inline.

export interface FeedEvent {
  event_id: string;
  kind: string;
  body?: string | null;
  body_ref?: string | null;
  content_type?: string | null;
  ts_millis?: number;
  direction?: string;
}

export interface FeedPicture {
  eventId: string;
  /** The media type the app published (`image/svg+xml`, `image/png`, …). */
  contentType: string;
  /** The body exactly as published: base64 of the bytes. */
  bodyB64: string;
  ts: number;
}

/** Which visual the app published last — what the screen shows. */
export type FeedVisual = 'doc' | 'image';

export interface FeedState {
  /** The worker's cursor to poll after ('' = from the feed's start). */
  cursor: string;
  latestDocJson: string | null;
  latestDocId: string | null;
  latestDocTs: number;
  latestPicture: FeedPicture | null;
  lastVisual: FeedVisual | null;
  seen: number;
}

export const initialFeed = (): FeedState => ({
  cursor: '',
  latestDocJson: null,
  latestDocId: null,
  latestDocTs: 0,
  latestPicture: null,
  lastVisual: null,
  seen: 0,
});

/** The media type an `image` event without one was published as (the daemon's default). */
export const DEFAULT_IMAGE_CONTENT_TYPE = 'image/jpeg';

/** base64 → UTF-8 text (browser `atob` + TextDecoder; Node has both). */
export function decodeBase64Utf8(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/** A media type an <img> may be handed: `image/<subtype>`, nothing else. */
export function isImageContentType(contentType: string): boolean {
  return /^image\/[a-z0-9.+-]+$/i.test(contentType.trim());
}

/** The picture an `image` event carries, or null when this renderer cannot show it. */
export function pictureOf(ev: FeedEvent): FeedPicture | null {
  if (ev.kind !== 'image' || !ev.body) return null;
  const contentType = (ev.content_type ?? '').trim() || DEFAULT_IMAGE_CONTENT_TYPE;
  if (!isImageContentType(contentType)) return null;
  if (!/^[A-Za-z0-9+/=\s]+$/.test(ev.body)) return null;
  return { eventId: ev.event_id, contentType, bodyB64: ev.body.replace(/\s+/g, ''), ts: ev.ts_millis ?? 0 };
}

export function reduceFeed(state: FeedState, events: FeedEvent[], cursor: string): FeedState {
  let next: FeedState = { ...state, cursor: cursor || state.cursor, seen: state.seen + events.length };
  for (const ev of events) {
    if (ev.kind === 'image') {
      const picture = pictureOf(ev);
      if (!picture) continue;
      next = { ...next, latestPicture: picture, lastVisual: 'image' };
      continue;
    }
    if (ev.kind !== 'doc' || !ev.body) continue;
    let json: string;
    try {
      json = decodeBase64Utf8(ev.body);
    } catch {
      continue;
    }
    next = { ...next, latestDocJson: json, latestDocId: ev.event_id, latestDocTs: ev.ts_millis ?? 0, lastVisual: 'doc' };
  }
  return next;
}

/** The picture fills the screen alone: it is the newest visual on the feed. */
export function showsPictureOnly(state: FeedState): boolean {
  return state.lastVisual === 'image' && state.latestPicture !== null;
}

/** The `src` an <img> renders the picture from. */
export function pictureDataUrl(p: FeedPicture): string {
  return `data:${p.contentType};base64,${p.bodyB64}`;
}
