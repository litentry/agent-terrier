// The display feed as the device sees it: a long-polled stream of channel
// events; the card is the LATEST `doc` event (older docs are superseded,
// `command` / `text` events are somebody else's). The body is base64 JSON —
// decoded here, validated by the wasm `parseCardJson` (the protocol's parser).

export interface FeedEvent {
  event_id: string;
  kind: string;
  body?: string | null;
  ts_millis?: number;
  direction?: string;
}

export interface FeedState {
  /** The worker's cursor to poll after ('' = from the feed's start). */
  cursor: string;
  latestDocJson: string | null;
  latestDocId: string | null;
  latestDocTs: number;
  seen: number;
}

export const initialFeed = (): FeedState => ({
  cursor: '',
  latestDocJson: null,
  latestDocId: null,
  latestDocTs: 0,
  seen: 0,
});

/** base64 → UTF-8 text (browser `atob` + TextDecoder; Node has both). */
export function decodeBase64Utf8(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

export function reduceFeed(state: FeedState, events: FeedEvent[], cursor: string): FeedState {
  let next: FeedState = { ...state, cursor: cursor || state.cursor, seen: state.seen + events.length };
  for (const ev of events) {
    if (ev.kind !== 'doc' || !ev.body) continue;
    let json: string;
    try {
      json = decodeBase64Utf8(ev.body);
    } catch {
      continue;
    }
    next = { ...next, latestDocJson: json, latestDocId: ev.event_id, latestDocTs: ev.ts_millis ?? 0 };
  }
  return next;
}
