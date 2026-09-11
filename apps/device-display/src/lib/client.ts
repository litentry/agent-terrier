// The device actor's broker + channel-worker calls, all through the wasm core:
// the K10 (DeviceIdentity), pairing/resolve (WebCore), the channel caps minted
// with the DEVICE's own session, and the worker poll/publish (ChannelWorker).
// Wire shapes are the protocol crate's, compiled in — nothing is re-typed here.
import { loadWasmModule } from './wasm-module';
import { describeError, sessionFromBroker } from './pairing';
import type { DeviceSession, PendingPairing } from './pairing';

type Wasm = Awaited<ReturnType<typeof loadWasmModule>>;

export interface DeviceClient {
  wasm: Wasm;
  core: InstanceType<Wasm['WebCore']>;
  identity: InstanceType<Wasm['DeviceIdentity']>;
  worker: InstanceType<Wasm['ChannelWorker']>;
  brokerUrl: string;
  workerUrl: string;
  address: string;
  deviceKeyHash: string;
}

export interface FeedCaps {
  sub: unknown;
  pub: unknown;
  mintedAt: number;
}

/** Cap TTL asked of the broker; re-minted at MINT_REFRESH_SECS. */
export const CAP_TTL_SECS = 300;
export const CAP_REFRESH_SECS = 240;

export async function createDeviceClient(brokerUrl: string, secretHex: string): Promise<DeviceClient> {
  const wasm = await loadWasmModule();
  const workerUrl = wasm.deriveWorkerUrl(brokerUrl, 'channel');
  if (!workerUrl) {
    throw new Error(
      `cannot derive the channel worker from broker ${brokerUrl} — use the stack's broker host (https://broker.<zone> / https://test-broker.<zone>)`,
    );
  }
  const identity = new wasm.DeviceIdentity(secretHex);
  return {
    wasm,
    core: new wasm.WebCore(brokerUrl),
    identity,
    worker: new wasm.ChannelWorker(workerUrl),
    brokerUrl,
    workerUrl,
    address: identity.address(),
    deviceKeyHash: identity.deviceKeyHash(),
  };
}

const nowSecs = () => Math.floor(Date.now() / 1000);

/** A bound device re-mints its session on every boot; null = not bound (pair). */
export async function resolveSession(c: DeviceClient): Promise<DeviceSession | null> {
  try {
    const r = (await c.core.agentResolve({
      device_pubkey: c.address,
      pop_sig: c.identity.agentPopSig(),
      is_device: true,
    })) as Parameters<typeof sessionFromBroker>[0];
    return sessionFromBroker(r, nowSecs());
  } catch (e) {
    const d = describeError(e);
    if (d.status !== null && d.status >= 400 && d.status < 500) return null;
    throw e;
  }
}

export async function requestPairing(c: DeviceClient): Promise<PendingPairing> {
  const r = (await c.core.pairingRequest({
    device_pubkey: c.address,
    pop_sig: c.identity.agentPopSig(),
  })) as { request_id: string; pairing_code: string; expires_at?: number };
  return { request_id: r.request_id, pairing_code: r.pairing_code, expires_at: r.expires_at ?? 0 };
}

/** null while the owner has not claimed + approved (the broker answers `pending`). */
export async function pollPairing(c: DeviceClient, requestId: string): Promise<DeviceSession | null> {
  const r = (await c.core.pairingPoll({
    request_id: requestId,
    device_pubkey: c.address,
    pop_sig: c.identity.agentPopSig(),
  })) as Parameters<typeof sessionFromBroker>[0];
  return sessionFromBroker(r, nowSecs());
}

export async function mintFeedCaps(c: DeviceClient, s: DeviceSession, feedId: string): Promise<FeedCaps> {
  const base = {
    operator_omni: s.operator_omni,
    actor_omni: s.actor_omni,
    device_key_hash: s.device_key_hash || c.deviceKeyHash,
    ttl_seconds: CAP_TTL_SECS,
  };
  const sub = await c.core.capChannelSub(s.session_jwt, { ...base, service: `channel-sub:${feedId}` });
  const pub = await c.core.capChannelPub(s.session_jwt, { ...base, service: `channel-pub:${feedId}` });
  return { sub, pub, mintedAt: nowSecs() };
}

export async function pollFeed(
  c: DeviceClient,
  subCap: unknown,
  after: string,
  waitSeconds: number,
): Promise<{ events: Array<{ event_id: string; kind: string; body?: string | null; ts_millis?: number }>; cursor: string }> {
  const r = (await c.worker.poll({ cap: subCap, after, wait_seconds: waitSeconds })) as {
    events: Array<{ event_id: string; kind: string; body?: string | null; ts_millis?: number }>;
    cursor: string;
  };
  return { events: r.events ?? [], cursor: r.cursor ?? after };
}

/** Tap an action: the protocol's `CardCommand` bytes, published as a `command`
 *  event attributed to THIS device (the cap carries the actor). */
export async function publishCommand(
  c: DeviceClient,
  pubCap: unknown,
  card: unknown,
  actionId: string,
): Promise<string> {
  const body_b64 = c.wasm.buildCardCommandBodyB64(card, actionId);
  const r = (await c.worker.publish({
    cap: pubCap,
    kind: 'command',
    direction: 'in',
    body_b64,
  })) as { event_id: string };
  return r.event_id;
}

export function parseCard(c: DeviceClient, json: string): unknown {
  return c.wasm.parseCardJson(json);
}
