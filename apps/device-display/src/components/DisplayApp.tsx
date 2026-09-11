import { useCallback, useEffect, useRef, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { CardView, LangSwitcher, ThemeSwitcher } from '@agentkeys/design-system/react';
import type { CardViewAction, CardViewDocument } from '@agentkeys/design-system/react';
import { DEFAULT_SETTINGS, loadSettings, normalizeBrokerUrl, normalizeId, saveSettings } from '../lib/settings';
import type { Settings } from '../lib/settings';
import { loadOrCreateSecretHex } from '../lib/identity';
import { initialFeed, reduceFeed } from '../lib/feed';
import type { FeedState } from '../lib/feed';
import {
  describeError,
  isExpired,
  pairingKey,
  pairingUri,
  sessionKey,
  sessionStale,
} from '../lib/pairing';
import type { DeviceSession, PendingPairing, Phase } from '../lib/pairing';
import {
  CAP_REFRESH_SECS,
  createDeviceClient,
  mintFeedCaps,
  parseCard,
  pollFeed,
  pollPairing,
  publishCommand,
  requestPairing,
  resolveSession,
} from '../lib/client';
import type { DeviceClient, FeedCaps } from '../lib/client';

// The kitchen display (#675): this tablet is its OWN device actor. Boot →
// resolve (bound? session) or pair (code + QR the owner claims in parent-control
// → Devices, approves with one Touch ID) → subscribe the display feed → render
// the latest card (the design system's CardView, the console's renderer) →
// taps publish `command` events attributed to this device.

const T = {
  en: {
    title: 'Kitchen display',
    settings: 'Settings',
    save: 'Save',
    cancel: 'Cancel',
    broker: 'Broker URL',
    feed: 'Display feed',
    label: 'Device label',
    unconfigured: 'Point this display at your family\u2019s broker to begin.',
    booting: 'Connecting…',
    pairTitle: 'Pair this display',
    pairSteps: 'In parent-control → Devices: enter this code, keep the label, attach the feed with listen + speak, then approve with Touch ID.',
    pairExpires: 'code valid until',
    pairExpired: 'The code expired — tap to get a new one.',
    newCode: 'New code',
    waiting: 'Waiting for the family chat card…',
    sent: 'Sent',
    fullscreen: 'Full screen',
    retry: 'Retry',
    forget: 'Forget this device',
    bound: 'paired',
  },
  zh: {
    title: '厨房屏',
    settings: '设置',
    save: '保存',
    cancel: '取消',
    broker: '服务地址',
    feed: '显示频道',
    label: '设备名称',
    unconfigured: '先填写家庭的服务地址。',
    booting: '连接中…',
    pairTitle: '配对此屏幕',
    pairSteps: '在家长端 → 设备：输入此配对码，保留名称，为频道勾选「收听 + 发言」，然后用 Touch ID 批准。',
    pairExpires: '配对码有效至',
    pairExpired: '配对码已过期——点击获取新码。',
    newCode: '新配对码',
    waiting: '等待家庭应用的卡片…',
    sent: '已发送',
    fullscreen: '全屏',
    retry: '重试',
    forget: '忘记此设备',
    bound: '已配对',
  },
} as const;

const storage = () => (typeof window === 'undefined' ? null : window.localStorage);
const nowSecs = () => Math.floor(Date.now() / 1000);

function readJson<T>(key: string): T | null {
  try {
    const raw = storage()?.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}
function writeJson(key: string, v: unknown) {
  try {
    if (v === null) storage()?.removeItem(key);
    else storage()?.setItem(key, JSON.stringify(v));
  } catch {
    /* private mode */
  }
}

export function DisplayApp() {
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [mounted, setMounted] = useState(false);
  const [phase, setPhase] = useState<Phase>({ kind: 'booting' });
  const [editing, setEditing] = useState(false);
  const [card, setCard] = useState<CardViewDocument | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const clientRef = useRef<DeviceClient | null>(null);
  const capsRef = useRef<FeedCaps | null>(null);
  const feedRef = useRef<FeedState>(initialFeed());
  const t = T[settings.locale];

  // ── boot: settings + identity (client-only) ──
  useEffect(() => {
    const s = loadSettings(storage(), window.location.search);
    setSettings(s);
    saveSettings(storage(), s);
    document.documentElement.dataset.theme = s.theme;
    setMounted(true);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = settings.theme;
  }, [settings.theme]);

  const say = useCallback((m: string) => {
    setToast(m);
    window.setTimeout(() => setToast(null), 2500);
  }, []);

  // ── the device lifecycle on the configured broker ──
  useEffect(() => {
    if (!mounted) return;
    if (!settings.brokerUrl) {
      setPhase({ kind: 'unconfigured' });
      return;
    }
    let cancelled = false;
    const run = async () => {
      setPhase({ kind: 'booting' });
      setCard(null);
      feedRef.current = initialFeed();
      capsRef.current = null;
      try {
        const secret = loadOrCreateSecretHex(storage(), (n) => crypto.getRandomValues(new Uint8Array(n)));
        const c = await createDeviceClient(settings.brokerUrl, secret);
        if (cancelled) return;
        clientRef.current = c;
        // 1. a bound device re-mints its session (chain is the SoT)
        const cached = readJson<DeviceSession>(sessionKey(settings.brokerUrl));
        let session = cached && !sessionStale(cached, nowSecs()) ? cached : null;
        if (!session) session = await resolveSession(c);
        if (cancelled) return;
        if (session) {
          writeJson(sessionKey(settings.brokerUrl), session);
          writeJson(pairingKey(settings.brokerUrl), null);
          setPhase({ kind: 'bound', session });
          return;
        }
        // 2. not bound: reuse an unexpired pending code, else open a new request
        let pending = readJson<PendingPairing>(pairingKey(settings.brokerUrl));
        if (!pending || isExpired(pending.expires_at, nowSecs())) {
          pending = await requestPairing(c);
          writeJson(pairingKey(settings.brokerUrl), pending);
        }
        if (cancelled) return;
        setPhase({ kind: 'pairing', pending });
      } catch (e) {
        if (cancelled) return;
        const d = describeError(e);
        setPhase({ kind: 'error', message: d.message, retryable: d.retryable });
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [mounted, settings.brokerUrl, tick]);

  // ── pairing: poll until the owner claims + approves ──
  useEffect(() => {
    if (phase.kind !== 'pairing') return;
    const c = clientRef.current;
    if (!c) return;
    let cancelled = false;
    const { pending } = phase;
    const loop = async () => {
      while (!cancelled) {
        if (isExpired(pending.expires_at, nowSecs())) {
          setPhase({ kind: 'error', message: t.pairExpired, retryable: true });
          return;
        }
        try {
          const session = await pollPairing(c, pending.request_id);
          if (cancelled) return;
          if (session) {
            writeJson(sessionKey(settings.brokerUrl), session);
            writeJson(pairingKey(settings.brokerUrl), null);
            setPhase({ kind: 'bound', session });
            return;
          }
        } catch (e) {
          if (cancelled) return;
          const d = describeError(e);
          if (!d.retryable) {
            writeJson(pairingKey(settings.brokerUrl), null);
            setPhase({ kind: 'error', message: d.message, retryable: true });
            return;
          }
        }
        await new Promise((r) => setTimeout(r, 3000));
      }
    };
    void loop();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase.kind === 'pairing' ? phase.pending.request_id : null]);

  // ── bound: caps + the feed long-poll ──
  useEffect(() => {
    if (phase.kind !== 'bound') return;
    const c = clientRef.current;
    if (!c) return;
    let cancelled = false;
    const { session } = phase;
    const loop = async () => {
      while (!cancelled) {
        try {
          if (!capsRef.current || nowSecs() - capsRef.current.mintedAt >= CAP_REFRESH_SECS) {
            capsRef.current = await mintFeedCaps(c, session, settings.feedId);
          }
          const { events, cursor } = await pollFeed(c, capsRef.current.sub, feedRef.current.cursor, 20);
          if (cancelled) return;
          const next = reduceFeed(feedRef.current, events, cursor);
          const changed = next.latestDocId !== feedRef.current.latestDocId;
          feedRef.current = next;
          if (changed && next.latestDocJson) {
            try {
              setCard(parseCard(c, next.latestDocJson) as CardViewDocument);
            } catch (e) {
              say(`card rejected: ${describeError(e).message}`);
            }
          }
        } catch (e) {
          if (cancelled) return;
          const d = describeError(e);
          if (d.status === 401 || d.status === 403) {
            // the session or the grant went away (revoked / rotated): re-resolve
            writeJson(sessionKey(settings.brokerUrl), null);
            capsRef.current = null;
            setTick((n) => n + 1);
            return;
          }
          say(d.message);
          await new Promise((r) => setTimeout(r, 5000));
        }
      }
    };
    void loop();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase.kind === 'bound' ? phase.session.session_jwt : null, settings.feedId]);

  const onAction = useCallback(
    async (a: CardViewAction) => {
      const c = clientRef.current;
      if (!c || !capsRef.current || !card) return;
      try {
        await publishCommand(c, capsRef.current.pub, card, a.id);
        say(`${t.sent} · ${a.label}`);
      } catch (e) {
        say(describeError(e).message);
      }
    },
    [card, say, t.sent],
  );

  const goFullscreen = () => {
    void document.documentElement.requestFullscreen?.();
    const nav = navigator as Navigator & { wakeLock?: { request: (k: 'screen') => Promise<unknown> } };
    void nav.wakeLock?.request('screen').catch(() => undefined);
  };

  const forget = () => {
    writeJson(sessionKey(settings.brokerUrl), null);
    writeJson(pairingKey(settings.brokerUrl), null);
    try {
      storage()?.removeItem('agentkeys.device.secret');
    } catch {
      /* ignore */
    }
    setTick((n) => n + 1);
  };

  if (!mounted) return null;

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', gap: 16, padding: 20 }}>
      <header style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <span style={{ fontFamily: "'Bricolage Grotesque', sans-serif", fontWeight: 700, fontSize: 20 }}>{t.title}</span>
        <span className="dd-code" style={{ fontSize: 12, opacity: 0.7 }}>{settings.label} · {settings.feedId}</span>
        <StatusPill phase={phase} label={t.bound} />
        <span style={{ flex: 1 }} />
        <LangSwitcher value={settings.locale} onChange={(l) => { const s = { ...settings, locale: l }; setSettings(s); saveSettings(storage(), s); }} />
        <button className="btn secondary" onClick={goFullscreen}>{t.fullscreen}</button>
        <button className="btn secondary" onClick={() => setEditing(true)}>{t.settings}</button>
      </header>

      {editing || phase.kind === 'unconfigured' ? (
        <SettingsForm
          settings={settings}
          t={t}
          onCancel={() => setEditing(false)}
          onSave={(s) => {
            setSettings(s);
            saveSettings(storage(), s);
            setEditing(false);
            setTick((n) => n + 1);
          }}
        />
      ) : null}

      {phase.kind === 'booting' && <p style={{ opacity: 0.7 }}>{t.booting}</p>}

      {phase.kind === 'pairing' && (
        <section style={{ display: 'flex', gap: 28, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ background: '#f3eee3', padding: 14, borderRadius: 14 }}>
            <QRCodeSVG value={pairingUri(phase.pending.pairing_code, settings.label, settings.feedId)} size={200} />
          </div>
          <div style={{ display: 'grid', gap: 10, maxWidth: 560 }}>
            <h2 style={{ margin: 0, fontFamily: "'Bricolage Grotesque', sans-serif" }}>{t.pairTitle}</h2>
            <div className="dd-code" style={{ fontSize: 40, fontWeight: 700 }} data-testid="pairing-code">{phase.pending.pairing_code}</div>
            <p style={{ margin: 0, opacity: 0.85 }}>{t.pairSteps}</p>
            <p className="dd-code" style={{ margin: 0, fontSize: 12, opacity: 0.6 }}>
              {t.pairExpires} {new Date(phase.pending.expires_at * 1000).toLocaleTimeString()} · {clientRef.current?.address}
            </p>
          </div>
        </section>
      )}

      {phase.kind === 'error' && (
        <section style={{ display: 'grid', gap: 10, maxWidth: 640 }}>
          <p style={{ margin: 0, color: '#ffb4a2' }}>{phase.message}</p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn primary" onClick={() => setTick((n) => n + 1)}>{t.retry}</button>
            <button className="btn secondary" onClick={forget}>{t.forget}</button>
          </div>
        </section>
      )}

      {phase.kind === 'bound' && (
        <section style={{ display: 'flex', justifyContent: 'center', flex: 1, alignItems: 'flex-start' }}>
          {card ? (
            <CardView card={card} locale={settings.locale} big onAction={onAction} />
          ) : (
            <p style={{ opacity: 0.7 }}>{t.waiting}</p>
          )}
        </section>
      )}

      {toast && (
        <div role="status" style={{ position: 'fixed', bottom: 20, left: '50%', transform: 'translateX(-50%)', background: '#f3eee3', color: '#15130f', padding: '10px 16px', borderRadius: 999, fontWeight: 600 }}>
          {toast}
        </div>
      )}
    </div>
  );
}

function StatusPill({ phase, label }: { phase: Phase; label: string }) {
  const text =
    phase.kind === 'bound' ? label : phase.kind === 'pairing' ? 'pairing' : phase.kind === 'error' ? 'error' : phase.kind;
  const color = phase.kind === 'bound' ? '#cebd09' : phase.kind === 'error' ? '#ffb4a2' : '#8c8474';
  return (
    <span className="dd-code" style={{ fontSize: 11, border: `1px solid ${color}`, color, borderRadius: 999, padding: '2px 8px' }}>
      {text}
    </span>
  );
}

function SettingsForm({
  settings,
  t,
  onSave,
  onCancel,
}: {
  settings: Settings;
  t: (typeof T)['en'] | (typeof T)['zh'];
  onSave: (s: Settings) => void;
  onCancel: () => void;
}) {
  const [broker, setBroker] = useState(settings.brokerUrl);
  const [feed, setFeed] = useState(settings.feedId);
  const [label, setLabel] = useState(settings.label);
  const [theme, setTheme] = useState(settings.theme);
  const valid = normalizeBrokerUrl(broker) !== '' && normalizeId(feed) !== '' && normalizeId(label) !== '';
  const field = { padding: '10px 12px', borderRadius: 10, border: '1px solid #4a463d', background: '#1b1813', color: '#f3eee3', fontSize: 15 } as const;
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!valid) return;
        onSave({ ...settings, brokerUrl: normalizeBrokerUrl(broker), feedId: normalizeId(feed), label: normalizeId(label), theme });
      }}
      style={{ display: 'grid', gap: 10, maxWidth: 520, background: '#1b1813', border: '1px solid #34302a', borderRadius: 16, padding: 16 }}
    >
      {!settings.brokerUrl && <p style={{ margin: 0, opacity: 0.85 }}>{t.unconfigured}</p>}
      <label style={{ display: 'grid', gap: 4 }}>
        <span style={{ fontSize: 12, opacity: 0.7 }}>{t.broker}</span>
        <input style={field} value={broker} onChange={(e) => setBroker(e.target.value)} placeholder="https://test-broker.agentterrier.cn" inputMode="url" />
      </label>
      <label style={{ display: 'grid', gap: 4 }}>
        <span style={{ fontSize: 12, opacity: 0.7 }}>{t.feed}</span>
        <input style={field} value={feed} onChange={(e) => setFeed(e.target.value)} placeholder="kitchen-display" />
      </label>
      <label style={{ display: 'grid', gap: 4 }}>
        <span style={{ fontSize: 12, opacity: 0.7 }}>{t.label}</span>
        <input style={field} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="kitchen-display" />
      </label>
      <ThemeSwitcher value={theme} onChange={setTheme} />
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn primary" type="submit" disabled={!valid}>{t.save}</button>
        {settings.brokerUrl && <button className="btn secondary" type="button" onClick={onCancel}>{t.cancel}</button>}
      </div>
    </form>
  );
}
