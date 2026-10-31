import { useCallback, useEffect, useRef, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { Button, CardView, LangSwitcher, ThemeSwitcher } from '@agentkeys/design-system/react';
import type { CardViewAction, CardViewDocument } from '@agentkeys/design-system/react';
import { DEFAULT_SETTINGS, loadSettings, normalizeBrokerUrl, normalizeId, saveSettings } from '../lib/settings';
import type { Settings } from '../lib/settings';
import { loadOrCreateSecretHex } from '../lib/identity';
import { initialFeed, pictureDataUrl, reduceFeed, showsPictureOnly } from '../lib/feed';
import type { FeedPicture, FeedState } from '../lib/feed';
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
// the latest card (the design system's CardView, the console's renderer) and
// the latest picture (an `image` event — the painter's drawing) → taps publish
// `command` events attributed to this device. Whichever the app published
// last wins the screen: a card is drawn beside the picture; a picture newer
// than the card fills the screen alone and stays, with the screen kept awake,
// until the next event (feed.ts).

const T = {
  en: {
    title: 'Kitchen display',
    pictureAlt: 'The picture on the family screen',
    showMenu: 'Tap the picture for the menu',
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
    pictureAlt: '家庭屏幕上的画',
    showMenu: '点一下画面显示菜单',
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
  const [picture, setPicture] = useState<FeedPicture | null>(null);
  // The picture is the newest visual on the feed: it fills the screen alone
  // and the chrome hides until a tap asks for it.
  const [pictureOnly, setPictureOnly] = useState(false);
  const [menuShown, setMenuShown] = useState(false);
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
      setPicture(null);
      setPictureOnly(false);
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
          const pictureChanged = next.latestPicture?.eventId !== feedRef.current.latestPicture?.eventId;
          feedRef.current = next;
          if (changed && next.latestDocJson) {
            try {
              setCard(parseCard(c, next.latestDocJson) as CardViewDocument);
            } catch (e) {
              say(`card rejected: ${describeError(e).message}`);
            }
          }
          if (pictureChanged) setPicture(next.latestPicture);
          setPictureOnly(showsPictureOnly(next));
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

  // ── bound: keep the screen awake (a paired display is always lit) ──
  // The Wake Lock API needs no gesture, only a visible page; the OS releases
  // it whenever the tab hides, so it is re-requested on every return.
  useEffect(() => {
    if (phase.kind !== 'bound') return;
    let released = false;
    let sentinel: { release: () => Promise<void> } | null = null;
    const request = () => {
      if (released || document.visibilityState !== 'visible') return;
      const nav = navigator as Navigator & {
        wakeLock?: { request: (k: 'screen') => Promise<{ release: () => Promise<void> }> };
      };
      nav.wakeLock
        ?.request('screen')
        .then((s) => {
          if (released) void s.release();
          else sentinel = s;
        })
        .catch(() => undefined);
    };
    request();
    document.addEventListener('visibilitychange', request);
    return () => {
      released = true;
      document.removeEventListener('visibilitychange', request);
      void sentinel?.release().catch(() => undefined);
    };
  }, [phase.kind]);

  // The menu a tap on a full-screen picture reveals hides again by itself.
  useEffect(() => {
    if (!menuShown) return;
    const timer = window.setTimeout(() => setMenuShown(false), 8000);
    return () => window.clearTimeout(timer);
  }, [menuShown]);

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

  const fullscreenPicture = phase.kind === 'bound' && pictureOnly && picture !== null;
  const chromeShown = !fullscreenPicture || menuShown || editing;

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', gap: 16, padding: fullscreenPicture ? 0 : 20 }}>
      {fullscreenPicture && (
        <img
          src={pictureDataUrl(picture)}
          alt={t.pictureAlt}
          data-testid="picture"
          onClick={() => setMenuShown((v) => !v)}
          style={{ position: 'fixed', inset: 0, width: '100vw', height: '100vh', objectFit: 'contain', background: '#15130f', cursor: 'pointer' }}
        />
      )}
      <header
        style={{
          display: chromeShown ? 'flex' : 'none',
          alignItems: 'center',
          gap: 12,
          flexWrap: 'wrap',
          ...(fullscreenPicture ? { position: 'relative' as const, zIndex: 1, padding: 20, background: 'rgba(21, 19, 15, 0.86)' } : {}),
        }}
      >
        <span style={{ fontFamily: "'Bricolage Grotesque', sans-serif", fontWeight: 700, fontSize: 20 }}>{t.title}</span>
        <span className="dd-code" style={{ fontSize: 12, opacity: 0.7 }}>{settings.label} · {settings.feedId}</span>
        <StatusPill phase={phase} label={t.bound} />
        <span style={{ flex: 1 }} />
        <LangSwitcher value={settings.locale} onChange={(l) => { const s = { ...settings, locale: l }; setSettings(s); saveSettings(storage(), s); }} />
        <Button onClick={goFullscreen}>{t.fullscreen}</Button>
        <Button onClick={() => setEditing(true)}>{t.settings}</Button>
      </header>

      {editing || phase.kind === 'unconfigured' ? (
        // Above the full-screen picture (a fixed <img> paints over any
        // non-positioned sibling), so the form stays reachable from the menu.
        <div style={fullscreenPicture ? { position: 'relative', zIndex: 1, padding: '0 20px 20px' } : undefined}>
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
        </div>
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
            <Button variant="primary" onClick={() => setTick((n) => n + 1)}>{t.retry}</Button>
            <Button onClick={forget}>{t.forget}</Button>
          </div>
        </section>
      )}

      {phase.kind === 'bound' && !fullscreenPicture && (
        <section style={{ display: 'flex', justifyContent: 'center', flex: 1, alignItems: 'flex-start', gap: 24, flexWrap: 'wrap' }}>
          {picture && (
            <img
              src={pictureDataUrl(picture)}
              alt={t.pictureAlt}
              data-testid="picture"
              style={{ flex: '1 1 480px', minWidth: 0, maxWidth: '100%', maxHeight: 'calc(100vh - 120px)', objectFit: 'contain', borderRadius: 16, background: '#fff7e6' }}
            />
          )}
          {card ? (
            <CardView card={card} locale={settings.locale} big onAction={onAction} />
          ) : (
            !picture && <p style={{ opacity: 0.7 }}>{t.waiting}</p>
          )}
        </section>
      )}
      {fullscreenPicture && chromeShown && (
        <p style={{ position: 'relative', zIndex: 1, margin: 0, padding: '0 20px', opacity: 0.7, fontSize: 12 }}>{t.showMenu}</p>
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
        <Button variant="primary" type="submit" disabled={!valid}>{t.save}</Button>
        {settings.brokerUrl && <Button type="button" onClick={onCancel}>{t.cancel}</Button>}
      </div>
    </form>
  );
}
