// The card schema is generated from agentkeys-protocol::card.

import { useRef, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';

export type CardLocale = 'en' | 'zh';

import type { CardAction as CardViewAction } from '../generated/CardAction';
import type { CardAlert as CardViewAlert } from '../generated/CardAlert';
import type { CardDocument as CardViewDocument } from '../generated/CardDocument';

export type { CardViewAction, CardViewAlert, CardViewDocument };
export type { CardItem as CardViewItem } from '../generated/CardItem';
export type { CardMetric as CardViewMetric } from '../generated/CardMetric';
export type { CardSection as CardViewSection } from '../generated/CardSection';

/** Pick the localized string; an empty `_zh` falls back to the base text. */
export function cardText(locale: CardLocale, base: string, zh?: string | null): string {
  return locale === 'zh' && zh && zh.trim() ? zh : base;
}

/** The staleness line a renderer shows (`now` injectable for tests). */
export function cardAge(updatedAt: number | undefined, now: number): string {
  if (!updatedAt) return '';
  const s = Math.max(0, now - updatedAt);
  if (s < 90) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

/** How long a tapped card stays refused after the tap, even when its send
 *  returns at once. */
export const CARD_TAP_HOLD_MS = 800;

/** Refuse repeat taps while a send is active or its hold has not elapsed. */
export function cardTapGate(holdMs = CARD_TAP_HOLD_MS, clock: () => number = Date.now) {
  let sending = false;
  let heldUntil = 0;
  return {
    begin(): boolean {
      if (sending || clock() < heldUntil) return false;
      sending = true;
      heldUntil = clock() + holdMs;
      return true;
    },
    end(): number {
      sending = false;
      return Math.max(0, heldUntil - clock());
    },
  };
}

const ALERT_COLOR: Record<NonNullable<CardViewAlert['level']>, string> = {
  info: '#93c5fd',
  warn: '#fcd34d',
  danger: '#fca5a5',
};

export function CardView({
  card,
  locale = 'en',
  onAction,
  big = false,
  now,
  style,
}: {
  card: CardViewDocument;
  locale?: CardLocale;
  /** Tapping an action hands it here — the caller publishes the `command`.
   *  Return the send's promise: the card's buttons stay disabled until it
   *  settles ([`cardTapGate`]). */
  onAction?: (action: CardViewAction) => void | Promise<unknown>;
  /** The 480×480 kitchen-screen scale. */
  big?: boolean;
  /** Unix seconds "now" for the staleness line (defaults to the wall clock). */
  now?: number;
  style?: CSSProperties;
}) {
  const gate = useRef<ReturnType<typeof cardTapGate> | null>(null);
  const [sendingId, setSendingId] = useState<string | null>(null);
  const tap = (action: CardViewAction) => {
    if (!onAction) return;
    gate.current ??= cardTapGate();
    const tapGate = gate.current;
    if (!tapGate.begin()) return;
    setSendingId(action.id);
    void Promise.resolve()
      .then(() => onAction(action))
      .catch(() => undefined)
      .finally(() => setTimeout(() => setSendingId(null), tapGate.end()));
  };
  const fs = big ? 1.5 : 1;
  const t = (base: string, zh?: string | null) => cardText(locale, base, zh);
  const age = cardAge(card.updated_at, now ?? Math.floor(Date.now() / 1000));
  const shell: CSSProperties = {
    background: '#15130f',
    color: '#f3eee3',
    borderRadius: 14,
    padding: big ? 28 : 16,
    fontFamily: 'var(--mono, ui-monospace, monospace)',
    width: big ? 480 : undefined,
    minHeight: big ? 480 : undefined,
    display: 'flex',
    flexDirection: 'column',
    gap: 10 * fs,
    ...style,
  };
  const muted: CSSProperties = { opacity: 0.75, fontSize: 11.5 * fs };
  const metrics = card.metrics ?? [];
  const sections = card.sections ?? [];
  const alerts = card.alerts ?? [];
  const actions = card.actions ?? [];
  const tagChip = (tag: string): ReactNode => (
    <span
      className={`ds-card-tag ds-card-tag--${tag}`}
      style={{
        fontSize: 10 * fs,
        border: '1px solid #4a463d',
        borderRadius: 6,
        padding: `${1 * fs}px ${5 * fs}px`,
        marginLeft: 6,
        opacity: 0.9,
      }}
    >
      {tag}
    </span>
  );
  return (
    <div className="ds-card-view" data-card-schema={card.card} style={shell}>
      <div className="ds-card-view__head">
        <div style={{ fontSize: 13 * fs, fontWeight: 700 }}>{t(card.title, card.title_zh)}</div>
        {(card.subtitle || card.subtitle_zh) && (
          <div style={{ ...muted, marginTop: 4 * fs }}>{t(card.subtitle ?? '', card.subtitle_zh)}</div>
        )}
      </div>
      {metrics.length > 0 && (
        <div className="ds-card-view__metrics" style={{ display: 'flex', gap: 12 * fs, flexWrap: 'wrap' }}>
          {metrics.map((m, i) => (
            <div key={`${m.label}-${i}`} className="ds-card-metric" style={{ minWidth: 96 * fs }}>
              <div style={muted}>{t(m.label, m.label_zh)}</div>
              <div style={{ fontSize: 15 * fs, fontWeight: 700 }}>
                {m.value}
                {m.unit ? <span style={{ ...muted, marginLeft: 3 }}>{m.unit}</span> : null}
              </div>
              {typeof m.progress === 'number' && (
                <div
                  className="ds-card-metric__bar"
                  role="progressbar"
                  aria-valuenow={Math.round(Math.max(0, Math.min(1, m.progress)) * 100)}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  style={{ height: 4 * fs, background: '#2a2823', borderRadius: 2, marginTop: 4 * fs }}
                >
                  <div
                    style={{
                      width: `${Math.round(Math.max(0, Math.min(1, m.progress)) * 100)}%`,
                      height: '100%',
                      background: '#a7f3d0',
                      borderRadius: 2,
                    }}
                  />
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      {sections.map((s, si) => (
        <div key={`${s.title}-${si}`} className="ds-card-section">
          <div style={{ fontSize: 12 * fs, fontWeight: 700, color: '#a7f3d0' }}>{t(s.title, s.title_zh)}</div>
          <ul style={{ margin: `${4 * fs}px 0 0`, paddingLeft: 16 * fs, fontSize: 12 * fs, lineHeight: 1.45 }}>
            {s.items.map((it, ii) => (
              <li key={`${it.text}-${ii}`} className="ds-card-item">
                <span>{t(it.text, it.text_zh)}</span>
                {(it.detail || it.detail_zh) && <span style={muted}> — {t(it.detail ?? '', it.detail_zh)}</span>}
                {it.tag ? tagChip(it.tag) : null}
              </li>
            ))}
          </ul>
        </div>
      ))}
      {alerts.map((a, ai) => (
        <div
          key={`${a.text}-${ai}`}
          className={`ds-card-alert ds-card-alert--${a.level ?? 'info'}`}
          role="status"
          style={{ fontSize: 11.5 * fs, color: ALERT_COLOR[a.level ?? 'info'] }}
        >
          {a.level === 'danger' ? '⚠ ' : a.level === 'warn' ? '! ' : 'ℹ '}
          {t(a.text, a.text_zh)}
        </div>
      ))}
      {(actions.length > 0 || age) && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginTop: 'auto', paddingTop: 8 * fs }}>
          {actions.map((a) => (
            <button
              key={a.id}
              type="button"
              className="ds-card-action"
              data-action-id={a.id}
              data-command={a.command}
              onClick={() => tap(a)}
              disabled={sendingId !== null}
              aria-busy={sendingId === a.id ? true : undefined}
              style={{
                ...(sendingId !== null ? { opacity: sendingId === a.id ? 0.8 : 0.45 } : {}),
                cursor: sendingId === null ? 'pointer' : 'progress',
                fontFamily: 'inherit',
                fontSize: 11.5 * fs,
                fontWeight: 600,
                background: '#2a2823',
                color: '#f3eee3',
                border: '1px solid #4a463d',
                borderRadius: 8,
                padding: `${7 * fs}px ${11 * fs}px`,
              }}
            >
              {t(a.label, a.label_zh)}
            </button>
          ))}
          {age ? (
            <span className="ds-card-view__age" style={{ ...muted, marginLeft: 'auto' }}>
              {age}
            </span>
          ) : null}
        </div>
      )}
    </div>
  );
}
