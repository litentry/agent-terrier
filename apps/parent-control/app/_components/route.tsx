'use client';

// #722 / household channels — the Route page: how a WeChat message is routed.
// The decision model (Kev / Jev) has no chat-style system prompt: every
// question carries its own guidance, every question sees the shared `state`
// (the message + the sender), and the questions cannot see each other. The
// options are the member's own CHANNELS, each rendered from its channel
// document (a shared channel is one row per app bound to it). This page shows
// exactly what is sent, and how the model answered.
import { Fragment, useCallback, useEffect, useState } from 'react';
import { gatewayClient, gatewayNotConfigured } from '@/lib/gatewayClient';
import type { GatewayRouterView } from '@/lib/generated/GatewayRouterView';
import type { RouterContactView } from '@/lib/generated/RouterContactView';
import type { RouterExchange } from '@/lib/generated/RouterExchange';
import { Chip, PageHead, Panel } from './shared';

const REFRESH_MS = 15_000;

const fmtMs = (ms?: number) => (ms == null ? '—' : ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms} ms`);
const pct = (p: number) => `${Math.round(p * 100)}%`;

function median(xs: number[]): number | undefined {
  if (xs.length === 0) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

/** The model server line: where it runs and what it reports about itself. */
function upstreamRows(u: unknown): { label: string; value: string }[] {
  const o = (u ?? {}) as Record<string, unknown>;
  if (typeof o.error === 'string') return [{ label: 'server', value: `not reachable — ${o.error}` }];
  const rows = [{ label: 'server', value: typeof o.base_url === 'string' ? o.base_url : '—' }];
  const models = (o.models ?? {}) as Record<string, unknown>;
  const list = Array.isArray(models.data) ? (models.data as Record<string, unknown>[]) : [];
  for (const m of list) {
    const facts = Object.entries(m)
      .filter(([, v]) => v !== null && typeof v !== 'object')
      .map(([k, v]) => `${k} ${String(v)}`)
      .join(' · ');
    rows.push({ label: 'serves', value: facts || JSON.stringify(m) });
  }
  if (list.length === 0 && o.models != null) rows.push({ label: 'serves', value: JSON.stringify(o.models) });
  return rows;
}

type Json = Record<string, unknown>;
const asObj = (v: unknown): Json => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {});
const asText = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : JSON.stringify(v, null, 2));

/** One member's System One request, laid out the way Kev reads it: the shared
 *  `state`, then each question with its type, `instructions` and `criteria`. */
function RequestView({ request, options }: { request: unknown; options: RouterContactView['options'] }) {
  const req = asObj(request);
  const state = asObj(req.state);
  const questions = asObj(req.questions);
  const option = (key: string) => {
    const [channel, app] = key.split('/');
    const o = options.find((x) => x.channel_id.toLowerCase() === channel.toLowerCase());
    return o ? { channel: o, app: app ? o.apps.find((a) => a.alias.toLowerCase() === app.toLowerCase()) : undefined } : undefined;
  };
  return (
    <table className="tab">
      <tbody>
        <tr>
          <td><span className="mono">state</span><div className="muted">every question sees it</div></td>
          <td>
            {Object.entries(state).map(([k, v]) => (
              <div key={k}><span className="mono">{k}</span>: {asText(v)}</div>
            ))}
          </td>
        </tr>
        {Object.entries(questions).map(([name, q]) => {
          const question = asObj(q);
          const criteria = asObj(question.criteria);
          return (
            <tr key={name}>
              <td>
                <span className="mono">questions.{name}</span>
                <div><Chip kind={question.type === 'choice' ? 'broker' : 'scope'}>{String(question.type)}</Chip></div>
                <div className="muted">sees state + its own guidance only</div>
              </td>
              <td>
                <div style={{ marginBottom: 6 }}>
                  <span className="mono">instructions</span>
                  <pre className="mono" style={{ whiteSpace: 'pre-wrap', margin: '2px 0 0' }}>{asText(question.instructions)}</pre>
                </div>
                <span className="mono">criteria</span>
                <table className="tab" style={{ marginTop: 2 }}>
                  <tbody>
                    {Object.entries(criteria).map(([key, text]) => {
                      const o = option(key);
                      return (
                        <tr key={key}>
                          <td className="mono">{key}</td>
                          <td style={{ whiteSpace: 'pre-wrap' }}>
                            {text == null ? <span className="muted">(no description — Kev sees the name alone)</span> : asText(text)}
                          </td>
                          <td>
                            {o && <div className="muted">{o.channel.name}{o.channel.operator_of ? ` · ${o.channel.operator_of}'s operator channel` : ''}</div>}
                            {o?.app && o.app.takes.length > 0 && <div className="muted">{o.app.alias} takes {o.app.takes.join(', ')}</div>}
                            {o && !o.app && o.channel.apps.length === 1 && o.channel.apps[0].takes.length > 0 && <div className="muted">{o.channel.apps[0].alias} takes {o.channel.apps[0].takes.join(', ')}</div>}
                            {o && <div className="muted">document v{o.channel.updated_at}</div>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function Answer({ x }: { x: RouterExchange }) {
  const ranked = Object.entries(x.probabilities)
    .map(([alias, p]): [string, number] => [alias, p ?? 0])
    .sort((a, b) => b[1] - a[1]);
  if (ranked.length === 0) return <span className="muted">{x.error ?? 'no answer'}</span>;
  return (
    <span>
      {ranked.map(([key, p]) => (
        <span key={key} style={{ marginRight: 10, fontWeight: key === x.routed_to || key === `${x.routed_to}/${x.addressee ?? ''}` ? 600 : 400 }}>
          {key} {pct(p)}
        </span>
      ))}
      {x.continues != null && (
        <span className="muted">
          · continues {x.last_channel} {pct(x.continues)}
        </span>
      )}
    </span>
  );
}

function verdictChip(x: RouterExchange) {
  if (x.verdict === 'route' || x.verdict === 'follow_up') {
    return <Chip kind="ok">{x.verdict === 'follow_up' ? 'follow-up' : 'route'} → {x.routed_to}{x.addressee ? ` · ${x.addressee}` : ''}</Chip>;
  }
  if (x.verdict === 'ask') return <Chip kind="warn">asked the member</Chip>;
  return <Chip kind="bad">{x.verdict}</Chip>;
}

/** The router's page. `embedded` renders it as the contact gate page's
 *  route tab: a one-line lead and the refresh button instead of a page head. */
export function RoutePage({ embedded = false }: { embedded?: boolean } = {}) {
  const [view, setView] = useState<GatewayRouterView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);
  const [open, setOpen] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    const r = await gatewayClient.router();
    if (r.ok) {
      setView(r.value);
      setError(null);
      setNotConfigured(false);
    } else {
      setError(r.detail ?? r.reason);
      setNotConfigured(gatewayNotConfigured(r));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), REFRESH_MS);
    return () => clearInterval(t);
  }, [refresh]);

  const photos = view?.recent.filter((x) => x.photo) ?? [];
  const texts = view?.recent.filter((x) => !x.photo) ?? [];
  const timing = [
    { label: 'text', n: texts.length, decide: median(texts.map((x) => x.decide_ms ?? 0)), total: median(texts.map((x) => x.total_ms)) },
    {
      label: 'photo',
      n: photos.length,
      describe: median(photos.flatMap((x) => (x.describe_ms != null ? [x.describe_ms] : []))),
      decide: median(photos.map((x) => x.decide_ms ?? 0)),
      total: median(photos.map((x) => x.total_ms)),
    },
  ];

  return (
    <div>
      {embedded ? (
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', margin: '0 0 12px' }}>
          <span className="muted" style={{ fontSize: 12.5, flex: 1 }}>
            What the contact gate sends the decision model for each WeChat message, and how it answered. The turn log lives in the gate&apos;s memory — a restart clears it.
          </span>
          <button className="btn sm" onClick={() => void refresh()}>refresh</button>
        </div>
      ) : (
        <PageHead
          crumb="route"
          title="How messages are routed"
          desc="What the contact gate sends the decision model for each WeChat message, and how it answered. The turn log lives in the gate's memory — a restart clears it."
          actions={<button className="btn" onClick={() => void refresh()}>refresh</button>}
        />
      )}
      {notConfigured && (
        <div className="banner" style={{ marginBottom: 12 }}>
          <span className="lbl">not set up</span>
          <span>The WeChat contact gate isn&apos;t connected to this console{error ? ` (${error})` : ''}.</span>
        </div>
      )}
      {error && !notConfigured && (
        <div className="banner warn" style={{ marginBottom: 12 }}>
          <span className="lbl">route</span>
          <span>{error}</span>
        </div>
      )}
      {view && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Panel title="decision model">
            <table className="tab">
              <tbody>
                <tr><td>engine</td><td className="mono">{view.engine}</td></tr>
                <tr><td>model asked for</td><td className="mono">{view.model}</td></tr>
                {upstreamRows(view.upstream).map((r, i) => (
                  <tr key={`u${i}`}><td>{r.label}</td><td className="mono">{r.value}</td></tr>
                ))}
                <tr><td>via</td><td className="mono">{view.gate_url ?? '—'} (the model gate — it holds the model&apos;s key and meters every decision)</td></tr>
                <tr><td>routes when</td><td>the pick is {pct(view.threshold)} or more, and above the runner-up; otherwise the member is asked (the ask waits {view.ask_ttl_secs} s)</td></tr>
                <tr><td>follow-up when</td><td>“continues” is {pct(view.continue_threshold)} or more, and the pick doesn&apos;t clearly point elsewhere</td></tr>
                <tr>
                  <td>photos</td>
                  <td>
                    {view.describe_photos
                      ? <>described first by <span className="mono">{view.describe_model ?? 'the stack’s chat model'}</span>, then routed by the description</>
                      : 'not described — routed by the apps’ declared kinds'}
                  </td>
                </tr>
                {view.describe_photos && (
                  <tr><td>describe prompt</td><td className="mono" style={{ whiteSpace: 'pre-wrap' }}>{view.describe_prompt}</td></tr>
                )}
              </tbody>
            </table>
          </Panel>

          <Panel title="what Kev is sent, per member">
            <div className="muted" style={{ marginBottom: 8 }}>
              Kev has no chat-style system prompt. Every question sees the shared <span className="mono">state</span> plus its own
              {' '}<span className="mono">instructions</span> and <span className="mono">criteria</span>, and the questions can&apos;t see each
              other. The options are the channels the member speaks on, each rendered from its channel document (what it is for, the apps
              bound to it with their binding descriptions, who else is in it; a shared channel is one row per app), so each member gets a
              different request; the follow-up question appears only once they have a previous channel. The message is a placeholder here.
            </div>
            {view.contacts.length === 0 && <div className="muted">No bound contacts yet.</div>}
            {view.contacts.map((c) => (
              <div key={c.contact} style={{ marginBottom: 16 }}>
                <div style={{ marginBottom: 4 }}>
                  <strong>{c.contact}</strong> <span className="muted">· {c.tier}</span>
                </div>
                <RequestView request={c.request} options={c.options} />
              </div>
            ))}
          </Panel>

          <Panel title={`recent decisions · ${view.recent.length}`}>
            <div className="muted" style={{ marginBottom: 8 }}>
              {timing
                .filter((t) => t.n > 0)
                .map((t) =>
                  `${t.label} (${t.n}): ${'describe' in t ? `describe ${fmtMs(t.describe)} · ` : ''}decide ${fmtMs(t.decide)} · whole turn ${fmtMs(t.total)}`,
                )
                .join('   ·   ') || 'No turn has consulted the model since the gate started.'}
              {view.recent.length > 0 && ' (medians)'}
            </div>
            {view.recent.length > 0 && (
              <table className="tab">
                <thead>
                  <tr>
                    <th>time</th>
                    <th>member</th>
                    <th>what the model read</th>
                    <th>answer</th>
                    <th>verdict</th>
                    <th>took</th>
                    <th>landed</th>
                  </tr>
                </thead>
                <tbody>
                  {view.recent.map((x, i) => (
                    <Fragment key={`${x.ts_ms}-${i}`}>
                      <tr onClick={() => setOpen(open === i ? null : i)} style={{ cursor: 'pointer' }}>
                        <td className="mono">{new Date(x.ts_ms).toLocaleTimeString()}</td>
                        <td>{x.contact} <span className="muted">· {x.tier}</span></td>
                        <td>{x.photo ? '📷 ' : ''}{x.text}</td>
                        <td><Answer x={x} /></td>
                        <td>{verdictChip(x)}</td>
                        <td className="mono">
                          {x.describe_ms != null && <>describe {fmtMs(x.describe_ms)}<br /></>}
                          decide {fmtMs(x.decide_ms)}<br />
                          turn {fmtMs(x.total_ms)}
                        </td>
                        <td>{x.delivered ? '✓' : '—'}</td>
                      </tr>
                      {open === i && (
                        <tr>
                          <td colSpan={7}>
                            <div className="muted" style={{ marginBottom: 4 }}>
                              answered by <span className="mono">{x.answered_by || '—'}</span>
                              {x.error ? ` · ${x.error}` : ''} · the request, exactly as sent:
                            </div>
                            <pre className="mono" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{JSON.stringify(x.request, null, 2)}</pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
