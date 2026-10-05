'use client';

// #722 / household channels — the Route page: how a WeChat message is routed.
// The decision model (Kev or Jev — the same API) has no chat-style system
// prompt: every question carries its own guidance, every question sees the
// shared `state` (the message + the sender), and the questions cannot see each
// other. The options are the member's own CHANNELS, each rendered from its
// channel document (a shared channel is one row per app bound to it). This page
// shows exactly what is sent and how the model answered; the household picks
// the model that routes here, and compare mode asks the other one too.
import { Fragment, useCallback, useEffect, useState } from 'react';
import { gatewayClient, gatewayNotConfigured } from '@/lib/gatewayClient';
import type { DecisionProvider } from '@/lib/generated/DecisionProvider';
import type { DecisionServerReport } from '@/lib/generated/DecisionServerReport';
import type { GatewayRouterSettingsRequest } from '@/lib/generated/GatewayRouterSettingsRequest';
import type { GatewayRouterView } from '@/lib/generated/GatewayRouterView';
import type { RouterContactView } from '@/lib/generated/RouterContactView';
import type { RouterExchange } from '@/lib/generated/RouterExchange';
import { Chip, PageHead, Panel } from './shared';

const REFRESH_MS = 15_000;

const fmtMs = (ms?: number) => (ms == null ? '—' : ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms} ms`);
const pct = (p: number) => `${Math.round(p * 100)}%`;

const PROVIDER_LABEL: Record<DecisionProvider, string> = { kev: 'Kev', jev: 'Jev' };

function median(xs: number[]): number | undefined {
  if (xs.length === 0) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

function quantile(xs: number[], q: number): number | undefined {
  if (xs.length === 0) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.round((s.length - 1) * q))];
}

type Json = Record<string, unknown>;
const asObj = (v: unknown): Json => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {});
const asText = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : JSON.stringify(v, null, 2));

/** What a server says it serves: Kev lists its revision and temperature
 *  (`data`), TypeSafe its model names (`models`). */
function modelFacts(models: unknown): string {
  const o = asObj(models);
  const list: unknown[] = Array.isArray(o.data) ? o.data : Array.isArray(o.models) ? o.models : [];
  const quiet = new Set(['id', 'name', 'object', 'description', 'created', 'owned_by', 'release_date']);
  return list
    .map((m) => {
      const e = asObj(m);
      const extra = Object.entries(e)
        .filter(([k, v]) => !quiet.has(k) && v !== null && typeof v !== 'object')
        .map(([k, v]) => `${k} ${String(v)}`);
      return [String(e.id ?? e.name ?? ''), ...extra].filter(Boolean).join(' ');
    })
    .filter(Boolean)
    .join(', ');
}

/** One provider's server, as the model gate reports it. */
function serverLine(s: DecisionServerReport): { kind: 'ok' | 'warn' | 'bad'; text: string } {
  if (!s.configured) return { kind: 'bad', text: s.error ?? 'the model gate holds no key for it' };
  if (s.error) return { kind: 'warn', text: `${s.base_url ?? 'its server'} not reachable — ${s.error}` };
  if (s.status != null && s.status >= 300) return { kind: 'warn', text: `${s.base_url ?? 'its server'} answered HTTP ${s.status}` };
  return { kind: 'ok', text: [s.base_url, modelFacts(s.models)].filter(Boolean).join(' · ') };
}

/** One member's System One request, laid out the way the model reads it: the
 *  shared `state`, then each question with its type, `instructions` and `criteria`. */
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
                            {text == null ? <span className="muted">(no description — the model sees the name alone)</span> : asText(text)}
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

/** One model's answer to a turn — the one that routed, or one asked to compare. */
type Side = {
  model: string;
  verdict: string;
  routed_to?: string;
  addressee?: string;
  confidence?: number;
  decide_ms?: number;
  input_tokens?: number;
  error?: string;
};

/** The model a turn was sent to (the request names it; Kev answers as that name). */
function sentModel(x: RouterExchange): string {
  const m = asObj(x.request).model;
  return typeof m === 'string' && m ? m : x.answered_by || '—';
}

function actingSide(x: RouterExchange): Side {
  return {
    model: sentModel(x),
    verdict: x.verdict,
    routed_to: x.routed_to,
    addressee: x.addressee,
    confidence: x.confidence,
    decide_ms: x.decide_ms,
    input_tokens: x.input_tokens,
    error: x.error,
  };
}

const routes = (s: Side) => s.verdict === 'route' || s.verdict === 'follow_up';

/** Same outcome: both route to the same channel (and the same app when both
 *  name one), or both ask, or both gave no usable answer. */
function sameOutcome(a: Side, b: Side): boolean {
  if (routes(a) && routes(b)) return a.routed_to === b.routed_to && (!a.addressee || !b.addressee || a.addressee === b.addressee);
  if (a.verdict === 'ask' || b.verdict === 'ask') return a.verdict === b.verdict;
  return !routes(a) && !routes(b);
}

function SideCell({ s, acted }: { s: Side; acted: boolean }) {
  const head = routes(s)
    ? <Chip kind="ok">{s.verdict === 'follow_up' ? 'follow-up' : 'route'} → {s.routed_to}{s.addressee ? ` · ${s.addressee}` : ''}</Chip>
    : s.verdict === 'ask'
      ? <Chip kind="warn">{acted ? 'asked the member' : 'would ask'}</Chip>
      : <Chip kind="bad">{s.verdict}</Chip>;
  return (
    <div>
      <div className="mono muted" style={{ fontSize: 11 }}>{s.model}</div>
      {head}
      <div className="muted" style={{ fontSize: 11 }}>
        {s.confidence != null ? `${pct(s.confidence)} · ` : ''}{fmtMs(s.decide_ms)}{s.error ? ` · ${s.error}` : ''}
      </div>
    </div>
  );
}

/** Compare mode, over the turns the gate still holds: per model the same
 *  numbers, how often they agreed, and each turn side by side. */
function ComparePanel({ view }: { view: GatewayRouterView }) {
  const turns = view.recent.filter((x) => x.compared.length > 0);
  if (!view.compare && turns.length === 0) return null;
  const byModel = new Map<string, Side[]>();
  let agreed = 0;
  for (const x of turns) {
    const acting = actingSide(x);
    const others: Side[] = x.compared.map((c) => ({ ...c }));
    if (others.every((o) => sameOutcome(acting, o))) agreed += 1;
    for (const s of [acting, ...others]) byModel.set(s.model, [...(byModel.get(s.model) ?? []), s]);
  }
  const rows = [...byModel.entries()].map(([model, sides]) => {
    const n = sides.length;
    const routed = sides.filter(routes);
    const times = sides.flatMap((s) => (s.decide_ms != null ? [s.decide_ms] : []));
    const tokens = sides.flatMap((s) => (s.input_tokens != null ? [s.input_tokens] : []));
    const conf = routed.flatMap((s) => (s.confidence != null ? [s.confidence] : []));
    return {
      model,
      n,
      routed: routed.length,
      asked: sides.filter((s) => s.verdict === 'ask').length,
      failed: sides.filter((s) => !routes(s) && s.verdict !== 'ask').length,
      p50: median(times),
      p90: quantile(times, 0.9),
      tokens: tokens.length ? Math.round(tokens.reduce((a, b) => a + b, 0) / tokens.length) : undefined,
      conf: conf.length ? conf.reduce((a, b) => a + b, 0) / conf.length : undefined,
    };
  });
  return (
    <Panel title={`compare · ${turns.length} turn${turns.length === 1 ? '' : 's'}`}>
      <div className="muted" style={{ marginBottom: 8 }}>
        Every turn the router decides is also sent to the other model; only the chosen model&apos;s answer routes. Answers arrive a moment
        after the turn. Counted over the turns the gate still holds in memory — a restart clears them.
      </div>
      {turns.length === 0 ? (
        <div className="muted">No turn compared yet — the next WeChat message the router decides will be.</div>
      ) : (
        <>
          <div className="stats">
            <div className="stat">
              <div className="v">{pct(agreed / turns.length)}</div>
              <div className="k">same outcome</div>
              <div className="delta">{agreed} of {turns.length} turns</div>
            </div>
            {rows.map((r) => (
              <div className="stat" key={r.model}>
                <div className="v">{fmtMs(r.p50)}</div>
                <div className="k">{r.model} · median</div>
                <div className="delta">p90 {fmtMs(r.p90)}</div>
              </div>
            ))}
          </div>
          <div style={{ overflowX: 'auto', marginBottom: 14 }}>
            <table className="tab">
              <thead>
                <tr>
                  <th>model</th>
                  <th className="right">answers</th>
                  <th className="right">routes</th>
                  <th className="right">asks</th>
                  <th className="right">no answer</th>
                  <th className="right">mean pick</th>
                  <th className="right">decide p50 / p90</th>
                  <th className="right">tokens in</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.model}>
                    <td className="mono">{r.model}</td>
                    <td className="right mono">{r.n}</td>
                    <td className="right mono">{r.routed} ({pct(r.routed / r.n)})</td>
                    <td className="right mono">{r.asked}</td>
                    <td className="right mono">{r.failed}</td>
                    <td className="right mono">{r.conf != null ? pct(r.conf) : '—'}</td>
                    <td className="right mono">{fmtMs(r.p50)} / {fmtMs(r.p90)}</td>
                    <td className="right mono">{r.tokens ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="tab">
              <thead>
                <tr>
                  <th>time</th>
                  <th>member</th>
                  <th>what the models read</th>
                  <th>routed by</th>
                  <th>compared with</th>
                  <th>same</th>
                </tr>
              </thead>
              <tbody>
                {turns.map((x, i) => {
                  const acting = actingSide(x);
                  return (
                    <tr key={`${x.id}-${i}`}>
                      <td className="mono">{new Date(x.ts_ms).toLocaleTimeString()}</td>
                      <td>{x.contact}</td>
                      <td>{x.photo ? '📷 ' : ''}{x.text}</td>
                      <td><SideCell s={acting} acted /></td>
                      <td>{x.compared.map((c, j) => <SideCell key={j} s={{ ...c }} acted={false} />)}</td>
                      <td>{x.compared.every((c) => sameOutcome(acting, { ...c })) ? '✓' : '✗'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Panel>
  );
}

/** The model switch: the offered models, each with its server as the model
 *  gate reports it, and compare mode. */
function ModelSwitch({
  view,
  busy,
  onSave,
}: {
  view: GatewayRouterView;
  busy: boolean;
  onSave: (req: GatewayRouterSettingsRequest) => void;
}) {
  const others = view.models.filter((m) => !m.active).map((m) => `${PROVIDER_LABEL[m.provider]} (${m.model})`);
  // Compare needs another model the model gate can reach; it can always be turned off.
  const canCompare = view.models.some((m) => !m.active && m.server.configured);
  return (
    <div style={{ marginBottom: 14 }}>
      <div role="radiogroup" aria-label="decision model" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
        {view.models.map((m) => {
          const line = serverLine(m.server);
          return (
            <button
              key={m.model}
              type="button"
              role="radio"
              aria-checked={m.active}
              className={`btn${m.active ? ' primary' : ''}`}
              disabled={busy || (!m.active && !m.server.configured)}
              title={m.active ? 'routes now' : line.kind === 'bad' ? line.text : `route with ${m.model}`}
              onClick={() => {
                if (!m.active) onSave({ model: m.model });
              }}
              style={{ textAlign: 'left', minWidth: 200 }}
            >
              <div>
                <strong>{PROVIDER_LABEL[m.provider]}</strong> <span className="mono">{m.model}</span>
              </div>
              <div style={{ fontSize: 11, opacity: 0.8 }}>
                {m.active ? 'routes now' : m.server.configured ? 'switch to this' : 'not set up'}
                {m.stack_default ? ' · stack default' : ''}
              </div>
            </button>
          );
        })}
      </div>
      {view.models.length > 1 && (
        <label style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 12.5 }}>
          <input
            type="checkbox"
            checked={view.compare}
            disabled={busy || (!view.compare && !canCompare)}
            onChange={(e) => onSave({ compare: e.target.checked })}
          />
          <span>
            Compare — also ask {others.join(' and ')} on every message the router decides. Only the chosen model routes; each of
            those messages then goes to both models&apos; servers.
          </span>
        </label>
      )}
      <table className="tab" style={{ marginTop: 10 }}>
        <tbody>
          {view.models.map((m) => {
            const line = serverLine(m.server);
            return (
              <tr key={m.model}>
                <td>{PROVIDER_LABEL[m.provider]} <span className="mono">{m.model}</span></td>
                <td><Chip kind={line.kind}>{line.kind === 'ok' ? 'ready' : line.kind === 'warn' ? 'not answering' : 'not set up'}</Chip></td>
                <td className="mono" style={{ whiteSpace: 'pre-wrap' }}>{line.text}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** The router's page. `embedded` renders it as the contact gate page's
 *  route tab: a one-line lead and the refresh button instead of a page head. */
export function RoutePage({ embedded = false }: { embedded?: boolean } = {}) {
  const [view, setView] = useState<GatewayRouterView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

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

  const save = useCallback(
    async (req: GatewayRouterSettingsRequest) => {
      setBusy(true);
      setSaveError(null);
      const r = await gatewayClient.routerSettings(req);
      if (!r.ok) setSaveError(r.detail ?? r.reason);
      await refresh();
      setBusy(false);
    },
    [refresh],
  );

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
  const active = view?.models.find((m) => m.active);

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
            {view.notice && (
              <div className="banner warn" style={{ marginBottom: 12 }}>
                <span className="lbl">model</span>
                <span>{view.notice}</span>
              </div>
            )}
            {saveError && (
              <div className="banner warn" style={{ marginBottom: 12 }}>
                <span className="lbl">not saved</span>
                <span>{saveError}</span>
              </div>
            )}
            <ModelSwitch view={view} busy={busy} onSave={(req) => void save(req)} />
            <table className="tab">
              <tbody>
                <tr><td>engine</td><td className="mono">{view.engine}</td></tr>
                <tr>
                  <td>routes now</td>
                  <td>
                    <span className="mono">{view.model}</span>
                    {active ? ` (${PROVIDER_LABEL[active.provider]})` : ''} —{' '}
                    {view.chosen_at != null
                      ? `chosen in this console ${new Date(view.chosen_at * 1000).toLocaleString()}`
                      : 'the stack’s default'}
                    {view.model !== view.default_model && <span className="muted"> · stack default {view.default_model}</span>}
                  </td>
                </tr>
                <tr><td>via</td><td className="mono">{view.gate_url ?? '—'} (the model gate — it holds each model&apos;s key and meters every decision)</td></tr>
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

          <ComparePanel view={view} />

          <Panel title="what the decision model is sent, per member">
            <div className="muted" style={{ marginBottom: 8 }}>
              Kev and Jev have no chat-style system prompt. Every question sees the shared <span className="mono">state</span> plus its own
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
              <div style={{ overflowX: 'auto' }}>
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
                      <Fragment key={`${x.id}-${x.ts_ms}-${i}`}>
                        <tr onClick={() => setOpen(open === i ? null : i)} style={{ cursor: 'pointer' }}>
                          <td className="mono">{new Date(x.ts_ms).toLocaleTimeString()}</td>
                          <td>{x.contact} <span className="muted">· {x.tier}</span></td>
                          <td>{x.photo ? '📷 ' : ''}{x.text}</td>
                          <td><Answer x={x} /></td>
                          <td>
                            {verdictChip(x)}
                            <div className="mono muted" style={{ fontSize: 11 }}>{sentModel(x)}</div>
                          </td>
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
                                {x.input_tokens != null ? ` · ${x.input_tokens} tokens in` : ''}
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
              </div>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
