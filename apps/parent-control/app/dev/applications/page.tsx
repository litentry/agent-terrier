'use client';

// Family APPLICATIONS — design preview inside the console (docs/plan/family-applications.md
// §3.10). Deliberately OUTSIDE the app shell like /dev/local-sandbox: no daemon, no session —
// every number here comes from the design-system fixtures, so the expected feature can be
// reviewed before the framework exists. The real page (plan step 16) swaps the fixtures for
// the app-registry / resource-registry docs and reuses the #617 sheet components.

import { useMemo, useState } from 'react';
import {
  APP_ACTIVITY, BIND_OPTIONS, CHEF_ASK, CHEF_CARD, INSTALLED_SEED, RESOURCE_ITEMS, SLOTS_TOTAL, TEMPLATES, TIERS,
  bi, compiledGrants, newWizard, resourceById, templateById,
} from '@agentkeys/design-system/app-data';
import type { AppEvent, AppTemplate, InstalledApp, Tier, WizardState, WizardStep } from '@agentkeys/design-system/app-data';
import { Chip, Dot, Modal, PageHead, Panel } from '@/app/_components/shared';

type View = 'apps' | 'resources' | 'display';
const L = 'en' as const;
const tierName: Record<Tier, string> = { owner: 'Owner', partner: 'Partner', elder: 'Elder', helper: 'Helper', kid: 'Kid' };
const statusOf = (s: InstalledApp['status']) => (s === 'active' ? { dot: 'ok' as const, text: 'active' } : s === 'waiting' ? { dot: 'warn' as const, text: 'waiting for a device' } : { dot: 'muted' as const, text: 'paused' });

/** The card contract's actions (mock) — a renderer publishes them back as `command` events. */
const CARD_ACTIONS = [
  { id: 'dinner.cooked', label: 'Cooked ✓' },
  { id: 'dinner.swap', label: 'Swap dinner' },
  { id: 'fridge.request-photo', label: 'Ask for a fridge photo' },
];

function KitchenCard({ onAction, big }: { onAction: (id: string, label: string) => void; big?: boolean }) {
  const fs = big ? 1.5 : 1;
  return (
    <div style={{ background: '#15130f', color: '#f3eee3', borderRadius: 14, padding: big ? 28 : 16, fontFamily: 'var(--mono, ui-monospace, monospace)', width: big ? 480 : undefined, minHeight: big ? 480 : undefined, display: 'flex', flexDirection: 'column' }}>
      <div style={{ fontSize: 13 * fs, fontWeight: 700 }}>{bi(L, CHEF_CARD.title)}</div>
      {CHEF_CARD.lines.map((l) => <div key={l.en} style={{ fontSize: 12 * fs, opacity: 0.85, marginTop: 8 * fs }}>{bi(L, l)}</div>)}
      <div style={{ fontSize: 13 * fs, fontWeight: 700, color: '#a7f3d0', marginTop: 14 * fs }}>{bi(L, CHEF_CARD.dinner)}</div>
      <div style={{ fontSize: 11.5 * fs, opacity: 0.75, marginTop: 5 * fs }}>{bi(L, CHEF_CARD.dinnerSub)}</div>
      <div style={{ fontSize: 11.5 * fs, color: '#fca5a5', marginTop: 10 * fs }}>{bi(L, CHEF_CARD.low)}</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 'auto', paddingTop: 16 * fs }}>
        {CARD_ACTIONS.map((a) => (
          <button key={a.id} onClick={() => onAction(a.id, a.label)} style={{ cursor: 'pointer', fontFamily: 'inherit', fontSize: 11.5 * fs, fontWeight: 600, background: '#2a2823', color: '#f3eee3', border: '1px solid #4a463d', borderRadius: 8, padding: `${7 * fs}px ${11 * fs}px` }}>{a.label}</button>
        ))}
      </div>
    </div>
  );
}

export default function ApplicationsPreviewPage() {
  const [view, setView] = useState<View>('apps');
  const [installed, setInstalled] = useState<InstalledApp[]>(() => INSTALLED_SEED.map((a) => ({ ...a })));
  const [selectedId, setSelectedId] = useState<string>('chef');
  const [askResolved, setAskResolved] = useState(false);
  const [extraEvents, setExtraEvents] = useState<Record<string, AppEvent[]>>({});
  const [commands, setCommands] = useState<{ ts: string; id: string; actor: string }[]>([]);
  const [wizard, setWizard] = useState<WizardState | null>(null);
  const [uninstalling, setUninstalling] = useState(false);

  const selected = installed.find((a) => a.id === selectedId) ?? installed[0];
  const catalog = TEMPLATES.filter((tp) => !installed.some((a) => a.id === tp.id));
  const now = () => new Date().toTimeString().slice(0, 5);

  const cardAction = (actor: string) => (id: string, label: string) => {
    setCommands((c) => [{ ts: now(), id, actor }, ...c]);
    if (!selected) return;
    setExtraEvents((m) => ({ ...m, [selected.id]: [{ time: now(), tag: 'you', text: { en: `You tapped “${label}” on the card → command:${id} published from ${actor}`, zh: '' } }, ...(m[selected.id] ?? [])] }));
  };
  const events = useMemo(() => (selected ? [...(extraEvents[selected.id] ?? []), ...(APP_ACTIVITY[selected.id] ?? [])] : []), [selected, extraEvents]);

  const install = (w: WizardState) => {
    const tp = templateById(w.templateId);
    const status: InstalledApp['status'] = tp.slots.some((s) => s.required && !w.bindings[s.slot]) ? 'waiting' : 'active';
    setInstalled((all) => [...all, { id: tp.id, label: w.label, status, slot: all.length + 1, bindings: { ...w.bindings }, resources: { ...w.resources }, audience: TIERS.filter((tier) => w.audience[tier]), installedAt: { en: 'Installed just now', zh: '' }, lastActivity: { en: status === 'active' ? 'Starting its first turn…' : 'Waiting for a device', zh: '' } }]);
    setWizard({ ...w, step: 'done' });
  };

  return (
    <main className="app-main" data-section="delegates" style={{ padding: '24px 28px', maxWidth: 1180, margin: '0 auto' }}>
      <div className="banner warn" style={{ marginBottom: 18 }}>
        <span className="lbl">design preview</span>
        <span>Mock data from <code>@agentkeys/design-system/app-data</code> — nothing here talks to the daemon. Plan: <code>docs/plan/family-applications.md</code> §3.10.</span>
      </div>
      <PageHead
        crumb="household · applications"
        title="Applications"
        desc="Compose devices, channels, a delegate, its memory, and read-only resources into one installable app. Install = one Touch ID minting exactly the sheet you see."
        actions={<>
          {(['apps', 'resources', 'display'] as View[]).map((v) => <button key={v} className={`btn ${view === v ? 'primary' : ''}`} onClick={() => setView(v)}>{v === 'apps' ? 'applications' : v === 'resources' ? 'resources' : 'kitchen display'}</button>)}
        </>}
      />

      {view === 'apps' && (<>
        <div className="stats">
          <div className="stat"><div className="v">{installed.length}</div><div className="k">apps installed</div></div>
          <div className="stat"><div className="v">{installed.length}/{SLOTS_TOTAL}</div><div className="k">agent slots used</div></div>
          <div className="stat"><div className="v">{askResolved ? 0 : 1}</div><div className="k">runtime asks today</div></div>
          <div className="stat"><div className="v">{RESOURCE_ITEMS.length}</div><div className="k">curated resources</div></div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr', gap: 16, marginTop: 16 }}>
          <Panel title="── installed" flush>
            <div className="device-grid" style={{ padding: 14 }}>
              {installed.map((a) => { const tp = templateById(a.id); const st = statusOf(a.status); return (
                <div key={a.id} className="device-card" style={{ padding: 14, cursor: 'pointer', outline: selected?.id === a.id ? '2px solid var(--ink)' : 'none' }} onClick={() => setSelectedId(a.id)}>
                  <div className="device-card-head" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ width: 34, height: 34, borderRadius: 9, background: tp.color, color: '#fff', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>{tp.letter}</span>
                    <div style={{ flex: 1 }}><div style={{ fontWeight: 600 }}>{bi(L, tp.name)} <span className="muted" style={{ fontSize: 11 }}>· {a.label}</span></div><div style={{ fontSize: 12 }}><Dot status={st.dot} /> {st.text} · slot {a.slot}/{SLOTS_TOTAL}</div></div>
                    <button className="btn sm" onClick={(e) => { e.stopPropagation(); setSelectedId(a.id); }}>manage →</button>
                  </div>
                  <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>{bi(L, a.lastActivity)} · {bi(L, a.installedAt)}</div>
                </div>
              ); })}
            </div>
          </Panel>
          <Panel title="── catalog" flush>
            {catalog.length === 0 && <div className="muted" style={{ padding: 16 }}>Everything in the catalog is installed.</div>}
            {catalog.map((tp) => (
              <div key={tp.id} className="feed-row" style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '12px 16px' }}>
                <span style={{ width: 34, height: 34, borderRadius: 9, background: tp.color, color: '#fff', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, flex: 'none' }}>{tp.letter}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600 }}>{bi(L, tp.name)} <span className="muted" style={{ fontSize: 11 }}>v{tp.version}</span></div>
                  <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>{bi(L, tp.tagline)}</div>
                  <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 7 }}>
                    {tp.slots.map((s) => <Chip key={s.slot}>{s.kind} · {s.direction}</Chip>)}
                    {tp.resources.map((r) => <Chip key={r.name} kind="ok">{r.kind}</Chip>)}
                    {tp.tools.map((tool) => <Chip key={tool} kind="warn">{tool}</Chip>)}
                  </div>
                </div>
                <button className="btn sm primary" onClick={() => setWizard(newWizard(tp.id))}>install →</button>
              </div>
            ))}
          </Panel>
        </div>

        {selected && <AppDetail app={selected} events={events} askResolved={askResolved} onAsk={() => setAskResolved(true)} onCardAction={cardAction('console device actor')} onStatus={(status) => setInstalled((all) => all.map((a) => (a.id === selected.id ? { ...a, status } : a)))} onUninstall={() => setUninstalling(true)} />}
      </>)}

      {view === 'resources' && (
        <Panel title="── resources the apps may read (read-only, revocable per app)" flush>
          {RESOURCE_ITEMS.map((it) => { const users = installed.filter((a) => Object.values(a.resources).includes(it.id)); return (
            <div key={it.id} className="feed-row" style={{ padding: '12px 16px', display: 'grid', gridTemplateColumns: '1.2fr 2fr 1fr', gap: 12, alignItems: 'start' }}>
              <div><div style={{ fontWeight: 600 }}>{bi(L, it.label)} {it.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>}</div><div className="muted" style={{ fontSize: 11 }}>{it.kind} · {it.version} · <code>{it.ns}</code></div></div>
              <div className="muted" style={{ fontSize: 12 }}>{bi(L, it.detail)}</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>{users.length === 0 ? <span className="muted" style={{ fontSize: 12 }}>not used by any app</span> : users.map((a) => <Chip key={a.id} kind="ok">{bi(L, templateById(a.id).name)} · read-only</Chip>)}</div>
            </div>
          ); })}
          <div style={{ padding: 14 }}><button className="btn">+ add a resource</button></div>
        </Panel>
      )}

      {view === 'display' && (
        <div style={{ display: 'grid', gridTemplateColumns: '480px 1fr', gap: 18 }}>
          <Panel title="── kitchen display · 480 × 480 · what the ESP32 renders" flush>
            <div style={{ padding: 14 }}><KitchenCard big onAction={cardAction('kitchen-display device actor')} /></div>
          </Panel>
          <div>
            <Panel title="── the card contract">
              <p className="muted" style={{ fontSize: 12.5, lineHeight: 1.5, margin: 0 }}>The app publishes one versioned <code>card</code> document (a <code>doc</code> event) to its display slot. Every renderer — this console, a shared kitchen tablet, the ESP32 — draws the same card and publishes its actions back as <code>command</code> events with its <em>own</em> device actor. Tapping here and tapping on the wall are the same event on the same feed, attributed to different actors.</p>
            </Panel>
            <Panel title="── commands published" flush>
              <div className="feed">
                {commands.length === 0 && <div className="muted" style={{ padding: 14 }}>Tap an action on the card.</div>}
                {commands.map((c, i) => <div key={i} className="feed-row"><span className="ts">{c.ts}</span> <code>command:{c.id}</code> <span className="muted">· from {c.actor}</span></div>)}
              </div>
            </Panel>
          </div>
        </div>
      )}

      {wizard && <InstallWizard w={wizard} setW={setWizard} onInstall={install} onOpen={(id) => { setWizard(null); setSelectedId(id); setView('apps'); }} installedCount={installed.length} />}
      {uninstalling && selected && (
        <Modal title={`Uninstall ${bi(L, templateById(selected.id).name)} and revoke every permission?`} onClose={() => setUninstalling(false)}
          footer={<>
            <button className="btn" onClick={() => setUninstalling(false)}>cancel</button>
            <button className="btn" onClick={() => { setInstalled((all) => all.filter((a) => a.id !== selected.id)); setUninstalling(false); setSelectedId(installed.find((a) => a.id !== selected.id)?.id ?? ''); }}>keep its memory (reinstall later)</button>
            <button className="btn danger" onClick={() => { setInstalled((all) => all.filter((a) => a.id !== selected.id)); setUninstalling(false); setSelectedId(installed.find((a) => a.id !== selected.id)?.id ?? ''); }}>delete its memory too</button>
          </>}>
          <p className="muted" style={{ fontSize: 13 }}>The archive ceremony frees slot {selected.slot}, revokes the grants on chain, and tears the sandbox down. Keeping the memory namespace lets a reinstall inherit it (#425 O2).</p>
        </Modal>
      )}
    </main>
  );
}

function AppDetail({ app, events, askResolved, onAsk, onCardAction, onStatus, onUninstall }: { app: InstalledApp; events: AppEvent[]; askResolved: boolean; onAsk: () => void; onCardAction: (id: string, label: string) => void; onStatus: (s: InstalledApp['status']) => void; onUninstall: () => void }) {
  const tp = templateById(app.id);
  const g = compiledGrants({ ...newWizard(app.id, app), label: app.label });
  const hasDisplay = tp.slots.some((s) => s.kind === 'display' && app.bindings[s.slot]);
  const chip = (tag: AppEvent['tag']) => (tag === 'allowed' ? <Chip kind="ok">allowed</Chip> : tag === 'blocked' ? <Chip kind="bad">blocked</Chip> : <Chip>you</Chip>);
  return (
    <div style={{ marginTop: 18 }}>
      <PageHead crumb={`applications · ${app.label}`} title={<>{bi(L, tp.name)} <span className="muted" style={{ fontSize: 14 }}>· delegate <code>{app.label}</code> · slot {app.slot}/{SLOTS_TOTAL}</span></>} desc={bi(L, tp.tagline)}
        actions={<>
          <button className="btn" onClick={() => onStatus(app.status === 'paused' ? 'active' : 'paused')}>{app.status === 'paused' ? 'resume' : 'pause'}</button>
          <button className="btn">update</button>
          <button className="btn danger" onClick={onUninstall}>uninstall</button>
        </>} />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {app.id === 'chef' && !askResolved && (
            <Panel title="── runtime ask (the #617 push)">
              <div style={{ fontWeight: 600 }}>{bi(L, CHEF_ASK.title)}: {bi(L, CHEF_ASK.body)}</div>
              <div className="muted" style={{ fontSize: 12, margin: '4px 0 10px' }}><code>{CHEF_ASK.scope}</code> · “always allow” routes to the grant ceremony, never a local rule</div>
              <div style={{ display: 'flex', gap: 8 }}><button className="btn primary" onClick={onAsk}>allow once</button><button className="btn" onClick={onAsk}>deny</button></div>
            </Panel>
          )}
          {hasDisplay && <Panel title="── on the kitchen display · interactive"><KitchenCard onAction={onCardAction} /><div className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>Rendered from the same card the app publishes; your taps publish <code>command</code> events from the console's own device actor.</div></Panel>}
          <Panel title="── today" flush>
            <div className="feed">{events.map((e, i) => <div key={i} className="feed-row" style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}><span className="ts">{e.time}</span><span style={{ flex: 1 }}>{bi(L, e.text)}</span>{chip(e.tag)}</div>)}</div>
          </Panel>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Panel title="── permissions · the sheet the install minted" flush>
            <div style={{ padding: 14 }}>
              <div className="perm-section-head"><span className="ttl">Data &amp; devices</span><span className="summary">{g.data.length} grants</span></div>
              <div className="perm-rows">{g.data.map((d) => <div key={d.svc} className="perm-row" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px' }}><code style={{ flex: 1 }}>{d.svc}</code><span className="muted" style={{ fontSize: 11 }}>{d.sub}</span>{d.sensitive && <Chip kind="bad">SENSITIVE</Chip>}<span className="perm-switch on" aria-label="granted" /></div>)}</div>
              <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">Capabilities</span><span className="summary">{g.tools.length}</span></div>
              <div className="perm-rows">{g.tools.map((tool) => <div key={tool} className="perm-row" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px' }}><code style={{ flex: 1 }}>{tool}</code><span className="perm-switch on" aria-label="granted" /></div>)}</div>
              <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">Built with</span></div>
              <div className="perm-rows">{g.builtWith.map((p) => <div key={p} className="perm-row" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px' }}><code style={{ flex: 1 }}>{p}</code><span className="muted" style={{ fontSize: 11 }}>read-only disclosure</span></div>)}</div>
              <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">What leaves your home</span></div>
              <ul className="muted" style={{ fontSize: 12, margin: 0, paddingLeft: 18 }}>{g.disclosure.map((d) => <li key={d.en}>{bi(L, d)}</li>)}</ul>
            </div>
          </Panel>
          <Panel title="── reads (read-only)">
            <dl className="kvs">{tp.resources.map((r) => { const it = app.resources[r.name] ? resourceById(app.resources[r.name]!) : undefined; return (<div key={r.name} style={{ display: 'contents' }}><dt>{r.name}</dt><dd>{it ? <>{bi(L, it.label)} · <code>{it.ns}</code> {it.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>}</> : <span className="muted">skipped</span>}</dd></div>); })}</dl>
          </Panel>
          <Panel title="── schedule"><dl className="kvs">{tp.schedule.map((s) => <div key={s.cron} style={{ display: 'contents' }}><dt>{s.at}</dt><dd>{bi(L, s.label)} · <code>{s.cron}</code> · <Chip>tool:schedule</Chip></dd></div>)}{tp.schedule.length === 0 && <div className="muted">none</div>}</dl></Panel>
          {tp.slots.some((s) => s.kind === 'messaging') && <Panel title="── who can talk to it"><div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>{TIERS.map((tier) => <Chip key={tier} kind={app.audience.includes(tier) ? 'ok' : 'default'}>{tierName[tier]}{app.audience.includes(tier) ? '' : ' · off'}</Chip>)}</div><div className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>Defaults from the template; a small model may propose this set later (small-model-requirements.md S1) — you confirm, never the model.</div></Panel>}
        </div>
      </div>
    </div>
  );
}

function InstallWizard({ w, setW, onInstall, onOpen, installedCount }: { w: WizardState; setW: (w: WizardState | null) => void; onInstall: (w: WizardState) => void; onOpen: (id: string) => void; installedCount: number }) {
  const tp: AppTemplate = templateById(w.templateId);
  const steps: WizardStep[] = ['slots'];
  if (tp.resources.length > 0) steps.push('resources');
  if (tp.slots.some((s) => s.kind === 'messaging' && s.direction !== 'pub')) steps.push('audience');
  steps.push('sheet');
  const idx = Math.max(0, steps.indexOf(w.step));
  const go = (d: 1 | -1) => setW({ ...w, step: steps[Math.min(steps.length - 1, Math.max(0, idx + d))] });
  const canNext = w.step === 'slots' ? !tp.slots.some((s) => s.required && s.kind === 'messaging' && !w.bindings[s.slot]) : w.step === 'resources' ? !tp.resources.some((r) => r.required && !w.resources[r.name]) : true;
  const g = compiledGrants(w);
  const opt = (selected: boolean, onClick: () => void, body: React.ReactNode) => <div className="perm-row" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', cursor: 'pointer' }} onClick={onClick}><span style={{ flex: 1 }}>{body}</span><span className={`perm-switch ${selected ? 'on' : ''}`} /></div>;
  return (
    <Modal title={w.step === 'done' ? 'Installed' : `Install ${bi(L, tp.name)} · step ${idx + 1} of ${steps.length} · ${w.step}`} onClose={() => setW(null)}
      footer={w.step === 'done'
        ? <button className="btn primary" onClick={() => onOpen(tp.id)}>open the app</button>
        : <>{idx > 0 && <button className="btn" onClick={() => go(-1)}>back</button>}{w.step !== 'sheet' ? <button className="btn primary" disabled={!canNext} onClick={() => go(1)}>next</button> : <button className="btn primary" onClick={() => onInstall(w)}>install with Touch ID</button>}</>}>
      {w.step === 'done' && <p>The delegate <code>{w.label}</code> is running in its own sandbox with exactly the sheet you approved · slot {installedCount} of {SLOTS_TOTAL}.</p>}
      {w.step === 'slots' && (<>
        <p className="muted" style={{ fontSize: 12.5 }}>Pick which channel or device fills each slot the app needs. Nothing is granted yet.</p>
        {tp.slots.map((s) => { const opts = BIND_OPTIONS[s.kind]; return (
          <div key={s.slot} style={{ marginBottom: 14 }}>
            <div className="perm-section-head"><span className="ttl">{bi(L, s.label)} · {s.kind} · {s.direction}</span><span className="summary">{s.required ? 'required' : 'optional'}</span></div>
            <div className="perm-rows">
              {opts.map((o) => <div key={o.id}>{opt(w.bindings[s.slot] === o.id, () => setW({ ...w, bindings: { ...w.bindings, [s.slot]: o.id } }), <>{bi(L, o.label)} <span className="muted" style={{ fontSize: 11 }}>· {bi(L, o.sub)} · <code>{o.id}</code></span></>)}</div>)}
              {opts.length === 0 && <div className="perm-row muted" style={{ padding: '8px 12px' }}>No paired device of this kind yet — pair one on the Devices page.</div>}
              {(!s.required || opts.length === 0) && <div>{opt(w.bindings[s.slot] === null, () => setW({ ...w, bindings: { ...w.bindings, [s.slot]: null } }), <span className="muted">skip for now</span>)}</div>}
            </div>
            <div className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>{bi(L, s.why)}</div>
          </div>
        ); })}
      </>)}
      {w.step === 'resources' && (<>
        <p className="muted" style={{ fontSize: 12.5 }}>Choose which curated resources the app may read. Read-only — an app can never change a resource.</p>
        {tp.resources.map((r) => { const opts = RESOURCE_ITEMS.filter((it) => it.kind === r.kind); return (
          <div key={r.name} style={{ marginBottom: 14 }}>
            <div className="perm-section-head"><span className="ttl">{bi(L, r.label)} · {r.kind}</span><span className="summary">{r.required ? 'required' : 'optional'}</span></div>
            <div className="perm-rows">
              {opts.map((it) => <div key={it.id}>{opt(w.resources[r.name] === it.id, () => setW({ ...w, resources: { ...w.resources, [r.name]: it.id } }), <>{bi(L, it.label)} {it.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>} <span className="muted" style={{ fontSize: 11 }}>· {bi(L, it.detail)}</span></>)}</div>)}
              {!r.required && <div>{opt(w.resources[r.name] === null, () => setW({ ...w, resources: { ...w.resources, [r.name]: null } }), <span className="muted">skip for now</span>)}</div>}
            </div>
            <div className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>{bi(L, r.why)}</div>
          </div>
        ); })}
      </>)}
      {w.step === 'audience' && (<>
        <p className="muted" style={{ fontSize: 12.5 }}>Who in the household may message this app through the family chat. Defaults from the template; a small model may propose this later — you confirm.</p>
        <div className="perm-rows">{TIERS.map((tier) => <div key={tier}>{opt(w.audience[tier], () => setW({ ...w, audience: { ...w.audience, [tier]: !w.audience[tier] } }), tierName[tier])}</div>)}</div>
      </>)}
      {w.step === 'sheet' && (<>
        <p className="muted" style={{ fontSize: 12.5 }}>This is everything the app will be able to do. One Touch ID grants it all; revoke any line later.</p>
        <div className="perm-section-head"><span className="ttl">Data &amp; devices</span><span className="summary">{g.data.length}</span></div>
        <div className="perm-rows">{g.data.map((d) => <div key={d.svc} className="perm-row" style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '8px 12px' }}><code style={{ flex: 1 }}>{d.svc}</code><span className="muted" style={{ fontSize: 11 }}>{d.sub}</span>{d.sensitive && <Chip kind="bad">SENSITIVE</Chip>}</div>)}</div>
        <div className="perm-section-head" style={{ marginTop: 12 }}><span className="ttl">Capabilities</span></div>
        <div className="perm-rows">{g.tools.map((tool) => <div key={tool} className="perm-row" style={{ padding: '8px 12px' }}><code>{tool}</code></div>)}</div>
        <div className="perm-section-head" style={{ marginTop: 12 }}><span className="ttl">Built with</span></div>
        <div className="perm-rows">{g.builtWith.map((p) => <div key={p} className="perm-row" style={{ padding: '8px 12px' }}><code>{p}</code> <span className="muted" style={{ fontSize: 11 }}>read-only disclosure</span></div>)}</div>
        <div className="perm-section-head" style={{ marginTop: 12 }}><span className="ttl">What leaves your home</span></div>
        <ul className="muted" style={{ fontSize: 12, margin: 0, paddingLeft: 18 }}>{g.disclosure.map((d) => <li key={d.en}>{bi(L, d)}</li>)}</ul>
      </>)}
    </Modal>
  );
}
