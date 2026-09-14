'use client';

// #682 — the APPLICATIONS page v1 (family applications, epic #660 stage 1):
// install / inspect / uninstall against the REAL registries. Every number on
// this page comes from the daemon — the catalog (broker, compiled-in
// templates), the app registry + resource registry (master-only Config-class
// docs), the chain (the install ceremony's build → ONE Touch ID → submit), and
// the app's display feed (the #670 card, rendered by the shared CardView; a
// tap publishes a `command` event from the console's own device actor).
//
// Framework, not Chef: nothing here names a meal. The wizard reads slots /
// resources / audience from the template manifest; the sheet renders the
// broker's compiled grant set + annotations verbatim.

import { useCallback, useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import { CardView } from '@agentkeys/design-system/react';
import type { CardViewAction } from '@agentkeys/design-system/react';
import { akLog } from '@/lib/debug';
import { getMasterCredId } from '@/lib/identityStore';
import { getAssertionOverHash } from '@/lib/webauthn';
import type { AgentKeysClient, ChannelDef } from '@/lib/client/types';
import type { AppDashboard } from '@/lib/generated/AppDashboard';
import type { AppInstallBindings } from '@/lib/generated/AppInstallBindings';
import type { AppInstallBuildResponse } from '@/lib/generated/AppInstallBuildResponse';
import type { AppInstanceRow } from '@/lib/generated/AppInstanceRow';
import type { ConsoleDeviceStatus } from '@/lib/generated/ConsoleDeviceStatus';
import type { ContactTier } from '@/lib/generated/ContactTier';
import type { GatewayDeviceStatus } from '@/lib/generated/GatewayDeviceStatus';
import type { PresetSummary } from '@/lib/generated/PresetSummary';
import type { ResourceItemRow } from '@/lib/generated/ResourceItemRow';
import type { ResourceKind } from '@/lib/generated/ResourceKind';
import type { ServiceAnnotation } from '@/lib/generated/ServiceAnnotation';
import { Chip, Dot, Modal, PageHead, Panel } from './shared';
import { KnowledgeItemModal } from './knowledge';
import { editReaches } from '@/lib/client/knowledge';
import { FEED_ID_RE, partitionSlotOptions, suggestedFeedId } from '@/lib/client/slotOptions';

type View = 'apps' | 'endpoints';

type CreateChannelFn = (input: { id: string; name: string; note?: string; kind?: ChannelDef['kind'] }) => Promise<ChannelDef | null>;
type WizardStep = 'slots' | 'resources' | 'audience' | 'sheet' | 'done';

const LABEL_RE = /^[a-z0-9-]{1,32}$/;
const TIERS: ContactTier[] = ['owner', 'partner', 'elder', 'kid', 'helper', 'guest'];
const TIER_NAME: Record<ContactTier, string> = { owner: 'Owner', partner: 'Partner', elder: 'Elder', kid: 'Kid', helper: 'Helper', guest: 'Guest' };
const INPUT: CSSProperties = { padding: '7px 9px', fontSize: 12.5, border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)', width: '100%' };

/** A template that composes at least one primitive is an APPLICATION; a
 *  zero-slot template is a role preset the Delegates page spawns. */
export const isApplication = (p: PresetSummary): boolean =>
  (p.slots?.length ?? 0) > 0 || (p.resources?.length ?? 0) > 0 || p.tools != null;

interface WizardState {
  templateId: string;
  label: string;
  step: WizardStep;
  bindings: Record<string, string | null>;
  resources: Record<string, string | null>;
  audience: Record<string, Record<ContactTier, boolean>>;
  built?: AppInstallBuildResponse;
  busy?: string | null;
  error?: string | null;
}

function newWizard(tp: PresetSummary): WizardState {
  const audience: WizardState['audience'] = {};
  for (const s of tp.slots ?? []) {
    if (s.kind === 'messaging') {
      const on = new Set(s.audience ?? []);
      audience[s.slot] = Object.fromEntries(TIERS.map((t) => [t, on.has(t)])) as Record<ContactTier, boolean>;
    }
  }
  return { templateId: tp.id, label: tp.id, step: 'slots', bindings: {}, resources: {}, audience, busy: null, error: null };
}

function toBindings(tp: PresetSummary, w: WizardState, resourceItems: ResourceItemRow[]): AppInstallBindings {
  const slots = (tp.slots ?? [])
    .filter((s) => w.bindings[s.slot])
    .map((s) => ({ slot: s.slot, channel_id: w.bindings[s.slot] as string }));
  const resources = (tp.resources ?? [])
    .filter((r) => w.resources[r.name])
    .map((r) => {
      const it = resourceItems.find((i) => i.id === w.resources[r.name]);
      return {
        name: r.name,
        item_id: w.resources[r.name] as string,
        ns: it?.ns ?? '',
        kind: it?.kind ?? r.kind,
        sensitivity: it?.sensitivity ?? 'safe',
      };
    });
  const audience = Object.entries(w.audience).map(([slot, tiers]) => ({
    slot,
    tiers: TIERS.filter((t) => tiers[t]),
  }));
  return { slots, resources, audience, tz_offset_minutes: -new Date().getTimezoneOffset() };
}

const statusOf = (a: AppInstanceRow): { dot: 'ok' | 'warn' | 'muted'; text: string } =>
  a.status === 'installed' ? { dot: 'ok', text: 'installed' } : a.status === 'uninstalled' ? { dot: 'muted', text: 'uninstalled' } : { dot: 'warn', text: String(a.status) };

const fmtTs = (s: number | null | undefined) => (s ? new Date(Number(s) * 1000).toLocaleString() : '—');

export function ApplicationsPage({
  client,
  channels,
  showToast,
  onGoChannels,
  onInstalled,
  onCreateChannel,
  initialView = 'apps',
}: {
  client: AgentKeysClient;
  channels: ChannelDef[];
  /** The view the page opens on. */
  initialView?: View;
  showToast: (msg: string, sticky?: boolean) => void;
  onGoChannels: () => void;
  /** Register a fresh feed of a slot's kind from inside the wizard (the shell refreshes `channels`). */
  onCreateChannel?: CreateChannelFn;
  /** Called after a CONFIRMED install/uninstall so the shell refreshes actors. */
  onInstalled: () => void;
}) {
  const [view, setView] = useState<View>(initialView);
  const [catalog, setCatalog] = useState<PresetSummary[] | null>(null);
  const [installed, setInstalled] = useState<AppInstanceRow[]>([]);
  const [storage, setStorage] = useState('ok');
  const [resources, setResources] = useState<ResourceItemRow[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [dashboard, setDashboard] = useState<AppDashboard | null>(null);
  const [dashError, setDashError] = useState<string | null>(null);
  const [wizard, setWizard] = useState<WizardState | null>(null);
  const [uninstalling, setUninstalling] = useState<AppInstanceRow | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // null = closed; `kind` pre-selects the kind (the wizard's empty slot), `slot` auto-binds the new
  // item to that slot on success, `edit` pre-fills an existing item (a re-add = the next version).
  const [addingResource, setAddingResource] = useState<null | { kind?: ResourceKind; slot?: string; edit?: ResourceItemRow }>(null);
  const [console_, setConsole] = useState<ConsoleDeviceStatus | null>(null);
  const [gateway, setGateway] = useState<GatewayDeviceStatus | null>(null);
  const [gatewayError, setGatewayError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const supported = !!client.listApps;

  const refresh = useCallback(async () => {
    if (!client.listApps || !client.listResources) {
      setLoadError('this backend has no applications surface (daemon only)');
      return;
    }
    const [cat, apps, res] = await Promise.all([client.presetCatalog(), client.listApps(), client.listResources()]);
    if (cat.ok) setCatalog(cat.data.presets.filter((p) => isApplication(p) && !p.hidden));
    else setLoadError(cat.status?.detail ?? 'catalog unavailable');
    if (apps.ok) {
      setInstalled(apps.data.apps);
      setStorage(apps.data.storage);
    } else setLoadError(apps.status?.detail ?? 'app registry unavailable');
    if (res.ok) setResources(res.data.items);
    if (client.consoleDeviceStatus) {
      const c = await client.consoleDeviceStatus();
      if (c.ok) setConsole(c.data);
    }
    if (client.gatewayDeviceStatus) {
      const g = await client.gatewayDeviceStatus();
      if (g.ok) {
        setGateway(g.data);
        setGatewayError(null);
      } else setGatewayError(g.status?.detail ?? 'contact gate unavailable');
    }
  }, [client]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // The wizard's empty slot opened the modal: a successful add binds the new item to that slot.
  const bindNewResourceToSlot = (id: string) => {
    const slot = addingResource?.slot;
    if (!slot) return;
    setWizard((w) => (w ? { ...w, resources: { ...w.resources, [slot]: id } } : w));
  };

  const openApp = useCallback(
    async (label: string) => {
      setSelected(label);
      setDashboard(null);
      setDashError(null);
      if (!client.appDashboard) return;
      const d = await client.appDashboard(label);
      if (d.ok) setDashboard(d.data);
      else setDashError(d.status?.detail ?? 'dashboard unavailable');
    },
    [client],
  );

  const live = installed.filter((a) => a.status !== 'uninstalled');
  const catalogFree = (catalog ?? []).filter((tp) => !live.some((a) => a.template_id === tp.id));

  // ── the card-action tap: a `command` event from the console's device actor
  const onCardAction = useCallback(
    async (label: string, channelId: string | null | undefined, updatedAt: number | undefined, a: CardViewAction) => {
      if (!client.appCommand) return;
      const r = await client.appCommand(label, { channel_id: channelId ?? undefined, action: a.id, command: a.command, args: a.args, card_updated_at: updatedAt ?? 0 });
      if (r.ok) {
        const who = (r.data as { attributed_to?: { actor?: string } })?.attributed_to?.actor ?? 'console';
        showToast(`“${a.label}” published as command:${a.command} (from ${who})`);
        void openApp(label);
      } else showToast(`command failed — ${r.status?.detail ?? 'publish error'}`, true);
    },
    [client, openApp, showToast],
  );

  // ── the install ceremony: build → ONE Touch ID → submit
  const install = useCallback(
    async (w: WizardState, tp: PresetSummary) => {
      if (!client.appInstallBuild || !client.appInstallSubmit) return;
      setWizard({ ...w, busy: 'Compiling the manifest + building the ceremony…', error: null });
      const built = await client.appInstallBuild({ template_id: tp.id, label: w.label, bindings: toBindings(tp, w, resources) });
      if (!built.ok) {
        setWizard({ ...w, busy: null, error: built.status?.detail ?? 'install build failed' });
        return;
      }
      const build = built.data.build as { user_op?: unknown; user_op_hash?: string; services?: string[]; slots_used?: number; slots_total?: number };
      akLog('apps: install built', { label: w.label, services: build.services, endpointScopes: built.data.endpoint_scopes });
      setWizard({ ...w, built: built.data, busy: `Slot ${(build.slots_used ?? 0) + 1} of ${build.slots_total ?? '?'} — approve with Touch ID…`, error: null });
      let assertion;
      try {
        const cred = getMasterCredId() || null;
        assertion = await getAssertionOverHash(String(build.user_op_hash ?? ''), cred ? [cred] : undefined);
      } catch {
        setWizard({ ...w, built: built.data, busy: null, error: 'Touch ID cancelled — nothing was installed (no slot consumed).' });
        return;
      }
      setWizard({ ...w, built: built.data, busy: 'Submitting on chain…', error: null });
      const submitted = await client.appInstallSubmit({ user_op: build.user_op, assertion });
      if (!submitted.ok) {
        setWizard({ ...w, built: built.data, busy: null, error: submitted.status?.detail ?? 'submit failed' });
        return;
      }
      akLog('apps: install confirmed', { txHash: submitted.data.tx_hash, installed: (submitted.data as { installed?: unknown }).installed });
      showToast(`${w.label} installed — its delegate is starting.`);
      setWizard({ ...w, built: built.data, busy: null, error: null, step: 'done' });
      onInstalled();
      await refresh();
    },
    [client, onInstalled, refresh, resources, showToast],
  );

  // ── the uninstall ceremony (archive): build → ONE Touch ID → submit
  const uninstall = useCallback(
    async (app: AppInstanceRow, keepMemory: boolean) => {
      if (!client.appUninstallBuild || !client.appUninstallSubmit) return;
      setBusy('Building the uninstall ceremony…');
      const built = await client.appUninstallBuild(app.label, { resources_kept: keepMemory });
      if (!built.ok) {
        setBusy(null);
        showToast(`Uninstall build failed — ${built.status?.detail ?? 'error'}`, true);
        return;
      }
      setBusy('Approve with Touch ID…');
      let assertion;
      try {
        const cred = getMasterCredId() || null;
        assertion = await getAssertionOverHash(String(built.data.user_op_hash), cred ? [cred] : undefined);
      } catch {
        setBusy(null);
        showToast('Touch ID cancelled — nothing changed.');
        return;
      }
      setBusy('Submitting on chain…');
      const submitted = await client.appUninstallSubmit(app.label, { user_op: built.data.user_op, assertion });
      setBusy(null);
      if (!submitted.ok) {
        showToast(`Uninstall submit failed — ${submitted.status?.detail ?? 'error'}`, true);
        return;
      }
      showToast(`${app.label} uninstalled — slot returned, grants revoked${keepMemory ? ', own namespace kept' : ''}.`);
      setUninstalling(null);
      setSelected(null);
      setDashboard(null);
      onInstalled();
      await refresh();
    },
    [client, onInstalled, refresh, showToast],
  );

  // ── a device-actor enrollment (console / contact gate): build → Touch ID → submit
  const enroll = useCallback(
    async (which: 'console' | 'gateway') => {
      const build = which === 'console' ? client.consoleEnrollBuild : client.gatewayEnrollBuild;
      const submit = which === 'console' ? client.consoleEnrollSubmit : client.gatewayEnrollSubmit;
      if (!build || !submit) return;
      setBusy(`Enrolling the ${which} as a device actor…`);
      const built = await build({});
      if (!built.ok) {
        setBusy(null);
        showToast(`${which} enrollment build failed — ${built.status?.detail ?? 'error'}`, true);
        return;
      }
      setBusy('Approve with Touch ID…');
      let assertion;
      try {
        const cred = getMasterCredId() || null;
        assertion = await getAssertionOverHash(String(built.data.user_op_hash), cred ? [cred] : undefined);
      } catch {
        setBusy(null);
        showToast('Touch ID cancelled — nothing enrolled.');
        return;
      }
      setBusy('Submitting on chain…');
      const submitted = await submit({ user_op: built.data.user_op, assertion });
      setBusy(null);
      if (!submitted.ok) {
        showToast(`${which} enrollment submit failed — ${submitted.status?.detail ?? 'error'}`, true);
        return;
      }
      showToast(`${which} enrolled as device actor ${String(submitted.data.actor_omni).slice(0, 12)}…`);
      await refresh();
    },
    [client, refresh, showToast],
  );

  const selectedRow = live.find((a) => a.label === selected) ?? installed.find((a) => a.label === selected);
  const selectedTemplate = selectedRow ? (catalog ?? []).find((tp) => tp.id === selectedRow.template_id) : undefined;

  return (
    <>
      <PageHead
        crumb="household · applications"
        title="Applications"
        desc="Compose channels, devices, a delegate, its own namespace and read-only knowledge into one installable app. Install = one Touch ID minting exactly the sheet you see."
        actions={
          <>
            {(['apps', 'endpoints'] as View[]).map((v) => (
              <button key={v} className={`btn ${view === v ? 'primary' : ''}`} onClick={() => setView(v)}>
                {v === 'apps' ? 'applications' : 'endpoints'}
              </button>
            ))}
            <button className="btn" onClick={() => void refresh()}>refresh</button>
          </>
        }
      />
      {!supported && (
        <div className="banner warn" style={{ marginBottom: 14 }}>
          <span className="lbl">no daemon</span>
          <span>The applications surface needs a running agentkeys-daemon (NEXT_PUBLIC_AGENTKEYS_BACKEND=daemon).</span>
        </div>
      )}
      {loadError && supported && (
        <div className="banner warn" style={{ marginBottom: 14 }}>
          <span className="lbl">load</span>
          <span>{loadError}</span>
        </div>
      )}
      {storage !== 'ok' && supported && (
        <div className="banner warn" style={{ marginBottom: 14 }}>
          <span className="lbl">{storage}</span>
          <span>The app registry is not durable on this daemon (no config worker) — installs are recorded in RAM only.</span>
        </div>
      )}
      {busy && (
        <div className="banner" style={{ marginBottom: 14 }}>
          <span className="lbl">working</span>
          <span>{busy}</span>
        </div>
      )}

      {view === 'apps' && (
        <>
          <div className="stats">
            <div className="stat"><div className="v">{live.length}</div><div className="k">apps installed</div></div>
            <div className="stat"><div className="v">{(catalog ?? []).length}</div><div className="k">templates in the catalog</div></div>
            <div className="stat"><div className="v">{resources.length}</div><div className="k">bindable knowledge items</div></div>
            <div className="stat"><div className="v">{console_?.enrolled ? '✓' : '—'}</div><div className="k">console device actor</div></div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr', gap: 16, marginTop: 16 }}>
            <Panel title="── installed" flush>
              {live.length === 0 && <div className="muted" style={{ padding: 16 }}>Nothing installed yet — pick a template from the catalog.</div>}
              <div className="device-grid" style={{ padding: live.length ? 14 : 0 }}>
                {live.map((a) => {
                  const st = statusOf(a);
                  const tp = (catalog ?? []).find((t) => t.id === a.template_id);
                  return (
                    <div key={a.label} className="device-card" style={{ padding: 14, cursor: 'pointer', outline: selected === a.label ? '2px solid var(--ink)' : 'none' }} onClick={() => void openApp(a.label)}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ width: 34, height: 34, borderRadius: 9, background: 'var(--ink)', color: 'var(--bg)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>{(tp?.name ?? a.template_id).slice(0, 1).toUpperCase()}</span>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontWeight: 600 }}>{tp?.name ?? a.template_id} <span className="muted" style={{ fontSize: 11 }}>· {a.label} · v{a.template_version}</span></div>
                          <div style={{ fontSize: 12 }}><Dot status={st.dot} /> {st.text} · {a.availability} · {a.bound_channels.length} bound feed(s)</div>
                        </div>
                        <button className="btn sm" onClick={(e) => { e.stopPropagation(); void openApp(a.label); }}>manage →</button>
                      </div>
                      <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>installed {fmtTs(a.installed_at)}</div>
                    </div>
                  );
                })}
              </div>
            </Panel>
            <Panel title="── catalog" flush>
              {catalog === null && <div className="muted" style={{ padding: 16 }}>Loading the catalog…</div>}
              {catalog !== null && catalogFree.length === 0 && <div className="muted" style={{ padding: 16 }}>Every application template is installed.</div>}
              {catalogFree.map((tp) => (
                <div key={tp.id} className="feed-row" style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '12px 16px' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600 }}>{tp.name} <span className="muted" style={{ fontSize: 11 }}>· {tp.name_zh} · v{tp.version}</span></div>
                    <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>{tp.description}</div>
                    <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 7 }}>
                      {(tp.slots ?? []).map((s) => <Chip key={s.slot}>{s.kind} · {s.direction}</Chip>)}
                      {(tp.resources ?? []).map((r) => <Chip key={r.name} kind="ok">{r.kind}</Chip>)}
                      {(tp.tools ?? []).map((t) => <Chip key={t} kind="warn">tool:{t.replace(/^tool:/, '')}</Chip>)}
                      <Chip>{tp.availability}</Chip>
                    </div>
                  </div>
                  <button className="btn sm primary" disabled={!client.appInstallBuild} onClick={() => setWizard(newWizard(tp))}>install →</button>
                </div>
              ))}
            </Panel>
          </div>
          {selectedRow && (
            <AppDetail
              app={selectedRow}
              template={selectedTemplate}
              dashboard={dashboard}
              error={dashError}
              onCardAction={(a) => void onCardAction(selectedRow.label, dashboard?.card_channel_id, dashboard?.card?.updated_at, a)}
              onUninstall={() => setUninstalling(selectedRow)}
              onRefresh={() => void openApp(selectedRow.label)}
              resources={resources}
              apps={live}
              onEditResource={(row) => setAddingResource({ edit: row })}
            />
          )}
        </>
      )}

      {view === 'endpoints' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <Panel title="── this console · device actor (#541)">
            <p className="muted" style={{ fontSize: 12.5, margin: '0 0 10px' }}>
              A card tap on this console publishes a <code>command</code> event from the console&apos;s OWN device actor — the same event a kitchen screen publishes. The first install that binds a display slot enrolls this console in the SAME Touch ID; this button is the standalone way.
            </p>
            <dl className="kvs">
              <div style={{ display: 'contents' }}><dt>enrolled</dt><dd>{console_?.enrolled ? <Chip kind="ok">yes</Chip> : <Chip>no</Chip>}</dd></div>
              <div style={{ display: 'contents' }}><dt>label</dt><dd>{console_?.label ?? console_?.suggested_label ?? '—'}</dd></div>
              <div style={{ display: 'contents' }}><dt>actor omni</dt><dd><code style={{ fontSize: 11 }}>{console_?.actor_omni ?? '—'}</code></dd></div>
            </dl>
            {!console_?.enrolled && <button className="btn primary" disabled={!client.consoleEnrollBuild || !!busy} onClick={() => void enroll('console')}>enroll this console · Touch ID</button>}
          </Panel>
          <Panel title="── contact gate · device actor (#667)">
            <p className="muted" style={{ fontSize: 12.5, margin: '0 0 10px' }}>
              The contact gate (the WeChat iLink bot / Telegram worker — not the model gate) relays family messages onto an app&apos;s feed as its own device actor; each install grants it the app&apos;s messaging feed. The first install that binds its transport enrolls it in the SAME Touch ID; this button is the standalone way.
            </p>
            {gatewayError && <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>gateway: {gatewayError}</div>}
            <dl className="kvs">
              <div style={{ display: 'contents' }}><dt>transport</dt><dd>{gateway?.transport || '—'}</dd></div>
              <div style={{ display: 'contents' }}><dt>enrolled</dt><dd>{gateway?.enrolled ? <Chip kind="ok">yes</Chip> : <Chip>{gateway?.configured ? 'no' : 'not configured'}</Chip>}</dd></div>
              <div style={{ display: 'contents' }}><dt>actor omni</dt><dd><code style={{ fontSize: 11 }}>{gateway?.actor_omni ?? '—'}</code></dd></div>
              <div style={{ display: 'contents' }}><dt>feed hop</dt><dd>{gateway?.feed_hop ? <Chip kind="ok">armed</Chip> : <span className="muted">{gateway?.blocker ?? '—'}</span>}</dd></div>
              <div style={{ display: 'contents' }}><dt>feeds</dt><dd>{(gateway?.feeds ?? []).length ? gateway?.feeds.map((f) => <Chip key={f}>{f}</Chip>) : <span className="muted">none</span>}</dd></div>
            </dl>
            {gateway && gateway.configured && !gateway.enrolled && <button className="btn primary" disabled={!client.gatewayEnrollBuild || !!busy} onClick={() => void enroll('gateway')}>enroll the gateway · Touch ID</button>}
          </Panel>
          <Panel title="── endpoint channels (what a slot can bind)" flush>
            {channels.length === 0 && <div className="muted" style={{ padding: 16 }}>No channels registered — <button className="btn sm" onClick={onGoChannels}>open channels</button></div>}
            {channels.map((c) => (
              <div key={c.id} className="feed-row" style={{ padding: '10px 16px', display: 'flex', gap: 10, alignItems: 'center' }}>
                <code style={{ flex: '0 0 160px' }}>{c.id}</code>
                <span style={{ flex: 1 }}>{c.name}</span>
                <Chip>{c.kind ?? 'unkinded'}</Chip>
                <span className="muted" style={{ fontSize: 11 }}>{c.endpointActorOmni ? `actor ${c.endpointActorOmni.slice(0, 12)}…` : 'no device actor'}</span>
              </div>
            ))}
          </Panel>
        </div>
      )}

      {wizard && (() => {
        const tp = (catalog ?? []).find((t) => t.id === wizard.templateId);
        if (!tp) return null;
        return (
          <InstallWizard
            w={wizard}
            tp={tp}
            channels={channels}
            resources={resources}
            setW={setWizard}
            onInstall={(w) => void install(w, tp)}
            onOpen={(label) => { setWizard(null); setView('apps'); void openApp(label); }}
            onGoChannels={onGoChannels}
            onCreateChannel={onCreateChannel}
            onAddResource={(kind, slot) => setAddingResource({ kind, slot })}
          />
        );
      })()}

      {uninstalling && (
        <Modal
          title={`Uninstall ${uninstalling.label} and revoke every permission?`}
          onClose={() => setUninstalling(null)}
          footer={
            <>
              <button className="btn" onClick={() => setUninstalling(null)} disabled={!!busy}>cancel</button>
              <button className="btn" onClick={() => void uninstall(uninstalling, true)} disabled={!!busy}>keep its own namespace (reinstall later) · Touch ID</button>
              <button className="btn danger" onClick={() => void uninstall(uninstalling, false)} disabled={!!busy}>delete its own namespace too · Touch ID</button>
            </>
          }
        >
          <p className="muted" style={{ fontSize: 13 }}>
            The archive ceremony revokes the delegate&apos;s grants on chain (and the contact gate&apos;s / console&apos;s grants on its feeds), returns the agent slot, and tears the sandbox down. Keeping its own namespace <code>{uninstalling.memory_ns}</code> lets a reinstall inherit it.
          </p>
        </Modal>
      )}

      {addingResource && (
        <KnowledgeItemModal
          client={client}
          initialKind={addingResource.kind}
          edit={addingResource.edit}
          onClose={() => setAddingResource(null)}
          onAdd={async (input) => {
            if (!client.resourceAdd) return false;
            const r = await client.resourceAdd(input);
            if (!r.ok) {
              showToast(`add failed — ${r.status?.detail ?? 'error'}`, true);
              return false;
            }
            showToast(`${input.id} v${r.data.version} planted into memory:${input.ns} (${r.data.storage})`);
            bindNewResourceToSlot(input.id);
            await refresh();
            return true;
          }}
          onUpload={async (input) => {
            if (!client.resourceUpload) return false;
            const r = await client.resourceUpload(input);
            if (!r.ok) {
              showToast(`upload failed — ${r.status?.detail ?? 'error'}`, true);
              return false;
            }
            const kept = r.data.raw_stored === true ? 'file kept' : r.data.raw_stored === false ? 'file not kept — no durable memory plane on this console' : 'no file';
            showToast(`${input.filename} → ${input.id} v${r.data.version}: ${r.data.extracted_bytes} B of text in memory:${input.ns} (${kept})`, r.data.raw_stored === false);
            bindNewResourceToSlot(input.id);
            await refresh();
            return true;
          }}
        />
      )}
    </>
  );
}

function AnnotationRows({ annotations }: { annotations: ServiceAnnotation[] }) {
  const data = annotations.filter((a) => a.role !== 'tool' && a.role !== 'plugin');
  const tools = annotations.filter((a) => a.role === 'tool');
  const plugins = annotations.filter((a) => a.role === 'plugin');
  const row = (a: ServiceAnnotation) => (
    <div key={a.service} className="perm-row" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px' }}>
      <code style={{ flex: 1 }}>{a.service}</code>
      <span className="muted" style={{ fontSize: 11 }}>{a.role}{a.slot ? ` · slot ${a.slot}` : ''}{a.resource ? ` · ${a.resource}` : ''}</span>
      {a.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>}
    </div>
  );
  return (
    <>
      <div className="perm-section-head"><span className="ttl">Data &amp; devices</span><span className="summary">{data.length} grants</span></div>
      <div className="perm-rows">{data.map(row)}</div>
      <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">Capabilities</span><span className="summary">{tools.length}</span></div>
      <div className="perm-rows">{tools.map(row)}</div>
      <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">Built with</span><span className="summary">{plugins.length}</span></div>
      <div className="perm-rows">{plugins.map(row)}</div>
    </>
  );
}

function AppDetail({
  app,
  template,
  dashboard,
  error,
  onCardAction,
  onUninstall,
  onRefresh,
  resources,
  apps,
  onEditResource,
}: {
  app: AppInstanceRow;
  template?: PresetSummary;
  dashboard: AppDashboard | null;
  error: string | null;
  onCardAction: (a: CardViewAction) => void;
  onUninstall: () => void;
  onRefresh: () => void;
  /** The registry rows (to edit a bound item in place) and the live apps (to say who else reads it). */
  resources: ResourceItemRow[];
  apps: AppInstanceRow[];
  onEditResource: (row: ResourceItemRow) => void;
}) {
  const st = statusOf(app);
  const display = app.bound_channels.find((b) => b.kind === 'display');
  return (
    <div style={{ marginTop: 18 }}>
      <PageHead
        crumb={`applications · ${app.label}`}
        title={<>{template?.name ?? app.template_id} <span className="muted" style={{ fontSize: 14 }}>· delegate <code>{app.label}</code> · <Dot status={st.dot} /> {st.text}</span></>}
        desc={template?.description ?? `template ${app.template_id}@${app.template_version}`}
        actions={
          <>
            <button className="btn" onClick={onRefresh}>refresh</button>
            {app.status !== 'uninstalled' && <button className="btn danger" onClick={onUninstall}>uninstall</button>}
          </>
        }
      />
      {error && <div className="banner warn" style={{ marginBottom: 12 }}><span className="lbl">dashboard</span><span>{error}</span></div>}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {display && (
            <Panel title={`── on ${display.channel_id} · interactive`}>
              {dashboard?.card ? (
                <>
                  <CardView card={dashboard.card} onAction={onCardAction} />
                  <div className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>
                    Rendered from the card the app published (event {dashboard.card_event_id}); a tap publishes a <code>command</code> event from {dashboard.console_actor_omni ? 'the console’s device actor' : 'the master (console not enrolled yet)'}.
                  </div>
                </>
              ) : (
                <div className="muted" style={{ fontSize: 12.5 }}>{dashboard ? 'No card published yet — the app publishes one on its schedule or when asked.' : 'Loading the display feed…'}</div>
              )}
            </Panel>
          )}
          <Panel title="── today" flush>
            <div className="feed">
              {(dashboard?.activity ?? []).length === 0 && <div className="muted" style={{ padding: 14 }}>No activity attributed to this app yet.</div>}
              {(dashboard?.activity ?? []).map((e) => (
                <div key={e.id} className="feed-row" style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
                  <span className="ts">{e.ts}</span>
                  <span style={{ flex: 1 }}>{e.detail}</span>
                  <Chip kind={e.sev === 'ok' ? 'ok' : e.sev === 'bad' ? 'bad' : 'default'}>{e.kind}</Chip>
                </div>
              ))}
            </div>
          </Panel>
          {(dashboard?.commands ?? []).length > 0 && (
            <Panel title="── commands published on the display feed" flush>
              <div className="feed">
                {(dashboard?.commands ?? []).map((c, i) => {
                  const row = c as { event_id?: string; ts_millis?: number; producer?: { actor_omni?: string }; command?: { action?: string; command?: string } };
                  return (
                    <div key={row.event_id ?? i} className="feed-row" style={{ display: 'flex', gap: 10 }}>
                      <span className="ts">{row.ts_millis ? new Date(Number(row.ts_millis)).toLocaleTimeString() : ''}</span>
                      <code>command:{row.command?.command ?? '?'}</code>
                      <span className="muted" style={{ fontSize: 11 }}>· from {row.producer?.actor_omni?.slice(0, 12) ?? '?'}…</span>
                    </div>
                  );
                })}
              </div>
            </Panel>
          )}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Panel title="── permissions · the sheet the install minted" flush>
            <div style={{ padding: 14 }}>
              <AnnotationRows annotations={dashboard?.annotations ?? []} />
              {template && (template.disclosure ?? []).length > 0 && (
                <>
                  <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">What leaves your home</span></div>
                  <ul className="muted" style={{ fontSize: 12, margin: 0, paddingLeft: 18 }}>{template.disclosure.map((d) => <li key={d.data}>{d.data} → {d.path}</li>)}</ul>
                </>
              )}
            </div>
          </Panel>
          <Panel title="── bindings">
            <dl className="kvs">
              {app.bound_channels.map((b) => (
                <div key={b.slot} style={{ display: 'contents' }}><dt>{b.slot}</dt><dd><code>{b.channel_id}</code> · {b.kind} · {b.direction}{b.endpoint_actor_omni ? ` · actor ${b.endpoint_actor_omni.slice(0, 10)}…` : ''}</dd></div>
              ))}
              {app.bindings.resources.map((r) => {
                const row = resources.find((it) => it.id === r.item_id);
                // The grant unit is the namespace: an edit reaches every app bound to
                // the item AND every app granted its namespace — say so before the edit.
                const others = editReaches({ ns: r.ns, curated: row ?? null }, apps, app.label);
                return (
                  <div key={r.name} style={{ display: 'contents' }}>
                    <dt>{r.name}</dt>
                    <dd>
                      {row?.name ?? r.item_id} · <code>memory:{r.ns}</code> · read-only {r.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>}
                      {row && <>{' '}<button className="btn sm" onClick={() => onEditResource(row)}>edit</button></>}
                      {!row && <span className="muted" style={{ fontSize: 11 }}> · item no longer in the registry</span>}
                      {others.length > 0 && <div className="muted" style={{ fontSize: 11 }}>also read by {others.join(', ')} — an edit reaches them at their next refresh</div>}
                    </dd>
                  </div>
                );
              })}
              <div style={{ display: 'contents' }}><dt>own namespace</dt><dd><code>memory:{app.memory_ns}</code> · <code>inbox:{app.memory_ns}</code></dd></div>
              <div style={{ display: 'contents' }}><dt>opchat</dt><dd><code>{app.chat_channel_id}</code></dd></div>
              <div style={{ display: 'contents' }}><dt>availability</dt><dd>{app.availability}</dd></div>
            </dl>
          </Panel>
          {template && (template.schedule ?? []).length > 0 && (
            <Panel title="── schedule">
              <dl className="kvs">
                {template.schedule.map((s) => <div key={s.cron} style={{ display: 'contents' }}><dt><code>{s.cron}</code></dt><dd>{s.label} · <Chip>tool:schedule</Chip></dd></div>)}
              </dl>
            </Panel>
          )}
          {app.bindings.audience.length > 0 && (
            <Panel title="── who can talk to it">
              {app.bindings.audience.map((a) => (
                <div key={a.slot} style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
                  <span className="muted" style={{ fontSize: 12 }}>{a.slot}:</span>
                  {TIERS.map((t) => <Chip key={t} kind={a.tiers.includes(t) ? 'ok' : 'default'}>{TIER_NAME[t]}{a.tiers.includes(t) ? '' : ' · off'}</Chip>)}
                </div>
              ))}
              <div className="muted" style={{ fontSize: 11.5 }}>Each allowed contact&apos;s reach carries the alias <code>{app.reach_aliases.join(', ') || app.label}</code>.</div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

function InstallWizard({
  w,
  tp,
  channels,
  resources,
  setW,
  onInstall,
  onOpen,
  onGoChannels,
  onCreateChannel,
  onAddResource,
}: {
  w: WizardState;
  tp: PresetSummary;
  channels: ChannelDef[];
  resources: ResourceItemRow[];
  setW: (w: WizardState | null) => void;
  onInstall: (w: WizardState) => void;
  onOpen: (label: string) => void;
  onGoChannels: () => void;
  onCreateChannel?: CreateChannelFn;
  /** Open the knowledge modal pre-set to the slot's kind; a successful add binds the new item to `slot`. */
  onAddResource?: (kind: ResourceKind, slot: string) => void;
}) {
  const slots = tp.slots ?? [];
  const reqs = tp.resources ?? [];
  const steps: WizardStep[] = ['slots'];
  if (reqs.length > 0) steps.push('resources');
  if (slots.some((s) => s.kind === 'messaging' && s.direction !== 'pub')) steps.push('audience');
  steps.push('sheet');
  const idx = Math.max(0, steps.indexOf(w.step));
  const go = (d: 1 | -1) => setW({ ...w, step: steps[Math.min(steps.length - 1, Math.max(0, idx + d))], error: null });
  const labelOk = LABEL_RE.test(w.label);
  const canNext =
    w.step === 'slots'
      ? labelOk && !slots.some((s) => s.required && !w.bindings[s.slot])
      : w.step === 'resources'
        ? !reqs.some((r) => r.required && !w.resources[r.name])
        : true;
  const opt = (selected: boolean, onClick: () => void, body: ReactNode) => (
    <div className="perm-row" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', cursor: 'pointer' }} onClick={onClick}>
      <span style={{ flex: 1 }}>{body}</span>
      <span className={`perm-switch ${selected ? 'on' : ''}`} />
    </div>
  );
  const build = w.built?.build as { services?: string[]; annotations?: ServiceAnnotation[]; bound_channels?: { slot: string; channel_id: string; kind: string; direction: string }[]; slots_used?: number; slots_total?: number } | undefined;
  return (
    <Modal
      wide
      title={w.step === 'done' ? 'Installed' : `Install ${tp.name} · step ${idx + 1} of ${steps.length} · ${w.step === 'resources' ? 'knowledge' : w.step}`}
      onClose={() => setW(null)}
      footer={
        w.step === 'done' ? (
          <button className="btn primary" onClick={() => onOpen(w.label)}>open the app</button>
        ) : (
          <>
            {idx > 0 && <button className="btn" onClick={() => go(-1)} disabled={!!w.busy}>back</button>}
            {w.step !== 'sheet' ? (
              <button className="btn primary" disabled={!canNext} onClick={() => go(1)}>next</button>
            ) : (
              <button className="btn primary" disabled={!!w.busy} onClick={() => onInstall(w)}>{w.busy ?? 'Install · Touch ID'}</button>
            )}
          </>
        )
      }
    >
      {w.error && <div className="banner warn" style={{ marginBottom: 12 }}><span className="lbl">refused</span><span>{w.error}</span></div>}
      {w.step === 'done' && (
        <p>The delegate <code>{w.label}</code> is running in its own sandbox with exactly the sheet you approved{build?.slots_total ? ` · slot ${(build.slots_used ?? 0) + 1} of ${build.slots_total}` : ''}.</p>
      )}
      {w.step === 'slots' && (
        <>
          <div style={{ marginBottom: 14 }}>
            <div className="perm-section-head"><span className="ttl">Delegate label</span><span className="summary">^[a-z0-9-]{'{1,32}'}$</span></div>
            <input style={INPUT} value={w.label} onChange={(e) => setW({ ...w, label: e.target.value.trim().toLowerCase() })} />
            {!labelOk && <div className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>lowercase letters, digits and dashes only</div>}
          </div>
          <p className="muted" style={{ fontSize: 12.5 }}>Pick which channel or device fills each slot the app needs. Nothing is granted yet.</p>
          {slots.map((s) => (
            <SlotChooser
              key={s.slot}
              slot={s}
              channels={channels}
              value={w.bindings[s.slot]}
              onPick={(id) => setW({ ...w, bindings: { ...w.bindings, [s.slot]: id } })}
              onCreateChannel={onCreateChannel}
              onGoChannels={onGoChannels}
            />
          ))}
        </>
      )}
      {w.step === 'resources' && (
        <>
          <p className="muted" style={{ fontSize: 12.5 }}>Choose which knowledge items the app may read. Read-only — an app can never change them, and binding one grants the app the item&apos;s whole namespace.</p>
          {reqs.map((r) => {
            const opts = resources.filter((it) => it.kind === r.kind);
            return (
              <div key={r.name} style={{ marginBottom: 14 }}>
                <div className="perm-section-head"><span className="ttl">{r.name} · {r.kind}</span><span className="summary">{r.required ? 'required' : 'optional'}{r.sensitivity_floor ? ` · floor ${r.sensitivity_floor}` : ''}</span></div>
                <div className="perm-rows">
                  {opts.map((it) => <div key={it.id}>{opt(w.resources[r.name] === it.id, () => setW({ ...w, resources: { ...w.resources, [r.name]: it.id } }), <>{it.name} {it.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>} <span className="muted" style={{ fontSize: 11 }}>· <code>{it.ns}</code> · v{it.version}</span></>)}</div>)}
                  {opts.length === 0 && (
                    <div className="muted" style={{ padding: '10px 12px', fontSize: 12.5, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                      <span>No {r.kind} curated yet.</span>
                      {onAddResource && <button className="btn sm" onClick={() => onAddResource(r.kind as ResourceKind, r.name)}>+ add a {r.kind} now</button>}
                      <span style={{ fontSize: 11.5 }}>(paste text or upload a file — it binds to this slot when saved)</span>
                    </div>
                  )}
                  {!r.required && <div>{opt(w.resources[r.name] === null, () => setW({ ...w, resources: { ...w.resources, [r.name]: null } }), <span className="muted">skip for now</span>)}</div>}
                </div>
                <div className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>{r.reason}</div>
              </div>
            );
          })}
        </>
      )}
      {w.step === 'audience' && (
        <>
          <p className="muted" style={{ fontSize: 12.5 }}>Who in the household may message this app. Defaults from the template; each allowed contact&apos;s reach gains the app&apos;s alias at install.</p>
          {Object.entries(w.audience).map(([slot, tiers]) => (
            <div key={slot} style={{ marginBottom: 12 }}>
              <div className="perm-section-head"><span className="ttl">{slot}</span></div>
              <div className="perm-rows">{TIERS.map((t) => <div key={t}>{opt(tiers[t], () => setW({ ...w, audience: { ...w.audience, [slot]: { ...tiers, [t]: !tiers[t] } } }), TIER_NAME[t])}</div>)}</div>
            </div>
          ))}
        </>
      )}
      {w.step === 'sheet' && (
        <>
          <p className="muted" style={{ fontSize: 12.5 }}>
            {build ? 'This is everything the app will be able to do — compiled by the broker from the template + your bindings. One Touch ID grants it all; revoke any line later.' : 'Press Install: the broker compiles the sheet from the template + your bindings, then Touch ID signs exactly that sheet.'}
          </p>
          {build?.annotations && <AnnotationRows annotations={build.annotations} />}
          {!build && (
            <>
              <div className="perm-section-head"><span className="ttl">Bindings</span></div>
              <dl className="kvs">
                {slots.map((s) => <div key={s.slot} style={{ display: 'contents' }}><dt>{s.slot}</dt><dd>{w.bindings[s.slot] ? <code>{w.bindings[s.slot]}</code> : <span className="muted">skipped</span>}</dd></div>)}
                {reqs.map((r) => <div key={r.name} style={{ display: 'contents' }}><dt>{r.name}</dt><dd>{w.resources[r.name] ? <code>{w.resources[r.name]}</code> : <span className="muted">skipped</span>}</dd></div>)}
              </dl>
            </>
          )}
          {(w.built?.endpoint_enrollments ?? []).length > 0 && (
            <>
              <div className="perm-section-head" style={{ marginTop: 12 }}><span className="ttl">Also enrolled by this Touch ID</span></div>
              <div className="perm-rows">{w.built!.endpoint_enrollments.map((e) => <div key={e.actor_omni} className="perm-row" style={{ padding: '8px 12px' }}><code>{e.label}</code> <span className="muted" style={{ fontSize: 11 }}>{e.kind === 'gateway' ? `the contact gate (${e.transport}) as a device actor` : 'this console as a device actor'} · {e.actor_omni.slice(0, 14)}…</span></div>)}</div>
            </>
          )}
          {(w.built?.endpoint_scopes ?? []).length > 0 && (
            <>
              <div className="perm-section-head" style={{ marginTop: 12 }}><span className="ttl">Endpoint actors granted in the same Touch ID</span></div>
              <div className="perm-rows">{w.built!.endpoint_scopes.map((e) => <div key={e.actor_omni} className="perm-row" style={{ padding: '8px 12px' }}><code>{e.actor_omni.slice(0, 14)}…</code> <span className="muted" style={{ fontSize: 11 }}>{e.services.join(', ')}</span></div>)}</div>
            </>
          )}
          {(tp.disclosure ?? []).length > 0 && (
            <>
              <div className="perm-section-head" style={{ marginTop: 12 }}><span className="ttl">What leaves your home</span></div>
              <ul className="muted" style={{ fontSize: 12, margin: 0, paddingLeft: 18 }}>{tp.disclosure.map((d) => <li key={d.data}>{d.data} → {d.path}</li>)}</ul>
            </>
          )}
        </>
      )}
    </Modal>
  );
}

type SlotSpec = NonNullable<PresetSummary['slots']>[number];

/** One slot's picker: the channels of exactly the slot's kind (sorted by name)
 *  with a filter once the list is long, everything else folded behind a
 *  button, single-select rows (a slot binds ONE channel), an inline
 *  "create + pick" for a fresh feed, and the explicit skip for optional slots. */
function SlotChooser({
  slot,
  channels,
  value,
  onPick,
  onCreateChannel,
  onGoChannels,
}: {
  slot: SlotSpec;
  channels: ChannelDef[];
  value: string | null | undefined;
  onPick: (id: string | null) => void;
  onCreateChannel?: CreateChannelFn;
  onGoChannels: () => void;
}) {
  const [query, setQuery] = useState('');
  const [showOthers, setShowOthers] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newId, setNewId] = useState(() => suggestedFeedId(slot.slot));
  const { matching, others } = useMemo(() => partitionSlotOptions(channels, slot.kind, query), [channels, slot.kind, query]);
  const selectedRow = channels.find((c) => c.id === value);
  const selectedIsOther = !!selectedRow && selectedRow.kind !== slot.kind;
  const canCreate = !!onCreateChannel && FEED_ID_RE.test(newId) && !channels.some((c) => c.id === newId);
  const create = async () => {
    if (!onCreateChannel || !canCreate) return;
    setCreating(true);
    try {
      const made = await onCreateChannel({ id: newId, name: newId, kind: slot.kind as ChannelDef['kind'] });
      if (made) onPick(made.id);
    } finally {
      setCreating(false);
    }
  };
  const row = (c: ChannelDef) => (
    <div
      key={c.id}
      role="radio"
      aria-checked={value === c.id}
      className="perm-row"
      style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', cursor: 'pointer' }}
      onClick={() => onPick(c.id)}
    >
      <span style={{ flex: 1 }}>
        {c.name} <span className="muted" style={{ fontSize: 11 }}><code>{c.id}</code> · {c.kind ?? 'unkinded'}</span>
      </span>
      <span className={`perm-switch ${value === c.id ? 'on' : ''}`} />
    </div>
  );
  return (
    <div style={{ marginBottom: 14 }}>
      <div className="perm-section-head">
        <span className="ttl">{slot.slot} · {slot.kind} · {slot.direction}</span>
        <span className="summary">{slot.required ? 'required' : 'optional'}{value ? ` · ${value}` : ''}</span>
      </div>
      {channels.length > 6 && (
        <input
          style={{ ...INPUT, marginBottom: 6 }}
          placeholder={`filter ${channels.length} channels…`}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label={`filter channels for ${slot.slot}`}
        />
      )}
      <div className="perm-rows" role="radiogroup" aria-label={slot.slot}>
        {matching.map(row)}
        {matching.length === 0 && (
          <div className="perm-row muted" style={{ padding: '8px 12px' }}>
            No <code>{slot.kind}</code> channel{query ? ' matches the filter' : ' registered yet'}
            {!onCreateChannel && <> — <button className="btn sm" type="button" onClick={onGoChannels}>register one on the channels page</button></>}.
          </div>
        )}
        {others.length > 0 && (
          <div className="perm-row" style={{ padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8 }}>
            <button className="btn sm" type="button" onClick={() => setShowOthers((v) => !v)}>
              {showOthers ? 'hide' : 'show'} {others.length} other channel{others.length === 1 ? '' : 's'} (unkinded or another kind)
            </button>
            {selectedIsOther && !showOthers && <span className="muted" style={{ fontSize: 11 }}>selected: <code>{value}</code></span>}
          </div>
        )}
        {showOthers && others.map(row)}
        {onCreateChannel && (
          <div className="perm-row" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px' }}>
            <span className="muted" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>new {slot.kind} feed</span>
            <input
              style={{ ...INPUT, width: 220 }}
              value={newId}
              onChange={(e) => setNewId(e.target.value.trim().toLowerCase())}
              aria-label={`new ${slot.kind} feed id for ${slot.slot}`}
            />
            <button className="btn sm primary" type="button" disabled={!canCreate || creating} onClick={() => void create()}>
              {creating ? 'creating…' : 'create + pick'}
            </button>
          </div>
        )}
        {(!slot.required || matching.length === 0) && (
          <div
            role="radio"
            aria-checked={value === null}
            className="perm-row"
            style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', cursor: 'pointer' }}
            onClick={() => onPick(null)}
          >
            <span className="muted" style={{ flex: 1 }}>skip for now</span>
            <span className={`perm-switch ${value === null ? 'on' : ''}`} />
          </div>
        )}
      </div>
      {slot.reason && <div className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>{slot.reason}</div>}
    </div>
  );
}
