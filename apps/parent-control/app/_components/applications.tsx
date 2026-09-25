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
import type { AppContextView } from '@/lib/generated/AppContextView';
import type { PresetSummary } from '@/lib/generated/PresetSummary';
import { scheduleCapability } from '@/lib/client/capabilityView';
import { AnnotationRows } from './permissionSheet';
import type { ResourceItemRow } from '@/lib/generated/ResourceItemRow';
import type { ResourceKind } from '@/lib/generated/ResourceKind';
import type { ServiceAnnotation } from '@/lib/generated/ServiceAnnotation';
import { Chip, Dot, LifecycleChip, Modal, PageHead, Panel } from './shared';
import { ChatPanel } from './chat';
import { cardAsks, onDemandTurnText } from '@/lib/client/askCard';
import { KnowledgeItemModal } from './knowledge';
import { editReaches } from '@/lib/client/knowledge';
import { FEED_ID_RE, gateRelayNote, partitionResourceOptions, partitionSlotOptions, suggestedFeedId } from '@/lib/client/slotOptions';

type View = 'apps' | 'endpoints';

/** The grant a template's schedule entries run under, from the capability catalog. */
const SCHEDULE_GRANT = scheduleCapability()?.service;

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
  /** The sealed context document (the anchor) as the daemon reads it back. */
  const [context, setContext] = useState<AppContextView | null>(null);
  const [contextErr, setContextErr] = useState<string | null>(null);
  const [wizard, setWizard] = useState<WizardState | null>(null);
  const [uninstalling, setUninstalling] = useState<AppInstanceRow | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // null = closed; `kind` pre-selects the kind (the wizard's empty slot), `slot` auto-binds the new
  // item to that slot on success, `edit` pre-fills an existing item (a re-add = the next version).
  const [addingResource, setAddingResource] = useState<null | { kind?: ResourceKind; slot?: string; edit?: ResourceItemRow }>(null);
  const [console_, setConsole] = useState<ConsoleDeviceStatus | null>(null);
  const [gateway, setGateway] = useState<GatewayDeviceStatus | null>(null);
  /** #717 — the rebind ceremony's current step, while one runs. */
  const [rebinding, setRebinding] = useState<string | null>(null);
  /** The anchor ceremonies (seal existing · re-hydrate): the current step + the last outcome. */
  const [anchorBusy, setAnchorBusy] = useState<string | null>(null);
  const [anchorNote, setAnchorNote] = useState<string | null>(null);
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
  // D-K2 — the type is metadata: a slot may bind ANY item; picking one of another
  // kind retypes it in place (no new version), then the wizard binds it.
  const retypeResource = async (id: string, kind: ResourceKind): Promise<boolean> => {
    if (!client.resourceRetype) return false;
    const r = await client.resourceRetype({ id, kind });
    if (!r.ok) {
      showToast(`retype failed — ${r.status?.detail ?? 'error'}`, true);
      return false;
    }
    showToast(`${id} is now a ${kind}`);
    await refresh();
    return true;
  };

  const bindNewResourceToSlot = (id: string) => {
    const slot = addingResource?.slot;
    if (!slot) return;
    setWizard((w) => (w ? { ...w, resources: { ...w.resources, [slot]: id } } : w));
  };

  const loadContext = useCallback(
    async (label: string) => {
      setContext(null);
      setContextErr(null);
      if (!client.appContext) return;
      const c = await client.appContext(label);
      if (c.ok) setContext(c.data);
      else setContextErr(c.status?.detail ?? 'context document unavailable');
    },
    [client],
  );

  const openApp = useCallback(
    async (label: string) => {
      setSelected(label);
      setDashboard(null);
      setDashError(null);
      void loadContext(label);
      if (!client.appDashboard) return;
      const d = await client.appDashboard(label);
      if (d.ok) setDashboard(d.data);
      else setDashError(d.status?.detail ?? 'dashboard unavailable');
    },
    [client, loadContext],
  );

  const live = installed.filter((a) => a.status !== 'uninstalled');
  const catalogFree = (catalog ?? []).filter((tp) => !live.some((a) => a.template_id === tp.id));

  // ── "ask for the card now": the entry's prompt as a turn on the app's
  // opchat feed (the clock's own mechanism, tagged on-demand), then the
  // display feed is polled until a NEW card event lands (bounded: a delegate
  // that is still booting or has no display grant never leaves the panel
  // spinning — the ask is recorded either way).
  const [asking, setAsking] = useState<{ label: string; entry: string; since: number; note: string } | null>(null);
  const askForCard = useCallback(
    async (row: AppInstanceRow, entry: { label: string; prompt: string }) => {
      if (asking) return;
      const before = dashboard?.card_event_id ?? null;
      setAsking({ label: row.label, entry: entry.label, since: Date.now(), note: 'sending the ask…' });
      // A scheduled app sleeps between its ticks (#669): an ask into a feed
      // nothing consumes spins for three minutes and lands nowhere (chef,
      // 2026-09-18 — its lease had ended 40 min earlier). Wake it first.
      const status = await client.agentImageStatus([row.device_key_hash]);
      const bare = row.device_key_hash.toLowerCase().replace(/^0x/, '');
      const rt = status.ok
        ? status.data.delegates.find((d) => d.device_key_hash.toLowerCase().replace(/^0x/, '') === bare)
        : undefined;
      if (rt && !rt.error && !rt.sandbox_id) {
        setAsking((a) =>
          a ? { ...a, note: `${row.label} has no runtime (it sleeps between its scheduled ticks) — waking it first: a cold start, up to ~2 minutes…` } : a,
        );
        const w = await client.agentUpdate({ deviceKeyHash: row.device_key_hash });
        const wakeError = w.ok ? w.data.sandbox_error : (w.status?.detail ?? 'wake failed');
        if (wakeError) {
          showToast(`${row.label}: could not wake its runtime — ${wakeError}`, true);
          setAsking(null);
          return;
        }
        setAsking((a) => (a ? { ...a, note: `${row.label} is awake — sending the ask…` } : a));
      }
      const r = await client.chatSend(row.chat_channel_id, onDemandTurnText(entry), 'text');
      if (!r.ok) {
        showToast(`${row.label}: the ask did not reach its feed — ${r.status?.detail ?? 'error'}`, true);
        setAsking(null);
        return;
      }
      setAsking((a) =>
        a
          ? { ...a, note: `${row.label} is composing — the card lands here when it publishes; its reply lands in the chat panel below` }
          : a,
      );
      for (let i = 0; i < 36; i++) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((res) => setTimeout(res, 5000));
        // eslint-disable-next-line no-await-in-loop
        const d = client.appDashboard ? await client.appDashboard(row.label) : null;
        if (d?.ok) {
          setDashboard(d.data);
          if (d.data.card && d.data.card_event_id !== before) {
            showToast(`${row.label} published its card.`);
            setAsking(null);
            return;
          }
        }
      }
      showToast(`${row.label} has not published a card in 3 minutes — read its reply in the chat panel below: it may have asked something back, or lack the display grant.`, true);
      setAsking(null);
    },
    [asking, client, dashboard?.card_event_id, showToast],
  );

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

  // ── the rebind ceremony (#717): build → ONE Touch ID → submit; the app
  // keeps running and re-sources its feeds — a commit, not a reinstall.
  const rebind = useCallback(
    async (app: AppInstanceRow, slots: Record<string, string>) => {
      if (!client.appRebindBuild || !client.appRebindSubmit) return;
      setRebinding('Compiling the new sheet…');
      const built = await client.appRebindBuild(app.label, { slots: Object.entries(slots).map(([slot, channel_id]) => ({ slot, channel_id })) });
      if (!built.ok) {
        setRebinding(null);
        showToast(`rebind build failed — ${built.status?.detail ?? 'error'}`, true);
        return;
      }
      const build = built.data.build as { user_op?: unknown; user_op_hash?: string };
      akLog('apps: rebind built', { label: app.label, changes: built.data.changes, endpointScopes: built.data.endpoint_scopes });
      setRebinding('Approve with Touch ID…');
      let assertion;
      try {
        const cred = getMasterCredId() || null;
        assertion = await getAssertionOverHash(String(build.user_op_hash ?? ''), cred ? [cred] : undefined);
      } catch {
        setRebinding(null);
        showToast('Touch ID cancelled — nothing changed.', true);
        return;
      }
      setRebinding('Committing on chain…');
      const submitted = await client.appRebindSubmit(app.label, { user_op: build.user_op, assertion });
      if (!submitted.ok) {
        setRebinding(null);
        showToast(`rebind submit failed — ${submitted.status?.detail ?? 'error'}`, true);
        return;
      }
      const rebound = (submitted.data as { rebound?: { runtime?: { mode?: string; detail?: string } } }).rebound;
      akLog('apps: rebind confirmed', { txHash: submitted.data.tx_hash, rebound });
      showToast(`${app.label} rebound — ${rebound?.runtime?.detail ?? 'committed'}`);
      setRebinding(null);
      await openApp(app.label);
      await refresh();
    },
    [client, openApp, refresh, showToast],
  );

  // ── the anchor: seal the apps installed before it existed (ONE Touch ID)
  const sealExisting = useCallback(async () => {
    if (!client.appAnchorsSealBuild || !client.appAnchorsSealSubmit) return;
    setAnchorBusy('Composing the context documents…');
    setAnchorNote(null);
    const built = await client.appAnchorsSealBuild({});
    if (!built.ok) {
      setAnchorBusy(null);
      setAnchorNote(`seal build failed — ${built.status?.detail ?? 'error'}`);
      return;
    }
    const build = built.data.build;
    setAnchorBusy(`Sealing ${built.data.labels.join(', ')} — approve with Touch ID…`);
    let assertion;
    try {
      const cred = getMasterCredId() || null;
      assertion = await getAssertionOverHash(String(build.user_op_hash ?? ''), cred ? [cred] : undefined);
    } catch {
      setAnchorBusy(null);
      setAnchorNote('Touch ID cancelled — nothing sealed.');
      return;
    }
    setAnchorBusy('Committing the seals on chain…');
    const submitted = await client.appAnchorsSealSubmit({ user_op: build.user_op, assertion });
    setAnchorBusy(null);
    if (!submitted.ok) {
      setAnchorNote(`seal submit failed — ${submitted.status?.detail ?? 'error'}`);
      return;
    }
    const sealed = (submitted.data.sealed ?? []) as { label: string; version: number; context_storage: string }[];
    setAnchorNote(`sealed ${sealed.map((s) => `${s.label} v${s.version} (${s.context_storage})`).join(' · ')}`);
    showToast(`${sealed.length} app${sealed.length === 1 ? '' : 's'} sealed on chain`);
    await refresh();
  }, [client, refresh, showToast]);

  // ── the anchor: a fresh broker rebuilds its rows from the sealed documents
  const rehydrate = useCallback(async () => {
    if (!client.appsRehydrate) return;
    setAnchorBusy('Re-hydrating the broker from the sealed documents…');
    setAnchorNote(null);
    const r = await client.appsRehydrate({});
    setAnchorBusy(null);
    if (!r.ok) {
      setAnchorNote(`re-hydrate failed — ${r.status?.detail ?? 'error'}`);
      return;
    }
    setAnchorNote(
      r.data.results
        .map((x) => {
          const res = (x.result ?? {}) as { row?: string; sealed_index?: number; error?: string };
          if (x.skipped) return `${x.label}: ${x.skipped}`;
          if (x.error) return `${x.label}: ${x.error}`;
          return `${x.label}: ${x.status === 200 ? `row ${res.row ?? 'ok'} (sealed root #${res.sealed_index ?? '?'})` : `HTTP ${x.status} ${res.error ?? ''}`}`;
        })
        .join(' · ') || 'no installed apps',
    );
    await refresh();
  }, [client, refresh]);

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
                          <div style={{ fontSize: 12, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}><span><Dot status={st.dot} /> {st.text} · {a.availability} · {a.bound_channels.length} bound feed(s)</span><LifecycleChip channelId={a.chat_channel_id} /></div>
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
              asking={asking?.label === selectedRow.label ? asking : null}
              onAskCard={(entry) => void askForCard(selectedRow, entry)}
              onRebind={(slots) => void rebind(selectedRow, slots)}
              rebinding={rebinding}
              context={context}
              contextErr={contextErr}
              onReloadContext={() => void loadContext(selectedRow.label)}
              channels={channels}
              gateway={gateway}
              onGoChannels={onGoChannels}
              onGoEndpoints={() => setView('endpoints')}
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
          <Panel title="── anchors · the sealed context documents">
            <p className="muted" style={{ fontSize: 12.5 }}>
              Each app&apos;s bound channels live in a context document on the memory plane, sealed on chain by the ceremony that changed it; the broker&apos;s row is a cache of it. An app installed before the anchor existed needs one seal, and a fresh broker rebuilds its rows from the documents.
            </p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <button className="btn sm primary" disabled={!!anchorBusy || live.every((a) => !!a.anchor)} onClick={() => void sealExisting()}>
                {anchorBusy ?? `seal ${live.filter((a) => !a.anchor).length} existing app${live.filter((a) => !a.anchor).length === 1 ? '' : 's'} (one Touch ID)`}
              </button>
              <button className="btn sm" disabled={!!anchorBusy} onClick={() => void rehydrate()}>re-hydrate runtime contexts</button>
            </div>
            {anchorNote && <div className="muted" style={{ fontSize: 11.5, marginTop: 6 }}>{anchorNote}</div>}
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
            gateway={gateway}
            setW={setWizard}
            onInstall={(w) => void install(w, tp)}
            onOpen={(label) => { setWizard(null); setView('apps'); void openApp(label); }}
            onGoChannels={onGoChannels}
            onGoEndpoints={() => setView('endpoints')}
            onCreateChannel={onCreateChannel}
            onAddResource={(kind, slot) => setAddingResource({ kind, slot })}
            onRetypeResource={retypeResource}
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
            if (!client.resourceAdd) return 'error';
            const r = await client.resourceAdd(input);
            if (!r.ok) {
              showToast(`add failed — ${r.status?.detail ?? 'error'}`, true);
              return 'error';
            }
            showToast(`${input.id} v${r.data.version} planted into knowledge:${input.ns} (${r.data.storage})`);
            bindNewResourceToSlot(input.id);
            await refresh();
            return 'ok';
          }}
          onUpload={async (input) => {
            if (!client.resourceUpload) return 'error';
            const r = await client.resourceUpload(input);
            if (!r.ok) {
              showToast(`upload failed — ${r.status?.detail ?? 'error'}`, true);
              return 'error';
            }
            const kept = r.data.raw_stored === true ? 'file kept' : r.data.raw_stored === false ? 'file not kept — no durable memory plane on this console' : 'no file';
            showToast(`${input.filename} → ${input.id} v${r.data.version}: ${r.data.extracted_bytes} B of text in knowledge:${input.ns} (${kept})`, r.data.raw_stored === false);
            bindNewResourceToSlot(input.id);
            await refresh();
            return 'ok';
          }}
        />
      )}
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
  asking,
  onAskCard,
  onRebind,
  rebinding,
  channels,
  gateway,
  onGoChannels,
  onGoEndpoints,
  context,
  contextErr,
  onReloadContext,
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
  /** An ask in flight for THIS app (entry label + status note), else null. */
  asking?: { entry: string; since: number; note: string } | null;
  /** "Ask for the card now" — run a schedule entry's prompt as a turn. */
  onAskCard?: (entry: { label: string; prompt: string }) => void;
  /** #717 — commit new channel bindings in place: one Touch ID, no reinstall. */
  onRebind?: (slots: Record<string, string>) => void;
  /** The rebind ceremony's current step, while one runs. */
  rebinding?: string | null;
  channels: ChannelDef[];
  gateway: GatewayDeviceStatus | null;
  onGoChannels: () => void;
  onGoEndpoints: () => void;
  /** The sealed context document as stored (the anchor), null while loading. */
  context?: AppContextView | null;
  contextErr?: string | null;
  onReloadContext?: () => void;
}) {
  const st = statusOf(app);
  const [editingBindings, setEditingBindings] = useState(false);
  const [draft, setDraft] = useState<Record<string, string | null>>({});
  const channelSlots = template?.slots ?? [];
  const currentOf = (slot: string) => app.bound_channels.find((b) => b.slot === slot)?.channel_id ?? null;
  const changedSlots = channelSlots.filter((s) => {
    const v = draft[s.slot];
    return typeof v === 'string' && v !== currentOf(s.slot);
  });
  const display = app.bound_channels.find((b) => b.kind === 'display');
  const asks = cardAsks(template?.schedule);
  const askRow = display && onAskCard && app.status !== 'uninstalled' && (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap', marginTop: dashboard?.card ? 10 : 8 }}>
      <span className="muted" style={{ fontSize: 11.5 }}>{dashboard?.card ? 'ask for a fresh card:' : 'ask for the card now:'}</span>
      {asks.map((e) => (
        <button key={e.label} className="btn sm" disabled={!!asking} title={e.prompt} onClick={() => onAskCard(e)}>
          ▶ {e.label}
        </button>
      ))}
      {asking && <span className="muted" style={{ fontSize: 11.5 }}>· {asking.entry} — {asking.note}</span>}
    </div>
  );
  return (
    <div style={{ marginTop: 18 }}>
      <PageHead
        crumb={`applications · ${app.label}`}
        title={<>{template?.name ?? app.template_id} <span className="muted" style={{ fontSize: 14 }}>· delegate <code>{app.label}</code> · <Dot status={st.dot} /> {st.text}</span> <LifecycleChip channelId={app.chat_channel_id} sync /></>}
        desc={template?.description ?? `template ${app.template_id}@${app.template_version}`}
        actions={
          <>
            <button className="btn" onClick={onRefresh}>refresh</button>
            {app.status !== 'uninstalled' && <button className="btn danger" onClick={onUninstall}>uninstall</button>}
          </>
        }
      />
      {error && <div className="banner warn" style={{ marginBottom: 12 }}><span className="lbl">dashboard</span><span>{error}</span></div>}
      {template && template.version !== app.template_version && app.status !== 'uninstalled' && onRebind && (
        <div className="banner" style={{ marginBottom: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <span className="lbl">update</span>
          <span style={{ flex: 1 }}>
            Template v{template.version} is available; this app runs v{app.template_version}. Updating applies the new version's permissions and slot directions with one Touch ID and re-applies its skills. Your bindings stay.
          </span>
          <button className="btn sm primary" disabled={!!rebinding} onClick={() => onRebind({})}>
            update to v{template.version}
          </button>
        </div>
      )}
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
                  {(dashboard?.non_card_docs ?? 0) > 0 && (
                    <div className="banner warn" style={{ marginTop: 8 }}>
                      <span className="lbl">newer, not a card</span>
                      <span>
                        The app published {dashboard!.non_card_docs} newer document{dashboard!.non_card_docs === 1 ? '' : 's'} on this feed that {dashboard!.non_card_docs === 1 ? 'is' : 'are'} not in the card format, so the screen keeps the last real card. That is what an app running without its skills does — wake or update its runtime on the Delegates page, then ask again.
                        {dashboard!.last_doc_preview ? ` Newest starts: ${dashboard!.last_doc_preview}` : ''}
                      </span>
                    </div>
                  )}
                  {askRow}
                </>
              ) : (
                <>
                  <div className="muted" style={{ fontSize: 12.5 }}>{dashboard ? "No card in this feed's recent window — the app publishes one on its schedule, or when you ask below." : 'Loading the display feed…'}</div>
                  {(dashboard?.non_card_docs ?? 0) > 0 && (
                    <div className="banner warn" style={{ marginTop: 8 }}>
                      <span className="lbl">newer, not a card</span>
                      <span>
                        The app published {dashboard!.non_card_docs} newer document{dashboard!.non_card_docs === 1 ? '' : 's'} on this feed that {dashboard!.non_card_docs === 1 ? 'is' : 'are'} not in the card format, so the screen keeps the last real card. That is what an app running without its skills does — wake or update its runtime on the Delegates page, then ask again.
                        {dashboard!.last_doc_preview ? ` Newest starts: ${dashboard!.last_doc_preview}` : ''}
                      </span>
                    </div>
                  )}
                  {dashboard && askRow}
                </>
              )}
            </Panel>
          )}
          {/* The app's opchat feed, in place (#430 ChatPanel): the schedule's
              asks go in here and the replies come back here — the only place
              to read what the app SAID when no card appears. Operator-only. */}
          {app.status !== 'uninstalled' && app.chat_channel_id && (
            <Panel title={`── chat · ${app.chat_channel_id} · operator-only`}>
              <ChatPanel
                key={app.chat_channel_id}
                channelId={app.chat_channel_id}
                emptyHint={`Direct chat with ${app.label} on ${app.chat_channel_id} — the transcript IS its durable opchat feed; the schedule's asks and its replies land here too.`}
              />
            </Panel>
          )}
          {/* The app's messaging slots (the family chat), read-only: what the
              app says to the family is readable HERE; it reaches the family
              only through a contact gate that serves this feed. */}
          {app.status !== 'uninstalled' &&
            app.bound_channels
              .filter((b) => b.kind === 'messaging' && b.channel_id !== app.chat_channel_id)
              .map((b) => (
                <Panel key={b.channel_id} title={`── ${b.slot} · ${b.channel_id} · read-only`}>
                  <ChatPanel
                    key={b.channel_id}
                    channelId={b.channel_id}
                    readOnly
                    emptyHint={`Nothing on ${b.channel_id} yet. What the app publishes here reaches the family only through a contact gate that serves this feed (the WeChat gate serves the feeds named after its transport, see the manual); any other feed is readable here and delivered nowhere.`}
                  />
                </Panel>
              ))}
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
              <AnnotationRows annotations={dashboard?.annotations ?? []} schedule={template?.schedule} />
              {template && (template.disclosure ?? []).length > 0 && (
                <>
                  <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">What leaves your home</span></div>
                  <ul className="muted" style={{ fontSize: 12, margin: 0, paddingLeft: 18 }}>{template.disclosure.map((d) => <li key={d.data}>{d.data} → {d.path}</li>)}</ul>
                </>
              )}
            </div>
          </Panel>
          <Panel
            title="── bindings"
            right={onRebind && app.status !== 'uninstalled' && !editingBindings ? <button className="btn sm" onClick={() => { setDraft({}); setEditingBindings(true); }}>edit bindings</button> : undefined}
          >
            <dl className="kvs">
              {app.bound_channels.map((b) => (
                <div key={b.slot} style={{ display: 'contents' }}>
                  <dt>{b.slot}</dt>
                  <dd>
                    <code>{b.channel_id}</code> · {b.kind} · {b.direction}
                    {b.kind === 'messaging' && (b.endpoint_actor_omni ? ' · relayed by the contact gate' : ' · no contact gate on it — rebind to enroll one')}
                    {b.kind !== 'messaging' && b.endpoint_actor_omni ? ` · actor ${b.endpoint_actor_omni.slice(0, 10)}…` : ''}
                  </dd>
                </div>
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
                      {row?.name ?? r.item_id} · <code>knowledge:{r.ns}</code> · read-only {r.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>}
                      {row && <>{' '}<button className="btn sm" onClick={() => onEditResource(row)}>edit</button></>}
                      {!row && <span className="muted" style={{ fontSize: 11 }}> · item no longer in the registry</span>}
                      {others.length > 0 && <div className="muted" style={{ fontSize: 11 }}>also read by {others.join(', ')} — an edit reaches them at their next refresh</div>}
                    </dd>
                  </div>
                );
              })}
              <div style={{ display: 'contents' }}><dt>own namespace</dt><dd><code>knowledge:{app.memory_ns}</code> · <code>proposal:{app.memory_ns}</code></dd></div>
              <div style={{ display: 'contents' }}><dt>opchat</dt><dd><code>{app.chat_channel_id}</code></dd></div>
              <div style={{ display: 'contents' }}><dt>availability</dt><dd>{app.availability}</dd></div>
              <div style={{ display: 'contents' }}>
                <dt>anchor</dt>
                <dd>
                  {app.anchor ? (
                    <>
                      v{app.anchor.version} · <code>{app.anchor.hash.slice(0, 14)}…</code>
                      {app.anchor.tx_hash ? ` · sealed in tx ${app.anchor.tx_hash.slice(0, 14)}…` : ' · seal pending'}
                    </>
                  ) : (
                    <span className="muted">not sealed yet — seal existing apps on the endpoints tab</span>
                  )}
                </dd>
              </div>
            </dl>
            {editingBindings && onRebind && (
              <div style={{ marginTop: 12 }}>
                <div className="banner" style={{ marginBottom: 10 }}>
                  <span className="lbl">rebind</span>
                  <span>Pick the new channel for a slot and commit. One Touch ID re-signs the app&apos;s grants and enrolls the contact gate on the new channel when it needs to; the running app re-sources its feeds in place — no reinstall, no slot consumed.</span>
                </div>
                {channelSlots.map((s) => (
                  <SlotChooser
                    key={s.slot}
                    slot={s}
                    label={app.label}
                    channels={channels}
                    gateway={gateway}
                    value={draft[s.slot] !== undefined ? draft[s.slot] : currentOf(s.slot)}
                    onPick={(id) => setDraft({ ...draft, [s.slot]: id })}
                    onGoChannels={onGoChannels}
                    onGoEndpoints={onGoEndpoints}
                  />
                ))}
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button
                    className="btn sm primary"
                    disabled={changedSlots.length === 0 || !!rebinding}
                    onClick={() => onRebind(Object.fromEntries(changedSlots.map((s) => [s.slot, draft[s.slot] as string])))}
                  >
                    {rebinding ?? `commit ${changedSlots.length} change${changedSlots.length === 1 ? '' : 's'} (one Touch ID)`}
                  </button>
                  <button className="btn sm" disabled={!!rebinding} onClick={() => { setEditingBindings(false); setDraft({}); }}>cancel</button>
                </div>
              </div>
            )}
          </Panel>
          <Panel
            title="── context · the sealed document (the anchor)"
            right={onReloadContext ? <button className="btn sm" onClick={onReloadContext}>re-read</button> : undefined}
          >
            {contextErr && (
              <div className="banner warn"><span className="lbl">unavailable</span><span>{contextErr}</span></div>
            )}
            {!contextErr && !context && <div className="muted" style={{ fontSize: 12.5 }}>Reading the document…</div>}
            {context && !context.doc && (
              <div className="banner">
                <span className="lbl">no document</span>
                <span>This app has no sealed context document yet ({context.source}) — seal existing apps on the endpoints tab.</span>
              </div>
            )}
            {context && context.doc && (
              <>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
                  <Chip kind={context.matches_anchor ? 'ok' : 'bad'}>{context.matches_anchor ? 'matches the sealed anchor' : 'does NOT match the sealed anchor'}</Chip>
                  <Chip kind={context.matches_row ? 'ok' : 'bad'}>{context.matches_row ? 'matches the bindings' : 'bindings differ from the document'}</Chip>
                  <Chip>read from the {context.source}</Chip>
                </div>
                <dl className="kvs">
                  <div style={{ display: 'contents' }}><dt>version</dt><dd>v{context.doc.version}{context.doc.previous_hash ? <> · previous <code>{context.doc.previous_hash.slice(0, 14)}…</code></> : ' · the first document'}</dd></div>
                  <div style={{ display: 'contents' }}><dt>hash</dt><dd><code>{context.hash}</code></dd></div>
                  <div style={{ display: 'contents' }}><dt>sealed</dt><dd>{context.anchor?.tx_hash ? <>tx <code>{context.anchor.tx_hash}</code> · {new Date(context.anchor.sealed_at * 1000).toLocaleString()}</> : <span className="muted">seal pending</span>}</dd></div>
                  <div style={{ display: 'contents' }}><dt>written</dt><dd>{new Date(context.doc.updated_at * 1000).toLocaleString()}</dd></div>
                  <div style={{ display: 'contents' }}><dt>template</dt><dd><code>{context.doc.preset_id || '(role preset)'}</code></dd></div>
                  <div style={{ display: 'contents' }}><dt>delegate</dt><dd>actor <code>{context.doc.actor_omni.slice(0, 14)}…</code> · device <code>{context.doc.device_key_hash.slice(0, 14)}…</code> · K10 <code>{context.doc.k10_address}</code></dd></div>
                  <div style={{ display: 'contents' }}><dt>opchat</dt><dd><code>{context.doc.chat_channel_id}</code></dd></div>
                  <div style={{ display: 'contents' }}><dt>memory</dt><dd><code>{context.doc.memory_ns}</code>{context.doc.memory_namespaces ? <> · mirrors <code>{context.doc.memory_namespaces}</code></> : null}</dd></div>
                  <div style={{ display: 'contents' }}><dt>availability</dt><dd>{context.doc.availability} · tz {context.doc.tz_offset_minutes >= 0 ? '+' : ''}{context.doc.tz_offset_minutes / 60}h</dd></div>
                  {context.doc.bound_channels.map((b) => (
                    <div key={b.slot} style={{ display: 'contents' }}>
                      <dt>{b.slot}</dt>
                      <dd><code>{b.channel_id}</code> · {b.kind} · {b.direction}{b.endpoint_actor_omni ? ' · relayed by an endpoint actor' : ''}</dd>
                    </div>
                  ))}
                </dl>
                <details style={{ marginTop: 8 }}>
                  <summary className="muted" style={{ fontSize: 11.5, cursor: 'pointer' }}>raw document — the exact bytes the seal hashed</summary>
                  <pre style={{ fontSize: 11, overflowX: 'auto', margin: '6px 0 0' }}>{context.doc_json}</pre>
                </details>
              </>
            )}
          </Panel>
          {template && (template.schedule ?? []).length > 0 && (
            <Panel title="── schedule">
              <dl className="kvs">
                {template.schedule.map((s) => <div key={s.cron} style={{ display: 'contents' }}><dt title={`cron ${s.cron} · household time`}>{s.when?.en ?? <code>{s.cron}</code>}</dt><dd>{s.label}{s.label_zh ? ` · ${s.label_zh}` : ''}{SCHEDULE_GRANT && <> · <Chip>{SCHEDULE_GRANT}</Chip></>}</dd></div>)}
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
  gateway,
  setW,
  onInstall,
  onOpen,
  onGoChannels,
  onGoEndpoints,
  onCreateChannel,
  onAddResource,
  onRetypeResource,
}: {
  w: WizardState;
  tp: PresetSummary;
  channels: ChannelDef[];
  resources: ResourceItemRow[];
  /** The contact gate's device status — the ONLY option a messaging slot may bind. */
  gateway: GatewayDeviceStatus | null;
  setW: (w: WizardState | null) => void;
  onInstall: (w: WizardState) => void;
  onOpen: (label: string) => void;
  onGoChannels: () => void;
  onGoEndpoints: () => void;
  onCreateChannel?: CreateChannelFn;
  /** Open the knowledge modal pre-set to the slot's kind; a successful add binds the new item to `slot`. */
  onAddResource?: (kind: ResourceKind, slot: string) => void;
  /** D-K2 — retype an item of another kind to the slot's kind (metadata only); resolves true when done. */
  onRetypeResource?: (id: string, kind: ResourceKind) => Promise<boolean>;
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
              label={w.label}
              channels={channels}
              gateway={gateway}
              value={w.bindings[s.slot]}
              onPick={(id) => setW({ ...w, bindings: { ...w.bindings, [s.slot]: id } })}
              onCreateChannel={onCreateChannel}
              onGoChannels={onGoChannels}
              onGoEndpoints={onGoEndpoints}
            />
          ))}
        </>
      )}
      {w.step === 'resources' && (
        <>
          <p className="muted" style={{ fontSize: 12.5 }}>Choose which knowledge items the app may read. Read-only — an app can never change them, and binding one grants the app the item&apos;s whole namespace.</p>
          {reqs.map((r) => {
            const { matching: opts, others } = partitionResourceOptions(resources, r.kind);
            return (
              <div key={r.name} style={{ marginBottom: 14 }}>
                <div className="perm-section-head"><span className="ttl">{r.name} · {r.kind}</span><span className="summary">{r.required ? 'required' : 'optional'}{r.sensitivity_floor ? ` · floor ${r.sensitivity_floor}` : ''}</span></div>
                <div className="perm-rows">
                  {opts.map((it) => <div key={it.id}>{opt(w.resources[r.name] === it.id, () => setW({ ...w, resources: { ...w.resources, [r.name]: it.id } }), <>{it.name} {it.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>} <span className="muted" style={{ fontSize: 11 }}>· <code>{it.ns}</code> · v{it.version}</span></>)}</div>)}
                  {others.length > 0 && onRetypeResource && (
                    <details style={{ padding: '6px 12px' }}>
                      <summary className="muted" style={{ fontSize: 12, cursor: 'pointer' }}>use another item as a {r.kind} · {others.length}</summary>
                      {others.map((it) => (
                        <div key={it.id}>
                          {opt(false, () => {
                            setW({ ...w, resources: { ...w.resources, [r.name]: it.id } });
                            void onRetypeResource(it.id, r.kind as ResourceKind);
                          }, <>{it.name} <Chip>{it.kind}</Chip> {it.sensitivity === 'sensitive' && <Chip kind="bad">SENSITIVE</Chip>} <span className="muted" style={{ fontSize: 11 }}>· <code>{it.ns}</code> · becomes a {r.kind}</span></>)}
                        </div>
                      ))}
                    </details>
                  )}
                  {opts.length === 0 && (
                    <div className="muted" style={{ padding: '10px 12px', fontSize: 12.5, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                      <span>No {r.kind} yet.</span>
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
          {build?.annotations && <AnnotationRows annotations={build.annotations} schedule={tp.schedule} />}
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
  label,
  channels,
  gateway,
  value,
  onPick,
  onCreateChannel,
  onGoChannels,
  onGoEndpoints,
}: {
  slot: SlotSpec;
  /** The delegate label being installed — names the gate's derived feed. */
  label: string;
  channels: ChannelDef[];
  gateway: GatewayDeviceStatus | null;
  value: string | null | undefined;
  onPick: (id: string | null) => void;
  onCreateChannel?: CreateChannelFn;
  onGoChannels: () => void;
  onGoEndpoints: () => void;
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
      {slot.kind === 'messaging' && (
        <div className="muted" style={{ fontSize: 11.5, marginBottom: 6 }}>
          {gateRelayNote(gateway, label)}
          {!gateway?.configured && <>{' '}<button className="btn sm" type="button" onClick={onGoEndpoints}>set up the contact gate</button></>}
        </div>
      )}
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
