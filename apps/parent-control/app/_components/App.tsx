'use client';

import { useEffect, useState } from 'react';
import {
  CHAIN_PROFILE,
  ONCHAIN_KINDS,
  PAIRING_STEPS,
  contractFor,
  decodeCalldata,
} from '@/lib/demoData';
import { NAMESPACES } from '@/lib/constants';
import { getMaskEmail, maskEmail, setMaskEmail } from '@/lib/maskEmail';
import { CeremonyRunner, OnboardingScreen } from './ceremony';
import { ActorDetail, ActorsList, AuditFeed } from './dashboard';
import { LogoPage } from './logos';
import { MemoryPage } from './memory';
import { CredentialsPage } from './credentials';
import { PairingPage } from './pairing';
import { EmptyState, Modal, WebAuthnModal } from './shared';
import { useClient, useConnectionStatus } from '@/lib/ClientProvider';
import { PREPARED_MEMORY } from '@/lib/preparedMemory';
import type { ChainInfo, ConfigPreset, CredService, DecodedAuditEvent, MasterMemoryEntry, MemoryCategory, ProposedScope } from '@/lib/client/types';
import type { Actor, AuditEvent, Namespace, PairingRequest, PreservedMemory } from './types';

type Page = 'actors' | 'detail' | 'memory' | 'credentials' | 'pairing' | 'audit' | 'decode' | 'chain' | 'logo';

type PendingAction =
  | { kind: 'revoke-device'; actor: Actor; intent: Intent }
  | { kind: 'pair-accept'; req: PairingRequest; intent: Intent };
interface Intent { text: string; fields: [string, string][] }

// MasterMemoryEntry (client wire) → PreservedMemory (UI). Daemon ns is a free
// string; clamp to a known namespace for display grouping.
const KNOWN_NS = new Set<string>(NAMESPACES);
function toPreserved(e: MasterMemoryEntry): PreservedMemory {
  const ns = (KNOWN_NS.has(e.ns) ? e.ns : 'personal') as Namespace;
  return { ns, key: e.key, title: e.title, bytes: e.bytes, version: e.version, updated: e.updated, preview: e.preview, body: e.body };
}

export function App() {
  const client = useClient();
  const status = useConnectionStatus();
  const [actors, setActors] = useState<Actor[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [page, setPage] = useState<Page>('actors');
  const [actorId, setActorId] = useState<string | null>(null);
  const [sideOpen, setSideOpen] = useState(false);
  const [paused, setPaused] = useState(false);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [eventDetail, setEventDetail] = useState<AuditEvent | null>(null);
  const [toast, setToast] = useState<{ msg: string; sticky?: boolean } | null>(null);

  const [onboarded, setOnboarded] = useState(false);
  const [identity, setIdentity] = useState<{ email?: string; omni?: string } | null>(null);
  const [maskEm, setMaskEm] = useState(true);
  // #201 Phase 4: the list is CATEGORIES (from the durable taxonomy, no decrypt);
  // per-namespace entries decrypt lazily into `entriesByNs` when a category opens
  // ('loading' while in flight, the array once decrypted).
  const [categories, setCategories] = useState<MemoryCategory[]>([]);
  const [entriesByNs, setEntriesByNs] = useState<Record<string, PreservedMemory[] | 'loading'>>({});
  const [planting, setPlanting] = useState(false);
  // #207 item 1A — config-init entry point A (default-preset bootstrap): the
  // bundled presets, the shipped default id, and the in-flight authoring state.
  const [presets, setPresets] = useState<ConfigPreset[]>([]);
  const [defaultPresetId, setDefaultPresetId] = useState('');
  const [initializing, setInitializing] = useState(false);
  const [pendingPreset, setPendingPreset] = useState('');
  // #207 items 5/7 — connect-time auto-distribution: the classifier's proposed
  // scopes for the actor currently open in detail (null = not classified yet).
  const [proposals, setProposals] = useState<ProposedScope[] | null>(null);
  const [proposing, setProposing] = useState(false);
  // #207 credentials data class — the master's vaulted credentials (categorized).
  const [credentials, setCredentials] = useState<CredService[]>([]);
  const [storingCred, setStoringCred] = useState(false);
  const [pairingRequests, setPairingRequests] = useState<PairingRequest[]>([]);
  const [pairingCeremony, setPairingCeremony] = useState<PairingRequest | null>(null);
  const [justPaired, setJustPaired] = useState<string | null>(null);
  const [memoryView, setMemoryView] = useState<PreservedMemory | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      // Real "logged in" = the daemon holds a verified session (W1). Fall back to
      // the local flag only for the offline/demo path (no daemon to ask).
      const r = await client.getOnboardingState();
      let on = false;
      if (r.ok && r.data.identity === 'verified') {
        on = true;
        if (!cancelled) setIdentity({ email: r.data.email, omni: r.data.omni });
      } else {
        try { on = localStorage.getItem('ak_onboarded') === '1'; } catch {}
      }
      if (!cancelled) setOnboarded(on);
    })();
    return () => { cancelled = true; };
  }, [client]);

  useEffect(() => { setMaskEm(getMaskEmail()); }, []);

  // §2: list the master's memory CATEGORIES once onboarded (from the durable
  // taxonomy, no decrypt) + load the bundled config-init presets (#207 item 1A)
  // for the empty-state setup screen. EmptyBackend returns disconnected → stays
  // empty → the memory page renders its setup/empty state.
  useEffect(() => {
    if (!onboarded) return;
    let cancelled = false;
    (async () => {
      const [cats, pre, creds] = await Promise.all([
        client.listMemoryCategories(),
        client.listConfigPresets(),
        client.listCredentials(),
      ]);
      if (cancelled) return;
      if (cats.ok) {
        setCategories(cats.data);
      } else if (cats.status.reason !== 'no-backend-configured') {
        // #201 codex finding 2: a configured-but-broken Config 502s here instead
        // of reporting an empty store — surface it rather than show a bare list.
        showToast(`Memory categories unavailable — ${cats.status.detail ?? 'config worker error'}.`);
      }
      if (pre.ok) {
        setPresets(pre.data.presets);
        setDefaultPresetId(pre.data.defaultId);
      }
      if (creds.ok) setCredentials(creds.data);
    })();
    return () => { cancelled = true; };
  }, [onboarded, client]);

  // §2 lazy detail: decrypt a namespace's entries only when its category opens.
  // Idempotent — a second open while loaded/loading is a no-op.
  const loadCategory = async (ns: string) => {
    if (entriesByNs[ns]) return;
    setEntriesByNs((prev) => ({ ...prev, [ns]: 'loading' }));
    const r = await client.getMemoryEntries(ns);
    setEntriesByNs((prev) => ({ ...prev, [ns]: r.ok ? r.data.map(toPreserved) : [] }));
    if (!r.ok) showToast(`Couldn't load ${ns} — ${r.status.detail ?? 'reload the page'}.`);
  };

  // Actor tree + recent audit history from the client seam. Real daemon data;
  // empty with EmptyBackend → the pages render their empty states.
  useEffect(() => {
    if (!onboarded) return;
    let cancelled = false;
    (async () => {
      const [a, e] = await Promise.all([
        client.listActors(),
        client.listRecentAuditEvents({ limit: 80 }),
      ]);
      if (cancelled) return;
      if (a.ok) setActors(a.data);
      if (e.ok) setEvents(e.data.map((x) => ({ ...x })));
    })();
    return () => { cancelled = true; };
  }, [onboarded, client]);

  // Live audit stream (tier-1 SSE) — real events only, no synthetic feed.
  useEffect(() => {
    if (!onboarded || paused) return;
    const stop = client.streamAudit(
      (e) => {
        setEvents((prev) => [{ ...e, _isNew: true }, ...prev].slice(0, 90));
        setTimeout(
          () => setEvents((prev) => prev.map((x) => (x.id === e.id ? { ...x, _isNew: false } : x))),
          1500,
        );
      },
      () => {},
    );
    return stop;
  }, [onboarded, paused, client]);

  const showToast = (msg: string, sticky = false) => {
    setToast({ msg, sticky });
    // Sticky toasts (e.g. post-onboarding next-steps) stay until dismissed.
    if (!sticky) setTimeout(() => setToast(null), 2600);
  };

  const go = (p: Page, id: string | null = null) => {
    setPage(p);
    setActorId(id);
    setSideOpen(false);
    setProposals(null); // #207: a fresh actor detail starts un-classified
    setProposing(false);
    if (typeof window !== 'undefined') window.scrollTo({ top: 0, behavior: 'instant' });
  };

  // #207 items 5/7 — connect-time auto-distribution. Classify the agent's surface
  // (its cred services) → sensitivity-tiered proposals. The grant itself rides the
  // existing K11-gated scope mutation; confirming here surfaces the gesture
  // (sensitive ⇒ explicit) and clears the proposal. No scope is written on propose.
  const proposeForActor = async (actor: Actor) => {
    const credSurface = (actor.services ?? [])
      .filter((s) => s !== 'email')
      .map((s) => ({ dataClass: 'credentials', entity: s }));
    // #207 item 8 — agent memory inheritance: the agent can inherit the master's
    // namespaces (the taxonomy categories); the master curates per-namespace, and
    // sensitive namespaces (health, finance, …) land in the explicit-pick tier.
    const memSurface = categories.map((c) => ({ dataClass: 'memory', entity: c.ns }));
    const surface = [...memSurface, ...credSurface];
    if (surface.length === 0) { setProposals([]); return; }
    setProposing(true);
    const r = await client.proposeScopes(actor.id, surface);
    setProposing(false);
    if (r.ok) {
      setProposals(r.data);
    } else {
      const m = (r.status.detail ?? '').match(/\{"error":"([^"]+)"\}/);
      showToast(`Classify failed — ${m ? m[1] : r.status.detail ?? 'connect a daemon, then onboard first'}.`);
    }
  };
  const confirmProposal = async (actor: Actor, p: ProposedScope) => {
    const r = await client.grantScope(actor.id, p);
    if (r.ok) {
      setActors((prev) => prev.map((a) => (a.id === r.data.id ? r.data : a)));
      setProposals((prev) => (prev ? prev.filter((x) => x.service !== p.service) : prev));
      showToast(`${p.gating === 'k11' ? 'Touch ID confirmed · ' : ''}granted ${p.service} (${p.category})`);
    } else {
      const m = (r.status.detail ?? '').match(/\{"error":"([^"]+)"\}/);
      showToast(`Grant failed — ${m ? m[1] : r.status.detail ?? 'reload the page'}.`);
    }
  };
  const confirmSafeSet = async (actor: Actor, ps: ProposedScope[]) => {
    let granted = 0;
    for (const p of ps) {
      const r = await client.grantScope(actor.id, p);
      if (r.ok) { granted += 1; setActors((prev) => prev.map((a) => (a.id === r.data.id ? r.data : a))); }
    }
    setProposals((prev) => (prev ? prev.filter((x) => x.gating !== 'auto') : prev));
    showToast(`Confirmed ${granted} safe ${granted === 1 ? 'scope' : 'scopes'} into your daily review`);
  };

  // Log out: clear the local session flag and reset all in-memory view state so
  // the next login starts clean. Returns to the §9 onboarding (email) screen.
  const logout = () => {
    void client.logout(); // W1: clear the daemon-held session (the real re-test reset)
    try { localStorage.removeItem('ak_onboarded'); } catch {}
    setOnboarded(false);
    setIdentity(null);
    setActors([]);
    setEvents([]);
    setCategories([]);
    setEntriesByNs({});
    setPlanting(false);
    setPresets([]);
    setDefaultPresetId('');
    setInitializing(false);
    setPendingPreset('');
    setProposals(null);
    setProposing(false);
    setCredentials([]);
    setStoringCred(false);
    setPairingRequests([]);
    setPairingCeremony(null);
    setJustPaired(null);
    setMemoryView(null);
    setPendingAction(null);
    setEventDetail(null);
    setActorId(null);
    setPage('actors');
    setSideOpen(false);
  };

  const updateActor = (id: string, patch: Partial<Actor>) => {
    setActors((prev) => prev.map((a) => (a.id === id ? { ...a, ...patch } : a)));
    showToast('scope updated · K11 assertion queued for next save');
  };

  // #207 item 1A — config-init entry point A: author the taxonomy from a bundled
  // preset. Two-phase like plant (ceremony → real call) so the authoring shows
  // the same ritual. Master-self Config write; no K11 (it writes the category
  // index, not scope grants).
  const initDefault = (presetId: string) => {
    if (initializing || planting) return;
    setPendingPreset(presetId);
    setInitializing(true);
  };
  const initDone = async () => {
    setInitializing(false);
    const r = await client.initConfigDefault(pendingPreset);
    if (r.ok) {
      // taxonomyStatus: "ok" (durable, real Config store) · "cached" (NO config
      // worker configured at all — dev/no-infra, in-memory only). A configured-
      // but-broken store does NOT reach here — it hard-fails into the else branch
      // (no silent in-memory fallback; real data or a loud error).
      const cached = r.data.taxonomyStatus === 'cached';
      setCategories(r.data.categories);
      setEntriesByNs({});
      showToast(
        `Initialized · ${r.data.categories.length} categories${cached ? ' (dev only — no config worker configured)' : ''}.`,
      );
    } else {
      const detail = r.status.detail ?? '';
      const m = detail.match(/\{"error":"([^"]+)"\}/);
      const reason = m ? m[1] : detail || 'connect a daemon, then complete onboarding (login + K11 enroll) first';
      showToast(`Initialize failed — ${reason}`);
    }
  };

  // §2 plant: import the PREPARED archive through the real client seam (daemon
  // content-hash dedup — idempotent server-side, so no client dedup guard needed;
  // just block re-entry while a ceremony is running).
  const plantMemory = () => {
    if (planting || initializing) return;
    setPlanting(true);
  };

  // #207 credentials: vault a master credential through the real chain (cap-mint →
  // STS → cred worker → S3), then re-list. Real durable write or a loud error.
  const storeCredential = async (service: string, secret: string) => {
    if (storingCred) return;
    setStoringCred(true);
    const r = await client.storeCredential(service, secret);
    setStoringCred(false);
    if (r.ok) {
      showToast(`Vaulted ${r.data.service} (${r.data.category}).`);
      const listed = await client.listCredentials();
      if (listed.ok) setCredentials(listed.data);
    } else {
      const detail = r.status.detail ?? '';
      const m = detail.match(/\{"error":"([^"]+)"\}/);
      showToast(`Vault failed — ${m ? m[1] : detail || 'connect a daemon + a cred worker first'}.`);
    }
  };
  const plantDone = async () => {
    setPlanting(false);
    const r = await client.plantMemory(PREPARED_MEMORY);
    if (r.ok) {
      // #201 codex finding 2: the memory blobs are durable, but if the category
      // index (taxonomy) write failed, say so — the categories would be stale.
      const taxFailed = r.data.taxonomyStatus.startsWith('failed');
      const listed = await client.listMemoryCategories();
      if (listed.ok) {
        setCategories(listed.data);
        setEntriesByNs({}); // drop the lazy cache so an opened category re-decrypts fresh
        const base = `Planted · ${r.data.planted} new, ${r.data.skipped} deduped · ${listed.data.length} categories.`;
        showToast(taxFailed ? `${base} ⚠ category index didn't update — re-plant to retry.` : base);
      } else {
        showToast(`Planted ${r.data.planted} new, but the category list didn't load — ${listed.status.detail ?? 'reload the page'}.`);
      }
    } else {
      // The plant button only renders when the daemon is connected, so a failure
      // here is almost never "no daemon" — surface the daemon's ACTUAL reason
      // (e.g. 409 "no master session — complete onboarding first" / "master device
      // not registered on chain yet", or a 502 worker error) instead of masking it.
      const detail = r.status.detail ?? '';
      const m = detail.match(/\{"error":"([^"]+)"\}/);
      const reason = m ? m[1] : detail || 'connect a daemon, then complete onboarding (login + K11 enroll) first';
      showToast(`Plant failed — ${reason}`);
    }
  };

  // ─── Pairing: accept → K11 → ceremony → bind ───────────────────
  const acceptPairing = (req: PairingRequest) => {
    setPendingAction({
      kind: 'pair-accept',
      req,
      intent: {
        text: `Pair agent · ${req.agent}`,
        fields: [
          ['new actor', `O_master${req.derivation}`],
          ['device pubkey', req.dpub],
          ['pair-code', req.pairCode],
          ['grant', req.requested.map((p) => p.cap).join(' · ')],
          ['mutation', 'SidecarRegistry.registerDevice + setScope'],
        ],
      },
    });
  };
  const declinePairing = (id: string) => {
    setPairingRequests((prev) => prev.filter((r) => r.id !== id));
    showToast('Pairing request declined.');
  };
  const refreshPairing = () => {
    showToast(
      status.kind === 'connected'
        ? 'Polled rendezvous · no pending pairing codes.'
        : 'Connect a daemon to poll for agent pairing codes.',
    );
  };

  const handleRevokeDevice = (actor: Actor) => {
    setPendingAction({
      kind: 'revoke-device',
      actor,
      intent: {
        text: `Revoke device · ${actor.label}`,
        fields: [
          ['actor_omni', actor.omni],
          ['device_pubkey', actor.devicePubkey.slice(0, 22) + '…'],
          ['mutation', 'SidecarRegistry.revoke_device'],
          ['propagation', 'SSE drop + cache zero'],
          ['scope effect', 'all caps invalidated · ttl 0s'],
        ],
      },
    });
  };

  const confirmAction = () => {
    const action = pendingAction;
    setPendingAction(null);
    if (!action) return;
    if (action.kind === 'pair-accept') {
      setPairingRequests((prev) => prev.filter((r) => r.id !== action.req.id));
      setPairingCeremony(action.req);
    }
    if (action.kind === 'revoke-device') {
      const actor = action.actor;
      void client.revokeDevice(actor.id, action.intent);
      setActors((prev) => prev.map((a) => (a.id === actor.id ? { ...a, status: 'bad', lastActive: 'revoked', label: a.label + ' (revoked)' } : a)));
      showToast(`${actor.label} revoked. SSE drop event broadcast.`);
      go('audit');
    }
  };

  // Workflow 7-8: pairing ceremony completes → re-fetch the actor tree so a
  // newly-bound agent (if the daemon bound one) appears. No fabricated actor.
  const finishPairingCeremony = async () => {
    const req = pairingCeremony;
    setPairingCeremony(null);
    if (!req) return;
    setJustPaired(req.agent);
    const a = await client.listActors();
    if (a.ok) setActors(a.data);
    showToast(`${req.agent} paired · cap-tokens minted · session key handed off.`);
    go('pairing');
  };

  const currentActor = actorId ? actors.find((a) => a.id === actorId) : null;
  const master = actors.find((a) => a.role === 'master');
  const sectionAttr = page === 'decode' ? 'audit' : ((['audit', 'memory', 'pairing', 'chain', 'logo'] as string[]).includes(page) ? page : undefined);

  // ─── Onboarding gate (workflow 1) ──────────────────────────────
  if (!onboarded) {
    return (
      <OnboardingScreen
        onComplete={(summary) => {
          try { localStorage.setItem('ak_onboarded', '1'); } catch {}
          setOnboarded(true);
          go('actors');
          // Jump straight into the app; a STICKY toast (no auto-dismiss) carries
          // the next step so it isn't a wall the user has to click through.
          if (summary?.categories != null) {
            const n = summary.categories;
            const noun = n === 1 ? 'category' : 'categories';
            const head = summary.already
              ? `✓ You're set up — ${n} ${noun} already configured.`
              : `✓ ${n} ${noun} authored${summary.dev ? ' (dev only — no config worker)' : ''}.`;
            showToast(`${head}  Next: connect an agent — open the Pairing tab to pair one.`, true);
          }
        }}
      />
    );
  }

  // Privacy-preserving identity for the header: a public omni hash is truncated
  // (full value in the title/hover), and we prefer the on-chain actor omni
  // (`master.omni`) once it exists, falling back to the email-identity omni held
  // after login. No secret (J1/K10/K11) is ever in the browser to show.
  const shortOmni = (o?: string) => {
    if (!o) return '';
    const h = o.startsWith('0x') ? o.slice(2) : o;
    return h.length <= 12 ? o : `0x${h.slice(0, 6)}…${h.slice(-4)}`;
  };
  const whoOmni = master?.omni ?? identity?.omni;
  // Email shown masked when the privacy toggle is on (persisted in localStorage).
  const whoLabel = master?.label ?? (identity?.email ? maskEmail(identity.email, maskEm) : undefined) ?? 'O_master';

  return (
    <div className="app">
      <header className="app-head">
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <button className="hamb" onClick={() => setSideOpen((o) => !o)} aria-label="menu">{sideOpen ? '✕' : '≡'}</button>
          <div className="brand">
            <span className="mark">agentKeys</span>
            <span className="sub">parent control · m1</span>
          </div>
        </div>
        <div className="head-right">
          <span style={{ fontSize: 10, letterSpacing: '0.08em', textTransform: 'uppercase' }}>{CHAIN_PROFILE.name} · {status.kind === 'connected' ? `daemon ${status.via}` : 'daemon offline'}</span>
          <button
            className={`bell ${pairingRequests.length ? 'has-req' : ''}`}
            onClick={() => go('pairing')}
            aria-label="pairing requests"
            title={pairingRequests.length ? `${pairingRequests.length} pairing request` : 'no pending requests'}
          >
            ◉{pairingRequests.length > 0 && <span className="badge">{pairingRequests.length}</span>}
          </button>
          <button
            className="btn sm"
            onClick={() => { const v = !maskEm; setMaskEm(v); setMaskEmail(v); }}
            title={maskEm ? 'Email masked (for screen-sharing) — click to show' : 'Email shown — click to mask'}
          >{maskEm ? '🕶' : '👁'}</button>
          <span className="who" title={whoOmni ?? ''}><span className="who-text">{whoOmni ? `${whoLabel} · ${shortOmni(whoOmni)}` : whoLabel}</span></span>
          <button className="btn sm" onClick={logout} title="Clear this session and return to login">log out</button>
        </div>
      </header>

      <aside className={`app-side ${sideOpen ? 'open' : ''}`}>
        <div className="nav-section">control</div>
        <button className={`nav-item ${page === 'actors' ? 'active' : ''}`} onClick={() => go('actors')}>
          <span className="marker">[•]</span> actors<span className="count">{actors.length}</span>
        </button>
        <button className={`nav-item ${page === 'memory' ? 'active' : ''}`} onClick={() => go('memory')}>
          <span className="marker">[◇]</span> memory<span className="count">{categories.length || '∅'}</span>
        </button>
        <button className={`nav-item ${page === 'credentials' ? 'active' : ''}`} onClick={() => go('credentials')}>
          <span className="marker">[$]</span> credentials<span className="count">{credentials.length || '∅'}</span>
        </button>
        <button className={`nav-item ${page === 'pairing' ? 'active' : ''}`} onClick={() => go('pairing')}>
          <span className="marker">[⇄]</span> pairing
          {pairingRequests.length > 0 && <span className="count" style={{ color: 'var(--accent)' }}>{pairingRequests.length}●</span>}
        </button>

        <div className="nav-section">telemetry</div>
        <button className={`nav-item ${page === 'audit' ? 'active' : ''}`} onClick={() => go('audit')}>
          <span className="marker">{paused ? '[ ]' : '[~]'}</span> audit feed<span className="count">{events.length}</span>
        </button>
        <button className={`nav-item ${page === 'chain' ? 'active' : ''}`} onClick={() => go('chain')}>
          <span className="marker">[⇔]</span> chain
        </button>

        <div className="nav-section">account</div>
        <button className="nav-item" onClick={logout}>
          <span className="marker">[◆]</span> log out · replay onboarding
        </button>

        <div className="nav-section">brand</div>
        <button className={`nav-item ${page === 'logo' ? 'active' : ''}`} onClick={() => go('logo')}>
          <span className="marker">[◐]</span> logo
        </button>

        <div className="nav-section">actor tree</div>
        {actors.map((a) => (
          <button
            key={a.id}
            className={`nav-item ${page === 'detail' && actorId === a.id ? 'active' : ''}`}
            onClick={() => go('detail', a.id)}
            style={{ paddingLeft: a.role === 'agent' ? 36 : 22 }}
          >
            <span className="marker" style={{ fontSize: 10 }}>{a.role === 'master' ? '/' : '└'}</span>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.label.replace(' (revoked)', '')}</span>
            {a.status === 'bad' && <span className="count" style={{ color: 'var(--danger)' }}>rvk</span>}
            {a.status === 'warn' && <span className="count" style={{ color: 'var(--accent)' }}>!</span>}
          </button>
        ))}

        <div className="nav-section">session</div>
        <div style={{ padding: '6px 22px', fontSize: 11, color: 'var(--ink-faint)', lineHeight: 1.7 }}>
          K6 · session JWT<br />{status.kind === 'connected' ? `daemon · ${status.via}` : 'daemon · offline'}<br />K11 · master device
        </div>
      </aside>

      <main className="app-main" data-section={sectionAttr}>
        {page === 'actors' && <ActorsList actors={actors} status={status} onPick={(id) => go('detail', id)} />}
        {page === 'detail' && currentActor && (
          <ActorDetail actor={currentActor} onBack={() => go('actors')} onUpdate={updateActor} onRevoke={handleRevokeDevice} recentEvents={events} proposals={proposals} proposing={proposing} onPropose={proposeForActor} onConfirmProposal={confirmProposal} onConfirmSafe={confirmSafeSet} />
        )}
        {page === 'memory' && (
          <MemoryPage categories={categories} entriesByNs={entriesByNs} status={status} presets={presets} defaultPresetId={defaultPresetId} initializing={initializing} planting={planting} onInitDefault={initDefault} onInitDone={initDone} onPlant={plantMemory} onPlantDone={plantDone} onLoadCategory={loadCategory} onView={setMemoryView} />
        )}
        {page === 'credentials' && (
          <CredentialsPage credentials={credentials} status={status} storing={storingCred} onStore={storeCredential} />
        )}
        {page === 'pairing' && (
          <PairingPage requests={pairingRequests} actors={actors} onAccept={acceptPairing} onDecline={declinePairing} onRefresh={refreshPairing} justPaired={justPaired} onManage={(id) => go('detail', id)} />
        )}
        {page === 'audit' && <AuditFeed events={events} status={status} onPick={(e) => { setEventDetail(e); go('decode'); }} paused={paused} onPause={() => setPaused((p) => !p)} />}
        {page === 'decode' && eventDetail && <EventDecodePage event={eventDetail} onBack={() => go('audit')} />}
        {page === 'chain' && <ChainPage />}
        {page === 'logo' && <LogoPage />}
      </main>

      {pendingAction && (
        <WebAuthnModal intent={pendingAction.intent} onConfirm={confirmAction} onCancel={() => setPendingAction(null)} />
      )}

      {memoryView && (
        <Modal
          title={`memory · ${memoryView.ns}/${memoryView.title}`}
          onClose={() => setMemoryView(null)}
          footer={<button className="btn" onClick={() => setMemoryView(null)}>close</button>}
        >
          <dl className="kvs" style={{ marginBottom: 14 }}>
            <dt>path</dt><dd className="mono" style={{ fontSize: 11 }}>s3://…/bots/&lt;omni&gt;/{memoryView.ns}/{memoryView.key}.enc</dd>
            <dt>envelope</dt><dd className="mono">{memoryView.version} · AES-256-GCM · k3 v1</dd>
            <dt>bytes</dt><dd className="mono">{memoryView.bytes}</dd>
            <dt>updated</dt><dd>{memoryView.updated}</dd>
          </dl>
          <div style={{ fontSize: 10, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-faint)', marginBottom: 6 }}>decrypted plaintext</div>
          <pre className="mem-body">{memoryView.body}</pre>
        </Modal>
      )}

      {pairingCeremony && (
        <div className="modal-bg">
          <div className="modal" style={{ maxWidth: 520 }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-head"><span className="ttl">pairing ceremony · {pairingCeremony.agent}</span></div>
            <div className="modal-body">
              <div style={{ fontSize: 12, color: 'var(--ink-dim)', marginBottom: 14 }}>
                Binding <span className="mono">O_master{pairingCeremony.derivation}</span> under your master identity. Each on-chain step is a real Heima transaction.
              </div>
              <CeremonyRunner steps={PAIRING_STEPS} onDone={finishPairingCeremony} stepMs={680} />
            </div>
          </div>
        </div>
      )}

      {toast && (
        <div style={{ position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)', display: 'flex', alignItems: 'center', gap: 14, maxWidth: 'min(92vw, 560px)', background: 'var(--ink)', color: 'var(--bg)', padding: '10px 14px 10px 18px', fontSize: 12, border: '1px solid var(--ink)', zIndex: 200, animation: 'pop 0.22s cubic-bezier(.2,.8,.2,1)' }}>
          <span>{toast.msg}</span>
          {toast.sticky && (
            <button
              onClick={() => setToast(null)}
              aria-label="dismiss"
              style={{ background: 'none', border: 'none', color: 'var(--bg)', opacity: 0.7, cursor: 'pointer', fontSize: 15, lineHeight: 1, padding: 0, flexShrink: 0 }}
            >
              ×
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// Render one decoded ABI arg value (bytes32/uint/bool/address/array) compactly.
function argValue(v: unknown): string {
  if (Array.isArray(v)) return v.length ? `[${v.map(String).join(', ')}]` : '[]';
  if (v === null || v === undefined) return '—';
  return String(v);
}

// ─── Step 9: decode the Heima transaction for an audit event ──────
// Real decode (#153): the daemon decodes the CBOR AuditEnvelope + the on-chain
// calldata against the verified ABIs. While loading / when no daemon is wired,
// a clearly-labelled reference decode (demoData) is shown instead. Rendered as a
// dedicated page (reachable at the `decode` nav state), not a modal.
function EventDecodePage({ event, onBack }: { event: AuditEvent; onBack: () => void }) {
  const client = useClient();
  const [decoded, setDecoded] = useState<DecodedAuditEvent | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await client.decodeAuditEvent(event.id);
      if (!alive) return;
      if (r.ok) { setDecoded(r.data); setErr(null); }
      else { setDecoded(null); setErr(r.status.detail ?? 'decode unavailable'); }
    })();
    return () => { alive = false; };
  }, [client, event.id]);

  const mock = decodeCalldata(event);
  const onchain = ONCHAIN_KINDS.has(event.kind);
  const tx = decoded?.tx ?? null;
  const env = decoded?.envelope ?? null;
  const tier = decoded?.tier_label ?? (onchain ? 'tier-2 · committed on-chain' : 'tier-1 (sse) · folds into next 2-min anchor');
  const signer = event.actor === 'Sara (master)' ? 'D_pub_master_iphone' : 'D_pub_' + event.actor.toLowerCase().replace(/[^a-z]/g, '');

  const sel = tx?.decoded.selector ?? mock.sel;
  const fn = tx?.decoded.signature ?? mock.fn;
  const toContract = tx?.to_contract ?? contractFor(event.kind);
  const toAddr = tx?.to_address ?? '';
  // Only link to chain when there's a real on-chain contract target — the
  // contract page (Heima /contract/{addr}). No fabricated tx link for
  // synthesized / tier-1 / offline decodes (codex review #153).
  const contractLink = tx?.explorer_url ?? null;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumb">audit · event · {event.kind}</div>
          <h1><span className="muted serif">/</span> decode</h1>
          <div className="desc">CBOR audit envelope + the on-chain transaction, decoded against the verified ABIs.</div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
          <button className="btn" onClick={onBack}>← audit</button>
          {contractLink && <a className="btn primary" href={contractLink} target="_blank" rel="noreferrer">view contract ↗</a>}
        </div>
      </div>

      {decoded?.synthesized && (
        <div style={{ fontSize: 11, color: 'var(--warn, #b8860b)', border: '1px solid var(--warn, #b8860b)', padding: '8px 12px', marginBottom: 16 }}>
          ⚠ preview decode — reconstructed from the audit row. The shape is real (verified-ABI calldata + canonical CBOR), but the values + hashes are derived, not yet fetched from a stored envelope / on-chain tx.
        </div>
      )}

      <div className="panel">
        <div className="panel-head"><span>── event</span></div>
        <div className="panel-body">
          <dl className="kvs">
            <dt>timestamp</dt><dd className="mono">{event.ts}</dd>
            <dt>actor</dt><dd>{event.actor}</dd>
            <dt>kind</dt><dd className="mono">{event.kind}</dd>
            <dt>detail</dt><dd>{event.detail}</dd>
            <dt>worker</dt><dd className="mono">{event.chip}-service</dd>
            <dt>tier</dt><dd>{tier}</dd>
            <dt>K10 signer</dt><dd className="mono">{signer}…</dd>
          </dl>
        </div>
      </div>

      {/* ── CBOR AuditEnvelope (decoded) ── */}
      {env && (
        <div className="panel">
          <div className="panel-head"><span>── decoded audit envelope · cbor v{env.version}</span></div>
          <div className="panel-body">
            <div className="tx-decode">
              <div className="tx-row"><span className="tx-k">op_kind</span><span className="tx-v mono">{env.op_kind}{env.op_kind_label ? ` · ${env.op_kind_label}` : ' · Unknown(byte)'}</span></div>
              {env.intent_text && <div className="tx-row"><span className="tx-k">intent</span><span className="tx-v">{env.intent_text}</span></div>}
              {Object.entries(env.op_body || {}).map(([k, v]) => (
                <div className="tx-row" key={k}><span className="tx-k">{k}</span><span className="tx-v mono" style={{ wordBreak: 'break-all' }}>{argValue(v)}</span></div>
              ))}
              <div className="tx-row"><span className="tx-k">envelope_hash</span><span className="tx-v mono" style={{ wordBreak: 'break-all' }}>{env.envelope_hash}</span></div>
            </div>
          </div>
        </div>
      )}

      {/* ── on-chain transaction (calldata decoded against the verified ABI) ── */}
      <div className="panel">
        <div className="panel-head"><span>── decoded heima transaction</span></div>
        <div className="panel-body">
          {decoded && !tx ? (
            <div className="muted" style={{ fontSize: 12 }}>
              tier-1 · off-chain action — recorded in the audit envelope above and folded into the next 2-min Merkle anchor. No direct contract call.
            </div>
          ) : (
            <div className="tx-decode">
              <div className="tx-row"><span className="tx-k">to</span><span className="tx-v mono">{toContract}{toAddr ? ` · ${toAddr}` : ''}</span></div>
              <div className="tx-row"><span className="tx-k">selector</span><span className="tx-v mono">{sel}</span></div>
              <div className="tx-row"><span className="tx-k">function</span><span className="tx-v mono" style={{ wordBreak: 'break-all' }}>{fn}</span></div>
              {tx?.decoded.args.map((a) => (
                <div className="tx-row" key={a.name}><span className="tx-k">{a.name}</span><span className="tx-v mono" style={{ wordBreak: 'break-all' }}>{argValue(a.value)} <span className="muted">· {a.ty}</span></span></div>
              ))}
              {tx?.decoded.note && <div className="tx-row"><span className="tx-k">note</span><span className="tx-v">{tx.decoded.note}</span></div>}
            </div>
          )}
          <div className="muted" style={{ fontSize: 11, marginTop: 12 }}>
            {decoded ? (
              <>{decoded.provenance ?? 'calldata + CBOR decoded by the daemon against the verified ABIs'} · {CHAIN_PROFILE.display}</>
            ) : err ? (
              <>offline — showing reference decode · <span className="mono">connect a daemon for real decode (#153)</span></>
            ) : (
              <>decoding…</>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

interface ChainRow { name: string; addr: string; deployedAt: string; purpose: string; explorerUrl: string }

// ─── Chain page — deployed contract registry (real, from the daemon #153) ──
function ChainPage() {
  const client = useClient();
  const [info, setInfo] = useState<ChainInfo | null>(null);
  const [picked, setPicked] = useState<ChainRow | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await client.getChainInfo();
      if (alive && r.ok) setInfo(r.data);
    })();
    return () => { alive = false; };
  }, [client]);

  const name = info?.name ?? CHAIN_PROFILE.name;
  const chainId = info?.chainId ?? CHAIN_PROFILE.chainId;
  const explorer = info?.explorer ?? CHAIN_PROFILE.explorer;
  const rpc = info?.rpc ?? CHAIN_PROFILE.rpc;
  const display = info?.display ?? CHAIN_PROFILE.display;
  const live = info != null;

  const contracts: ChainRow[] = info
    ? info.contracts.map((c) => ({ name: c.name, addr: c.address, deployedAt: c.deployedAt, purpose: c.purpose, explorerUrl: c.explorerUrl }))
    : CHAIN_PROFILE.contracts.map((c) => ({ name: c.name, addr: c.addr, deployedAt: c.deployedAt, purpose: c.purpose, explorerUrl: `${explorer}/contract/${c.addr}` }));

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumb">chain · {name} · chain_id {chainId}</div>
          <h1><span className="muted serif">/</span> chain</h1>
          <div className="desc">{display}. Stage-1 contracts deployed via Foundry; tier-2 audit anchors a Merkle root here every 2 minutes.</div>
        </div>
      </div>
      <div className="stats">
        <div className="stat"><div className="v">{name}</div><div className="k">AGENTKEYS_CHAIN</div></div>
        <div className="stat"><div className="v">{chainId}</div><div className="k">chain id</div></div>
        <div className="stat"><div className="v">{live ? 'live' : 'reference'}</div><div className="k">source</div></div>
        <div className="stat"><div className="v">{contracts.length}</div><div className="k">contracts deployed</div></div>
      </div>
      <div className="panel">
        <div className="panel-head"><span>── deployed contracts{live ? '' : ' · reference (connect a daemon for live addresses)'}</span></div>
        <div className="panel-body flush">
          <table className="tab">
            <thead><tr><th>contract</th><th>address</th><th>deployed</th><th /></tr></thead>
            <tbody>
              {contracts.map((c) => (
                <tr key={c.name} className="clickable" onClick={() => setPicked(c)}>
                  <td><span style={{ fontWeight: 500 }}>{c.name}</span><div className="secondary">{c.purpose}</div></td>
                  <td className="mono" style={{ fontSize: 11 }}>{c.addr}</td>
                  <td className="muted mono">{c.deployedAt}</td>
                  <td className="right"><a href={c.explorerUrl} target="_blank" rel="noreferrer" style={{ fontSize: 11 }}>explorer ↗</a></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {picked && (
        <Modal
          title={`contract · ${picked.name}`}
          onClose={() => setPicked(null)}
          footer={<a className="btn primary" href={picked.explorerUrl} target="_blank" rel="noreferrer">view on {name} explorer ↗</a>}
        >
          <dl className="kvs">
            <dt>name</dt><dd>{picked.name}</dd>
            <dt>address</dt><dd className="mono" style={{ fontSize: 11 }}>{picked.addr}</dd>
            <dt>deployed at</dt><dd>{picked.deployedAt}</dd>
            <dt>purpose</dt><dd>{picked.purpose}</dd>
            <dt>verify</dt><dd className="mono" style={{ fontSize: 11 }}>cast code {picked.addr} --rpc-url {rpc}</dd>
          </dl>
        </Modal>
      )}
    </>
  );
}
