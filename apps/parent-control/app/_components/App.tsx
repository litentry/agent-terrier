'use client';

import { useEffect, useState } from 'react';
import {
  CHAIN_PROFILE,
  ONCHAIN_KINDS,
  PAIRING_STEPS,
  contractFor,
  decodeCalldata,
  txHash,
} from '@/lib/demoData';
import { NAMESPACES } from '@/lib/constants';
import { getMaskEmail, maskEmail, setMaskEmail } from '@/lib/maskEmail';
import { CeremonyRunner, OnboardingScreen } from './ceremony';
import { ActorDetail, ActorsList, AuditFeed } from './dashboard';
import { LogoPage } from './logos';
import { MemoryPage } from './memory';
import { PairingPage } from './pairing';
import { EmptyState, Modal, WebAuthnModal } from './shared';
import { useClient, useConnectionStatus } from '@/lib/ClientProvider';
import { PREPARED_MEMORY } from '@/lib/preparedMemory';
import type { MasterMemoryEntry, MemoryCategory } from '@/lib/client/types';
import type { Actor, AuditEvent, Namespace, PairingRequest, PreservedMemory } from './types';

type Page = 'actors' | 'detail' | 'memory' | 'pairing' | 'audit' | 'chain' | 'logo';

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
  const [toast, setToast] = useState<string | null>(null);

  const [onboarded, setOnboarded] = useState(false);
  const [identity, setIdentity] = useState<{ email?: string; omni?: string } | null>(null);
  const [maskEm, setMaskEm] = useState(true);
  // #201 Phase 4: the list is CATEGORIES (from the durable taxonomy, no decrypt);
  // per-namespace entries decrypt lazily into `entriesByNs` when a category opens
  // ('loading' while in flight, the array once decrypted).
  const [categories, setCategories] = useState<MemoryCategory[]>([]);
  const [entriesByNs, setEntriesByNs] = useState<Record<string, PreservedMemory[] | 'loading'>>({});
  const [planting, setPlanting] = useState(false);
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
  // taxonomy, no decrypt). EmptyBackend returns disconnected → stays empty → the
  // memory page renders its empty state.
  useEffect(() => {
    if (!onboarded) return;
    let cancelled = false;
    (async () => {
      const r = await client.listMemoryCategories();
      if (cancelled) return;
      if (r.ok) {
        setCategories(r.data);
      } else if (r.status.reason !== 'no-backend-configured') {
        // #201 codex finding 2: a configured-but-broken Config 502s here instead
        // of reporting an empty store — surface it rather than show a bare list.
        showToast(`Memory categories unavailable — ${r.status.detail ?? 'config worker error'}.`);
      }
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

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 2600);
  };

  const go = (p: Page, id: string | null = null) => {
    setPage(p);
    setActorId(id);
    setSideOpen(false);
    if (typeof window !== 'undefined') window.scrollTo({ top: 0, behavior: 'instant' });
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

  // §2 plant: import the PREPARED archive through the real client seam
  // (daemon content-hash dedup). Gated in the UI to connected + empty.
  const plantMemory = () => {
    if (categories.length > 0) return; // dedup guard — already planted
    setPlanting(true);
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
  const sectionAttr = (['audit', 'memory', 'pairing', 'chain', 'logo'] as string[]).includes(page) ? page : undefined;

  // ─── Onboarding gate (workflow 1) ──────────────────────────────
  if (!onboarded) {
    return (
      <OnboardingScreen
        onComplete={() => {
          try { localStorage.setItem('ak_onboarded', '1'); } catch {}
          setOnboarded(true);
          go('actors');
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
          <ActorDetail actor={currentActor} onBack={() => go('actors')} onUpdate={updateActor} onRevoke={handleRevokeDevice} recentEvents={events} />
        )}
        {page === 'memory' && (
          <MemoryPage categories={categories} entriesByNs={entriesByNs} status={status} planting={planting} onPlant={plantMemory} onPlantDone={plantDone} onLoadCategory={loadCategory} onView={setMemoryView} />
        )}
        {page === 'pairing' && (
          <PairingPage requests={pairingRequests} actors={actors} onAccept={acceptPairing} onDecline={declinePairing} onRefresh={refreshPairing} justPaired={justPaired} onManage={(id) => go('detail', id)} />
        )}
        {page === 'audit' && <AuditFeed events={events} status={status} onPick={setEventDetail} paused={paused} onPause={() => setPaused((p) => !p)} />}
        {page === 'chain' && <ChainPage />}
        {page === 'logo' && <LogoPage />}
      </main>

      {pendingAction && (
        <WebAuthnModal intent={pendingAction.intent} onConfirm={confirmAction} onCancel={() => setPendingAction(null)} />
      )}

      {eventDetail && <EventDecodeModal event={eventDetail} onClose={() => setEventDetail(null)} />}

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
        <div style={{ position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)', background: 'var(--ink)', color: 'var(--bg)', padding: '10px 18px', fontSize: 12, border: '1px solid var(--ink)', zIndex: 200, animation: 'pop 0.22s cubic-bezier(.2,.8,.2,1)' }}>
          {toast}
        </div>
      )}
    </div>
  );
}

// ─── Step 9: decode the Heima transaction for an audit event ──────
function EventDecodeModal({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  const dec = decodeCalldata(event);
  const onchain = ONCHAIN_KINDS.has(event.kind);
  const tx = txHash(event.id + event.kind);
  const signer = event.actor === 'Sara (master)' ? 'D_pub_master_iphone' : 'D_pub_' + event.actor.toLowerCase().replace(/[^a-z]/g, '');
  const toContract = contractFor(event.kind);
  return (
    <Modal
      title={`event · ${event.kind}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>close</button>
          <a className="btn primary" href={`${CHAIN_PROFILE.explorer}/tx/${tx}`} target="_blank" rel="noreferrer">view on heima ↗</a>
        </>
      }
    >
      <dl className="kvs">
        <dt>timestamp</dt><dd className="mono">{event.ts}</dd>
        <dt>actor</dt><dd>{event.actor}</dd>
        <dt>kind</dt><dd className="mono">{event.kind}</dd>
        <dt>detail</dt><dd>{event.detail}</dd>
        <dt>worker</dt><dd className="mono">{event.chip}-service</dd>
        <dt>tier</dt><dd>{onchain ? 'tier-2 · committed on-chain' : 'tier-1 (sse) · folds into next 2-min anchor'}</dd>
        <dt>K10 signer</dt><dd className="mono">{signer}…</dd>
      </dl>

      <div className="hr-ascii" style={{ margin: '14px 0' }}>{'─'.repeat(220)}</div>

      <div style={{ fontSize: 10, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-faint)', marginBottom: 8 }}>decoded heima transaction</div>
      <div className="tx-decode">
        <div className="tx-row"><span className="tx-k">tx_hash</span><span className="tx-v mono">{tx}</span></div>
        <div className="tx-row"><span className="tx-k">status</span><span className="tx-v">{onchain ? '✓ success · finalized' : 'tier-1 · not yet anchored'}</span></div>
        <div className="tx-row"><span className="tx-k">to</span><span className="tx-v mono">{toContract} · {CHAIN_PROFILE.contracts[0].addr.slice(0, 14)}…</span></div>
        <div className="tx-row"><span className="tx-k">selector</span><span className="tx-v mono">{dec.sel}</span></div>
        <div className="tx-row"><span className="tx-k">function</span><span className="tx-v mono">{dec.fn}</span></div>
        <div className="tx-row"><span className="tx-k">gas</span><span className="tx-v mono">{onchain ? '0.0009 HEI' : '— (off-chain)'}</span></div>
      </div>
      <div className="muted" style={{ fontSize: 10.5, marginTop: 10 }}>
        calldata decoded against verified ABI · {CHAIN_PROFILE.display} · <span className="mono">mock — real decode: GH #153</span>
      </div>
    </Modal>
  );
}

// ─── Lightweight chain page (deployed contracts + anchor countdown) ──
function ChainPage() {
  const p = CHAIN_PROFILE;
  const [picked, setPicked] = useState<(typeof p.contracts)[number] | null>(null);
  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumb">chain · {p.name} · chain_id {p.chainId}</div>
          <h1><span className="muted serif">/</span> chain</h1>
          <div className="desc">Four stage-1 contracts deployed via Foundry. Tier-2 audit anchors a Merkle root here every 2 minutes.</div>
        </div>
      </div>
      <div className="stats">
        <div className="stat"><div className="v">{p.name}</div><div className="k">AGENTKEYS_CHAIN</div></div>
        <div className="stat"><div className="v">{p.chainId}</div><div className="k">chain id</div></div>
        <div className="stat"><div className="v">{p.block}</div><div className="k">latest block</div></div>
        <div className="stat"><div className="v">{p.contracts.length}</div><div className="k">contracts deployed</div></div>
      </div>
      <div className="panel">
        <div className="panel-head"><span>── deployed contracts · stage-1</span></div>
        <div className="panel-body flush">
          <table className="tab">
            <thead><tr><th>contract</th><th>address</th><th>deployed</th><th /></tr></thead>
            <tbody>
              {p.contracts.map((c) => (
                <tr key={c.name} className="clickable" onClick={() => setPicked(c)}>
                  <td><span style={{ fontWeight: 500 }}>{c.name}</span><div className="secondary">{c.purpose}</div></td>
                  <td className="mono" style={{ fontSize: 11 }}>{c.addr}</td>
                  <td className="muted mono">{c.deployedAt}</td>
                  <td className="right"><a href={`${p.explorer}/address/${c.addr}`} target="_blank" rel="noreferrer" style={{ fontSize: 11 }}>explorer ↗</a></td>
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
          footer={<a className="btn primary" href={`${p.explorer}/address/${picked.addr}`} target="_blank" rel="noreferrer">view on {p.name} explorer ↗</a>}
        >
          <dl className="kvs">
            <dt>name</dt><dd>{picked.name}</dd>
            <dt>address</dt><dd className="mono" style={{ fontSize: 11 }}>{picked.addr}</dd>
            <dt>deployed at</dt><dd>{picked.deployedAt}</dd>
            <dt>purpose</dt><dd>{picked.purpose}</dd>
            <dt>verify</dt><dd className="mono" style={{ fontSize: 11 }}>cast code {picked.addr} --rpc-url {p.rpc}</dd>
          </dl>
        </Modal>
      )}
    </>
  );
}
