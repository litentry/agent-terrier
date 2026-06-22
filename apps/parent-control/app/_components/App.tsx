'use client';

import { useEffect, useState } from 'react';
import {
  clearMasterIdentity,
  ensureActiveChain,
  getMasterCredId,
  getOnboardedFlag,
  setActiveChain,
  setOnboardedFlag,
} from '@/lib/identityStore';
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
import type { ApiInboxItem } from '@/lib/generated/ApiInboxItem';
import { MemoryPage } from './memory';
import { CredentialsPage } from './credentials';
import { PairingPage } from './pairing';
import { getAssertionOverHash } from '@/lib/webauthn';
import { akLog } from '@/lib/debug';
import { EmptyState, Modal, WebAuthnModal } from './shared';
import { useClient, useConnectionStatus } from '@/lib/ClientProvider';
import { PREPARED_MEMORY } from '@/lib/preparedMemory';
import type { ChainInfo, ChainListEntry, ConfigPreset, CredService, DecodedAuditEvent, MasterMemoryEntry, MemoryCategory, ProposedScope } from '@/lib/client/types';
import type { Actor, AuditEvent, Namespace, PairingRequest, PreservedMemory } from './types';

// #242: does a daemon error detail mean the master J1 lapsed (vs a genuine
// missing-config / transport error)? The daemon says "master session expired —
// re-authenticate (one passkey prompt)…"; match that so we offer Touch ID re-auth
// rather than a dead-end toast. NOT triggered by partial-config errors.
const looksSessionExpired = (detail?: string): boolean =>
  !!detail && /session expired|re-?authenticate/i.test(detail);

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
  const [toast, setToast] = useState<{ msg: string; sticky?: boolean; action?: { label: string; fn: () => void } } | null>(null);

  const [onboarded, setOnboarded] = useState(false);
  const [identity, setIdentity] = useState<{ email?: string; omni?: string } | null>(null);
  const [maskEm, setMaskEm] = useState(true);
  // #201 Phase 4: the list is CATEGORIES (from the durable taxonomy, no decrypt);
  // per-namespace entries decrypt lazily into `entriesByNs` when a category opens
  // ('loading' while in flight, the array once decrypted).
  const [categories, setCategories] = useState<MemoryCategory[]>([]);
  const [entriesByNs, setEntriesByNs] = useState<Record<string, PreservedMemory[] | 'loading'>>({});
  const [planting, setPlanting] = useState(false);
  // #339 P2 — the absorption-inbox curate queue (delegate proposals awaiting the
  // master's accept-into-canonical or reject); `inboxBusy` blocks re-entry while
  // a curate action is in flight.
  const [inbox, setInbox] = useState<ApiInboxItem[]>([]);
  const [inboxBusy, setInboxBusy] = useState(false);
  // #242 — the master J1 can lapse while the user stays "logged in" (coords are
  // persisted). When a chain read 502s with "master session expired", surface a
  // Touch ID re-auth banner instead of a dead-end toast; ONE passkey prompt
  // restores the session (NO re-onboarding). `reloadKey` re-runs the data loads
  // after a successful re-auth.
  const [sessionExpired, setSessionExpired] = useState(false);
  const [reauthBusy, setReauthBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
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
  const [claiming, setClaiming] = useState(false);
  const [pairingRequests, setPairingRequests] = useState<PairingRequest[]>([]);
  const [pairingCeremony, setPairingCeremony] = useState<PairingRequest | null>(null);
  const [justPaired, setJustPaired] = useState<string | null>(null);
  const [memoryView, setMemoryView] = useState<PreservedMemory | null>(null);
  // The chain the daemon actually operates on (from /v1/chain/list), so the
  // header badge reflects the live AGENTKEYS_CHAIN instead of the build-time
  // CHAIN_PROFILE constant (which is always 'heima').
  const [daemonChain, setDaemonChain] = useState<string | null>(null);

  useEffect(() => {
    if (status.kind !== 'connected') { setDaemonChain(null); return; }
    let cancelled = false;
    (async () => {
      const r = await client.getChainList();
      if (!cancelled && r.ok) {
        setDaemonChain(r.data.daemonChain);
        // Bind the chain-scoped identity store to the daemon's operational chain
        // so master pointer reads/writes target THIS chain (Heima↔Base switch).
        setActiveChain(r.data.daemonChain);
      }
    })();
    return () => { cancelled = true; };
  }, [client, status.kind]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      // Bind the identity store to the daemon's chain before the offline-flag
      // read below, so the per-chain `ak_onboarded` resolves to THIS chain.
      await ensureActiveChain(async () => {
        const c = await client.getChainList();
        return c.ok ? c.data.daemonChain : null;
      });
      // Real "logged in" = the daemon holds a verified session (W1). Fall back to
      // the local flag only for the offline/demo path (no daemon to ask).
      const r = await client.getOnboardingState();
      let on = false;
      if (r.ok && r.data.identity === 'verified') {
        on = true;
        if (!cancelled) setIdentity({ email: r.data.email, omni: r.data.omni });
      } else {
        on = getOnboardedFlag();
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
      const [cats, pre, creds, inb] = await Promise.all([
        client.listMemoryCategories(),
        client.listConfigPresets(),
        client.listCredentials(),
        client.listInbox(),
      ]);
      if (cancelled) return;
      if (cats.ok) {
        setCategories(cats.data);
        setSessionExpired(false); // a successful chain read proves the J1 is live
      } else if (looksSessionExpired(cats.status.detail)) {
        // #242: the J1 lapsed (coords still persisted) — surface the Touch ID
        // re-auth banner, NOT a dead-end toast. ONE passkey prompt restores it.
        setSessionExpired(true);
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
      if (inb.ok) setInbox(inb.data);
    })();
    return () => { cancelled = true; };
  }, [onboarded, client, reloadKey]);

  // #339 P2 — re-fetch the curate queue (after an accept/reject, or on demand).
  const refreshInbox = async () => {
    const r = await client.listInbox();
    if (r.ok) setInbox(r.data);
  };

  // #242 — restore an expired master session with ONE Touch ID (no re-onboarding).
  // Mirrors the login screen's relogin ceremony: reloginStart mints a chain-bound
  // broker challenge, the BOUND passkey signs it, reloginFinish verifies on chain +
  // restores the daemon session; then re-run the data loads that 502'd while expired.
  const reauthenticate = async () => {
    if (reauthBusy) return;
    setReauthBusy(true);
    const start = await client.reloginStart();
    if (!start.ok) {
      setReauthBusy(false);
      showToast(`Re-authentication couldn't start — ${start.status.detail ?? 'daemon unreachable'}.`);
      return;
    }
    try {
      const assertion = await getAssertionOverHash(start.data.challenge, [getMasterCredId()]);
      const fin = await client.reloginFinish(start.data.challenge, assertion);
      if (fin.ok) {
        setSessionExpired(false);
        setReloadKey((k) => k + 1); // re-run the loads that failed while expired
        showToast('Session restored — no re-onboarding needed.');
      } else {
        showToast(
          `Re-authentication failed — ${fin.status.detail ?? 'rejected'}. If your master passkey was deleted, reset the master and re-onboard.`,
        );
      }
    } catch (e) {
      showToast(`Touch ID cancelled or failed — ${(e as Error)?.message ?? ''}.`);
    }
    setReauthBusy(false);
  };

  // #339 P2 — fetch one proposal's full body for the curate review (lazy: the
  // list carries only metadata). Returns the body, or throws so the panel can
  // surface the error.
  const viewInboxBody = async (s3Key: string): Promise<string> => {
    const r = await client.getInboxItem(s3Key);
    if (r.ok) return r.data.body;
    const detail = r.status.detail ?? '';
    const m = detail.match(/\{"error":"([^"]+)"\}/);
    throw new Error(m ? m[1] : detail || 'could not load the proposal body');
  };

  // #339 P2 — accept one proposal INTO canonical memory (merge + GC), then
  // refresh both the queue and the category list (a new namespace may appear).
  const acceptInboxItem = async (s3Key: string) => {
    if (inboxBusy) return;
    setInboxBusy(true);
    const r = await client.acceptInbox(s3Key);
    setInboxBusy(false);
    if (r.ok) {
      showToast(`Curated ${r.data.ns}/${r.data.key} into canonical (${r.data.planted} new).`);
      await refreshInbox();
      const listed = await client.listMemoryCategories();
      if (listed.ok) {
        setCategories(listed.data);
        setEntriesByNs({}); // drop the lazy cache so the updated namespace re-decrypts
      }
    } else {
      const detail = r.status.detail ?? '';
      const m = detail.match(/\{"error":"([^"]+)"\}/);
      showToast(`Accept failed — ${m ? m[1] : detail || 'connect a daemon + memory worker first'}.`);
    }
  };

  // #339 P2 — reject (discard) one proposal; it never enters canonical.
  const rejectInboxItem = async (s3Key: string) => {
    if (inboxBusy) return;
    setInboxBusy(true);
    const r = await client.rejectInbox(s3Key);
    setInboxBusy(false);
    if (r.ok) {
      showToast('Proposal discarded.');
      await refreshInbox();
    } else {
      const detail = r.status.detail ?? '';
      const m = detail.match(/\{"error":"([^"]+)"\}/);
      showToast(`Reject failed — ${m ? m[1] : detail || 'reload the page'}.`);
    }
  };

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

  const showToast = (msg: string, sticky = false, action?: { label: string; fn: () => void }) => {
    setToast({ msg, sticky, action });
    // Sticky toasts (e.g. post-onboarding next-steps) stay until dismissed.
    if (!sticky) setTimeout(() => setToast(null), 2600);
  };

  // #225 E7 — fully unbind the master so the operator can re-onboard a fresh passkey
  // (used when the bound passkey was deleted in the OS password manager, or an accept
  // fails with a wrong-passkey signature after a re-onboard). The daemon clears BOTH
  // local state AND the on-chain operatorMasterWallet (owner-gated resetMaster), which
  // is what actually lets the fresh passkey re-bind. Cannot delete the OS passkey
  // (WebAuthn) — the toast tells the operator to do that manually.
  const resetMaster = async () => {
    if (status.kind !== 'connected') { showToast('Connect a daemon first.'); return; }
    // #260 — an account-master's agents can ONLY be revoked by the master
    // P256Account itself, and resetMaster clears operatorMasterWallet (after
    // which NOBODY can revoke them). So revoke the whole fleet FIRST: ONE
    // executeBatch([revokeAgentDevice × N]) UserOp, ONE Touch ID, before the
    // unbind. This also runs before the localStorage clear below — the
    // assertion wants the stored master cred id.
    const fleetHashes = actors
      .filter((a) => a.role === 'agent' && a.deviceKeyHash)
      .map((a) => a.deviceKeyHash as string);
    if (fleetHashes.length > 0) {
      akLog('reset: building fleet revoke (one Touch ID for all paired agents)', {
        count: fleetHashes.length,
      });
      const built = await client.revokeBuild({ deviceKeyHashes: fleetHashes });
      if (built.ok) {
        showToast(`Approve with Touch ID — one approval revokes ${fleetHashes.length} paired agent(s)…`);
        let assertion;
        try {
          const masterCred = getMasterCredId() || null;
          assertion = await getAssertionOverHash(
            built.data.user_op_hash,
            masterCred ? [masterCred] : undefined,
          );
        } catch {
          showToast('Touch ID cancelled — reset aborted; the fleet is still bound.');
          return;
        }
        const submitted = await client.revokeSubmit({ user_op: built.data.user_op, assertion });
        if (!submitted.ok) {
          const detail = submitted.status?.detail ?? 'handleOps error';
          akLog('reset: fleet revoke submit FAILED ❌', { detail });
          showToast(`Fleet revoke failed — reset aborted (${detail}). The agents are still bound; retry.`);
          return;
        }
        akLog('reset: fleet revoke landed ✅', {
          txHash: submitted.data.txHash,
          auditEnvelopeHashes: submitted.data.auditEnvelopeHashes,
        });
      } else {
        const detail = built.status?.detail ?? '';
        // legacy EOA master → the daemon's script teardown signs these;
        // nothing-to-revoke → the fleet is already revoked on chain. Anything
        // else would strand the bindings once the master unbinds — abort.
        if (!/legacy EOA|nothing to revoke/i.test(detail)) {
          akLog('reset: fleet revoke build FAILED ❌', { detail });
          showToast(`Fleet revoke build failed — reset aborted (${detail || 'check master session + chain'}).`);
          return;
        }
        akLog('reset: no Touch-ID fleet revoke needed', { detail });
      }
    }
    const r = await client.resetMaster();
    if (!r.ok) {
      akLog('reset: FAILED ❌', { detail: r.status?.detail });
      showToast(`Reset failed — ${r.status?.detail ?? 'daemon error'}`);
      return;
    }
    if (r.data.ok === false) {
      // #260 hard stop: the daemon refused the unbind (account-master agents
      // still bound on chain) and mutated NOTHING — keep the view intact so the
      // operator can run the fleet revoke and retry.
      akLog('reset: daemon aborted — fleet still bound', { fleet: r.data.fleet });
      showToast(
        `Reset blocked — ${r.data.note ?? 'agents are still bound on chain; approve the Touch-ID fleet revoke, then reset again.'}`,
        true,
      );
      return;
    }
    const cleared = getMasterCredId() || null;
    akLog('reset: clearing master binding (local + on-chain; OS passkey untouched)', {
      clearedCredentialId: cleared,
    });
    // Per-chain wipe: only THIS chain's master pointer (the other chain's
    // master, if any, stays bound).
    clearMasterIdentity();
    const onchain = r.data.onchain;
    const fleet = r.data.fleet;
    akLog('reset: done', { onchain, fleet });
    // #243: the daemon tore the fleet down too — mirror it in the view state so
    // the UI doesn't show ghost agents/pairings until the next refetch.
    setActors([]);
    setPairingRequests([]);
    setProposals(null);
    // The fleet summary rides every outcome toast; failures are spelled out —
    // a partially-torn-down fleet must never read as fully disconnected.
    const fleetBits: string[] = [];
    if (fleet) {
      fleetBits.push(`${fleet.agents_revoked.length} agent(s) revoked on chain`);
      fleetBits.push(`${fleet.pending_declined} pending pairing(s) declined`);
      if (fleet.failures.length > 0) fleetBits.push(`⚠ ${fleet.failures.join(' · ')}`);
    }
    const fleetNote = fleetBits.length ? `  Fleet: ${fleetBits.join(', ')}.` : '';
    const onchainCleared =
      onchain?.status === 'reset' ||
      (onchain?.status === 'skipped' && onchain?.reason === 'already-unbound');
    if (onchainCleared) {
      showToast(
        `Master unbound (local + on-chain).${fleetNote} Delete the master passkey in System Settings ▸ Passwords, then re-onboard once.`,
        true,
      );
    } else {
      // On-chain unbind didn't land — re-onboarding will still SIG_VALIDATION-fail until
      // it does. Surface the reason so the operator (or dev) can fix it.
      const why = onchain?.error ?? onchain?.reason ?? 'unknown';
      showToast(
        `Local binding cleared, but the ON-CHAIN unbind did NOT land (${why}).${fleetNote} Re-onboarding will still fail until it does — ensure the registry has resetMaster (VERSION ≥ 0.3) + the deployer key, then retry.`,
        true,
      );
    }
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
    setOnboardedFlag(false);
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
  };

  // #249/#248 — the memory namespaces the operator can grant: the loaded
  // taxonomy categories when available (the real per-master namespace set),
  // else the canonical four. Drives the pairing accept picker, the claim's
  // default requested scope, and the permissions panel.
  const availableNamespaces =
    categories.length > 0 ? categories.map((c) => c.ns) : (NAMESPACES as readonly string[]).slice();

  // #248 — commit the permissions panel's staged memory grant on chain: ONE
  // setScope (set-replace) UserOp signed by the master K11 (Touch ID), relayed
  // via the broker → bundler → EntryPoint.handleOps. Returns true on success so
  // the panel clears its staged state; the #233 mirror then re-reads the grant
  // from chain on the refetch below (persistence across refetch + restart).
  const commitScope = async (actor: Actor, services: string[], readOnly: boolean): Promise<boolean> => {
    if (status.kind !== 'connected') {
      showToast('Connect a daemon to commit scope changes.');
      return false;
    }
    if (services.length === 0) {
      const proceed = window.confirm(
        `Commit ZERO grants for ${actor.label}? This revokes every memory namespace on chain — the agent will be denied everywhere.\n\nRevoke all?`,
      );
      if (!proceed) return false;
    }
    showToast(`Building setScope for ${actor.label}…`);
    // setScope is set-replace — echo the mirror's unmatched on-chain service ids
    // (e.g. cred:<service> granted at accept) so a memory toggle can't wipe them.
    const built = await client.scopeBuild({
      actorOmni: actor.omniHex,
      services,
      preserveServiceIds: actor.scopeUnknownServiceIds ?? [],
      readOnly,
    });
    if (!built.ok) {
      showToast(`Scope build failed — ${built.status?.detail ?? 'check master session + chain'}`);
      return false;
    }
    showToast('Approve with Touch ID…');
    let assertion;
    try {
      const masterCred = getMasterCredId() || null;
      akLog('scope: signing userOpHash (Touch ID)', {
        actor: actor.id,
        services,
        readOnly,
        userOpHash: built.data.user_op_hash,
      });
      assertion = await getAssertionOverHash(
        built.data.user_op_hash,
        masterCred ? [masterCred] : undefined,
      );
    } catch {
      showToast('Touch ID cancelled — scope unchanged on chain.');
      return false;
    }
    const submitted = await client.scopeSubmit({ user_op: built.data.user_op, assertion });
    if (!submitted.ok) {
      const detail = submitted.status?.detail ?? 'handleOps error';
      akLog('scope: submit FAILED ❌', { actor: actor.id, detail });
      if (/SIG_VALIDATION|wrong passkey|reverted on-chain/i.test(detail)) {
        showToast(
          `Scope commit failed (${detail}). Your signing passkey ≠ the one bound to your master account — reset, delete the old passkey, re-onboard once.`,
          true,
          { label: 'Reset master', fn: resetMaster },
        );
      } else {
        showToast(`Scope commit failed — ${detail}`);
      }
      return false;
    }
    akLog('scope: submit OK ✅', {
      actor: actor.id,
      txHash: submitted.data.txHash,
      auditEnvelopeHashes: submitted.data.auditEnvelopeHashes,
    });
    const scopeReceipt = submitted.data.auditEnvelopeHashes?.[0];
    showToast(
      `${actor.label} scope committed on chain (Touch ID · setScope).` +
        (scopeReceipt ? ` Audit receipt ${scopeReceipt.slice(0, 10)}….` : ''),
    );
    const a = await client.listActors();
    if (a.ok) setActors(a.data);
    return true;
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

  // ─── Pairing: accept → register on chain (§10.2 P.2) ───────────────
  // #214: the daemon submits registerAgentDevice for the binding + acks the broker.
  // The agent's scope grant (Touch ID, P.3) is the next step via its actor detail.
  //
  // #249: `services` is the operator's SELECTION from the accept card's namespace
  // picker (default = the requested tokens), not a blind compile of the request —
  // the operator adjusts the grant BEFORE Touch ID, so §B's "review the device +
  // requested scope → accept" actually ends with the agent scoped.
  const acceptPairing = async (req: PairingRequest, services: string[]) => {
    if (status.kind !== 'connected') {
      showToast('Connect a daemon to approve a pairing.');
      return;
    }
    // #225 E7 — the real Touch-ID gate: build the sponsored executeBatch UserOp on
    // the broker, sign its userOpHash with K11 (Touch ID), submit → handleOps. This
    // does BOTH registerAgentDevice (P.2) + setScope (P.3) atomically, in one block.
    if (services.length === 0) {
      // Binding with zero grants is legitimate (grant later from the actor page),
      // but it must NEVER be silent (#245 floor) — and per #249 it now needs an
      // EXPLICIT confirmation, because zero grants is exactly the deny-everywhere
      // trap the runbook's pairing story does not expect.
      const proceed = window.confirm(
        `${req.agent} would be bound with ZERO scope grants — it cannot read any memory or credentials until you grant scopes from its actor page.\n\nBind with zero grants?`,
      );
      if (!proceed) return;
      showToast(
        `Heads-up: this accept binds ${req.agent} with ZERO grants. Grant scopes from its actor page afterwards (permissions · commit · Touch ID).`,
        true,
      );
    }
    showToast(`Building accept for ${req.agent}…`);
    const built = await client.acceptBuild({
      requestId: req.id,
      services,
      readOnly: false,
      maxPerCall: '0',
      maxPerPeriod: '0',
      maxTotal: '0',
      periodSeconds: 0,
    });
    if (!built.ok) {
      showToast(`Accept build failed — ${built.status?.detail ?? 'check master session + chain (cutover?)'}`);
      return;
    }
    showToast('Approve with Touch ID…');
    const masterAccount = built.data.user_op?.sender;
    akLog('accept: built UserOp — master account = operatorMasterWallet', {
      masterAccount,
      userOpHash: built.data.user_op_hash,
      entryPoint: built.data.entry_point,
    });
    let assertion;
    try {
      // Auto-select the master passkey (stored at K11 enrollment) so the browser
      // skips its picker and the right key signs. Absent ⇒ full picker (fallback).
      const masterCred = getMasterCredId() || null;
      akLog('accept: signing userOpHash (Touch ID)', {
        masterAccount,
        requestedCredentialId: masterCred ?? '(none — full picker)',
        userOpHash: built.data.user_op_hash,
      });
      assertion = await getAssertionOverHash(
        built.data.user_op_hash,
        masterCred ? [masterCred] : undefined,
      );
      // THE key diagnostic: the passkey that actually signed vs the one we requested.
      // If signingCredentialId ≠ the credential bound at onboarding, the accept will
      // SIG_VALIDATION_FAILED on chain (the account verifies only the bound pubkey).
      akLog('accept: assertion produced', {
        masterAccount,
        requestedCredentialId: masterCred ?? '(none)',
        signingCredentialId: assertion.credential_id,
        autoSelectMatched: !masterCred || assertion.credential_id === masterCred,
      });
    } catch {
      // Either the operator cancelled, OR the bound master passkey was deleted in the
      // OS password manager (the picker then has nothing to sign with).
      showToast(
        'Touch ID cancelled — or your master passkey was deleted. If you deleted it, reset + re-onboard once.',
        true,
        { label: 'Reset master', fn: resetMaster },
      );
      return;
    }
    const submitted = await client.acceptSubmit({ user_op: built.data.user_op, assertion });
    if (!submitted.ok) {
      const detail = submitted.status?.detail ?? 'handleOps error';
      akLog('accept: submit FAILED ❌', {
        masterAccount,
        signingCredentialId: assertion.credential_id,
        detail,
      });
      // A SIG_VALIDATION_FAILED / on-chain revert here almost always means the signing
      // passkey ≠ the one bound to the master account — typically a stale binding after a
      // passkey was deleted/regenerated. The reset path now unbinds on-chain (owner-gated
      // resetMaster) so a fresh enroll CAN re-bind. Offer the reset + re-onboard path.
      if (/SIG_VALIDATION|wrong passkey|reverted on-chain/i.test(detail)) {
        showToast(
          `Accept failed (${detail}). Your signing passkey ≠ the one bound to your master account — reset, delete the old passkey, re-onboard once.`,
          true,
          { label: 'Reset master', fn: resetMaster },
        );
      } else {
        showToast(`Accept submit failed — ${detail}`);
      }
      return;
    }
    akLog('accept: submit OK ✅', {
      masterAccount,
      signingCredentialId: assertion.credential_id,
      txHash: submitted.data.txHash,
      auditEnvelopeHashes: submitted.data.auditEnvelopeHashes,
    });
    const acceptReceipts = submitted.data.auditEnvelopeHashes?.length ?? 0;
    showToast(
      `${req.agent} accepted on chain (Touch ID · register + scope, one block).` +
        (acceptReceipts > 0 ? ` ${acceptReceipts} audit receipt${acceptReceipts > 1 ? 's' : ''} recorded.` : ''),
    );
    // Drop it from the pending list. The accept registered the agent on-chain, but the
    // broker only clears the rendezvous row on an explicit ack (the accept/submit body
    // carries no request_id) — without this the request reappears on every refresh.
    // Remove locally for instant feedback, then ack the broker so it stays gone.
    setPairingRequests((prev) => prev.filter((r) => r.id !== req.id));
    const acked = await client.ackPairing(req.id);
    if (!acked.ok) akLog('accept: ack pending-binding failed (request may reappear)', { detail: acked.status?.detail });
    await refreshPairing();
    const a = await client.listActors();
    if (a.ok) setActors(a.data);
  };
  const declinePairing = async (id: string) => {
    // Actually drop the request on the broker (J1-gated, no Touch ID) — not just
    // the local list, or it reappears on the next refresh.
    const r = await client.declinePairing(id);
    if (!r.ok) {
      showToast(`Decline failed — ${r.status?.detail ?? 'check the master session'}`);
      return;
    }
    setPairingRequests((prev) => prev.filter((req) => req.id !== id));
    showToast('Pairing request declined.');
    await refreshPairing();
  };
  // #214: poll the REAL broker rendezvous (daemon GET /v1/agent/pairing/pending)
  // for agents the master has claimed that await on-chain approval. Replaces the
  // former local-state mock.
  const refreshPairing = async () => {
    if (status.kind !== 'connected') {
      showToast('Connect a daemon to poll for agent pairing codes.');
      return;
    }
    const r = await client.listPairingRequests();
    if (!r.ok) {
      showToast('Could not reach the daemon to poll agent pairings.');
      return;
    }
    setPairingRequests(r.data);
    showToast(
      r.data.length > 0
        ? `${r.data.length} agent${r.data.length > 1 ? 's' : ''} awaiting on-chain approval.`
        : 'Polled rendezvous · no pending agent pairings.',
    );
  };

  // #214 §10.2 P.1 — claim the agent's pairing code via the daemon → broker; on
  // success, re-poll so the claimed agent appears in the rendezvous (awaiting
  // on-chain register + scope approval).
  //
  // #249: the claim declares a NAMESPACE-QUALIFIED default scope (`memory:<ns>`
  // per known namespace) — never a bare `memory`. A bare token can't compile to
  // an on-chain service, which is how an accept silently landed `setScope([])`;
  // with qualified defaults the accept card's picker has the real namespaces
  // preselected and §B ends with the agent actually scoped.
  const claimPairing = async (input: { code: string; label: string }) => {
    if (status.kind !== 'connected') {
      showToast('Connect a daemon to claim a pairing code.');
      return;
    }
    setClaiming(true);
    const scope = availableNamespaces.map((ns) => `memory:${ns}`).join(',');
    const r = await client.claimPairing({ ...input, scope });
    setClaiming(false);
    if (!r.ok) {
      showToast('Claim failed — check the code + that your master session is active.');
      return;
    }
    showToast(`Claimed ${input.label} — now awaiting your on-chain approval.`);
    await refreshPairing();
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

  const confirmAction = async () => {
    const action = pendingAction;
    setPendingAction(null);
    if (!action) return;
    if (action.kind === 'pair-accept') {
      setPairingRequests((prev) => prev.filter((r) => r.id !== action.req.id));
      setPairingCeremony(action.req);
    }
    if (action.kind === 'revoke-device') {
      const actor = action.actor;
      // The binding isn't gone until SidecarRegistry says so. revokeAgentDevice
      // requires msg.sender == operatorMasterWallet — for an account-master
      // operator that's the passkey P256Account, so the unpair is a Touch-ID
      // UserOp (build → K11-sign → submit), NOT the deployer-signed script
      // (which reverts NotAuthorized — real 2026-06-11 incident).
      //
      // Gate ONLY on having the device hash. Whether the master is a
      // P256Account is the BROKER's chain read (operatorMasterWallet +
      // has-code) — the local accountType field can be stale (`none` on a
      // restored session, real 2026-06-11 follow-up incident) and gating on it
      // silently sent account-master operators down the doomed script path.
      // A genuine legacy-EOA master gets the broker's 409 → script fallback.
      const legacyRevoke = async (): Promise<boolean> => {
        showToast(`Revoking ${actor.label} on chain…`);
        const r = await client.revokeDevice(actor.id, action.intent);
        if (!r.ok) {
          showToast(`Revoke failed — ${r.status?.detail ?? 'check the daemon + chain config'}`);
          return false;
        }
        return true;
      };
      if (actor.deviceKeyHash) {
        showToast(`Building revoke for ${actor.label}…`);
        const built = await client.revokeBuild({ deviceKeyHashes: [actor.deviceKeyHash] });
        if (!built.ok) {
          const buildDetail = built.status?.detail ?? '';
          if (/legacy EOA|nothing to revoke/i.test(buildDetail)) {
            // legacy EOA: the broker chain-read says the master IS an EOA — the
            // script can sign this revoke. nothing-to-revoke: the chain already
            // reads `revoked` — the script's read-only pre-check converges
            // local state without signing anything. Either way: legacy path.
            akLog('revoke: falling back to the script path', { actor: actor.id, detail: buildDetail });
            if (!(await legacyRevoke())) return;
            const a0 = await client.listActors();
            if (a0.ok) setActors(a0.data);
            showToast(`${actor.label} revoked on chain.`);
            go('audit');
            return;
          }
          showToast(`Revoke build failed — ${buildDetail || 'check master session + chain'}`);
          return;
        }
        showToast('Approve with Touch ID…');
        let assertion;
        try {
          const masterCred = getMasterCredId() || null;
          akLog('revoke: signing userOpHash (Touch ID)', {
            actor: actor.id,
            deviceKeyHash: actor.deviceKeyHash,
            userOpHash: built.data.user_op_hash,
          });
          assertion = await getAssertionOverHash(
            built.data.user_op_hash,
            masterCred ? [masterCred] : undefined,
          );
        } catch {
          showToast('Touch ID cancelled — the device is still bound.');
          return;
        }
        const submitted = await client.revokeSubmit({ user_op: built.data.user_op, assertion });
        if (!submitted.ok) {
          const detail = submitted.status?.detail ?? 'handleOps error';
          akLog('revoke: submit FAILED ❌', { actor: actor.id, detail });
          if (/SIG_VALIDATION|wrong passkey|reverted on-chain/i.test(detail)) {
            showToast(
              `Revoke failed (${detail}). Your signing passkey ≠ the one bound to your master account — reset, delete the old passkey, re-onboard once.`,
              true,
              { label: 'Reset master', fn: resetMaster },
            );
          } else {
            showToast(`Revoke submit failed — ${detail}`);
          }
          return;
        }
        const txHash = submitted.data.txHash;
        const auditEnvelopeHashes = submitted.data.auditEnvelopeHashes;
        akLog('revoke: submit OK ✅', { actor: actor.id, txHash, auditEnvelopeHashes });
        // The daemon re-reads the registry (device must read `revoked`) before
        // flipping local state — the chain stays the source of truth. The #97
        // receipts ride along so the feed event carries the real envelope hash.
        const r = await client.revokeDevice(actor.id, action.intent, { txHash, auditEnvelopeHashes });
        if (!r.ok) {
          showToast(`Revoke landed on chain but the daemon verify failed — ${r.status?.detail ?? 'refresh'}`);
          return;
        }
      } else if (!(await legacyRevoke())) {
        // No on-chain device hash recorded (legacy local-only row) — script path.
        return;
      }
      const a = await client.listActors();
      if (a.ok) setActors(a.data);
      showToast(`${actor.label} revoked on chain.`);
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
          setOnboardedFlag(true);
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
          <span style={{ fontSize: 10, letterSpacing: '0.08em', textTransform: 'uppercase' }}>{(daemonChain ?? CHAIN_PROFILE.name)} · {status.kind === 'connected' ? `daemon ${status.via}` : 'daemon offline'}</span>
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
        <button
          className="nav-item"
          style={{ color: 'var(--danger)' }}
          title="Unbind the master (local + on-chain) so you can re-onboard a fresh passkey — e.g. after the master passkey was deleted in your OS password manager, or an accept fails with SIG_VALIDATION."
          onClick={() => {
            // #243: state the blast radius — reset tears down the whole fleet.
            const agentCount = actors.filter((a) => a.role === 'agent').length;
            const pendingCount = pairingRequests.length;
            if (window.confirm(`Unbind the master so you can re-onboard a fresh passkey?\n\n• Clears the local binding AND the on-chain operatorMasterWallet (so a fresh passkey can re-bind)\n• Disconnects your whole fleet: revokes ${agentCount} paired agent(s) on chain (ONE Touch ID approval covers all of them, asked first) + declines ${pendingCount} pending pairing request(s) — re-pairing needs a fresh ceremony\n• Does NOT delete the OS passkey — delete it in System Settings ▸ Passwords\n\nContinue?`)) resetMaster();
          }}
        >
          <span className="marker">[⟲]</span> reset master · re-onboard passkey
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
        {/* #242 — the master J1 lapsed but the coords are still held: ONE Touch ID
            restores it (no re-onboarding). Only SESSION-GATED, encrypted reads
            (memory / credentials / inbox — cap-mint → STS → worker → decrypt) are
            paused; the actor tree + audit are PUBLIC on-chain reads (eth_call) and
            still load without the J1 — so the banner must NOT claim "chain reads". */}
        {sessionExpired && (
          <div className="banner" role="alert" style={{ marginBottom: 14, borderColor: 'var(--danger, #b3261e)' }}>
            <span className="lbl">⚠ session expired</span>
            <span>
              Your master session lapsed — reading your encrypted memory + credentials is paused (the actor tree
              still loads, since it&apos;s read from chain). You&apos;re still bound, so this is
              <strong> one Touch ID</strong>, not a re-onboarding.
              <button
                className="btn primary sm"
                style={{ marginLeft: 10 }}
                disabled={reauthBusy}
                onClick={reauthenticate}
              >
                {reauthBusy ? 'authenticating…' : '⊕ re-authenticate (Touch ID)'}
              </button>
            </span>
          </div>
        )}
        {page === 'actors' && <ActorsList actors={actors} status={status} onPick={(id) => go('detail', id)} />}
        {page === 'detail' && currentActor && (
          <ActorDetail actor={currentActor} onBack={() => go('actors')} onUpdate={updateActor} onCommitScope={commitScope} onRevoke={handleRevokeDevice} recentEvents={events} proposals={proposals} proposing={proposing} onPropose={proposeForActor} onConfirmProposal={confirmProposal} onConfirmSafe={confirmSafeSet} onResetMaster={resetMaster} />
        )}
        {page === 'memory' && (
          <MemoryPage categories={categories} entriesByNs={entriesByNs} actors={actors} status={status} presets={presets} defaultPresetId={defaultPresetId} initializing={initializing} planting={planting} inbox={inbox} inboxBusy={inboxBusy} onInitDefault={initDefault} onInitDone={initDone} onPlant={plantMemory} onPlantDone={plantDone} onLoadCategory={loadCategory} onView={setMemoryView} onAcceptInbox={acceptInboxItem} onRejectInbox={rejectInboxItem} onRefreshInbox={refreshInbox} onViewInboxBody={viewInboxBody} />
        )}
        {page === 'credentials' && (
          <CredentialsPage credentials={credentials} status={status} storing={storingCred} onStore={storeCredential} />
        )}
        {page === 'pairing' && (
          <PairingPage requests={pairingRequests} actors={actors} namespaces={availableNamespaces} onAccept={acceptPairing} onDecline={declinePairing} onRefresh={refreshPairing} onClaim={claimPairing} claiming={claiming} justPaired={justPaired} onManage={(id) => go('detail', id)} onUnpair={handleRevokeDevice} />
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
                Binding <span className="mono">O_master{pairingCeremony.derivation}</span> under your master identity. Each on-chain step is a real transaction on the daemon&apos;s chain.
              </div>
              <CeremonyRunner steps={PAIRING_STEPS} onDone={finishPairingCeremony} stepMs={680} />
            </div>
          </div>
        </div>
      )}

      {toast && (
        <div style={{ position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)', display: 'flex', alignItems: 'center', gap: 14, maxWidth: 'min(92vw, 560px)', background: 'var(--ink)', color: 'var(--bg)', padding: '10px 14px 10px 18px', fontSize: 12, border: '1px solid var(--ink)', zIndex: 200, animation: 'pop 0.22s cubic-bezier(.2,.8,.2,1)' }}>
          <span>{toast.msg}</span>
          {toast.action && (
            <button
              onClick={() => { toast.action!.fn(); }}
              style={{ background: 'var(--bg)', color: 'var(--ink)', border: '1px solid var(--bg)', cursor: 'pointer', fontSize: 11, lineHeight: 1, padding: '5px 9px', flexShrink: 0, whiteSpace: 'nowrap' }}
            >
              {toast.action.label}
            </button>
          )}
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

// ─── Step 9: decode the on-chain transaction for an audit event ──────
// Real decode (#153): the daemon decodes the CBOR AuditEnvelope + the on-chain
// calldata against the verified ABIs. While loading / when no daemon is wired,
// a clearly-labelled reference decode (demoData) is shown instead. Rendered as a
// dedicated page (reachable at the `decode` nav state), not a modal.
function EventDecodePage({ event, onBack }: { event: AuditEvent; onBack: () => void }) {
  const client = useClient();
  const [decoded, setDecoded] = useState<DecodedAuditEvent | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // The daemon's live chain display (e.g. "Base mainnet"), so the decode footer
  // names the chain the event was actually committed on — not the build-time
  // CHAIN_PROFILE constant. Falls back to that constant until the list loads.
  const [chainDisplay, setChainDisplay] = useState<string | null>(null);

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

  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await client.getChainList();
      if (!alive || !r.ok) return;
      const entry = r.data.chains.find((c) => c.name === r.data.daemonChain);
      setChainDisplay(entry?.display ?? r.data.daemonChain);
    })();
    return () => { alive = false; };
  }, [client]);

  const mock = decodeCalldata(event);
  const onchain = ONCHAIN_KINDS.has(event.kind);
  const tx = decoded?.tx ?? null;
  const env = decoded?.envelope ?? null;
  // #97: real decodes carry EVERY fetched envelope (an accept has two:
  // DeviceAdd + ScopeGrant); synthesized previews keep the single one.
  const envs = decoded?.envelopes?.length ? decoded.envelopes : env ? [env] : [];
  const realTxHash = event.txHash ?? decoded?.tx_hash;
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
      {decoded && decoded.synthesized === false && (
        <div style={{ fontSize: 11, color: 'var(--ok, #2e7d32)', border: '1px solid var(--ok, #2e7d32)', padding: '8px 12px', marginBottom: 16 }}>
          ✓ {decoded.provenance ?? 'real decode — envelope(s) fetched from the audit worker by the submit receipt hashes.'}
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
            {realTxHash && (<><dt>tx</dt><dd className="mono" style={{ wordBreak: 'break-all' }}>{realTxHash}</dd></>)}
            {event.auditEnvelopeHashes && event.auditEnvelopeHashes.length > 0 && (
              <>
                <dt>audit receipts</dt>
                <dd className="mono" style={{ wordBreak: 'break-all' }}>
                  {event.auditEnvelopeHashes.join(' · ')}
                </dd>
              </>
            )}
          </dl>
        </div>
      </div>

      {/* ── CBOR AuditEnvelope(s) (decoded) — one panel per fetched envelope ── */}
      {envs.map((e, i) => (
        <div className="panel" key={e.envelope_hash || i}>
          <div className="panel-head"><span>── decoded audit envelope{envs.length > 1 ? ` ${i + 1}/${envs.length}` : ''} · cbor v{e.version}</span></div>
          <div className="panel-body">
            <div className="tx-decode">
              <div className="tx-row"><span className="tx-k">op_kind</span><span className="tx-v mono">{e.op_kind}{e.op_kind_label ? ` · ${e.op_kind_label}` : ' · Unknown(byte)'}</span></div>
              {e.intent_text && <div className="tx-row"><span className="tx-k">intent</span><span className="tx-v">{e.intent_text}</span></div>}
              {Object.entries(e.op_body || {}).map(([k, v]) => (
                <div className="tx-row" key={k}><span className="tx-k">{k}</span><span className="tx-v mono" style={{ wordBreak: 'break-all' }}>{argValue(v)}</span></div>
              ))}
              <div className="tx-row"><span className="tx-k">envelope_hash</span><span className="tx-v mono" style={{ wordBreak: 'break-all' }}>{e.envelope_hash}</span></div>
            </div>
          </div>
        </div>
      ))}

      {/* ── on-chain transaction (calldata decoded against the verified ABI) ── */}
      <div className="panel">
        <div className="panel-head"><span>── decoded on-chain transaction</span></div>
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
              <>{decoded.provenance ?? 'calldata + CBOR decoded by the daemon against the verified ABIs'} · {chainDisplay ?? CHAIN_PROFILE.display}</>
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
  // #282 chain switcher — VIEW any built-in chain's registry. Display-only:
  // the daemon's operational chain (ceremonies, audit, onboarding) never moves.
  const [chains, setChains] = useState<ChainListEntry[]>([]);
  const [daemonChain, setDaemonChain] = useState<string | null>(null);
  const [view, setView] = useState<string>('');

  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await client.getChainList();
      if (alive && r.ok) {
        setChains(r.data.chains);
        setDaemonChain(r.data.daemonChain);
        setView((v) => v || r.data.daemonChain);
      }
    })();
    return () => { alive = false; };
  }, [client]);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await client.getChainInfo(view || undefined);
      if (alive && r.ok) setInfo(r.data);
    })();
    return () => { alive = false; };
  }, [client, view]);

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
          <div className="desc">{display}. Contracts deployed via Foundry; tier-2 audit anchors a Merkle root here every 2 minutes.</div>
        </div>
        {chains.length > 0 && (
          <div>
            <select
              value={view}
              onChange={(e) => setView(e.target.value)}
              aria-label="view chain"
              style={{ padding: '7px 9px', fontSize: 12.5 }}
            >
              {chains.map((c) => (
                <option key={c.name} value={c.name}>
                  {c.name} · {c.chainId}{c.name === daemonChain ? ' · daemon' : ''}
                </option>
              ))}
            </select>
            {daemonChain && view && view !== daemonChain && (
              <div className="muted" style={{ fontSize: 11, marginTop: 6, maxWidth: 280 }}>
                viewing {view} — the daemon operates on {daemonChain} (ceremonies + audit stay there)
              </div>
            )}
          </div>
        )}
      </div>
      <div className="stats">
        <div className="stat"><div className="v">{name}</div><div className="k">{daemonChain && view && view !== daemonChain ? 'viewing chain' : 'AGENTKEYS_CHAIN'}</div></div>
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
