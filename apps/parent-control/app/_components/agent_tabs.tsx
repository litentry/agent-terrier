'use client';
// #431 (epic #425 S5) — the per-agent panel: three tabs mirroring the three
// interaction surfaces. Context = AUTHORITY FIRST (what it can reach: persona +
// skills + grants, hydrated from the #424 manifest — never hash-guessing) with
// the #428 preset suggestions rendered INERT; Chat = the #430 surface; Feeds =
// the D13 operator-only history browser over every subscribed channel.
// Devices never render this panel (the #404 kind rule — gated in dashboard.tsx).

import { useEffect, useMemo, useState } from 'react';
import type { PresetSummary } from '@/lib/generated/PresetSummary';
import { useClient } from '@/lib/ClientProvider';
import { AgentPanel } from './agent';
import { ChatPanel } from './chat';
import { Chip, Panel } from './shared';
import {
  actorHoldsChannelGrant,
  agentChatChannelId,
  isValidChannelId,
  type Actor,
} from './types';

type Tab = 'context' | 'chat' | 'feeds';

export function AgentTabsPanel({ actor }: { actor: Actor }) {
  const api = useClient();
  const [tab, setTab] = useState<Tab>('context');
  const [preset, setPreset] = useState<PresetSummary | null>(null);

  const rt = actor.runtimeStatus;
  const services = actor.services ?? [];
  const subscribedChannels = useMemo(
    () =>
      Array.from(
        new Set(
          services
            .filter((s) => s.startsWith('channel-sub:'))
            .map((s) => s.slice('channel-sub:'.length)),
        ),
      ),
    [services],
  );
  // The DEFAULT chat channel comes from the agent's GRANT, never from its
  // display label (see agentChatChannelId — a placeholder label like
  // "agent 0x346391ed…" is not a legal channel id and made every poll/send 400
  // `invalid channel_id`). The AUTHORITY can override it below: the master owns
  // every channel (§22e ownership without participation), so the operator may
  // pub/sub on any feed — the grant only decides whether the DELEGATE hears.
  const chatChannelId = useMemo(() => agentChatChannelId(actor), [actor]);
  const [chatOverride, setChatOverride] = useState<string | null>(null);
  const [chatDraftChannel, setChatDraftChannel] = useState('');
  const activeChatChannel = chatOverride ?? chatChannelId;

  const [feedChannel, setFeedChannel] = useState<string | null>(null);

  useEffect(() => {
    setFeedChannel(subscribedChannels[0] ?? null);
  }, [subscribedChannels]);

  useEffect(() => {
    if (!actor.presetId) {
      setPreset(null);
      return;
    }
    (async () => {
      const cat = await api.presetCatalog();
      if (cat.ok) setPreset(cat.data.presets.find((p) => p.id === actor.presetId) ?? null);
    })();
  }, [api, actor.presetId]);

  return (
    <Panel
      title={
        <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          Agent panel
          <span className="view-toggle" style={{ display: 'inline-flex', gap: 4 }}>
            {(['context', 'chat', 'feeds'] as Tab[]).map((t) => (
              <button
                key={t}
                className={`btn sm ${tab === t ? 'primary' : ''}`}
                onClick={() => setTab(t)}
              >
                {t === 'context' ? 'Context' : t === 'chat' ? 'Chat' : 'Feeds'}
              </button>
            ))}
          </span>
        </span>
      }
    >
      {/* #543 — the spawn ceremony's runtime/metering outcome, on EVERY tab:
          a spawn-failed delegate's chat is silent and an unmetered one bills
          nothing, and neither should require broker logs to notice. */}
      {rt && (rt.spawnError || rt.gateStatus !== 'provisioned') ? (
        <div
          style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', marginBottom: 10 }}
        >
          {rt.spawnError ? (
            <>
              <Chip kind="bad">runtime spawn failed</Chip>
              <span className="muted" style={{ fontSize: 12 }}>
                {/* The gate error is the CAUSE whenever provisioning failed: the
                    spawn error only reports the fail-closed refusal downstream,
                    and showing it alone sent an operator to re-check wiring that
                    was already correct (#543 live). Cause first, effect second. */}
                {rt.gateError ? (
                  <>
                    <strong>gate {rt.gateStatus}:</strong> {rt.gateError} — so the spawn was
                    refused rather than run unmetered.{' '}
                  </>
                ) : null}
                {rt.spawnError} — no sandbox is serving this agent (its chat stays silent);
                archive + respawn after fixing the cause.
              </span>
            </>
          ) : (
            <>
              <Chip kind="warn">UNMETERED</Chip>
              <span className="muted" style={{ fontSize: 12 }}>
                gate {rt.gateStatus}
                {rt.gateError ? ` — ${rt.gateError}` : ''}; this agent&apos;s LLM turns bypass
                the metering gate until re-provisioned.
              </span>
            </>
          )}
        </div>
      ) : null}
      {tab === 'context' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>What it can reach</div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {services.length === 0 && (
                <span className="muted">No grants — this agent can reach nothing yet.</span>
              )}
              {services.map((s) => (
                <Chip key={s}>{s}</Chip>
              ))}
            </div>
            <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
              {actor.memoryNs ? (
                <>
                  Memory namespace: <code>memory:{actor.memoryNs}</code> ·{' '}
                </>
              ) : null}
              {actor.presetId ? (
                <>
                  Spawned from preset <code>{actor.presetId}</code> ·{' '}
                </>
              ) : null}
              {rt?.gateStatus === 'provisioned' ? (
                <>LLM metered at the gate — per-delegate relay key, provisioned at spawn.</>
              ) : (
                <>
                  LLM usage is metered at the gate per turn (provisioned at spawn); live usage
                  numbers surface here once the gate is wired on this stack.
                </>
              )}
            </div>
          </div>
          {preset &&
            (preset.suggested_channels.length > 0 || preset.suggested_context.length > 0) && (
              <div>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>
                  Preset suggestions — inert until you grant them
                </div>
                <ul className="muted" style={{ fontSize: 13, paddingLeft: 18 }}>
                  {preset.suggested_channels.map((c) => (
                    <li key={`ch-${c.id}`}>
                      channel <code>{c.id}</code> — {c.reason} (grant it from the permissions
                      panel · Touch ID)
                    </li>
                  ))}
                  {preset.suggested_context.map((c) => (
                    <li key={`ctx-${c.ns}`}>
                      context <code>{c.ns}</code> — {c.reason} (grant it from the permissions
                      panel · Touch ID)
                    </li>
                  ))}
                </ul>
              </div>
            )}
          <AgentPanel actor={actor} />
        </div>
      )}
      {tab === 'chat' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="muted" style={{ fontSize: 12 }}>
              channel:{' '}
              {activeChatChannel ? (
                <>
                  <code>{activeChatChannel}</code>{' '}
                  {chatOverride
                    ? '(manual)'
                    : chatChannelId
                      ? '(from grant)'
                      : ''}
                </>
              ) : (
                'none — this agent holds no channel grant; enter one to debug'
              )}
            </span>
            <input
              style={{ width: 180 }}
              placeholder="opchat-…"
              value={chatDraftChannel}
              onChange={(e) => setChatDraftChannel(e.target.value.trim())}
            />
            <button
              className="btn sm"
              disabled={!isValidChannelId(chatDraftChannel)}
              onClick={() => setChatOverride(chatDraftChannel)}
            >
              Use
            </button>
            {chatOverride && (
              <button className="btn sm" onClick={() => setChatOverride(null)}>
                Reset
              </button>
            )}
            {chatDraftChannel !== '' && !isValidChannelId(chatDraftChannel) && (
              <span className="muted" style={{ fontSize: 12 }}>
                invalid id ([a-z0-9-], 1–48, no edge dash)
              </span>
            )}
          </div>
          {activeChatChannel && !actorHoldsChannelGrant(actor, activeChatChannel) && (
            <div className="muted" style={{ fontSize: 12 }}>
              ⚠ {actor.label} holds no grant on <code>{activeChatChannel}</code> — it cannot hear
              or reply there until you grant <code>channel-pub/sub:{activeChatChannel}</code>{' '}
              (permissions panel · Touch ID). You can still publish/subscribe as the channel
              owner to inspect the feed.
            </div>
          )}
          {activeChatChannel ? (
            <ChatPanel
              key={activeChatChannel}
              channelId={activeChatChannel}
              emptyHint={`Direct chat with ${actor.label} on ${activeChatChannel} — the transcript IS its durable opchat feed (operator-only, D13).`}
            />
          ) : (
            <div className="muted">
              Enter a channel id above (e.g. <code>opchat-test1</code>) to open the authority
              chat surface for this agent.
            </div>
          )}
        </div>
      )}
      {tab === 'feeds' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {subscribedChannels.length === 0 ? (
            <div className="muted">
              No subscribed channels — grant a <code>channel-sub:&lt;id&gt;</code> from the
              permissions panel first.
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {subscribedChannels.map((id) => (
                  <button
                    key={id}
                    className={`btn sm ${feedChannel === id ? 'primary' : ''}`}
                    onClick={() => setFeedChannel(id)}
                  >
                    {id}
                  </button>
                ))}
              </div>
              <div className="muted" style={{ fontSize: 12 }}>
                Operator-only history (D13) · retention follows the channel defaults (manual
                teardown today — no automatic GC).
              </div>
              {feedChannel && (
                <ChatPanel
                  key={feedChannel}
                  channelId={feedChannel}
                  readOnly
                  emptyHint="No events in this feed yet."
                />
              )}
            </>
          )}
        </div>
      )}
    </Panel>
  );
}
