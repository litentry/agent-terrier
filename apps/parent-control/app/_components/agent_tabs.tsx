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
import type { Actor } from './types';

type Tab = 'context' | 'chat' | 'feeds';

export function AgentTabsPanel({ actor }: { actor: Actor }) {
  const api = useClient();
  const [tab, setTab] = useState<Tab>('context');
  const [preset, setPreset] = useState<PresetSummary | null>(null);

  const chatChannelId = `opchat-${actor.label}`;
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
              LLM usage is metered at the gate per turn (provisioned at spawn); live usage
              numbers surface here once the gate is wired on this stack.
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
        <ChatPanel
          channelId={chatChannelId}
          emptyHint={`Direct chat with ${actor.label} — the transcript IS its durable opchat feed (operator-only, D13).`}
        />
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
