'use client';

// #390 — the Agent panel: view + edit the bound agent's persona (`SOUL.md`),
// roll back kept versions, restart (re-source) the agent, and inspect the LIVE
// context files shaping it (SOUL.md, AGENTS.md, the locked agent-terrier.md
// base layer, redacted config.yaml). Persona is the strictest context kind
// (master-hub §16): master-authored only — a delegate can propose knowledge or
// skills through the inbox, never a persona. Edits are validated server-side
// (size cap, no secrets, the agent-agnostic guardrail) and versioned; the
// sandbox apply leg is surfaced explicitly (`applied` + detail), never silent.

import { useCallback, useEffect, useState } from 'react';
import type { ApiPersonaState } from '@/lib/generated/ApiPersonaState';
import type { ApiPersonaEditResponse } from '@/lib/generated/ApiPersonaEditResponse';
import type { AgentContextView, Result } from '@/lib/client/types';
import { useClient } from '@/lib/ClientProvider';
import { Panel } from './shared';
import type { Actor } from './types';

const errText = (r: { ok: false; status: { detail?: string; reason: string } }) =>
  r.status.detail || r.status.reason;

export function AgentPanel({ actor }: { actor: Actor }) {
  const api = useClient();
  const delegate = actor.omniHex || actor.omni;
  const [state, setState] = useState<ApiPersonaState | null>(null);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [context, setContext] = useState<AgentContextView | null>(null);
  const [openFile, setOpenFile] = useState<string | null>(null);
  const [confirmRestart, setConfirmRestart] = useState(false);

  const refresh = useCallback(async () => {
    const r = await api.getPersona(delegate);
    if (r.ok) {
      setState(r.data);
      setDraft(r.data.current?.body ?? '');
    } else {
      setError(errText(r));
    }
    const c = await api.getAgentContext();
    if (c.ok) setContext(c.data);
  }, [api, delegate]);

  useEffect(() => {
    setState(null);
    setDraft('');
    setError(null);
    setNotice(null);
    setConfirmRestart(false);
    void refresh();
  }, [refresh]);

  const afterCommit = (r: Result<ApiPersonaEditResponse>, verb: string) => {
    if (!r.ok) {
      setError(errText(r));
      return;
    }
    setError(null);
    // The apply leg is explicit: stored-canonically-but-not-applied is a real
    // partial state the owner must see (sandbox unconfigured / unreachable).
    setNotice(
      r.data.applied
        ? `${verb} → v${r.data.version} · ${r.data.apply_detail}`
        : `${verb} → v${r.data.version} · NOT applied — ${r.data.apply_detail}`,
    );
    void refresh();
  };

  const save = async () => {
    setBusy(true);
    setNotice(null);
    afterCommit(await api.editPersona(delegate, draft), 'saved');
    setBusy(false);
  };

  const rollback = async (version: number) => {
    setBusy(true);
    setNotice(null);
    afterCommit(await api.rollbackPersona(delegate, version), `rolled back to v${version}`);
    setBusy(false);
  };

  const restart = async () => {
    if (!confirmRestart) {
      setConfirmRestart(true);
      return;
    }
    setConfirmRestart(false);
    setBusy(true);
    const r = await api.restartAgent();
    if (r.ok) {
      setNotice('agent re-sourced — context files re-read; the conversation starts fresh');
      setError(null);
    } else {
      setError(errText(r));
    }
    setBusy(false);
  };

  const dirty = draft !== (state?.current?.body ?? '');
  const versionNum = (v: string) => Number.parseInt(v.replace(/^v/, ''), 10) || 0;

  return (
    <Panel title="── agent · persona + context (#390)" flush>
      <div className="banner" style={{ margin: '8px 12px' }}>
        <span className="lbl">☰ persona</span>
        <span>
          <strong>SOUL.md</strong> frames every turn of this agent — edit it here and it applies{' '}
          <strong>live</strong> (the agent re-sources; hermes reloads the persona at session start).
          The AgentKeys preset (<span className="mono">agent-terrier.md</span>) is a{' '}
          <strong>locked base layer</strong>, always appended and never editable. Edits are
          validated (size cap, no secrets, the persona may never claim to BE AgentKeys) and
          versioned — roll back below.
        </span>
      </div>

      {error && (
        <div className="banner" style={{ margin: '0 12px 8px', color: 'var(--danger, #b3261e)' }}>
          <span className="lbl">✗</span>
          <span>{error}</span>
        </div>
      )}
      {notice && (
        <div className="banner" style={{ margin: '0 12px 8px' }}>
          <span className="lbl">↺</span>
          <span>{notice}</span>
        </div>
      )}

      <div style={{ padding: '0 12px 10px' }}>
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={
            'Write this agent’s persona (SOUL.md) — voice, tone, house rules. ' +
            'Master-authored only; delegates cannot propose a persona.'
          }
          rows={10}
          style={{
            width: '100%',
            fontFamily: 'var(--mono, monospace)',
            fontSize: 12.5,
            lineHeight: 1.55,
            padding: 10,
            boxSizing: 'border-box',
          }}
        />
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 6 }}>
          <button className="btn primary sm" disabled={busy || !dirty || !draft.trim()} onClick={save}>
            save persona{state?.current ? ` (→ v${versionNum(state.current.version) + 1})` : ' (v1)'}
          </button>
          <button className="btn sm" disabled={busy} onClick={restart}>
            {confirmRestart ? 'confirm restart? (resets the conversation)' : '↻ restart agent (re-source)'}
          </button>
          {state && !state.sandbox_configured && (
            <span className="muted" style={{ fontSize: 11.5 }}>
              sandbox not configured — edits persist and apply at the next spawn
            </span>
          )}
        </div>
      </div>

      {state && state.versions.length > 0 && (
        <div style={{ padding: '0 12px 10px' }}>
          <div className="secondary" style={{ marginBottom: 4 }}>
            kept versions (newest first, max 5)
          </div>
          <table className="tab">
            <tbody>
              {state.versions.map((v) => (
                <tr key={v.key}>
                  <td className="mono">{v.version}</td>
                  <td className="muted">{v.updated || '—'}</td>
                  <td className="muted" style={{ maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {v.preview}
                  </td>
                  <td className="right">
                    <button className="btn ghost sm" disabled={busy} onClick={() => rollback(versionNum(v.version))}>
                      roll back
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ padding: '0 12px 12px' }}>
        <div className="secondary" style={{ marginBottom: 4 }}>
          live context files{' '}
          {context && !context.configured && (
            <span className="muted">— sandbox not configured; nothing to read</span>
          )}
        </div>
        {context?.configured && (
          <table className="tab">
            <tbody>
              {context.files.map((f) => (
                <tr key={f.id}>
                  <td colSpan={4} style={{ padding: 0 }}>
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '4px 8px' }}>
                      <button className="btn ghost sm" onClick={() => setOpenFile(openFile === f.id ? null : f.id)}>
                        {openFile === f.id ? '▾' : '▸'} <span className="mono">{f.path}</span>
                      </button>
                      <span className="muted" style={{ fontSize: 11 }}>
                        {f.editable ? 'editable' : f.id === 'agent_terrier' ? 'LOCKED base layer' : 'read-only'}
                        {f.present ? ` · ${f.bytes ?? 0} bytes` : ' · absent'}
                      </span>
                    </div>
                    {openFile === f.id && f.present && (
                      <pre style={{ margin: '0 8px 8px', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 11.5, lineHeight: 1.5, maxHeight: 320, overflow: 'auto', background: 'var(--bg-elev, #faf8f2)', padding: 8 }}>
                        {f.content}
                      </pre>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}
