// #693 — the delegate launch / pull lifecycle as the console shows it: the
// stage word, a progress fraction while syncing, the last pass's cost, and the
// errors — parsed from a `lifecycle` feed event's JSON body.
import type { DelegateLifecycle } from '../generated/DelegateLifecycle';

export function parseLifecycle(text: string): DelegateLifecycle | null {
  try {
    const v = JSON.parse(text) as Partial<DelegateLifecycle>;
    if (!v || typeof v !== 'object' || typeof v.stage !== 'string') return null;
    return {
      stage: v.stage,
      detail: typeof v.detail === 'string' ? v.detail : '',
      done: Number(v.done ?? 0),
      total: Number(v.total ?? 0),
      mirrored: Number(v.mirrored ?? 0),
      deleted: Number(v.deleted ?? 0),
      ms: Number(v.ms ?? 0),
      errors: Array.isArray(v.errors) ? v.errors.map(String) : [],
      ts_millis: Number(v.ts_millis ?? 0),
    };
  } catch {
    return null;
  }
}

const fmtMs = (ms: number): string => (ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`);

/** The chip text: `syncing 2/3`, `ready · 1.2 s`, `degraded`, … */
export function stageLabel(lc: DelegateLifecycle): string {
  switch (lc.stage) {
    case 'syncing':
      return lc.total > 0 ? `syncing ${lc.done}/${lc.total}` : 'syncing';
    case 'ready':
      return lc.ms > 0 ? `ready · ${fmtMs(lc.ms)}` : 'ready';
    case 'pulling':
      return 'pulling';
    case 'degraded':
      return 'degraded';
    case 'restoring':
      return 'restoring';
    default:
      return 'booting';
  }
}

/** `ok` when the knowledge is there, `bad` when it is unavailable, else `warn`. */
export function stageTone(stage: DelegateLifecycle['stage']): 'ok' | 'warn' | 'bad' {
  return stage === 'ready' || stage === 'pulling' ? 'ok' : stage === 'degraded' ? 'bad' : 'warn';
}

/** The one-line explanation under the chip (title / status line). */
export function stageDetail(lc: DelegateLifecycle): string {
  const parts = [lc.detail];
  if (lc.stage === 'ready' || lc.stage === 'degraded') {
    parts.push(`${lc.mirrored} line${lc.mirrored === 1 ? '' : 's'} mirrored`);
    if (lc.deleted > 0) parts.push(`${lc.deleted} removed`);
  }
  if (lc.errors.length > 0) parts.push(`errors: ${lc.errors.join(' · ')}`);
  return parts.filter(Boolean).join(' · ');
}
