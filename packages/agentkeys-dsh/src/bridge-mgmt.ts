/**
 * @module @agentkeys/dsh-suite/bridge-mgmt — the #577/#594 management surface
 * over DSH_HOME (#616): export/import the runtime home as the byte-compatible
 * snapshot document the broker relay and the daemon checkpoint already speak.
 *
 * Contract (byte-identical to the hermes bridge, spec §3.2):
 *   export: {version:1, hermes_home, files:[{path,content_b64}], total_bytes,
 *            skipped:[], snapshot_at}          (field name `hermes_home` kept
 *            verbatim — consumers read only `jobs`/`applied`/counts, and the
 *            name is part of the frozen wire shape)
 *   import: same doc + {restart}; newer-wins RAM guard (`<=` last applied ⇒
 *            {applied:false, reason:"stale_snapshot", …}); all-or-nothing
 *            validation; atomic .tmp+rename writes; excluded paths silently
 *            skipped on BOTH sides.
 *
 * dsh-specific exclusions: anything under node_modules/ (the profile symlink
 * farm + installs — image-owned and huge) and the baked profile config
 * (package.json / cordis.patch.yml) — restoring an old copy over a bumped
 * image would wedge the fresh runtime, the same reason the hermes bridge
 * excluded its config.yaml family.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';

export const MGMT_SNAPSHOT_MAX_BYTES = 32 * 1024 * 1024;

export interface SnapshotFile {
  path: string;
  content_b64: string;
}
export interface SnapshotDoc {
  version: 1;
  hermes_home: string;
  files: SnapshotFile[];
  total_bytes: number;
  skipped: string[];
  snapshot_at: number;
}

/** dsh home paths excluded from export AND silently skipped on import. */
export function isExcludedPath(rel: string): boolean {
  const parts = rel.split('/');
  if (parts.includes('node_modules')) return true;
  if (parts.length === 3 && parts[0] === 'profiles' && (parts[2] === 'package.json' || parts[2] === 'cordis.patch.yml')) {
    return true;
  }
  return false;
}

/** The hermes `_mgmt_rel_path_ok` twin: relative, sane, no traversal. */
export function relPathOk(rel: string): boolean {
  if (typeof rel !== 'string' || rel.length === 0 || rel.length > 512) return false;
  if (rel.startsWith('/') || rel.includes('\\') || rel.includes('\0')) return false;
  const parts = rel.split('/');
  return parts.every((p) => p.length > 0 && p !== '.' && p !== '..');
}

export async function exportHome(root: string, nowSecs = Math.floor(Date.now() / 1000)): Promise<SnapshotDoc> {
  const files: SnapshotFile[] = [];
  const skipped: string[] = [];
  let total = 0;
  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    // bytewise sort (matches hermes' Python sorted() — case-sensitive ASCII);
    // localeCompare interleaves case and would drift the wire order.
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      const rel = path.relative(root, abs).split(path.sep).join('/');
      if (isExcludedPath(rel)) {
        skipped.push(rel);
        continue;
      }
      if (e.isSymbolicLink()) {
        skipped.push(rel);
        continue;
      }
      if (e.isDirectory()) {
        await walk(abs);
        continue;
      }
      if (!e.isFile()) {
        skipped.push(rel);
        continue;
      }
      const buf = await fs.readFile(abs);
      total += buf.length;
      if (total > MGMT_SNAPSHOT_MAX_BYTES) {
        throw Object.assign(new Error(`home exceeds the ${MGMT_SNAPSHOT_MAX_BYTES}-byte cap (at ${rel})`), { code: 413 });
      }
      files.push({ path: rel, content_b64: buf.toString('base64') });
    }
  }
  await walk(root);
  return { version: 1, hermes_home: root, files, total_bytes: total, skipped, snapshot_at: nowSecs };
}

export interface ImportOutcome {
  ok: true;
  applied: boolean;
  reason?: 'stale_snapshot';
  restored_files: number;
  last_applied_snapshot_at?: number;
}

/** Process-lifetime newer-wins state (RAM-only by design — it protects one
 *  instance's boot window; a fresh instance starts open). */
let lastImportSnapshotAt: number | undefined;
export function resetImportGuardForTests(): void {
  lastImportSnapshotAt = undefined;
}

export async function importHome(root: string, doc: unknown): Promise<ImportOutcome> {
  const d = doc as Partial<SnapshotDoc> & { snapshot_at?: unknown };
  if (d.version !== 1) throw Object.assign(new Error(`unsupported snapshot version ${JSON.stringify(d.version)}`), { code: 400 });
  if (!Array.isArray(d.files)) throw Object.assign(new Error('files must be a list'), { code: 400 });

  const snapAt = typeof d.snapshot_at === 'number' && Number.isFinite(d.snapshot_at) && typeof d.snapshot_at !== 'boolean'
    ? d.snapshot_at
    : undefined;
  if (snapAt !== undefined && lastImportSnapshotAt !== undefined && snapAt <= lastImportSnapshotAt) {
    return { ok: true, applied: false, reason: 'stale_snapshot', restored_files: 0, last_applied_snapshot_at: lastImportSnapshotAt };
  }

  // validate everything BEFORE any byte lands
  const rootReal = path.resolve(root);
  let total = 0;
  const writes: Array<{ abs: string; buf: Buffer }> = [];
  for (const f of d.files) {
    const rel = (f as SnapshotFile).path;
    if (!relPathOk(rel)) throw Object.assign(new Error(`snapshot path ${JSON.stringify(rel)} invalid`), { code: 400 });
    const abs = path.resolve(rootReal, rel);
    if (abs !== rootReal && !abs.startsWith(rootReal + path.sep)) {
      throw Object.assign(new Error(`snapshot path ${JSON.stringify(rel)} escapes the home`), { code: 400 });
    }
    let buf: Buffer;
    try {
      buf = Buffer.from((f as SnapshotFile).content_b64, 'base64');
      if (buf.toString('base64').replace(/=+$/, '') !== String((f as SnapshotFile).content_b64).replace(/=+$/, '')) {
        throw new Error('roundtrip mismatch');
      }
    } catch {
      throw Object.assign(new Error(`snapshot ${JSON.stringify(rel)}: not valid base64`), { code: 400 });
    }
    total += buf.length;
    if (total > MGMT_SNAPSHOT_MAX_BYTES) {
      throw Object.assign(new Error(`snapshot exceeds the ${MGMT_SNAPSHOT_MAX_BYTES}-byte cap`), { code: 400 });
    }
    if (isExcludedPath(rel)) continue; // image-owned: silently skipped on write too
    writes.push({ abs, buf });
  }
  for (const w of writes) {
    await fs.mkdir(path.dirname(w.abs), { recursive: true });
    const tmp = `${w.abs}.tmp`;
    await fs.writeFile(tmp, w.buf);
    await fs.rename(tmp, w.abs);
  }
  lastImportSnapshotAt = snapAt ?? Math.floor(Date.now() / 1000);
  return { ok: true, applied: true, restored_files: writes.length };
}

export async function homeBytes(root: string): Promise<number> {
  let total = 0;
  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) await walk(abs);
      else if (e.isFile()) total += (await fs.stat(abs)).size;
    }
  }
  await walk(root);
  return total;
}
