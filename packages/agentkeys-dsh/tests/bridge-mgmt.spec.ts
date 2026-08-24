import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { exportHome, importHome, isExcludedPath, relPathOk, resetImportGuardForTests } from '../src/bridge-mgmt.js';

let home: string;
beforeEach(async () => {
  resetImportGuardForTests();
  home = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-home-'));
});
afterEach(async () => {
  await fs.rm(home, { recursive: true, force: true });
});

describe('bridge mgmt snapshot (#616)', () => {
  it('exports files sorted, excludes node_modules + baked profile config', async () => {
    await fs.mkdir(path.join(home, 'sessions'), { recursive: true });
    await fs.writeFile(path.join(home, 'sessions', 'a.jsonl'), 'log');
    await fs.writeFile(path.join(home, 'SOUL.md'), 'persona');
    await fs.mkdir(path.join(home, 'profiles', 'agentkeys', 'node_modules', 'x'), { recursive: true });
    await fs.writeFile(path.join(home, 'profiles', 'agentkeys', 'node_modules', 'x', 'y.js'), 'dep');
    await fs.writeFile(path.join(home, 'profiles', 'agentkeys', 'cordis.patch.yml'), 'baked');
    const doc = await exportHome(home, 1234);
    const paths = doc.files.map((f) => f.path);
    expect(paths).toEqual(['SOUL.md', 'sessions/a.jsonl']); // sorted, exclusions gone
    expect(doc.snapshot_at).toBe(1234);
    expect(doc.hermes_home).toBe(home); // field name kept for wire compat
    expect(doc.skipped).toContain('profiles/agentkeys/cordis.patch.yml');
  });

  it('round-trips through import into a fresh home', async () => {
    await fs.writeFile(path.join(home, 'MEMORY.md'), 'remembered');
    await fs.mkdir(path.join(home, 'skills'), { recursive: true });
    await fs.writeFile(path.join(home, 'skills', 's.md'), 'skill');
    const doc = await exportHome(home, 100);
    const dst = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-restore-'));
    const outcome = await importHome(dst, { ...doc, snapshot_at: 100 });
    expect(outcome).toMatchObject({ ok: true, applied: true, restored_files: 2 });
    expect(await fs.readFile(path.join(dst, 'MEMORY.md'), 'utf8')).toBe('remembered');
    expect(await fs.readFile(path.join(dst, 'skills', 's.md'), 'utf8')).toBe('skill');
    await fs.rm(dst, { recursive: true, force: true });
  });

  it('newer-wins guard: a <= snapshot is stale, no write', async () => {
    const dst = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-guard-'));
    const doc = (at: number) => ({ version: 1 as const, hermes_home: dst, files: [{ path: 'f', content_b64: Buffer.from('x').toString('base64') }], total_bytes: 1, skipped: [], snapshot_at: at });
    expect((await importHome(dst, doc(200))).applied).toBe(true);
    const stale = await importHome(dst, doc(200));
    expect(stale).toMatchObject({ applied: false, reason: 'stale_snapshot', last_applied_snapshot_at: 200 });
    expect((await importHome(dst, doc(201))).applied).toBe(true); // newer applies
    await fs.rm(dst, { recursive: true, force: true });
  });

  it('rejects version, traversal, and non-list files before writing', async () => {
    const dst = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-reject-'));
    await expect(importHome(dst, { version: 2, files: [] })).rejects.toThrow(/unsupported snapshot version/);
    await expect(importHome(dst, { version: 1, files: 'no' })).rejects.toThrow(/files must be a list/);
    await expect(importHome(dst, { version: 1, files: [{ path: '../escape', content_b64: 'x' }] })).rejects.toThrow(/invalid|escape/);
    await fs.rm(dst, { recursive: true, force: true });
  });

  it('path + exclusion predicates', () => {
    expect(relPathOk('a/b.md')).toBe(true);
    expect(relPathOk('/abs')).toBe(false);
    expect(relPathOk('a/../b')).toBe(false);
    expect(relPathOk('a\\b')).toBe(false);
    expect(isExcludedPath('profiles/agentkeys/node_modules/x/y.js')).toBe(true);
    expect(isExcludedPath('profiles/agentkeys/package.json')).toBe(true);
    expect(isExcludedPath('sessions/a.jsonl')).toBe(false);
  });
});
