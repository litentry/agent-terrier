/**
 * #619 — the no-standing-allows boot assertion.
 *
 * Structurally, dsh cannot express a standing allow today (`ApprovalOutcome`
 * has no durable grant; `ApprovalPolicy` is ask|never). These tests pin the
 * tripwire that fires the day that changes AND a profile configures it — the
 * boot-time twin of the dsh-bump permission-contract diff.
 */
import { describe, expect, it, vi } from 'vitest';
import { ALLOWED_POLICIES, apply, PACKAGE_NAME, standingAllowViolation } from '../src/invariant.js';

describe('standingAllowViolation (#619)', () => {
  it('passes the reviewed vocabulary and an absent config', () => {
    expect(standingAllowViolation(undefined)).toBeUndefined();
    expect(standingAllowViolation({})).toBeUndefined();
    for (const policy of ALLOWED_POLICIES) {
      expect(standingAllowViolation({ policy })).toBeUndefined();
    }
  });

  it('fails a policy outside the reviewed vocabulary', () => {
    // the shape a future dsh durable-grant release would take
    const reason = standingAllowViolation({ policy: 'always' });
    expect(reason).toMatch(/outside the reviewed vocabulary/);
    expect(reason).toMatch(/spec/);
  });

  it('fails any non-empty standing-rule container', () => {
    expect(standingAllowViolation({ rules: [{ tool: 'bash' }] })).toMatch(/standing allow rules/);
    expect(standingAllowViolation({ allow: { bash: true } })).toMatch(/standing allow rules/);
    expect(standingAllowViolation({ alwaysAllow: ['web_fetch'] })).toMatch(/standing allow rules/);
  });

  it('tolerates the empty containers a stock profile carries', () => {
    expect(standingAllowViolation({ policy: 'ask', rules: [], allow: {}, alwaysAllow: undefined })).toBeUndefined();
  });
});

describe('invariant registration (#619)', () => {
  it('registers under the package name when the dev registry is composed', async () => {
    const register = vi.fn(() => () => {});
    const ctx = { invariants: { register } } as never;
    await apply(ctx);
    expect(register).toHaveBeenCalledWith(PACKAGE_NAME, expect.any(Function));
  });

  it('is inert in a shipped host (no invariants registry) — never throws', async () => {
    await expect(apply({} as never)).resolves.toBeInstanceOf(Function);
  });

  it('the installed check fails the profile when a standing allow is configured', async () => {
    let installed!: (c: unknown, fail: (m: string) => never) => void;
    const ctx = {
      approval: { config: { policy: 'ask', alwaysAllow: ['bash'] } },
      invariants: {
        register: (_p: string, installer: typeof installed) => {
          installed = installer;
          return () => {};
        },
      },
    } as never;
    await apply(ctx);
    const fail = vi.fn((m: string) => {
      throw new Error(m);
    });
    expect(() => installed(ctx, fail as never)).toThrow(/standing allow rules/);
  });
});
