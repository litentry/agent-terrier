/**
 * @module @agentkeys/dsh-suite/credentials — the vault/cap-backed credential
 * provider (#612, spec delegate-runtime-dsh §6).
 *
 * dsh's credentials seam: config carries REFERENCES (env-var-style names), the
 * provider owns values, consumers re-resolve per operation and never cache.
 * This provider maps each configured reference to an AgentKeys vault service
 * and resolves it through the co-located daemon
 * (`POST /v1/sandbox/self/credential`) — the daemon holds the delegate
 * identity, mints a per-operation `CredFetch` cap, the worker re-verifies
 * against the chain, and the value flows through one response: nothing at rest
 * in the sandbox, rotation/revocation land on the very next request.
 *
 * Unmapped references fall through to the PROCESS ENVIRONMENT (then resolve
 * `undefined` = unconfigured). The fallthrough is load-bearing, not a
 * convenience: dsh consults ONLY the mounted credentials service when one
 * exists (`resolveApiKey` is a ternary, not a chain — #631), and the sandbox
 * env contract (spec §3.2) delivers the gate LLM key AS env (`ARK_API_KEY`).
 * Without the fallthrough, mounting this provider makes the gate route
 * unresolvable on every pod. Mapped refs never consult env — vault-owned.
 * Writes are rejected: vault stores are master ceremonies, never a
 * delegate-side write. The record half is unsupported (no AgentKeys consumer).
 *
 * This is a Service class — the ONE case where a default export is correct
 * (mounted as a class plugin, like dsh's own credentials-local).
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { CredentialProvider } from '@deepseek-ai/dsh-credentials';
import { DaemonClient, DEFAULT_DAEMON_URL } from './daemon-client.js';
import type {
  CredentialInfo,
  CredentialKey,
  CredentialRecord,
  CredentialRecordEntry,
  CredentialRecordInfo,
  CredentialRef,
  ResolvedCredential,
} from '@deepseek-ai/dsh-credentials';

export const DEFAULT_CREDENTIAL_URL = `${DEFAULT_DAEMON_URL}/v1/sandbox/self/credential`;

export interface Config {
  credentialUrl?: string;
  bridgeToken?: string;
  /** reference (env-var-style name) → AgentKeys vault service (e.g.
   *  `{ "OPENROUTER_API_KEY": "openrouter" }`). Explicit by design — no magic
   *  name derivation; an unmapped ref is simply unconfigured. */
  refs?: Record<string, string>;
}

export class AgentKeysCredentialProvider extends CredentialProvider {
  static Config: z<Config> = z.object({
    credentialUrl: z.string().default(DEFAULT_CREDENTIAL_URL),
    bridgeToken: z.string(),
    refs: z.dict(z.string()),
  });

  constructor(
    ctx: Context,
    public config: Config,
  ) {
    super(ctx);
  }

  private serviceOf(ref: CredentialRef): string | undefined {
    return (this.config.refs ?? {})[String(ref)];
  }

  async resolve(ref: CredentialRef): Promise<ResolvedCredential | undefined> {
    const service = this.serviceOf(ref);
    if (!service) {
      const fromEnv = process.env[String(ref)];
      if (typeof fromEnv === 'string' && fromEnv.length > 0) {
        return { value: fromEnv, source: 'launch-env' };
      }
      return undefined;
    }
    const url = this.config.credentialUrl ?? DEFAULT_CREDENTIAL_URL;
    try {
      const client = new DaemonClient({ bridgeToken: this.config.bridgeToken });
      // unconfigured / denied both read as absent to the consumer (a
      // DaemonError lands in the catch like any transport failure)
      const body = await client.postJson<{ value_b64?: unknown; source?: unknown }>(url, { service }, { timeoutMs: 30_000 });
      if (typeof body.value_b64 !== 'string' || body.value_b64.length === 0) return undefined;
      const value = Buffer.from(body.value_b64, 'base64').toString('utf8');
      if (!value) return undefined; // seam-wide rule: empty is absent everywhere
      return { value, source: typeof body.source === 'string' ? body.source : 'agentkeys-vault' };
    } catch {
      return undefined;
    }
  }

  async describe(ref: CredentialRef): Promise<CredentialInfo> {
    if (this.serviceOf(ref) !== undefined) {
      return { configured: true, source: 'agentkeys-vault', writable: false };
    }
    const fromEnv = process.env[String(ref)];
    if (typeof fromEnv === 'string' && fromEnv.length > 0) {
      return { configured: true, source: 'launch-env', writable: false };
    }
    return { configured: false, writable: false };
  }

  async set(_ref: CredentialRef, _value: string): Promise<void> {
    throw new Error('agentkeys vault credentials are stored by the master ceremony, never from a delegate');
  }

  async unset(_ref: CredentialRef): Promise<void> {
    throw new Error('agentkeys vault credentials are revoked by the master ceremony, never from a delegate');
  }

  async readRecord(_key: CredentialKey): Promise<CredentialRecord | undefined> {
    return undefined;
  }

  async describeRecord(_key: CredentialKey): Promise<CredentialRecordInfo> {
    return { configured: false, writable: false } as CredentialRecordInfo;
  }

  async listRecords(): Promise<readonly CredentialRecordEntry[]> {
    return [];
  }

  async modifyRecord(
    _key: CredentialKey,
    _mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>,
  ): Promise<CredentialRecord | undefined> {
    throw new Error('credential records are unsupported by the AgentKeys provider');
  }

  async deleteRecord(_key: CredentialKey): Promise<void> {
    throw new Error('credential records are unsupported by the AgentKeys provider');
  }
}

export default AgentKeysCredentialProvider;
