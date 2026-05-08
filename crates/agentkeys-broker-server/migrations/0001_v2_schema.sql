-- Stage 7 issue#64 — v2 schema baseline (US-024).
--
-- This file is the canonical reference for the broker's v2 schema.
-- Each store module (`src/storage/*.rs`, `src/plugins/audit/sqlite.rs`)
-- runs the equivalent CREATE TABLE IF NOT EXISTS at boot via
-- `init_schema()` so a fresh DB matches this file byte-for-byte.
--
-- This file does NOT replace the per-module init_schema() calls in
-- Phase 0/A.1; it exists as a single-source-of-truth review surface
-- and as the future input for a real migration runner (Phase E
-- US-039 promotes this to a tracked schema-version table).
--
-- Tables introduced by Stage 7 issue#64:
--   - plugin_mint_log     (audit anchor: SqliteAnchor; src/plugins/audit/sqlite.rs)
--   - wallets             (wallet provisioner: ClientSideKeystore; src/storage/wallets.rs)
--   - auth_nonces         (WalletSig SIWE single-use; src/storage/auth_nonces.rs)
--   - email_tokens        (EmailLink magic-link single-use; src/storage/email_tokens.rs)
--   - email_request_status (EmailLink CLI poll status; src/storage/email_tokens.rs)
--   - email_rate_limits   (EmailLink per-bucket counters; src/storage/email_rate_limits.rs)
--
-- Pre-existing tables (Stage 7 phases 1+2, NOT modified by issue#64):
--   - mint_log            (legacy AuditLog; src/audit.rs)

PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

-- Phase 0: SqliteAnchor — replaces the legacy mint_log (still present
-- during the cutover transition). Columns mirror the AuditRecord shape
-- from `src/plugins/audit/mod.rs`. Status takes one of:
--   'confirmed' (Phase 0: written directly on success)
--   'pending'   (Phase C: pre-EVM-receipt staging row)
--   'quarantined' (Phase C: EVM anchor failed, awaits reconciliation)
CREATE TABLE IF NOT EXISTS plugin_mint_log (
    id            TEXT PRIMARY KEY,
    minted_at     INTEGER NOT NULL,
    record_hash   TEXT NOT NULL,
    omni_account  TEXT NOT NULL,
    wallet        TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    service       TEXT NOT NULL,
    grant_id      TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'confirmed',
    outcome       TEXT NOT NULL,
    outcome_detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_plugin_mint_log_minted_at
    ON plugin_mint_log(minted_at);
CREATE INDEX IF NOT EXISTS idx_plugin_mint_log_omni_account
    ON plugin_mint_log(omni_account);
CREATE INDEX IF NOT EXISTS idx_plugin_mint_log_record_hash
    ON plugin_mint_log(record_hash);
CREATE INDEX IF NOT EXISTS idx_plugin_mint_log_status
    ON plugin_mint_log(status);

-- Phase 0: ClientSideKeystoreProvisioner — broker stores ONLY the
-- (omni_account, address) binding; user holds the seed.
CREATE TABLE IF NOT EXISTS wallets (
    omni_account     TEXT NOT NULL,
    address          TEXT NOT NULL,
    role             TEXT NOT NULL CHECK(role IN ('master', 'daemon')),
    parent_address   TEXT,
    created_at       INTEGER NOT NULL,
    PRIMARY KEY (omni_account, address)
);
CREATE INDEX IF NOT EXISTS idx_wallets_omni_account
    ON wallets(omni_account);

-- Phase 0: SiweWalletAuth — single-use nonce table, race-safe via
-- conditional UPDATE on `consumed_at IS NULL`.
CREATE TABLE IF NOT EXISTS auth_nonces (
    nonce        TEXT PRIMARY KEY,
    address      TEXT NOT NULL,
    issued_at    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    consumed_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_auth_nonces_address
    ON auth_nonces(address);
CREATE INDEX IF NOT EXISTS idx_auth_nonces_expires_at
    ON auth_nonces(expires_at);

-- Phase A.1: EmailLink — magic-link tokens (single-use, fragment-token
-- wire format) AND per-request-id status row (CLI poll).
CREATE TABLE IF NOT EXISTS email_tokens (
    token_hash   TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL UNIQUE,
    email        TEXT NOT NULL,
    issued_at    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    consumed_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_email_tokens_request_id
    ON email_tokens(request_id);
CREATE INDEX IF NOT EXISTS idx_email_tokens_email
    ON email_tokens(email);
CREATE INDEX IF NOT EXISTS idx_email_tokens_expires_at
    ON email_tokens(expires_at);

CREATE TABLE IF NOT EXISTS email_request_status (
    request_id     TEXT PRIMARY KEY,
    status         TEXT NOT NULL CHECK(status IN ('pending', 'verified', 'failed')),
    session_jwt    TEXT,
    omni_account   TEXT,
    expires_at     INTEGER NOT NULL,
    failure_reason TEXT
);

-- Phase A.1: EmailLink — fixed-window-counter rate-limit buckets.
CREATE TABLE IF NOT EXISTS email_rate_limits (
    bucket_id     TEXT NOT NULL,
    window_start  INTEGER NOT NULL,
    count         INTEGER NOT NULL,
    PRIMARY KEY (bucket_id, window_start)
);
CREATE INDEX IF NOT EXISTS idx_email_rate_limits_window
    ON email_rate_limits(window_start);

-- Phase B (PENDING — US-025): capability grants + master-gated recovery.
-- Phase C (PENDING — US-030+): EVM-anchor reconciliation state.
-- Phase D (PENDING — US-037): idempotency-key dedup table.
-- Each phase appends to this file as schema lands; Phase E US-039
-- introduces a real migration runner with a tracked schema_version
-- table that consumes this file.
