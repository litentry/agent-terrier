The local stack includes a durable off-chain audit archive. Storage workers record canonical envelopes there; an owner explicitly anchors an envelope hash on the local chain. The CLI and website use the same envelope schema, hash calculation and chain-event decoder. Storing an envelope alone does not submit a transaction or prove that its described action occurred.

## Start and inspect

Prepare the [local services](./local-services.md), register a fresh development owner and log in. Local, from the public checkout and the same selected state directory:

```sh
./terrier stack start
export AGENT_TERRIER_OWNER_NAME="${AGENT_TERRIER_OWNER_NAME:-developer}"
./terrier owner register --name "${AGENT_TERRIER_OWNER_NAME}"
./terrier owner login --name "${AGENT_TERRIER_OWNER_NAME}" \
  --broker-url "$(./terrier stack status | jq -er '.services.services.broker.url')"
printf %s 'synthetic-local-example' |
  ./terrier cred store example --name "${AGENT_TERRIER_OWNER_NAME}" --secret-stdin
./terrier audit list --name "${AGENT_TERRIER_OWNER_NAME}"
```

The credential worker must obtain an archive receipt before reporting success. Audit bodies carry operation metadata and commitments, not the credential plaintext. Operation metadata can still be sensitive. Do not put passwords, keys or personal information in a manually submitted audit body or share generated state and raw logs.

`list` returns the authenticated owner's off-chain hashes, including envelopes not yet anchored. Use its `next_cursor` with `--cursor` and a `--limit` from 1 through 100. This cursor is an envelope hash, different from the block/log cursor returned by `recent`.

## Fetch, anchor and decode

Choose one `envelope_hash` from the index. Local, from the same checkout and selected state:

```sh
./terrier audit fetch --name "${AGENT_TERRIER_OWNER_NAME}" \
  --hash "${AGENT_TERRIER_AUDIT_HASH:?Select an envelope hash from audit list}"
./terrier audit anchor --name "${AGENT_TERRIER_OWNER_NAME}" \
  --hash "${AGENT_TERRIER_AUDIT_HASH}"
./terrier audit recent --name "${AGENT_TERRIER_OWNER_NAME}"
./terrier audit decode --name "${AGENT_TERRIER_OWNER_NAME}" \
  --id "${AGENT_TERRIER_AUDIT_EVENT_ID:?Select event.id from audit recent}"
```

`fetch` checks canonical CBOR, its hash and the owner namespace. `anchor` fetches and verifies that envelope first, then uses the existing owner-controlled P-256/ERC-4337 signing and receipt verification. The broker never holds this owner passkey or signs the transaction. The anchor receipt must report `anchored` and `verified`. `recent` reads actual chain events. `decode` checks the archived envelope against the selected event and reports `synthesized: false`. An unavailable or mismatched body fails this envelope decode; the command does not report a preview as verified.

An owner-only journal records the unsigned operation identity before submission. Repeating `anchor` for the same hash checks the recorded operation and recovers its confirmed transaction; it does not sign or submit again. A pending or missing receipt remains an error. Restore and inspect the original state rather than deleting the journal to force a retry. The journal contains no signed transaction or passkey. These recovery reads are limited to the local development chain.

## Append an application envelope

Use `append --op-kind … --body-stdin` for an explicit typed application record. The numeric kind and body schema are owned by [`AuditOpKind`](../../crates/agentkeys-web-core/src/audit/op_kind.rs) and [typed bodies](../../crates/agentkeys-web-core/src/audit/bodies.rs). Unknown kinds and mismatched bodies fail. The bounded JSON body comes from stdin; owner identity, timestamp and success result are supplied by the native CLI. Its receipt says `stored: true` and `anchored: false`. Anchor separately when needed. A submitted claim is not independent proof of its contents or an authorization grant.

## Protection, persistence and limits

The archive listens only on loopback and requires its generated stack credential. Browsers and owner CLI clients use the broker origin with their existing authenticated session; the credential never reaches them or a managed agent. The broker verifies the current chain owner binding before index/read access and rejects a foreign owner's hash. An active bound agent may append only its own supported runtime event kinds; it cannot list or read another actor's archive. Trusted local storage workers append their receipts through the private service channel. The runtime reuses its existing bounded, best-effort audit plugin for tool outcomes and approval decisions; archive unavailability can lose that tee output, while the private runtime session log retains the detailed tool record. This is not an exactly-once event-delivery guarantee.

The supervisor owns the original protected `services/audit/service.key` and `services/audit/archive.db` under the selected private state directory. SQLite persists canonical CBOR in immutable content-addressed records bound to the selected deployment. Reads verify the saved hash again. Stop/start and whole-stack restart retain the archive; explicit confirmed reset erases it with the rest of that installation. Updating a stopped pre-archive stack creates the new archive files once while preserving existing keys. Once migrated, a missing credential or database refuses startup instead of recreating it.

The public development executable exposes neither the historical unauthenticated fixture routes nor automatic Merkle-root signing. There is no background chain writer, production custody, encrypted archive-at-rest guarantee, remote backup or hard storage quota. Host administrators can read or alter local files; hash verification detects a modified envelope but cannot prevent host deletion. Protect and back up the whole state directory according to your development needs. On-chain commitments retain hashes, not the off-chain body.

## CLI qualification

Local, after preparing contract inputs and rebuilding native binaries:

```sh
./terrier test focused --component audit
./terrier test qualification --component audit
```

The explicit qualifier uses a fresh local chain and actual owner sessions. It checks a real worker receipt, owner-signed anchoring, shared website decoding, lost-response recovery without another chain submission, durable restart, unauthorized/foreign-owner denial and unchanged archive contents after refused requests. It starts no browser, Docker container or model server. The nightly GitHub Actions service lane runs it; ordinary development can select it independently.
