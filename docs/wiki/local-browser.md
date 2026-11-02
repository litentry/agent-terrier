**Scope:** the local CLI can approve a public browser enrollment request using an existing development owner. The browser setup screen is still being integrated; command availability does not yet mean the complete browser onboarding journey is ready.

## Approval

Start the [managed website](./local-website.md) at its saved `http://localhost:<port>` origin. Register and log in a [local owner](./local-owner.md). The approval uses that owner's protected session, request key and development passkey. It does not export those files to the browser.

The request uses the shared `HostedSignerApproval` schema: browser public keys, account/origin, expiry and public possession proofs. Compare the entire device fingerprint with the browser that you intend to authorize. A file by itself is not a trusted confirmation. The selected account and website origin must also match.

Locally, from the repository root with the same selected local state:

```bash
printf 'Existing local owner name: '
IFS= read -r owner_name
printf 'Public browser request file: '
IFS= read -r browser_request
printf 'Device fingerprint shown by the browser: '
IFS= read -r browser_fingerprint
python3 terrier browser approve \
  --name "$owner_name" \
  --request-file "$browser_request" \
  --confirm-device-key-hash "$browser_fingerprint"
```

Only the guarded local development chain is supported. The request must be a regular file owned by the current user, without links or shared write access. Public read permissions are allowed. The native parser bounds input to the protocol-owned size limit and checks the browser's P-256 and device proofs, owner/account/chain, exact localhost origin, expiry and current operator nonce.

The existing authenticated broker prepare/build/submit endpoints perform their independent checks. Before signing the operation, the CLI recomputes its hash and compares the exact registration batch, account, nonce, empty initialization/signature and unsponsored local execution. It uses the actual owner's active request-key binding for recovery approval. No account is created and no owner secret enters the exchange file.

## Confirmation and retry

Success is a structured receipt with `complete: true`, the account, origin and device fingerprint. A new submission also includes its operation and transaction hashes. The CLI verifies the actual chain receipt and current account-signer/device bindings. The browser must then authenticate with its own passkey; possession of the request file cannot log in.

Before submission, the CLI writes an unsigned protected record under the selected owner's `browser-approvals` directory. A repeated command checks this saved operation without signing or submitting again, including after the owner's passkey file becomes unavailable. Current owner authentication and matching record bindings remain required. Concurrent attempts for the same request are refused.

An uncertain result returns a nonzero exit and `complete: false` with the operation hash. Restore service connectivity and repeat the same command. Do not delete its record or submit a replacement while its outcome is uncertain. If the process stopped before broadcast, the saved operation may remain unconfirmed; automatic re-signing is deliberately unavailable. Retain the record for diagnosis or explicitly reset an entirely disposable local stack.

## Qualification

The explicit website qualification includes a real-chain CLI scenario with fresh software proof keys. It covers approval, browser-credential login, wrong-owner/fingerprint/origin/nonce/expiry/signature denials with unchanged chain state, and receipt recovery without the owner passkey. This is functional CLI evidence, not physical authenticator or browser-PRF acceptance.

Locally, from the repository root after preparing contracts, native services and the website build:

```bash
python3 terrier test qualification --component website
```

The ordinary fast lane runs pure proof/payload and file-safety tests without starting a browser or chain. The real qualification is explicit and belongs in extended scheduled checks.
