The optional email-link sign-in method can deliver messages to a private local outbox. It requires no mail account or external delivery service. This is development-only: possession of a saved link is sufficient to complete that sign-in request.

The public broker includes the injected `EmailSender` interface and its local implementation. Build with the `auth-email-link` feature to enable the HTTP endpoints. Its binary refuses other delivery backends and refuses local delivery unless `BROKER_DEV_MODE=true`.

## Configuration

Configure these settings in the environment used to launch your local broker:

| Setting | Purpose |
|---|---|
| `BROKER_AUTH_METHODS` | Include `email_link` alongside the desired authentication methods. |
| `BROKER_DEV_MODE` | Must be `true` for local file delivery. |
| `BROKER_EMAIL_FROM_ADDRESS` | Synthetic sender identity, such as `sender@example.test`. |
| `BROKER_EMAIL_OUTBOX_DIR` | Absolute path to a directory owned by you with mode `0700`. New directories are created privately. |
| `BROKER_EMAIL_SENDER` | Omit or set to `local-outbox`; other values fail. |
| `BROKER_EMAIL_LANDING_URL_BASE` | Optional local broker URL; otherwise uses the configured issuer. |

Messages are individual mode-`0600` JSON files with a random filename. They contain the recipient, sign-in link and an explicit development marker. The hidden readiness file contains no sign-in link. The outbox has a bounded file count and refuses delivery when full; remove old messages explicitly. Expired links are rejected by the existing token store, but their files remain until removed.

Links keep the existing single-use, expiry and request-rate rules. The outbox is a local delivery mechanism, not a bypass of authentication or chain grants. A sign-in session alone does not grant storage access. Keep the outbox outside the source tree and public artifacts. The standard `terrier services` profile currently uses its qualified owner/passkey flow; it does not enable this optional method automatically.

## Checks

Local, from the public checkout:

```sh
cargo test -p agentkeys-broker-server --lib local_outbox
cargo test -p agentkeys-broker-server --test email_flow --test local_boot
```

The HTTP flow reads a real outbox message, completes verification and polling, then checks replay rejection and unchanged delivery files. File-security checks cover unsafe permissions and links without changing unrelated files. The separate owner/storage qualification exercises actual local contracts; this optional email test does not replace that qualification.
