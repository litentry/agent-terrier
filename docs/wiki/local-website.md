The console uses one server-provided backend configuration. The browser client and gateway client consume the same selected backend and origin. Reusing a built website with another local broker does not require rebuilding its JavaScript.

## Prepare and start

Local, from the public repository root, after installing the pinned Rust toolchain, its WASM target and `wasm-pack`:

```sh
npm ci --ignore-scripts
python3 scripts/build-browser-core.py
npm --prefix apps/parent-control run build
```

After preparing the [local service binaries](./local-services.md), local from the public repository root:

```sh
./terrier stack start --website
./terrier stack status
```

The website URL appears under `services.services.website.url`. An optional `--web-port` with `--website` selects the port on the first start. Otherwise a free loopback port is chosen and persisted in the existing service manifest. Later starts and restarts retain that origin because browser storage belongs to it. A changed port is refused; use separate state for another website origin. Stop the service group before enabling the website on an already-running stack. The terminal manager uses the same saved configuration.

The existing service supervisor owns the website process group, private logs and isolated home. It starts the prepared Next server with the active broker origin and permits exactly the website origin on the broker and storage workers. It never builds or installs dependencies implicitly and refuses `.env*` files in the application or repository root. A port owned by another process is left untouched; partial startup cleans up only owned children. No second supervisor, backend-address resolver or Docker controller is added.

`status` and `doctor` check a bounded, uncached website health response against the current instance and selected backend. This proves website delivery and configuration, not authenticated browser readiness. Audit/classification service wiring and browser enrollment remain open. `stack stop` and `restart` include the website and preserve data. Private diagnostics are included in `services logs` and `stack logs`.

## Standalone website process

Local, in `apps/parent-control` inside that same checkout, set `AGENT_TERRIER_WEB_BROKER_URL` to the broker URL reported by `terrier services status` and choose `AGENT_TERRIER_WEB_PORT`:

```sh
AGENT_TERRIER_WEB_BACKEND=core \
  AGENT_TERRIER_WEB_BROKER_URL="${AGENT_TERRIER_WEB_BROKER_URL:?Set the local broker origin}" \
  npx --no-install next start --hostname 127.0.0.1 \
  --port "${AGENT_TERRIER_WEB_PORT:?Choose the local website port}"
```

This starts the website only. The broker and workers must separately permit the exact website origin for cross-origin browser requests. The managed startup above owns that wiring. Complete browser enrollment and auxiliary-service integration remain open; successful HTML delivery is not an authenticated application acceptance result.

## Configuration ownership

`lib/backendConfiguration.ts` owns the public shape, validation and default native endpoint. The server reads these settings for each dynamically rendered page:

| Setting | Meaning |
| --- | --- |
| `AGENT_TERRIER_WEB_BACKEND` | `core` for the browser client, `daemon` for an existing native client, or `empty`; default `daemon` |
| `AGENT_TERRIER_WEB_BROKER_URL` | Required origin for `core` |
| `AGENT_TERRIER_WEB_DAEMON_URL` | Optional native origin; default is the shared `DEFAULT_DAEMON_URL` constant |

Only the selected kind and public origin are serialized into the page. No key, token, environment inventory or service credential belongs in this configuration. URLs must be HTTPS or loopback HTTP origins without user information, paths, queries or fragments. Unknown backends, invalid configuration and unexpected fields fail. An absent or invalid page configuration cannot make the gateway silently contact a local daemon.

The former `NEXT_PUBLIC_AGENTKEYS_BACKEND`, `NEXT_PUBLIC_AGENTKEYS_BROKER_URL` and `NEXT_PUBLIC_AGENTKEYS_DAEMON_URL` settings are refused with migration guidance. Remove them and use the server settings above. The console needs its Node server; the old static-export switch is refused. [Next.js runtime environment guidance](https://nextjs.org/docs/app/guides/environment-variables#runtime-environment-variables) explains why public build-time variables cannot select a new endpoint after compilation.

## Verification

Local, from the prepared public repository root:

```sh
./terrier test focused --component ui
./terrier test qualification --component ui
./terrier test qualification --component website
```

The fast lane uses component tests without a browser. Explicit qualification builds once, starts the actual server twice with different runtime broker origins and verifies unchanged build identity, uncached configuration, HTML and executable assets. Removed development proxy routes must return 404 without contacting a controlled bridge. Test servers have owned process groups and are stopped through the shared cleanup implementation. This checks configuration and delivery; it does not claim browser passkey, signing or full user-journey acceptance.

The explicit website qualifier reuses real local chain/service scenario helpers and the same lifecycle commands. It checks an occupied port with an untouched positive listener, exact-origin headers and foreign-origin absence, unauthenticated session rejection, unchanged origin/configuration across restart, fresh instance identity and confirmed shutdown. This lane requires the prebuilt website and native service binaries; it does not start a browser. Failed runs retain private diagnostics outside the checkout.
