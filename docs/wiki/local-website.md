The console uses one server-provided backend configuration. The browser client and gateway client consume the same selected backend and origin. Reusing a built website with another local broker does not require rebuilding its JavaScript.

## Prepare and start

Local, from the public repository root, after installing the pinned Rust toolchain, its WASM target and `wasm-pack`:

```sh
npm ci --ignore-scripts
python3 scripts/build-browser-core.py
npm --prefix apps/parent-control run build
```

Local, in `apps/parent-control` inside that same checkout, set `AGENT_TERRIER_WEB_BROKER_URL` to the broker URL reported by `terrier services status` and choose `AGENT_TERRIER_WEB_PORT`:

```sh
AGENT_TERRIER_WEB_BACKEND=core \
  AGENT_TERRIER_WEB_BROKER_URL="${AGENT_TERRIER_WEB_BROKER_URL:?Set the local broker origin}" \
  npx --no-install next start --hostname 127.0.0.1 \
  --port "${AGENT_TERRIER_WEB_PORT:?Choose the local website port}"
```

This starts the website only. The broker and workers must separately permit the exact website origin for cross-origin browser requests. Managed website startup, automatic local-origin wiring and complete browser enrollment remain open; successful HTML delivery is not an authenticated application acceptance result.

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
```

The fast lane uses component tests without a browser. Explicit qualification builds once, starts the actual server twice with different runtime broker origins and verifies unchanged build identity, uncached configuration, HTML and executable assets. Removed development proxy routes must return 404 without contacting a controlled bridge. Test servers have owned process groups and are stopped through the shared cleanup implementation. This checks configuration and delivery; it does not claim browser passkey, signing or full user-journey acceptance.
