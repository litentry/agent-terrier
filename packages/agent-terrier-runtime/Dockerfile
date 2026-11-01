FROM public.ecr.aws/docker/library/rust@sha256:a41f7740f8b45d45795624eec13a8b42263cc700f19f7e4e86e04d3dda08a479 AS daemon-build
RUN apk add --no-cache make=4.4.1-r4 perl=5.42.2-r1
WORKDIR /opt/terrier
COPY rust-toolchain.toml ./
RUN rustup toolchain install --no-self-update
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY presets ./presets
ARG TARGETARCH
ARG CARGO_BUILD_JOBS=2
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="--remap-path-prefix=/opt/terrier=/source --remap-path-prefix=/usr/local/cargo=/dependencies"
RUN --mount=type=cache,id=terrier-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=terrier-daemon-${TARGETARCH},target=/opt/terrier/target \
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS}" cargo build --locked --release -p agentkeys-daemon -p agentkeys-runtime --features agentkeys-daemon/vendored-openssl \
    && install -D target/release/agentkeys-daemon /opt/runtime/agentkeys-daemon \
    && install -D target/release/agent-terrier-runtime /opt/runtime/agent-terrier-runtime \
    && strip /opt/runtime/agentkeys-daemon /opt/runtime/agent-terrier-runtime

FROM public.ecr.aws/docker/library/node@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /opt/terrier
COPY packages/package.json packages/package-lock.json ./packages/
COPY packages/agentkeys-dsh/package.json ./packages/agentkeys-dsh/
COPY packages/agent-terrier-runtime/package.json ./packages/agent-terrier-runtime/
RUN npm ci --prefix packages --ignore-scripts --no-audit --no-fund
COPY packages/agentkeys-dsh/src ./packages/agentkeys-dsh/src
COPY packages/agentkeys-dsh/tsconfig.json packages/agentkeys-dsh/tsconfig.build.json ./packages/agentkeys-dsh/
RUN npm run build --prefix packages && npm prune --prefix packages --omit=dev --ignore-scripts --no-audit --no-fund

FROM public.ecr.aws/docker/library/node@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS runtime
WORKDIR /opt/terrier
ENV NODE_ENV=production
COPY --from=daemon-build /opt/runtime/agentkeys-daemon /usr/local/bin/agentkeys-daemon
COPY --from=daemon-build /opt/runtime/agent-terrier-runtime /usr/local/bin/agent-terrier-runtime
COPY --from=build /opt/terrier/packages/node_modules ./packages/node_modules
COPY --from=build /opt/terrier/packages/agentkeys-dsh/lib ./packages/agentkeys-dsh/lib
COPY packages/agentkeys-dsh/package.json packages/agentkeys-dsh/README.md ./packages/agentkeys-dsh/
COPY packages/agent-terrier-runtime/package.json packages/agent-terrier-runtime/start.mjs packages/agent-terrier-runtime/service-transport.mjs ./packages/agent-terrier-runtime/
COPY presets/local-models.json ./presets/local-models.json
COPY LICENSE NOTICE ./
COPY LICENSES ./LICENSES
RUN node --input-type=module -e 'import { mkdirSync, chownSync, chmodSync } from "node:fs"; import { STATE_DIRECTORY, USER_ID, GROUP_ID } from "./packages/agentkeys-dsh/lib/generated/runtime-layout.js"; mkdirSync(STATE_DIRECTORY, { recursive: true, mode: 0o700 }); chownSync(STATE_DIRECTORY, USER_ID, GROUP_ID); chmodSync(STATE_DIRECTORY, 0o700);'
USER node
ENTRYPOINT ["agent-terrier-runtime"]

FROM runtime AS qualification
COPY packages/agent-terrier-runtime/runtime.test.mjs packages/agent-terrier-runtime/daemon.test.mjs packages/agent-terrier-runtime/managed.test.mjs packages/agent-terrier-runtime/service-transport.test.mjs packages/agent-terrier-runtime/test-support.mjs packages/agent-terrier-runtime/qualify-model.mjs ./packages/agent-terrier-runtime/
COPY crates/agentkeys-core/chain-profiles/anvil.json ./crates/agentkeys-core/chain-profiles/anvil.json
ENTRYPOINT ["node", "--test", "packages/agent-terrier-runtime/runtime.test.mjs", "packages/agent-terrier-runtime/service-transport.test.mjs", "packages/agent-terrier-runtime/daemon.test.mjs", "packages/agent-terrier-runtime/managed.test.mjs"]

FROM runtime AS final
