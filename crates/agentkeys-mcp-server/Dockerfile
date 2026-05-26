# syntax=docker/dockerfile:1
# AgentKeys MCP server (issue #107, Phase 1).
#
# Two-stage build: rust:slim to compile, debian:slim to run. Final image
# is a single static-ish binary + ca-certs (TLS to broker/workers).

ARG RUST_VERSION=1.84
FROM rust:${RUST_VERSION}-slim AS build

WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy workspace skeleton first to maximize Docker layer cache on dep
# changes vs source changes.
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --release -p agentkeys-mcp-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r mcp && useradd -r -g mcp mcp

COPY --from=build /src/target/release/agentkeys-mcp-server /usr/local/bin/agentkeys-mcp-server

USER mcp
EXPOSE 8088
ENV MCP_TRANSPORT=http \
    MCP_LISTEN=0.0.0.0:8088

ENTRYPOINT ["/usr/local/bin/agentkeys-mcp-server"]
