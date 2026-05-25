# syntax=docker/dockerfile:1.7

FROM --platform=$TARGETPLATFORM rust:1.95-alpine AS builder
WORKDIR /src
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM --platform=$TARGETPLATFORM ghcr.io/sagernet/sing-box:latest AS singbox

FROM --platform=$TARGETPLATFORM alpine:latest AS runtime
LABEL org.opencontainers.image.title="Proton-Singbox Orchestrator"
LABEL org.opencontainers.image.description="PSO control plane with bundled sing-box runtime"
RUN set -ex \
    && apk add --no-cache --upgrade bash tzdata ca-certificates nftables
COPY --from=builder /src/target/release/pso /usr/local/bin/pso
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["/usr/local/bin/pso"]
CMD ["--config", "/etc/pso/pso.config.json", "--state-dir", "/var/lib/pso", "run"]
