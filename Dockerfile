FROM --platform=$BUILDPLATFORM rust:1.85-slim AS builder

WORKDIR /app

# Cache dependencies by copying manifests and building a dummy binary first
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    mkdir -p src/api/routes src/config src/core/engine src/core/security src/core/session src/data/analytics src/data/storage src/services/llm src/services/proxy src/utils && \
    for f in \
    src/main.rs \
    src/api/mod.rs src/api/app.rs \
    src/api/routes/mod.rs src/api/routes/dashboard.rs src/api/routes/init.rs src/api/routes/internal.rs src/api/routes/proxy.rs \
    src/config/mod.rs src/config/settings.rs \
    src/core/mod.rs \
    src/core/engine/mod.rs src/core/engine/rules.rs src/core/engine/waf_engine.rs \
    src/core/security/mod.rs src/core/security/challenge.rs src/core/security/rate_limit.rs \
    src/core/session/mod.rs src/core/session/manager.rs \
    src/data/mod.rs \
    src/data/analytics/mod.rs src/data/analytics/aggregator.rs \
    src/data/storage/mod.rs src/data/storage/base.rs src/data/storage/manager.rs \
    src/services/mod.rs \
    src/services/llm/mod.rs src/services/llm/client.rs \
    src/services/proxy/mod.rs src/services/proxy/forwarder.rs \
    src/utils/mod.rs src/utils/compression.rs src/utils/http_utils.rs src/utils/query_parser.rs src/utils/ua_parser.rs; \
    do \
    echo "" > "$f"; \
    done && \
    cargo build --release && \
    rm -rf src

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r biubo && \
    useradd -r -g biubo -d /app -s /sbin/nologin biubo

WORKDIR /app

COPY --from=builder /app/target/release/biubo-waf .

RUN chown -R biubo:biubo /app

USER biubo

EXPOSE 8080

ENV RUST_LOG=info

LABEL org.opencontainers.image.source="https://github.com/mc-yzy15/Biubo-rust" \
    org.opencontainers.image.description="A Web Application Firewall that Thinks, Remembers, and Visualizes" \
    org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["./biubo-waf"]
