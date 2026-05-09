FROM --platform=$BUILDPLATFORM rust:1.85-slim AS builder

WORKDIR /app

# Cache dependencies by copying manifests and building a dummy binary first
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY . .

RUN touch src/main.rs && cargo build --release

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
