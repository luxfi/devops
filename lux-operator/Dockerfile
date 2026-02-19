# Multi-stage build for lux-operator
# Stage 1: Build the Rust binary
FROM rust:1.88-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Limit parallelism to reduce memory usage
ENV CARGO_BUILD_JOBS=2

# Copy workspace files first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY lux-operator/Cargo.toml lux-operator/Cargo.toml

# Create dummy source files for dependency caching
RUN mkdir -p lux-operator/src && \
    echo "fn main() {}" > lux-operator/src/main.rs

# Create stub Cargo.toml entries for other workspace members
RUN for pkg in lux-core luxd luxup bench benchup lux-faucet staking-key-downloader staking-signer-downloader; do \
      mkdir -p "$pkg/src"; \
      printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' "$pkg" > "$pkg/Cargo.toml"; \
      echo "fn main() {}" > "$pkg/src/main.rs"; \
    done && \
    echo "" > lux-core/src/main.rs && echo "pub fn stub() {}" > lux-core/src/lib.rs

# Build dependencies only (cached layer)
RUN cargo build --release -p lux-operator 2>/dev/null || true

# Copy actual source code
COPY lux-operator/ lux-operator/

# Touch source files to invalidate the cached build
RUN touch lux-operator/src/main.rs

# Build the operator
RUN cargo build --release -p lux-operator

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -f luxop && useradd -r -s /bin/false -g luxop luxop

COPY --from=builder /build/target/release/lux-operator /usr/local/bin/lux-operator
RUN chmod +x /usr/local/bin/lux-operator

USER luxop

EXPOSE 8080 8081

ENTRYPOINT ["/usr/local/bin/lux-operator"]
