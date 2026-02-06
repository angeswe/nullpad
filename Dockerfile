# Multi-stage build for minimal runtime image

# Stage 1: Build
FROM rust:slim-bookworm@sha256:5c5066e3f3bdd22a5cec7ba22ef0ee6e0bf6eaf63b65b63c9bf25f6f69a5e26a AS builder

WORKDIR /build

# Copy manifests and cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    touch src/lib.rs && \
    cargo build --release && \
    rm -rf src target/release/nullpad target/release/deps/nullpad-* target/release/deps/libnullpad-* target/release/.fingerprint/nullpad-*

# Copy source code and build for real
COPY src ./src
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim@sha256:6458e6ce2b6448e31bfdced4be7d8aa88d389e6694ab09f5a718a694abe147f4

# Install runtime dependencies and apply security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r nullpad && \
    useradd -r -g nullpad -s /bin/false nullpad

# Create app directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/nullpad /app/nullpad

# Copy static files (tools/ is for local use only, not served)
COPY static /app/static

# Change ownership
RUN chown -R nullpad:nullpad /app

# Switch to non-root user
USER nullpad

# Expose port
EXPOSE 3000

# Set default bind address
ENV BIND_ADDR=0.0.0.0:3000

# Run the application
CMD ["/app/nullpad"]
