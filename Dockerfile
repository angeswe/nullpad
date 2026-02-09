# Multi-stage build for minimal runtime image

# Stage 1: Build
FROM rust:slim-bookworm AS builder

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
FROM debian:bookworm-slim

# Install runtime dependencies and apply security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user with explicit UID 1000 (matches k8s runAsUser)
RUN groupadd -g 1000 nullpad && \
    useradd -u 1000 -g nullpad -s /bin/false nullpad

# Create app directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/nullpad /app/nullpad

# Copy static files and SRI update script
COPY static /app/static
COPY tools/update-sri.sh /app/tools/update-sri.sh

# Regenerate SRI hashes at build time, then remove openssl
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    bash /app/tools/update-sri.sh && \
    rm -rf /app/tools && \
    apt-get purge -y openssl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

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
