# Multi-stage build for minimal runtime image

# Stage 1: Build
# Pin base images by digest for reproducible builds.
# To update: docker pull rust:slim-bookworm && docker inspect --format='{{index .RepoDigests 0}}' rust:slim-bookworm
FROM rust:slim-bookworm@sha256:5b9332190bb3b9ece73b810cd1f1e9f06343b294ce184bcb067f0747d7d333ea AS builder

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
RUN cargo build --release --locked

# Stage 2: Runtime
# To update: docker pull debian:bookworm-slim && docker inspect --format='{{index .RepoDigests 0}}' debian:bookworm-slim
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

# Install runtime dependencies and apply security updates
# curl is needed for Docker healthcheck (hits /healthz)
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
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

# Build version (set via --build-arg or defaults to git short hash)
ARG BUILD_VERSION=dev

# Regenerate SRI hashes and stamp build version, then remove openssl
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    bash /app/tools/update-sri.sh && \
    rm -rf /app/tools && \
    apt-get purge -y openssl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* && \
    find /app/static -name '*.html' -exec sed -i "s/__BUILD_VERSION__/${BUILD_VERSION}/g" {} +

# Create paste storage directory
RUN mkdir -p /data/pastes

# Ensure static files are world-readable and change ownership
RUN chmod -R a+rX /app/static && chown -R nullpad:nullpad /app /data

# Switch to non-root user
USER nullpad

# Expose port
EXPOSE 3000

# Set default bind address
ENV BIND_ADDR=0.0.0.0:3000

# Run the application
CMD ["/app/nullpad"]
