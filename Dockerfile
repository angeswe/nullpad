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
    rm -rf src

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
