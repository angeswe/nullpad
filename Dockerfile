# Multi-stage build for minimal runtime image

# Stage 1: Build
FROM rust:1.84-slim-bookworm AS builder

WORKDIR /build

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r nullpad && \
    useradd -r -g nullpad -s /bin/false nullpad

# Create app directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/nullpad /app/nullpad

# Copy static files
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
