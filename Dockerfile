FROM rust:1.84-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release && rm -rf src

COPY src/ src/
RUN touch src/main.rs && cargo build --release

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/nullpad /usr/local/bin/nullpad
COPY static/ /app/static/
COPY favicon.svg /app/static/favicon.svg

WORKDIR /app
EXPOSE 3000

CMD ["nullpad"]
