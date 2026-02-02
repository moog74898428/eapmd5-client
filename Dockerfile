FROM rust:1.84-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release && strip target/release/eapmd5-client

# ------- runtime image -------
FROM debian:bookworm-slim

COPY --from=builder /app/target/release/eapmd5-client /usr/local/bin/eapmd5-client

ENTRYPOINT ["eapmd5-client"]
