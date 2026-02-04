FROM --platform=$BUILDPLATFORM rust:1.84-bookworm AS builder

ARG TARGETARCH

# musl targetをインストール（静的リンク用）
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools gcc-aarch64-linux-gnu && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

# アーキテクチャに応じたターゲットを選択してビルド
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc && \
      cargo build --release --target aarch64-unknown-linux-musl && \
      mv target/aarch64-unknown-linux-musl/release/eapmd5-client /eapmd5-client; \
    else \
      cargo build --release --target x86_64-unknown-linux-musl && \
      mv target/x86_64-unknown-linux-musl/release/eapmd5-client /eapmd5-client; \
    fi

# ------- runtime image -------
FROM gcr.io/distroless/static-debian12

COPY --from=builder /eapmd5-client /eapmd5-client

ENTRYPOINT ["/eapmd5-client"]
