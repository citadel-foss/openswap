# OpenSwap Dockerfile
# Contains makerd, maker-cli, and taker

## --- Builder Stage ---
FROM rust:1.90-alpine3.20 AS builder

RUN apk add --no-cache \
    build-base \
    protobuf \
    cmake \
    git \
    curl \
    pkgconfig \
    openssl-dev \
    sqlite-dev \
    sqlite-static \
    zeromq-dev \
    ca-certificates \
    openssl-libs-static \
    libgcc \
    musl-dev

WORKDIR /usr/src/openswap
COPY . .
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo build --release

## --- Runtime Stage ---
FROM alpine:3.20

RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
    build-base \
    protobuf \
    cmake \
    git \
    curl \
    pkgconfig \
    openssl-dev \
    sqlite-dev \
    sqlite-static \
    zeromq-dev \
    ca-certificates \
    openssl-libs-static \
    libgcc \
    musl-dev

RUN adduser -D -u 1001 openswap

RUN mkdir -p /app/bin /home/openswap/.openswap && \
    chown -R openswap:openswap /app /home/openswap

COPY --from=builder --chown=openswap:openswap /usr/src/openswap/target/release/makerd /app/bin/
COPY --from=builder --chown=openswap:openswap /usr/src/openswap/target/release/maker-cli /app/bin/
COPY --from=builder --chown=openswap:openswap /usr/src/openswap/target/release/taker /app/bin/

RUN chmod +x /app/bin/*

USER openswap
WORKDIR /app

ENV PATH="/app/bin:$PATH"

ENV OPENSWAP_DATA_DIR="/home/openswap/.openswap"



VOLUME ["/home/openswap/.openswap"]

CMD ["makerd"]
