# syntax=docker/dockerfile:1
# aivpn-mikrotik: runs aivpn-client inside a MikroTik RouterOS container
# Build: docker build --build-arg MUSL_IMAGE_TAG=aarch64-musl --build-arg TARGET_TRIPLE=aarch64-unknown-linux-musl -t aivpn-mikrotik .
# See build-mikrotik.sh for multi-arch manifest push

ARG MUSL_IMAGE_TAG=aarch64-musl
ARG TARGET_TRIPLE=aarch64-unknown-linux-musl

# Stage 1: cross-compile aivpn-client as a static musl binary
FROM --platform=linux/amd64 messense/rust-musl-cross:${MUSL_IMAGE_TAG} AS builder

ARG TARGET_TRIPLE

WORKDIR /app
COPY Cargo.toml ./
COPY crates/aivpn-common crates/aivpn-common/
COPY crates/aivpn-client crates/aivpn-client/
COPY crates/aivpn-server crates/aivpn-server/
COPY crates/aivpn-android-core crates/aivpn-android-core/
COPY crates/aivpn-ios-core crates/aivpn-ios-core/
COPY crates/aivpn-windows crates/aivpn-windows/
COPY crates/aivpn-linux crates/aivpn-linux/
COPY assets/masks assets/masks/

RUN cargo build --release --target "${TARGET_TRIPLE}" -p aivpn-client --bin aivpn-client \
    && cp "target/${TARGET_TRIPLE}/release/aivpn-client" /aivpn-client

# Stage 2: minimal runtime image with iproute2 for ip commands
FROM alpine:3.19
RUN apk add --no-cache iproute2 ca-certificates \
    && rm -rf /var/cache/apk/*

COPY --from=builder /aivpn-client /usr/local/bin/aivpn-client
COPY platforms/mikrotik/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/aivpn-client

# Required at runtime: /dev/net/tun must be mounted from RouterOS host
# Required capability: NET_ADMIN (set by RouterOS container runtime)
ENTRYPOINT ["/entrypoint.sh"]
