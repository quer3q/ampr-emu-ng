# PS5 build toolchain: Rust nightly features via RUSTC_BOOTSTRAP (build-std) + ps5-payload-sdk.
# Recipe from quer3q/ps5-dump-forge ps5/Dockerfile; the std patch step is dropped (core+alloc only).
FROM rust:1.99.0-slim-trixie@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates clang-19 lld-19 llvm-19 make curl unzip python3 \
    && rm -rf /var/lib/apt/lists/*
ENV PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk LLVM_CONFIG=/usr/bin/llvm-config-19
ENV PATH=/usr/lib/llvm-19/bin:$PATH
ENV RUSTUP_TOOLCHAIN=1.99.0 RUSTUP_AUTO_INSTALL=0
ARG SDK_URL=https://github.com/ps5-payload-dev/sdk/releases/download/v0.43/ps5-payload-sdk.zip
ARG SDK_SHA256=a9cc9929f21b2b2c5d5b309f3bab4997067c45281c0622cf4838b1aecba66fcb
RUN curl -fsSL --proto =https --retry 3 "$SDK_URL" -o /tmp/sdk.zip \
    && echo "$SDK_SHA256  /tmp/sdk.zip" | sha256sum -c - \
    && unzip -q /tmp/sdk.zip -d /opt && rm /tmp/sdk.zip \
    && test -x "$PS5_PAYLOAD_SDK/bin/prospero-clang"
RUN rustup component add rust-src
WORKDIR /work
