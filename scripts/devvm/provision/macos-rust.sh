#!/usr/bin/env bash
# Installs the pinned Rust toolchain (rustup, version from .github/ci-toolchain) and
# cargo-nextest (CI's pin) for the guest's `admin` user, so
# `devvm.py run macos-arm64 -- cargo nextest run ...` has something to run. The Cirrus base
# image ships the Command Line Tools (the linker); it does not ship Rust.
#
# Usage: macos-rust.sh <tree-dir> [--rosetta]
#   <tree-dir>  staged cosca tree; its .github/ci-toolchain names the toolchain.
#   --rosetta   also install Rosetta 2 and the x86_64-apple-darwin target, so x86_64 test
#               binaries can run in the guest. An approximation of the Intel lane only.
# Idempotent: each step skips itself if already done.
set -euo pipefail

TREE="${1:?usage: macos-rust.sh <tree-dir> [--rosetta]}"
ROSETTA=0
[ "${2:-}" = "--rosetta" ] && ROSETTA=1

TOOLCHAIN="$(tr -d '[:space:]' <"$TREE/.github/ci-toolchain")"
CARGO="$HOME/.cargo/bin/cargo"

if [ -x "$CARGO" ] && "$HOME/.cargo/bin/rustup" toolchain list | grep -q "^$TOOLCHAIN"; then
    echo "devvm: toolchain $TOOLCHAIN already present, skipping rustup install"
else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
        sh -s -- -y --profile minimal --default-toolchain "$TOOLCHAIN"
fi
"$HOME/.cargo/bin/rustup" default "$TOOLCHAIN" >/dev/null
echo "devvm: $("$CARGO" --version)"

# Same version as CI (NEXTEST_VERSION in .github/workflows/ci.yaml). Prebuilt universal
# tarball (arm64 + x86_64); compiling nextest from source is too slow for a throwaway VM.
# Tag and checksum share a line so Renovate moves both together.
NEXTEST_TAG_UNIVERSAL="cargo-nextest-0.9.146" NEXTEST_SHA256_UNIVERSAL="39785160b3c2f6ed9a765049cf4fa79f3b39aa02eb7598a5a0e2a1a0b9ffb9a8"
NEXTEST_VERSION="${NEXTEST_TAG_UNIVERSAL#cargo-nextest-}"
INSTALLED="$("$CARGO" nextest --version 2>/dev/null | head -n1 | awk '{print $2}' || true)"
if [ "$INSTALLED" = "$NEXTEST_VERSION" ]; then
    echo "devvm: cargo-nextest $NEXTEST_VERSION already present, skipping"
else
    TARBALL="$(mktemp -t nextest).tar.gz"
    curl --proto '=https' --tlsv1.2 -sSf -L -o "$TARBALL" \
        "https://github.com/nextest-rs/nextest/releases/download/$NEXTEST_TAG_UNIVERSAL/cargo-nextest-$NEXTEST_VERSION-universal-apple-darwin.tar.gz"
    ACTUAL="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
    if [ "$ACTUAL" != "$NEXTEST_SHA256_UNIVERSAL" ]; then
        echo "devvm: cargo-nextest checksum mismatch: expected $NEXTEST_SHA256_UNIVERSAL, got $ACTUAL" >&2
        rm -f "$TARBALL"
        exit 1
    fi
    mkdir -p "$HOME/.cargo/bin"
    tar -xzf "$TARBALL" -C "$HOME/.cargo/bin" cargo-nextest
    rm -f "$TARBALL"
    AFTER="$("$CARGO" nextest --version 2>/dev/null | head -n1 | awk '{print $2}' || true)"
    if [ "$AFTER" != "$NEXTEST_VERSION" ]; then
        echo "devvm: cargo-nextest verification failed: expected $NEXTEST_VERSION, got '$AFTER'" >&2
        exit 1
    fi
    echo "devvm: installed cargo-nextest $AFTER"
fi

if [ "$ROSETTA" = 1 ]; then
    if /usr/bin/pgrep -q oahd; then
        echo "devvm: Rosetta already present"
    else
        sudo softwareupdate --install-rosetta --agree-to-license
    fi
    "$HOME/.cargo/bin/rustup" target add x86_64-apple-darwin
fi
