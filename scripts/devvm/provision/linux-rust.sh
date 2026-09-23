#!/usr/bin/env bash
# Installs a Rust toolchain (via rustup), a C linker (via apt), and cargo-nextest for the
# `vagrant` user, so `devvm.py run <linux guest> -- cargo nextest run ...` has something to
# run — Rust needs a system `cc` to link even pure-Rust binaries. Idempotent: each step skips
# itself if already done.
set -euo pipefail

if command -v cc >/dev/null 2>&1; then
    echo "devvm: cc already present, skipping apt install"
else
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -qq -y build-essential >/dev/null
fi

if command -v cargo >/dev/null 2>&1; then
    echo "devvm: cargo already present ($(cargo --version)), skipping rustup install"
else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    echo '. "$HOME/.cargo/env"' >>"$HOME/.bashrc"
    echo "devvm: installed $("$HOME/.cargo/bin/cargo" --version)"
fi

# cosca's CI (the Skuld migration) pins cargo-nextest at this exact version — install the
# same one here so `devvm.py run <linux guest> -- cargo nextest run ...` matches what CI runs
# instead of whatever a fresh install would resolve to today.
#
# Downloads nextest's own prebuilt release tarball rather than `cargo install
# cargo-nextest --locked` (compiling it from source). Measured directly (2026-09-23, on the
# Windows guest, but the same tradeoff applies here): compiling cargo-nextest from source ran
# for over an hour without finishing under this project's typical emulated/virtualized guest
# CPU — not hung, just too slow to be workable for a throwaway VM that gets destroyed and
# recreated often. The prebuilt binary is standalone; it doesn't need to have been built with
# the same toolchain as whatever `cargo` ends up building cosca's own test binaries with.
NEXTEST_VERSION="0.9.137"
CARGO="$HOME/.cargo/bin/cargo"
# `cargo nextest --version` is multi-line ("cargo-nextest X (hash date)", then "release:
# X", "commit-hash: ...", "commit-date: ...", "host: ..." - confirmed directly, 2026-09-23).
# `head -n1` before `awk` matters: piping all lines through `awk '{print $2}'` prints one
# $2 per input line (X duplicated, then the hash/date/host values), which both corrupts this
# log line and breaks the comparison below every time (a multi-line INSTALLED_VERSION can
# never equal NEXTEST_VERSION, so the "already present" skip would never fire).
INSTALLED_VERSION="$("$CARGO" nextest --version 2>/dev/null | head -n1 | awk '{print $2}' || true)"
if [ "$INSTALLED_VERSION" = "$NEXTEST_VERSION" ]; then
    echo "devvm: cargo-nextest $NEXTEST_VERSION already present, skipping"
else
    case "$(uname -m)" in
    x86_64) NEXTEST_TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64) NEXTEST_TARGET="aarch64-unknown-linux-gnu" ;;
    *)
        echo "devvm: no known cargo-nextest release target for uname -m '$(uname -m)'" >&2
        exit 1
        ;;
    esac
    NEXTEST_TARBALL="/tmp/cargo-nextest-$NEXTEST_VERSION.tar.gz"
    curl --proto '=https' --tlsv1.2 -sSf -L -o "$NEXTEST_TARBALL" \
        "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$NEXTEST_VERSION/cargo-nextest-$NEXTEST_VERSION-$NEXTEST_TARGET.tar.gz"
    mkdir -p "$HOME/.cargo/bin"
    tar -xzf "$NEXTEST_TARBALL" -C "$HOME/.cargo/bin" cargo-nextest
    rm -f "$NEXTEST_TARBALL"
    echo "devvm: installed cargo-nextest $("$CARGO" nextest --version | head -n1 | awk '{print $2}')"
fi
