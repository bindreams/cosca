#!/usr/bin/env bash
# Builds the workspace's rustdoc (for the host, or `CARGO_BUILD_TARGET`). Run by the `cargo-doc` prek hook.
set -euo pipefail

if ! command -v cargo > /dev/null 2>&1; then
    echo "error: cargo is not installed; see https://rustup.rs" >&2
    exit 1
fi

RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
