#!/usr/bin/env bash
# This repo's clippy policy, run on the host target by the `cargo-clippy` prek hook, both locally and in the CI Test
# lanes. Three passes: all features, all features in release (the only build that compiles `cfg(not(debug_assertions))`
# code), and no features (a build with every feature off has dead-code gaps all-features never shows).
set -euo pipefail

if ! cargo clippy --version > /dev/null 2>&1; then
    echo "error: cargo clippy is not installed; run: rustup component add clippy" >&2
    exit 1
fi

cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features --release -- -D warnings
cargo clippy --locked --workspace --all-targets -- -D warnings
