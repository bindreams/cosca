#!/usr/bin/env bash
# Builds the workspace's rustdoc (for the host, or `CARGO_BUILD_TARGET`). Run by the `cargo-doc` prek hook. cosca alone
# with no features and with each feature (`[features]` in Cargo.toml) catches a link to an item another feature gates;
# cosca-path has none. The all-features pass runs last so `target/doc` ends holding the full docs.
set -euo pipefail

if ! command -v cargo > /dev/null 2>&1; then
    echo "error: cargo is not installed; see https://rustup.rs" >&2
    exit 1
fi

for features in "" pty serde tokio; do
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p cosca --no-default-features --features "$features" --locked
done
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
