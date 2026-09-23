#!/usr/bin/env bash
# Installs a Rust toolchain (via rustup) and a C linker (via apt) for the `vagrant` user, so
# `devvm.py run <linux guest> -- cargo test ...` has something to run — Rust needs a system
# `cc` to link even pure-Rust binaries. Idempotent: each step skips itself if already done.
set -euo pipefail

if command -v cc >/dev/null 2>&1; then
    echo "devvm: cc already present, skipping apt install"
else
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -qq -y build-essential >/dev/null
fi

if command -v cargo >/dev/null 2>&1; then
    echo "devvm: cargo already present ($(cargo --version)), skipping rustup install"
    exit 0
fi

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
echo '. "$HOME/.cargo/env"' >>"$HOME/.bashrc"
echo "devvm: installed $("$HOME/.cargo/bin/cargo" --version)"
