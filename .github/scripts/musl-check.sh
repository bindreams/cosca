#!/usr/bin/env bash
# Checks the library builds for musl, which has broken the build before (#172: msghdr/cmsghdr field types differ from
# glibc). Run by the `musl-check` prek hook.
#
# `--lib` only: the dev-dependencies' C code (libsqlite3-sys) needs a musl C compiler.
set -euo pipefail

target="x86_64-unknown-linux-musl"

if ! command -v rustup > /dev/null 2>&1; then
    echo "error: rustup is not installed; see https://rustup.rs" >&2
    exit 1
fi

installed="$(rustup target list --installed)"
if ! grep -qx "$target" <<< "$installed"; then
    echo "error: the rustup target $target is not installed; run: rustup target add $target" >&2
    exit 1
fi

cargo check --locked --all-features --lib --target "$target"
