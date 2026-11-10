#!/usr/bin/env bash
# Runs `cargo fmt --check` or clippy in each standalone tool crate (the root workspace does not reach them).
# Usage: tools.sh fmt|clippy
set -euo pipefail

crates=(
    .github/libtest-lint
    scripts/skuld-rewrite
)

mode="${1:?usage: tools.sh fmt|clippy}"

case "$mode" in
    fmt | clippy) ;;
    *)
        echo "error: unknown mode '$mode'; usage: tools.sh fmt|clippy" >&2
        exit 1
        ;;
esac

if ! cargo "$mode" --version > /dev/null 2>&1; then
    echo "error: cargo $mode is not installed; run: rustup component add $([[ "$mode" == fmt ]] && echo rustfmt || echo clippy)" >&2
    exit 1
fi

# Each crate runs from its own directory: clippy reads that crate's own clippy.toml, not the repo's.
for crate in "${crates[@]}"; do
    case "$mode" in
        fmt) (cd "$crate" && cargo fmt --check) ;;
        clippy) (cd "$crate" && cargo clippy --locked --all-targets -- -D warnings) ;;
    esac
done
