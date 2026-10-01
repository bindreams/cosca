#!/usr/bin/env bash
# Single source of truth for this repo's clippy policy. Called both by the
# local prek hook (host target, no `--feature-powerset` — stays fast) and by
# CI's clippy-powerset composite action (extra `--target`/`--feature-powerset`
# for cross-target, cross-feature coverage the host-only prek hook can't give).
#
# After clippy it runs the libtest guard (libtest-guard.sh) with the same flags, so every caller
# is guarded and none can skip it.
#
# Usage: clippy.sh [--target TRIPLE] [--feature-powerset] [--release]
set -euo pipefail

target=""
powerset=0
release=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            target="${2:?--target requires a value}"
            shift 2
            ;;
        --feature-powerset)
            powerset=1
            shift
            ;;
        --release)
            release=1
            shift
            ;;
        *)
            echo "::error::Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

cmd=(cargo)
if [[ "$powerset" -eq 1 ]]; then
    cmd+=(hack clippy --locked)
else
    cmd+=(clippy --locked)
fi

if [[ -n "$target" ]]; then
    cmd+=(--target "$target")
fi

# Code under `cfg(not(debug_assertions))` (and its clippy bans) is only compiled by a release build.
if [[ "$release" -eq 1 ]]; then
    cmd+=(--release)
fi

cmd+=(--all-targets)

if [[ "$powerset" -eq 1 ]]; then
    cmd+=(--feature-powerset)
fi

cmd+=(-- -D warnings)

"${cmd[@]}"

guard=("$(dirname "${BASH_SOURCE[0]}")/libtest-guard.sh")
[[ -n "$target" ]] && guard+=(--target "$target")
[[ "$powerset" -eq 1 ]] && guard+=(--feature-powerset)
[[ "$release" -eq 1 ]] && guard+=(--release)
exec "${guard[@]}"
