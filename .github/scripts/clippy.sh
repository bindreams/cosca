#!/usr/bin/env bash
# Single source of truth for this repo's clippy policy. Called both by the
# local prek hook (host target, no `--feature-powerset` — stays fast) and by
# CI's clippy-powerset composite action (extra `--target`/`--feature-powerset`
# for cross-target, cross-feature coverage the host-only prek hook can't give).
#
# Usage: clippy.sh [--target TRIPLE] [--feature-powerset]
set -euo pipefail

target=""
powerset=0

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

cmd+=(--all-targets)

if [[ "$powerset" -eq 1 ]]; then
    cmd+=(--feature-powerset)
fi

cmd+=(-- -D warnings)

exec "${cmd[@]}"
