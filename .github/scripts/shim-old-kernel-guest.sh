#!/usr/bin/env bash
# Runs inside the virtme-ng guest of shim-old-kernels.yaml: checks which kernel booted, then runs the
# shim's tests on it. Usage: shim-old-kernel-guest.sh <kernel tag, such as v5.6>
set -euxo pipefail

kernel="${1:?kernel tag}"
uname -r
case "$(uname -r)" in
    "${kernel#v}"*) ;;
    *)
        echo "booted $(uname -r), not $kernel"
        exit 1
        ;;
esac

cargo nextest run --locked --lib --no-fail-fast --no-tests=fail \
    -E 'test(elevation::shim::run::) | test(elevation::shim::creds)'
