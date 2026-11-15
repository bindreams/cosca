#!/usr/bin/env bash
# Runs the STRAY_SIGNAL group's tests, which may signal an unrelated process.
#
# Usage: stray-signal-lane.sh <target> [release]
# Run it from the checkout, on a machine that is a sandbox (a CI runner, a devvm guest): the group consents here. With
# `release` it runs the `--lib` tests with `debug_assertions` off. CI runs it under `run-nextest.py stray-signal` and
# `stray-signal-release`. Only the Unix lanes have such tests.
#
# `binary(cosca)` and `binary(=process)` are the skuld binaries that hold them; libtest binaries ignore `SKULD_LABELS`.
set -euo pipefail

target="${1:?usage: stray-signal-lane.sh <target> [release]}"
export COSCA_TEST_STRAY_SIGNAL=1 COSCA_TEST_STRAY_SIGNAL_CONSENT=1 SKULD_LABELS=stray_signal
if [[ "${2:-}" == release ]]; then
    exec cargo nextest run --locked --no-tests=fail --release --lib --features tokio --target "$target" --profile "${NEXTEST_PROFILE:-ci-stray-signal-release}"
fi
exec cargo nextest run --locked --no-tests=fail --features tokio --target "$target" --profile "${NEXTEST_PROFILE:-ci-stray-signal}" -E 'binary(cosca) | binary(=process)'
