#!/usr/bin/env bash
# Runs the TRACER group's tests, which attach a tracer to the tests' own children as a debugger would.
#
# Usage: tracer-lane.sh <target> [release]
# Run it from the checkout, on a machine that is a sandbox (a CI runner, a devvm guest): the group consents here. With
# `release` it runs the `--lib` tests with `debug_assertions` off. CI runs it under `run-nextest.py tracer` and
# `tracer-release`.
#
# `-E binary(cosca)` keeps libtest binaries out: they ignore `SKULD_LABELS`. `tokio` is for the group's one async test.
set -euo pipefail

target="${1:?usage: tracer-lane.sh <target> [release]}"
export COSCA_TEST_TRACER=1 COSCA_TEST_TRACER_CONSENT=1 SKULD_LABELS=tracer
if [[ "${2:-}" == release ]]; then
    exec cargo nextest run --locked --no-tests=fail --release --lib --features tokio --target "$target" --profile "${NEXTEST_PROFILE:-ci-tracer-release}"
fi
exec cargo nextest run --locked --no-tests=fail --features tokio --target "$target" --profile "${NEXTEST_PROFILE:-ci-tracer}" -E 'binary(cosca)'
