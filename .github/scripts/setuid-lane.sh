#!/usr/bin/env bash
# Runs the SETUID group's tests as the ordinary user, against a setuid-root helper.
#
# Usage: setuid-lane.sh <target> <helper>
# Run it from the checkout, as the ordinary user, after `setuid-helper.sh <target> <helper>` and
# `setuid-lane-check.sh <helper>`; the group consents here. CI runs it under `run-nextest.py setuid`.
#
# The group is selected by its label, in the two binaries that carry it (principle 10); libtest binaries ignore
# `SKULD_LABELS`.
set -euo pipefail

target="${1:?usage: setuid-lane.sh <target> <helper>}"
export COSCA_TEST_SETUID=1 COSCA_TEST_SETUID_CONSENT=1 COSCA_TESTCFG_SETUID_HELPER="${2:?usage: setuid-lane.sh <target> <helper>}" SKULD_LABELS=setuid
exec cargo nextest run --locked --no-tests=fail --features tokio --target "$target" --profile ci-setuid -E 'binary(cosca) | binary(group_teardown_setuid)'
