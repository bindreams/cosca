#!/usr/bin/env bash
# Run the privilege tests inside a root-lane container (see `resolve_root_lanes` in ci.yaml).
# Environment: PREFIX (words that change identity, may be empty), PRIVILEGE_TESTS (nextest
# filterset), FOREIGN_TMPDIR, and the EXPECT_* variables root-lane-check.sh reads.
set -euxo pipefail

if [[ "${FOREIGN_TMPDIR:-}" == "true" ]]; then
    mkdir -p /tmp/foreign
    chown 1000:1000 /tmp/foreign
    chmod 0700 /tmp/foreign
    export TMPDIR=/tmp/foreign
fi

# `PREFIX` must word-split into separate argv entries.
# shellcheck disable=SC2086
${PREFIX:-} bash /repo/.github/scripts/root-lane-check.sh

# The JUnit file is copied out of the container's nextest store afterwards, even when nextest failed.
status=0
# shellcheck disable=SC2086
${PREFIX:-} cargo-nextest nextest run \
    --archive-file /artifacts/root-lane.tar.zst \
    --workspace-remap /repo \
    --profile ci \
    -E "${PRIVILEGE_TESTS:?}" || status=$?
if [[ -f /repo/target/nextest/ci/junit.xml ]]; then
    cp /repo/target/nextest/ci/junit.xml /junit-out/lane.xml
elif ((status == 0)); then
    echo "nextest succeeded but wrote no JUnit file"
    status=1
fi
exit "$status"
