#!/usr/bin/env bash
# Archives the tests the cgroup lanes run, as the ordinary user: `cgroup-lane.sh` and `cgroup-setuid-lane.sh` run it.
#
# Usage: cgroup-archive.sh <target>
# Run it from the checkout, with RUNNER_TEMP set. It writes `cgroup.tar.zst` there. Only running the archive needs root.
set -euxo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP names where the archive goes}"
cargo nextest archive --locked --features pty,tokio --target "${1:?usage: cgroup-archive.sh <target>}" --archive-file "$RUNNER_TEMP/cgroup.tar.zst"
