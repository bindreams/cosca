#!/usr/bin/env bash
# Usage: run-nextest.sh <name> <command> [args...]
#
# Runs a nextest command, then moves the `ci` profile's JUnit file to `$RUNNER_TEMP/junit/<name>.xml`,
# where the job's single `upload-junit` step picks it up. The file is removed first so a stale one
# can never stand in for this run's. A command that succeeded without writing one fails the step.
# On Unix the command runs under `run_forwarding`, so the runner's timeout signal reaches it.
set -uo pipefail

name=${1:?usage: run-nextest.sh <name> <command> [args...]}
shift
src=target/nextest/ci/junit.xml
dir="${RUNNER_TEMP:?}/junit"

mkdir -p "$dir"
rm -f "$src"

status=0
if [[ $OSTYPE == msys* || $OSTYPE == cygwin* ]]; then
    # Windows: the runner ends the whole process tree itself.
    "$@" || status=$?
else
    # shellcheck source=forward-signals.sh
    source "$(dirname "${BASH_SOURCE[0]}")/forward-signals.sh"
    run_forwarding "$@" || status=$?
fi

if [[ -f $src ]]; then
    mv "$src" "$dir/$name.xml"
elif ((status == 0)); then
    echo "::error::nextest succeeded but wrote no JUnit file at $src"
    status=1
fi
exit "$status"
