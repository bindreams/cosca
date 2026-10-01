#!/usr/bin/env bash
# Tests for run-nextest.sh, with a stand-in command that writes (or does not write) the JUnit file.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

check() { # check <name> <expected> <actual>
    if [[ "$2" == "$3" ]]; then
        echo "ok: $1"
    else
        echo "FAIL: $1: expected '$2', got '$3'"
        failures=$((failures + 1))
    fi
}

# run <case> <command...>: runs run-nextest.sh in a fresh workspace; sets `status` and `ws`.
run() {
    ws="$work/$1"
    shift
    mkdir -p "$ws/target/nextest/ci" "$ws/temp"
    if [[ -n ${stale:-} ]]; then echo stale >"$ws/target/nextest/ci/junit.xml"; fi
    status=0
    (cd "$ws" && RUNNER_TEMP="$ws/temp" bash "$script_dir/run-nextest.sh" "$@") >"$ws/log" 2>&1 || status=$?
}

writes='mkdir -p target/nextest/ci && echo fresh > target/nextest/ci/junit.xml'

stale='' run writes tests bash -c "$writes"
check "a run that writes a file has it collected under its name" "fresh" "$(cat "$ws/temp/junit/tests.xml")"
check "the file is moved, not copied" "absent" "$([[ -e $ws/target/nextest/ci/junit.xml ]] && echo present || echo absent)"
check "a successful run keeps status 0" "0" "$status"

stale='' run silent tests true
check "success without a JUnit file fails the step" "1" "$status"

stale='' run failing tests bash -c "$writes; exit 5"
check "a failing run keeps its own status" "5" "$status"
check "a failing run's file is still collected" "fresh" "$(cat "$ws/temp/junit/tests.xml")"

stale='' run no-file-failing tests bash -c 'exit 6'
check "a failing run without a file keeps its own status" "6" "$status"

stale=1 run stale tests true
check "a stale file never stands in for this run's" "1" "$status"
check "the stale file is not collected" "absent" "$([[ -e $ws/temp/junit/tests.xml ]] && echo present || echo absent)"

exit "$failures"
