#!/usr/bin/env bash
# Source this file, then `run_forwarding <command> [args...]`.
#
# The runner enforces a step's `timeout-minutes` on Unix by signalling only the step's top-level
# shell (`actions/runner`, `ProcessInvoker.SendSignal`), so a child that shell is waiting on never
# hears about it and outlives the step. `run_forwarding` runs the command in its own process
# group, forwards SIGINT/SIGTERM to that whole group, and returns the command's status once it has
# exited. A step that runs one command should `exec` it instead.

run_forwarding() {
    local child status=0
    set -m
    "$@" &
    child=$!
    trap 'kill -TERM -- "-$child" 2>/dev/null || true' INT TERM
    wait "$child" || status=$?
    # A forwarded signal interrupts `wait` before the command has exited; wait for it to be gone.
    while kill -0 "$child" 2>/dev/null; do
        wait "$child" || status=$?
    done
    trap - INT TERM
    set +m
    return "$status"
}
