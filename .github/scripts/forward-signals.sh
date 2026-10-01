#!/usr/bin/env bash
# Source this file, then `run_forwarding <command> [args...]`.
#
# The runner enforces a step's `timeout-minutes` on Unix by signalling only the step's top-level
# shell (`actions/runner`, `ProcessInvoker.SendSignal`), so a child that shell is waiting on never
# hears about it and outlives the step. `run_forwarding` runs the command in its own process
# group, forwards SIGINT/SIGTERM to that whole group, and returns the command's status once it has
# exited. A step whose one command forwards signals to its own children can `exec` it instead.

run_forwarding() {
    local child='' pending='' status=0
    set -m
    # The trap goes in before the spawn: a signal that lands before `child` is known is remembered
    # and forwarded as soon as it is.
    trap 'pending=1; if [[ -n $child ]]; then kill -TERM -- "-$child" 2>/dev/null || true; fi' INT TERM
    "$@" &
    child=$!
    if [[ -n $pending ]]; then
        kill -TERM -- "-$child" 2>/dev/null || true
    fi
    # A forwarded signal interrupts `wait` before the command has exited. The shell's own job table
    # says whether the command is gone; its pid could already belong to another process.
    while true; do
        status=0
        wait "$child" || status=$?
        jobs %% >/dev/null 2>&1 || break
    done
    trap - INT TERM
    set +m
    return "$status"
}
