#!/usr/bin/env bash
# Runs the executing probes: the SHELL_PROBES and ELEVATION_ROUTES groups of `windows_shell_resolution` and
# `windows_elevation_routes`. They plant a `.bat` and hand it to `ShellExecuteEx`, so they EXECUTE code chosen by the
# path rules they measure, and the elevation probes create a throwaway local administrator and register a scheduled
# task: run them only on a disposable machine (a GitHub-hosted runner, a devvm guest).
#
# Usage: shell-probes-lane.sh <target> [<isolated label>]
# Run it from the checkout in Git Bash. `COSCA_PROBE_MARKERS` names the directory each probe that passes leaves a marker
# in. `FILTER`, when set, is a test-name filter. Without a label it runs every probe but the three isolated ones; with
# one (`isolated_trailing_dot`, `isolated_pathext_precedence`, `isolated_existing_extensionless`) it runs that probe
# alone, in an invocation of its own: a leftover `OpenWith.exe` from one probe that hands `ShellExecuteExW` an existing
# extensionless target was a candidate explanation for an intermittent hang (the module doc of
# `tests/windows_shell_resolution.rs` has what was measured). Run the labelled invocations consecutively, after the
# first one.
#
# Survey probes print what they measured; probes with a specific expectation assert on it. `--no-capture` is the point,
# and also forces nextest to run every test in an invocation serially. The first invocation runs both binaries at once:
# nextest fails a run whose filter matches nothing, so a `FILTER` naming only an elevation-route test would match zero
# tests in `windows_shell_resolution`. It uses `--no-tests=warn` for the case that excluding the three isolated probes
# creates: a `FILTER` that narrows it to exactly one of them matches nothing here. A labelled invocation likewise warns
# instead of failing when a `FILTER` excludes its probe.
set -euo pipefail

target="${1:?usage: shell-probes-lane.sh <target> [<isolated label>]}"
isolated="${2:-}"
: "${COSCA_PROBE_MARKERS:?COSCA_PROBE_MARKERS names where each probe that passes leaves a marker}"
filter="${FILTER:-}"

export COSCA_TEST_SHELL_PROBES=1 COSCA_TEST_SHELL_PROBES_CONSENT=1
export COSCA_TEST_ELEVATION_ROUTES=1 COSCA_TEST_ELEVATION_ROUTES_CONSENT=1
mkdir -p "$COSCA_PROBE_MARKERS"

if [[ -z "$isolated" ]]; then
    export COSCA_PROBE_ALLOW_ACCOUNTS=1 COSCA_PROBE_ALLOW_STATE=1
    export SKULD_LABELS="(shell_probes | elevation_routes) & !isolated_trailing_dot & !isolated_pathext_precedence & !isolated_existing_extensionless"
    args=(nextest run --locked --profile ci --target "$target" --test windows_shell_resolution --test windows_elevation_routes --no-capture --no-tests=warn)
else
    export SKULD_LABELS="$isolated"
    none=fail
    if [[ -n "$filter" ]]; then
        none=warn
    fi
    args=(nextest run --locked --profile ci --target "$target" --test windows_shell_resolution --no-capture "--no-tests=$none")
fi
if [[ -n "$filter" ]]; then
    args+=("$filter")
fi
exec cargo "${args[@]}"
