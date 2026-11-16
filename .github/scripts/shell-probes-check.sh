#!/usr/bin/env bash
# Fails unless an executing probe left a marker: a `FILTER` matching no test would otherwise pass having asserted
# nothing.
#
# Usage: shell-probes-check.sh
# `COSCA_PROBE_MARKERS` names the directory `shell-probes-lane.sh` made the probes leave their markers in.
set -euo pipefail

: "${COSCA_PROBE_MARKERS:?COSCA_PROBE_MARKERS names where each probe that passes leaves a marker}"
shopt -s nullglob
passed=("$COSCA_PROBE_MARKERS"/*)
if ((${#passed[@]} == 0)); then
    echo "::error::no executing probe ran: the run asserted nothing"
    exit 1
fi
printf 'executing probe passed: %s\n' "${passed[@]##*/}"
