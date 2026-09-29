#!/usr/bin/env bash
# Probe the sccache server; a dead cache backend must degrade to an uncached build, not fail the job.
# GHA storage and the never-idle timeout are set only for this probe: a server that a later compile respawns
# inherits neither, so it falls back to the local-disk cache, which a remote 503 cannot fail.
set -euo pipefail

err_file="$(mktemp)"
trap 'rm -f "$err_file"' EXIT

status=0
SCCACHE_GHA_ENABLED=true SCCACHE_IDLE_TIMEOUT=0 sccache --start-server 2>"$err_file" || status=$?
cat "$err_file" >&2

if [[ "$status" -eq 0 ]]; then
    echo "SCCACHE_IGNORE_SERVER_IO_ERROR=1" >>"$GITHUB_ENV"
    echo "RUSTC_WRAPPER=sccache" >>"$GITHUB_ENV"
else
    # Workflow-command data escapes: % first, then CR and LF.
    cause="$(<"$err_file")"
    cause="${cause//'%'/'%25'}"
    cause="${cause//$'\r'/'%0D'}"
    cause="${cause//$'\n'/'%0A'}"
    echo "::warning title=sccache unavailable::sccache --start-server exited ${status}; building without the compile cache. Cause: ${cause}"
fi
