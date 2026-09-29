#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/../actions/setup-rust/enable-sccache.sh"
failures=0

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"

# Stub `sccache`: records the env it was probed with, prints a two-line error, exits with $STUB_EXIT.
cat >"$work/bin/sccache" <<'STUB'
#!/usr/bin/env bash
echo "gha=${SCCACHE_GHA_ENABLED:-} idle=${SCCACHE_IDLE_TIMEOUT:-}" >"$STUB_RECORD"
if [[ "$STUB_EXIT" -ne 0 ]]; then
    printf 'sccache: error: 50%% Egress is over the limit\nsecond line\n' >&2
fi
exit "$STUB_EXIT"
STUB
chmod +x "$work/bin/sccache"

run() { # run <stub-exit>; sets status, out, env_file, record
    env_file="$work/github_env"
    record="$work/record"
    : >"$env_file"
    status=0
    out="$(PATH="$work/bin:$PATH" GITHUB_ENV="$env_file" STUB_EXIT="$1" STUB_RECORD="$record" \
        bash "$target" 2>/dev/null)" || status=$?
}

check() { # check <description> <condition-exit-status>
    if [[ "$2" -eq 0 ]]; then
        echo "ok   - $1"
    else
        echo "FAIL - $1"
        failures=$((failures + 1))
    fi
}

run 0
check "success: exits 0" "$((status != 0))"
check "success: exports RUSTC_WRAPPER" "$(grep -qx 'RUSTC_WRAPPER=sccache' "$env_file"; echo $?)"
check "success: exports IGNORE_SERVER_IO_ERROR" "$(grep -qx 'SCCACHE_IGNORE_SERVER_IO_ERROR=1' "$env_file"; echo $?)"
check "success: does not persist GHA storage" "$(grep -q 'SCCACHE_GHA_ENABLED' "$env_file"; echo $((! $?)))"
check "success: does not persist idle timeout" "$(grep -q 'SCCACHE_IDLE_TIMEOUT' "$env_file"; echo $((! $?)))"
check "success: emits no warning" "$(grep -q '::warning' <<<"$out"; echo $((! $?)))"
check "probe runs with GHA storage and no idle timeout" "$(grep -qx 'gha=true idle=0' "$record"; echo $?)"

run 1
check "failure: exits 0" "$((status != 0))"
check "failure: leaves RUSTC_WRAPPER unset" "$(grep -q 'RUSTC_WRAPPER' "$env_file"; echo $((! $?)))"
check "failure: persists nothing" "$(grep -q . "$env_file"; echo $((! $?)))"
check "failure: warns with status and escaped cause" \
    "$(grep -qxF '::warning title=sccache unavailable::sccache --start-server exited 1; building without the compile cache. Cause: sccache: error: 50%25 Egress is over the limit%0Asecond line' <<<"$out"; echo $?)"

if [[ "$failures" -ne 0 ]]; then
    echo "${failures} failure(s)"
    exit 1
fi
