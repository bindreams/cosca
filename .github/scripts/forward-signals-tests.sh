#!/usr/bin/env bash
# Tests for forward-signals.sh: a SIGTERM to the shell reaches the command's whole process group,
# and the command's status is returned. Synchronises on FIFOs, never on time.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkfifo "$work/ready" "$work/grandchild-ready"
failures=0

check() { # check <name> <expected> <actual>
    if [[ "$2" == "$3" ]]; then
        echo "ok: $1"
    else
        echo "FAIL: $1: expected '$2', got '$3'"
        failures=$((failures + 1))
    fi
}

# The wrapper runs a command that has a grandchild, both of which record SIGTERM and exit.
cat >"$work/tree.sh" <<'TREE'
#!/usr/bin/env bash
work="$1"
(
    sleep 1000 &
    sp=$!
    trap 'echo term >"$work/grandchild-got"; kill "$sp" 2>/dev/null; exit 0' TERM
    echo up >"$work/grandchild-ready"
    wait "$sp"
) &
gc=$!
trap 'echo term >"$work/child-got"; wait "$gc"; exit 7' TERM
echo up >"$work/ready"
wait "$gc"
TREE
cat >"$work/wrapper.sh" <<WRAP
#!/usr/bin/env bash
# shellcheck source=forward-signals.sh
source "$script_dir/forward-signals.sh"
status=0
run_forwarding bash "$work/tree.sh" "$work" || status=\$?
echo "\$status" >"$work/status"
WRAP

bash "$work/wrapper.sh" &
wrapper=$!
read -r <"$work/ready"
read -r <"$work/grandchild-ready"
kill -TERM "$wrapper"
wait "$wrapper" || true
check "the command hears SIGTERM" "term" "$(cat "$work/child-got")"
check "the command's process group hears SIGTERM" "term" "$(cat "$work/grandchild-got")"
check "the command's status is returned" "7" "$(cat "$work/status")"

# shellcheck source=forward-signals.sh
source "$script_dir/forward-signals.sh"
status=0
run_forwarding bash -c 'exit 3' || status=$?
check "a plain exit status passes through" "3" "$status"

# A command that handles SIGTERM and then exits 0 reports 0, not the signal's 128+n.
cat >"$work/clean.sh" <<'CLEAN'
#!/usr/bin/env bash
work="$1"
sleep 1000 &
sp=$!
trap 'kill "$sp" 2>/dev/null; exit 0' TERM
echo up >"$work/ready"
wait "$sp"
CLEAN
cat >"$work/clean-wrapper.sh" <<WRAP
#!/usr/bin/env bash
# shellcheck source=forward-signals.sh
source "$script_dir/forward-signals.sh"
status=0
run_forwarding bash "$work/clean.sh" "$work" || status=\$?
echo "\$status" >"$work/clean-status"
WRAP
bash "$work/clean-wrapper.sh" &
wrapper=$!
read -r <"$work/ready"
kill -TERM "$wrapper"
wait "$wrapper" || true
check "a forwarded signal does not leak into the status of a command that then exits 0" "0" "$(cat "$work/clean-status")"

# A signal that lands between the command's fork and the function's next statement is forwarded,
# not lost. The DEBUG hook sends it right before the statement after the spawn (`child=$!`), the
# only point where a trap installed after the spawn would not exist yet. The hook records the
# child's pid first, because a wrapper that dies leaves nobody else to report it.
mkfifo "$work/never"
cat >"$work/window-wrapper.sh" <<WRAP
#!/usr/bin/env bash
set -T
trap '[[ \$BASH_COMMAND == child=* ]] && { trap - DEBUG; echo \$! >"$work/window-child"; kill -TERM \$\$; }' DEBUG
# shellcheck source=forward-signals.sh
source "$script_dir/forward-signals.sh"
status=0
run_forwarding bash -c 'read <"$work/never"' || status=\$?
echo "\$status" >"$work/window-status"
WRAP
bash "$work/window-wrapper.sh" || true
if [[ -f "$work/window-status" ]]; then
    check "a signal in the fork-to-trap window is forwarded and the command dies" "143" "$(cat "$work/window-status")"
else
    check "a signal in the fork-to-trap window is forwarded and the command dies" "forwarded" "the wrapper died with the command still running"
    kill -KILL "$(cat "$work/window-child")" 2>/dev/null || true
fi

exit "$failures"
