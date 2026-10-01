#!/usr/bin/env bash
# Tests for root-group.sh and reap-root-group.sh. Linux, as root, inside a fresh PID namespace whose
# next pid the tests set through /proc/sys/kernel/ns_last_pid, so pid reuse is forced, not hoped
# for. Synchronises on FIFOs, never on time. Run it as: sudo bash root-group-tests.sh
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${ROOT_GROUP_TESTS_INNER:-} != 1 ]]; then
    exec env ROOT_GROUP_TESTS_INNER=1 unshare --pid --fork --mount-proc bash "$0"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
# `reap-root-group.sh` calls sudo; the tests already run as root.
printf '#!/usr/bin/env bash\nexec "$@"\n' >"$work/bin/sudo"
chmod +x "$work/bin/sudo"
export PATH="$work/bin:$PATH"
# shellcheck source=forward-signals.sh
source "$script_dir/forward-signals.sh"
failures=0

check() { # check <name> <expected> <actual>
    if [[ "$2" == "$3" ]]; then
        echo "ok: $1"
    else
        echo "FAIL: $1: expected '$2', got '$3'"
        failures=$((failures + 1))
    fi
}
alive() { kill -0 "$1" 2>/dev/null && echo alive || echo dead; }
group_alive() { kill -0 -- "-$1" 2>/dev/null && echo alive || echo dead; }

# start_bystander <pid>: starts, in its own session, a process that asks for <pid> as its pid.
# Sets `bystander` to the pid it really got. It blocks until `release_bystander`.
start_bystander() {
    mkfifo "$work/up" "$work/release"
    echo $(($1 - 1)) >/proc/sys/kernel/ns_last_pid
    setsid bash -c 'echo $$ >"$0"; read -r <"$1"' "$work/up" "$work/release" &
    read -r bystander <"$work/up"
}
release_bystander() {
    echo >"$work/release"
    wait
    rm -f "$work/up" "$work/release"
}

# Control: a recorded group id with nobody left in the group is free to be reused, and a naive
# kill of it lands on the stranger that got the number.
run_forwarding bash -c 'echo $$ >"$0"' "$work/naive-pgid"
naive=$(<"$work/naive-pgid")
start_bystander "$naive"
check "control: the empty group's id was reused" "$naive" "$bystander"
kill -KILL -- "-$naive"
wait || true
check "control: a naive kill of the reused id hits the stranger" "dead" "$(alive "$bystander")"
rm -f "$work/up" "$work/release"

# With the keeper, the id stays taken: the stranger cannot get it, and the reaper kills exactly
# the group.
base="$work/idle"
run_forwarding bash "$script_dir/root-group.sh" "$base" true
gid=$(<"$base")
start_bystander "$gid"
if [[ $bystander != "$gid" ]]; then reused=no; else reused=yes; fi
check "the group id cannot be reused while the keeper lives" "no" "$reused"
bash "$script_dir/reap-root-group.sh" "$base"
check "the reaper kills the group" "dead" "$(group_alive "$gid")"
check "the reaper leaves a process outside the group alone" "alive" "$(alive "$bystander")"
check "the reaper consumes its files" "none" "$(ls "$base" "$base.keeper" 2>/dev/null || echo none)"
release_bystander

# The step dies while root nextest survives: the reaper ends the survivor and the keeper.
base="$work/orphan"
mkfifo "$work/standin-up" "$work/standin-block"
cat >"$work/step.sh" <<STEP
#!/usr/bin/env bash
source "$script_dir/forward-signals.sh"
run_forwarding bash "$script_dir/root-group.sh" "$base" bash -c 'echo \$\$ >"$work/standin-up"; read -r <"$work/standin-block"'
STEP
bash "$work/step.sh" &
step=$!
read -r standin <"$work/standin-up"
kill -KILL "$step"
wait "$step" || true
check "the stand-in outlives its step" "alive" "$(alive "$standin")"
gid=$(<"$base")
start_bystander "$gid"
bash "$script_dir/reap-root-group.sh" "$base"
check "the reaper kills the survivor" "dead" "$(alive "$standin")"
check "the reaper kills its whole group" "dead" "$(group_alive "$gid")"
check "the bystander is untouched" "alive" "$(alive "$bystander")"
release_bystander

exit "$failures"
