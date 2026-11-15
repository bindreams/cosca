#!/usr/bin/env bash
# Runs inside the virtme-ng guest of the "Shim on Linux" steps in ci.yaml. Checks which kernel booted, then runs the
# elevation shim's tests and the fork-exec core's (`child::spawn::fork_exec`, `child::spawn::fork_spawn`: the vfork
# release and the spawn's records) on it: first as the unprivileged user that built them, with a setuid-root copy
# of the test binary for the test that refuses one, then as root for the tests that need root. It
# writes <result file> only on full success ("ok <tag> <uname -r>"); the host step reads that file,
# so a guest that failed, or never ran, cannot pass the job.
# Usage: shim-old-kernel-guest.sh <kernel tag, such as v5.6> <result file> <uid> <gid> <test binary>
set -euo pipefail

kernel="${1:?kernel tag}"
result="${2:?result file}"
uid="${3:?uid of the user that built the tests}"
gid="${4:?gid of the user that built the tests}"
testbin="${5:?the built cosca_testbin}"

rm -f "$result"
trap 'status=$?; if ((status != 0)); then echo "failed (exit $status)" >"$result"; fi' EXIT

release="$(uname -r)"
echo "uname -r: $release"
want="${kernel#v}"
# `6.1` names 6.1.x, never 6.10.
if [[ "$release" != "$want" && "$release" != "$want".* && "$release" != "$want"-* ]]; then
    echo "booted $release, not $kernel"
    exit 1
fi

# The groups that are off by default are off, as in CI: the checkout the guest shares holds
# `.github/test-group-defaults.env`. Each run then opts in to its own groups: the unprivileged run to the setuid
# one, the root run to exactly the root ones, selected by label.
set -a
. "$(dirname "${BASH_SOURCE[0]}")/../test-group-defaults.env"
set +a
groups_unprivileged=(COSCA_TEST_SETUID=1 COSCA_TEST_SETUID_CONSENT=1)
groups_root=(COSCA_TEST_NAMESPACES=1 COSCA_TEST_NAMESPACES_CONSENT=1
    COSCA_TEST_TRACER=1 COSCA_TEST_TRACER_CONSENT=1 COSCA_TEST_UID_SWITCH=1 COSCA_TEST_UID_SWITCH_CONSENT=1
    "SKULD_LABELS=namespaces | tracer | uid_switch")
filter='test(elevation::shim::) | test(child::spawn::fork_exec) | test(child::spawn::fork_spawn)'
nextest=(cargo nextest run --locked --lib --no-fail-fast --no-tests=fail -E "$filter")

passed() { # <log> <test name>: the log says the test passed
    grep -E "^[[:space:]]*PASS .*[: ]$2\$" "$1" >/dev/null || {
        echo "the test $2 did not pass or did not run"
        return 1
    }
}

# The setuid-root copy of the test binary, in a directory the unprivileged user can enter.
helper_dir="$(mktemp -d)"
chmod 755 "$helper_dir"
helper="$helper_dir/cosca_testbin_setuid"
cp "$testbin" "$helper"
chown root:root "$helper"
chmod 4755 "$helper"

# The same-uid tests, as the user that built them: with no capability, the kernel validates the
# credentials a peer sends (SCM_CREDENTIALS), which root skips.
unpriv_log="$(mktemp)"
status=0
setpriv --reuid="$uid" --regid="$gid" --clear-groups env "${groups_unprivileged[@]}" "COSCA_TESTCFG_SETUID_HELPER=$helper" \
    "${nextest[@]}" >"$unpriv_log" 2>&1 || status=$?
cat "$unpriv_log"
((status == 0)) || exit "$status"
for name in foreign_writer_of_a_is_refused owner_exit_before_answer_is_123 owner_pidfd_errno_mapping \
    owner_pidfd_emfile_is_116_not_123 owner_exit_kills_the_program_despite_fd_copies \
    owner_exit_between_the_recheck_and_the_clone_never_starts_the_program \
    a_signal_after_the_answer_and_before_the_start_is_not_started \
    the_kernel_refuses_credentials_that_are_not_the_senders setuid_shim_is_refused_before_anything \
    the_vfork_kind_returns_only_after_the_child_ran_its_steps \
    a_fork_without_exec_holding_the_channel_does_not_hold_the_return \
    a_child_fd_on_the_status_channels_number_does_not_hide_a_failed_exec \
    a_failed_exec_is_an_error_with_two_of_fds_0_to_2_closed; do
    passed "$unpriv_log" "$name"
done

# The tests that need root: pid namespaces, a tracer, a real uid switch.
root_log="$(mktemp)"
env "${groups_root[@]}" "${nextest[@]}" >"$root_log" 2>&1 || status=$?
cat "$root_log"
((status == 0)) || exit "$status"
for name in owner_reaped_and_reused_after_a_is_123 owner_pid_reused_before_connect_never_starts \
    reaped_childs_pid_reused_leaves_the_stranger_alive \
    traced_zombie_waits_for_the_tracer_and_reports_the_exact_status cosca_with_ruid_ne_euid_starts \
    missing_proc_is_refused_and_says_proc_must_be_mounted; do
    passed "$root_log" "$name"
done

echo "ok $kernel $release" >"$result"
