#!/usr/bin/env bash
# Runs the tests that are in both the `cgroup` and the `setuid` group, as the ordinary user, in a cgroup it owns.
#
# Usage: cgroup-setuid-lane.sh <cargo-nextest> <archive>
# Run it as the ordinary user, from the checkout, with COSCA_TEST_CGROUP, COSCA_TEST_SETUID, their `_CONSENT`
# variables, COSCA_TESTCFG_SETUID_HELPER (see `setuid-helper.sh`) and SKULD_LABELS set. The archive is the one
# `cgroup-lane.sh` runs.
#
# These tests need a delegated cgroup and a caller that is not root (the helper is only unsignalable by one), which
# the cgroup lane, run as root, leaves out. Root makes the cgroup, hands it over and moves this shell into it: the user
# cannot move itself out of the cgroup it started in.
#
# No `-e`: the exit trap reports what a failed run left behind.
set -ux

CG=/sys/fs/cgroup/cosca-ci-user
PRIOR="/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup)"
sudo mkdir "$CG" || exit 1
# Back out of the lane cgroup and remove it on every exit. If a test left processes or cgroups in it,
# report them, kill the subtree and still fail; the sandbox is thrown away after the job.
leave() {
    echo $$ | sudo tee "$PRIOR/cgroup.procs" > /dev/null || { echo "could not leave $CG" >&2; exit 1; }
    sudo find "$CG" -depth -type d -exec rmdir {} \; && return
    echo "could not remove $CG; left in it:" >&2
    sudo grep -r "" "$CG" --include=cgroup.procs >&2 || true
    echo 1 | sudo tee "$CG/cgroup.kill" > /dev/null || echo "could not kill $CG" >&2
    exit 1
}
trap leave EXIT
sudo chown "$(id -u):$(id -g)" "$CG" "$CG/cgroup.procs" "$CG/cgroup.subtree_control" "$CG/cgroup.threads"
echo $$ | sudo tee "$CG/cgroup.procs" > /dev/null
"$1" nextest run --archive-file "$2" --workspace-remap "$PWD" --profile ci-cgroup-setuid --no-tests=fail -E "binary(cosca)"
