#!/usr/bin/env bash
# Runs the cgroup v2 containment and namespace tests as root, in a fresh cgroup leaf.
#
# Usage: cgroup-lane.sh <cargo-nextest> <archive> <uid:gid>
# Run it from the checkout, as root (CI runs `sudo python3 forward.py bash -ux cgroup-lane.sh ...` under
# `run-nextest.py cgroup`) or, after sourcing `devvm/lane-env.sh`, as an ordinary user that may `sudo`: it runs
# itself again under `sudo`, keeping that script's kernel-floor switches. `sudo`'s `secure_path` drops
# `~/.cargo/bin`, so the unprivileged user passes in
# `cargo-nextest`'s resolved path, the archive it built (`cgroup-archive.sh`) and its own `uid:gid`, which gets
# `target/` back.
#
# The live cgroup tests belong to the CGROUP group: on unless COSCA_TEST_CGROUP=0 and, enabled, they need
# COSCA_TEST_CGROUP_CONSENT=1 and fail without it. Plain `sudo` resets the environment, so this lane sets its own
# variables below. The tests need a cgroup the supervisor may create child cgroups under. We make a fresh leaf directly
# under the unified root cgroup: its `cgroup.subtree_control` is empty, so the v2 "no internal processes" rule does not
# apply and a cgroup may hold BOTH the test process and a child leaf. We move this shell into it and run the labelled
# tests there (as root, in parallel) across the `--lib` unit-test binary (which carries the white-box
# CgroupLeaf::wait_drained coverage in src/containment/cgroup/leaf_tests.rs, and with `tokio` the async spawn's
# post-fork failure path), `spawn_io` and `tokio_io`. The tests assert CgroupV2/build a real leaf and FAIL LOUDLY if it
# is unusable, never a silent skip.
#
# The labels: `cgroup` (the CGROUP group, every test of `containment::cgroup`, and the tests labelled `cgroup`
# explicitly; most use fake leaves and also run in the main lanes) and `namespaces` (the NAMESPACES group, which also
# gets its own consent here). `-E binary(...)`: libtest binaries ignore `SKULD_LABELS` and would run whole. A test that
# is also in the `setuid` group needs a caller that is not root, so this root run leaves it out (`!setuid`); the
# cgroup-setuid lane runs it.
#
# No `-e`: the nextest status is collected below, and the exit trap reports what a failed run left behind.
set -ux

if [[ $EUID != 0 ]]; then
    exec sudo --preserve-env="${COSCA_LANE_FLOOR_VARS:?source devvm/lane-env.sh first}" bash "$0" "$@"
fi

CG=/sys/fs/cgroup/cosca-ci
PRIOR="/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup)"
mkdir "$CG" || exit 1
# Back out of the lane cgroup and remove it on every exit. If a test left processes or cgroups in it, report
# them, kill the subtree, wait for the kernel to report it empty, remove the leaves, and still fail.
leave() {
    echo $$ > "$PRIOR/cgroup.procs" || { echo "could not leave $CG" >&2; exit 1; }
    rmdir "$CG" && return
    echo "could not remove $CG; left in it:" >&2
    find "$CG" -type d | while read -r d; do echo "$d: $(tr "\n" " " < "$d/cgroup.procs")"; done >&2
    echo 1 > "$CG/cgroup.kill" || echo "could not kill $CG" >&2
    # `cgroup.events` signals a change to `populated`, so poll it rather than wait a time.
    python3 - "$CG/cgroup.events" <<'PY' || echo "could not wait for $CG to empty" >&2
import select, sys
events = open(sys.argv[1])
poller = select.poll()
poller.register(events, select.POLLPRI | select.POLLERR)
while True:
    events.seek(0)
    if "populated 0" in events.read().split("\n"):
        break
    poller.poll()
PY
    find "$CG" -depth -type d -exec rmdir {} \; || echo "could not remove the leaves of $CG" >&2
    exit 1
}
trap leave EXIT
echo $$ > "$CG/cgroup.procs" || exit 1
# A delegated cgroup and root in a sandbox (a CI runner, a devvm guest), so consent is given.
# The profile is passed explicitly: sudo-rs (Ubuntu 26.04) ignores -E, so no variable survives.
export COSCA_TEST_CGROUP=1 COSCA_TEST_CGROUP_CONSENT=1
export COSCA_TEST_NAMESPACES=1 COSCA_TEST_NAMESPACES_CONSENT=1
# For the namespace tests that also attach a foreign tracer; no other test here takes it.
export COSCA_TEST_TRACER=1 COSCA_TEST_TRACER_CONSENT=1
status=0
SKULD_LABELS="(cgroup | namespaces) & !setuid" "$1" nextest run --archive-file "$2" --workspace-remap "$PWD" --profile ci-cgroup --no-capture --no-tests=fail -E "binary(cosca) | binary(spawn_io) | binary(tokio_io)" || status=1
# Hand the target dir back so later steps can write to it.
chown -R "$3" "$PWD/target" || status=1
exit "$status"
