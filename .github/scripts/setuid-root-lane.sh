#!/usr/bin/env bash
# Runs the setuid-root process-group teardown test as root.
#
# Usage: setuid-root-lane.sh <cargo-nextest> <archive> <extraction directory> <helper>
# Run it from the checkout, after `setuid-root-archive.sh`, as root (CI wraps `sudo bash setuid-root-lane.sh ...` in
# `run-nextest.py setuid-root`) or as an ordinary user that may `sudo` (it runs itself again under `sudo`, keeping the
# kernel-floor switches of `devvm/lane-env.sh`). `sudo` resets the environment, drops `~/.cargo/bin` from `PATH` (so
# `cargo-nextest`'s resolved path is an argument) and, on Ubuntu 26.04 (sudo-rs), ignores `-E`: the lane sets the
# group's variables itself. `<helper>` is the setuid-root copy `setuid-helper.sh` made.
set -eux

if [[ $EUID != 0 ]]; then
    exec sudo --preserve-env=COSCA_TEST_PIDFD_GROUP_SIGNAL,COSCA_TEST_PIDFD_GET_INFO bash "$0" "$@"
fi

export COSCA_TEST_SETUID=1 COSCA_TEST_SETUID_CONSENT=1 COSCA_TESTCFG_SETUID_HELPER="$4" SKULD_LABELS=setuid_root
"$1" nextest run --archive-file "$2" --extract-to "$3" --workspace-remap "$PWD" --profile ci-setuid-root --no-tests=fail -E "binary(group_teardown_setuid)"
