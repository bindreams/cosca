#!/usr/bin/env bash
# Runs the setuid-root process-group teardown test as root.
#
# Usage: setuid-root-lane.sh <cargo-nextest> <archive> <extraction directory>
# Run it as root, from the checkout, with COSCA_TEST_SETUID, COSCA_TEST_SETUID_CONSENT,
# COSCA_TESTCFG_SETUID_HELPER and SKULD_LABELS=setuid_root set, after `setuid-root-archive.sh`. `sudo` resets the
# environment and drops `~/.cargo/bin` from `PATH`: pass those variables with `--preserve-env` (Ubuntu 26.04's sudo-rs
# ignores `-E`) and `cargo-nextest`'s resolved path as an argument.
set -eux

"$1" nextest run --archive-file "$2" --extract-to "$3" --workspace-remap "$PWD" --profile ci-setuid-root --no-tests=fail -E "binary(group_teardown_setuid)"
