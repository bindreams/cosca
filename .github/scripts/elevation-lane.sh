#!/usr/bin/env bash
# The ELEVATION group's Linux lane, start to finish: the same text runs on a CI runner and in a devvm guest.
#
# Usage: elevation-lane.sh <target triple>
# Run it from the checkout, as an unprivileged user that may `sudo` without a password, on a machine that
# `unattended-gui-elevation.py` accepts as disposable (a hosted runner or a devvm guest). `RUNNER_TEMP` names where
# the lane keeps its records and the JUnit file (`$RUNNER_TEMP/junit/elevation.xml`). CI runs it under `forward.py`,
# which passes the runner's stop signal on to the script's tree.
#
# Tests are selected by the label `elevation`; `-E binary(=elevation)` is the only binary with elevation tests, and
# libtest binaries ignore `SKULD_LABELS` and would run whole. The machine is disposable, so the group consents.
#
# The password is made here and goes to the tests in the environment, never to a log or a file: nothing here runs under
# xtrace. Keep it so.
#
# Every exit, whatever its cause, undoes the lane in this order:
#   1. the sudo rules (`elevation-lane-sudoers.sh --cleanup`). First, because once they apply every `sudo` but `id`
#      and the testbin asks for a password, and the steps after this one need a `sudo` that does not.
#   2. the polkit rule (`unattended-gui-elevation.py --revert`), which restarts polkit.
#   3. the packages and `/etc/doas.conf` (`elevation-lane-linux.sh --cleanup`), which needs polkit settled.
# Each is a no-op where its setup did not run.
set -euo pipefail

target="${1:?usage: $0 <target triple>}"
: "${RUNNER_TEMP:?RUNNER_TEMP names where the lane keeps its records and JUnit file}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
user="$(id -un)"
disposable=--this-machine-is-disposable
# `sudo` resets the environment, which `unattended-gui-elevation.py` reads its guard from.
policy() { sudo env GITHUB_ACTIONS="${GITHUB_ACTIONS:-}" RUNNER_ENVIRONMENT="${RUNNER_ENVIRONMENT:-}" python3 "$here/unattended-gui-elevation.py" "$disposable" --user "$user" "$@"; }

COSCA_TESTCFG_ELEVATION_PASSWORD="$(openssl rand -hex 16)"
export COSCA_TESTCFG_ELEVATION_PASSWORD

restore() {
    local status=$? failed=0
    trap - EXIT
    bash "$here/elevation-lane-sudoers.sh" "$disposable" --cleanup "$user" || failed=1
    policy --revert || failed=1
    bash "$here/elevation-lane-linux.sh" "$disposable" --cleanup || failed=1
    exit "$((status != 0 ? status : failed))"
}

python3 "$here/unattended-gui-elevation.py" "$disposable" --check-only
trap restore EXIT
bash "$here/elevation-lane-linux.sh" "$disposable" --record
sudo apt-get -o DPkg::Lock::Timeout=-1 update
sudo apt-get -o DPkg::Lock::Timeout=-1 install --no-install-recommends -y polkitd pkexec opendoas
policy

printf 'permit nopass %s as root\n' "$user" | sudo tee /etc/doas.conf >/dev/null
doas -C /etc/doas.conf
test "$(doas -n id -u)" = 0

cargo nextest run --locked --no-run --features tokio --target "$target" --profile ci
bash "$here/elevation-lane-sudoers.sh" "$disposable" "$user" "$PWD/target/$target/debug/cosca_testbin"

COSCA_TEST_ELEVATION=1 COSCA_TEST_ELEVATION_CONSENT=1 SKULD_LABELS=elevation \
    python3 "$here/run-nextest.py" elevation cargo nextest run --locked --features tokio --target "$target" --no-tests=fail -E 'binary(=elevation)'
python3 "$here/check-junit.py" "$RUNNER_TEMP/junit/elevation.xml" --tests 9
