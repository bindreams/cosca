#!/usr/bin/env bash
# Makes `sudo` on a throwaway Linux CI runner honest for the ELEVATION group's live tests.
#
# Usage: COSCA_TEST_ELEVATION_PASSWORD=<password> elevation-lane-sudoers.sh <user> <cosca_testbin>
#
# The group's tests run as <user>. Two kinds of test need two kinds of `sudo`:
#   - `Auth::NonInteractive` runs `id` and <cosca_testbin>, so those two commands need no password
#     (`sudo -n`).
#   - `Auth::Stdin` and `Auth::Askpass` run `whoami`, so that command asks for <user>'s password,
#     which the test must deliver. With a passwordless `sudo` they would pass without delivering it.
# `timestamp_timeout=0` keeps the first password from answering for the second test.
#
# The rules go in the last file `sudoers.d` reads: the last matching rule wins, so they override any
# `NOPASSWD: ALL` the runner image grants <user>. Run as <user> with passwordless `sudo`. Fails if
# the result is not what the tests rely on.
set -euo pipefail
exec 2>&1

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <user> <cosca_testbin>" >&2
    exit 2
fi
user="$1"
testbin="$2"
: "${COSCA_TEST_ELEVATION_PASSWORD:?the password the tests deliver to sudo}"

if [[ "$testbin" != /* || ! -x "$testbin" ]]; then
    echo "cosca_testbin must be an absolute path to an executable file: $testbin" >&2
    exit 2
fi

rules="$(mktemp)"
trap 'rm -f "$rules"' EXIT
cat >"$rules" <<RULES
Defaults timestamp_timeout=0
$user ALL=(ALL:ALL) ALL
$user ALL=(ALL:ALL) NOPASSWD: /usr/bin/id, $testbin
RULES

sudo visudo -cf "$rules"
printf '%s:%s\n' "$user" "$COSCA_TEST_ELEVATION_PASSWORD" | sudo chpasswd
sudo install -m 0440 -o root -g root "$rules" /etc/sudoers.d/zz-cosca-elevation

# What the tests rely on.
if [[ "$(sudo -n /usr/bin/id -u)" != 0 ]]; then
    echo "sudo -n id -u did not run as root" >&2
    exit 1
fi
if [[ "$(sudo -n "$testbin" is-elevated-report)" != 1 ]]; then
    echo "sudo -n cosca_testbin did not run elevated" >&2
    exit 1
fi
if sudo -n whoami; then
    echo "whoami needs no password: Auth::Stdin and Auth::Askpass would prove nothing" >&2
    exit 1
fi
if [[ "$(printf '%s\n' "$COSCA_TEST_ELEVATION_PASSWORD" | sudo -S whoami)" != root ]]; then
    echo "sudo -S whoami with the password did not run as root" >&2
    exit 1
fi
