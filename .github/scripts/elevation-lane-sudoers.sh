#!/usr/bin/env bash
# Makes `sudo` on a throwaway Linux or macOS CI runner honest for the ELEVATION group's live tests.
#
# Usage (every form starts with the flag; the password is in COSCA_TEST_ELEVATION_PASSWORD):
#   elevation-lane-sudoers.sh --this-machine-is-disposable --create-account <user>   # macOS only
#   elevation-lane-sudoers.sh --this-machine-is-disposable <user> <cosca_testbin>
#   elevation-lane-sudoers.sh --this-machine-is-disposable --cleanup <user>
#
# It changes the machine's sudo rules and, on Linux, the user's password, so it runs the same guard as
# unattended-gui-elevation.py: the flag plus a machine fact (a hosted runner or a devvm guest; a container does not
# count).
#
# The group's tests run as <user>. Two kinds of test need two kinds of `sudo`:
#   - `Auth::NonInteractive` runs `id` and <cosca_testbin>, so those two commands need no password
#     (`sudo -n`).
#   - `Auth::Stdin` and `Auth::Askpass` run `whoami`, so that command asks for <user>'s password,
#     which the test must deliver. With a passwordless `sudo` they would pass without delivering it.
# `timestamp_timeout=0` keeps the first password from answering for the second test.
#
# The rules go in the last file `sudoers.d` reads: the last matching rule wins, so they override any
# `NOPASSWD: ALL` the runner image grants <user>. Run as a user with passwordless `sudo` (<user> itself
# on Linux). Fails if the result is not what the tests rely on.
#
# Setup writes a marker, /etc/cosca-elevation-setup, before it changes anything, and refuses to run when the
# marker exists (a second run would overwrite what the first saved). On Linux the marker holds `<user>:<the user's
# original password entry>`, which `--cleanup` puts back; on macOS it names the account `--create-account` made,
# which is the only account `--cleanup` deletes. `--cleanup` does nothing when there is no marker.
#
# Never run this under `set -x`: it handles the password.
set -euo pipefail
exec 2>&1

rules_file=/etc/sudoers.d/zz-cosca-elevation
marker=/etc/cosca-elevation-setup
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" != --this-machine-is-disposable ]]; then
    echo "usage: $0 --this-machine-is-disposable (--create-account <user> | <user> <cosca_testbin> | --cleanup <user>)" >&2
    exit 2
fi
shift
# The guard of unattended-gui-elevation.py, which reads its facts from the environment: pass them through `sudo`, which
# resets it.
python3 "$here/unattended-gui-elevation.py" --this-machine-is-disposable --check-only
darwin=false
if [[ "$(uname -s)" == Darwin ]]; then
    darwin=true
fi

# `-e` needs no read access to the marker.
have_marker() {
    [[ -e "$marker" ]]
}

# Creates the marker exclusively (`set -C`): failing because it exists is the refusal of a second setup.
write_marker() {
    local failure
    if ! failure="$(printf '%s\n' "$1" | sudo sh -c 'set -C && umask 077 && cat > "$1"' sh "$marker" 2>&1)"; then
        if [[ -e "$marker" ]]; then
            echo "$marker exists, so a setup already ran here (a second one would overwrite what it saved)" >&2
        else
            echo "could not create $marker: $failure" >&2
        fi
        return 1
    fi
}

case "${1:-}" in
--create-account)
    if [[ "$darwin" != true ]]; then
        echo "--create-account is for macOS; on Linux the user is the runner's own" >&2
        exit 2
    fi
    account="${2:?usage: $0 --this-machine-is-disposable --create-account <user>}"
    : "${COSCA_TEST_ELEVATION_PASSWORD:?the password for the new account}"
    if dscl . -read "/Users/$account" >/dev/null 2>&1; then
        echo "the account $account already exists; refusing to adopt it" >&2
        exit 1
    fi
    # The record first (exclusively: it is also the refusal of a second setup), then the account. A marker
    # without an account is fine for `--cleanup`; an account without a marker would be left behind.
    write_marker "$account"
    sudo sysadminctl -addUser "$account" -password "$COSCA_TEST_ELEVATION_PASSWORD"
    exit 0
    ;;
--cleanup)
    cleanup_user="${2:?usage: $0 --this-machine-is-disposable --cleanup <user>}"
    if ! have_marker; then
        echo "no setup marker at $marker: nothing to clean up"
        exit 0
    fi
    if [[ "$darwin" != true ]]; then
        : "${COSCA_TEST_ELEVATION_PASSWORD:?the password the setup set}"
        # The user's own `sudo` asks its password until the rules file is gone.
        printf '%s\n' "$COSCA_TEST_ELEVATION_PASSWORD" | sudo -S rm -f "$rules_file"
    fi
    recorded="$(sudo cat "$marker")"
    if [[ "$darwin" == true ]]; then
        if [[ "$recorded" != "$cleanup_user" ]]; then
            echo "$marker records the account '$recorded', not '$cleanup_user'; refusing to delete another account" >&2
            exit 1
        fi
        sudo rm -f "$rules_file"
        if dscl . -read "/Users/$cleanup_user" >/dev/null 2>&1; then
            # Nothing of the account may be running when it goes: SIGKILL its processes first (pkill exits 1 when
            # there are none, which is fine).
            sudo pkill -KILL -u "$cleanup_user" || [[ $? -eq 1 ]]
            sudo sysadminctl -deleteUser "$cleanup_user"
            if dscl . -read "/Users/$cleanup_user" >/dev/null 2>&1; then
                echo "the account $cleanup_user is still there after the cleanup" >&2
                exit 1
            fi
        else
            echo "the marker names $cleanup_user but the account does not exist; removing the marker"
        fi
    else
        # The marker is `<user>:<original password entry>`; an entry has no colon.
        recorded_user="${recorded%%:*}"
        recorded_entry="${recorded#*:}"
        if [[ "$recorded_user" != "$cleanup_user" ]]; then
            echo "$marker records the user '$recorded_user', not '$cleanup_user'; refusing to touch another account" >&2
            exit 1
        fi
        if [[ -z "$recorded_entry" ]]; then
            echo "the saved password entry in $marker is empty; refusing to blank the password of $cleanup_user" >&2
            exit 1
        fi
        sudo usermod -p "$recorded_entry" "$cleanup_user"
    fi
    sudo rm -f "$marker"
    if [[ -e "$rules_file" ]]; then
        echo "$rules_file is still there after the cleanup" >&2
        exit 1
    fi
    exit 0
    ;;
esac

if [[ $# -ne 2 ]]; then
    echo "usage: $0 --this-machine-is-disposable (--create-account <user> | <user> <cosca_testbin> | --cleanup <user>)" >&2
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

if [[ "$darwin" == true ]]; then
    if ! have_marker || [[ "$(sudo cat "$marker")" != "$user" ]]; then
        echo "$user is not the account a --create-account run recorded in $marker" >&2
        exit 1
    fi
else
    # Keep the user's own password entry for `--cleanup`; an empty entry could not be put back.
    original_entry="$(sudo getent shadow "$user" | cut -d: -f2)"
    if [[ -z "$original_entry" ]]; then
        echo "$user has no password entry to save; refusing to change its password" >&2
        exit 1
    fi
    write_marker "$user:$original_entry" || exit 1
    printf '%s:%s\n' "$user" "$COSCA_TEST_ELEVATION_PASSWORD" | sudo chpasswd
fi
sudo install -m 0440 -o root -g 0 "$rules" "$rules_file"

# What the tests rely on, as <user> sees it.
as_user() {
    if [[ "$(id -un)" == "$user" ]]; then
        "$@"
    else
        sudo -u "$user" -H "$@"
    fi
}

if [[ "$(as_user sudo -n /usr/bin/id -u)" != 0 ]]; then
    echo "sudo -n id -u did not run as root" >&2
    exit 1
fi
if [[ "$(as_user sudo -n "$testbin" is-elevated-report)" != 1 ]]; then
    echo "sudo -n cosca_testbin did not run elevated" >&2
    exit 1
fi
# `whoami` must fail BECAUSE it asks for a password: classic sudo says "a password is required", sudo-rs
# "interactive authentication is required".
if whoami_out="$(as_user sudo -n whoami 2>&1)"; then
    echo "whoami needs no password: Auth::Stdin and Auth::Askpass would prove nothing" >&2
    exit 1
fi
case "$whoami_out" in
*"a password is required"* | *"authentication is required"*) ;;
*)
    echo "sudo -n whoami failed for another reason than a missing password: $whoami_out" >&2
    exit 1
    ;;
esac
if [[ "$(printf '%s\n' "$COSCA_TEST_ELEVATION_PASSWORD" | as_user sudo -S whoami)" != root ]]; then
    echo "sudo -S whoami with the password did not run as root" >&2
    exit 1
fi
