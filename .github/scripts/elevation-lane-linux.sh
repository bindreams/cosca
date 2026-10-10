#!/usr/bin/env bash
# Records, then restores, the Linux elevation lane's package and `doas` state.
#
# Usage (every form starts with the flag):
#   elevation-lane-linux.sh --this-machine-is-disposable --record     # before the lane installs anything
#   elevation-lane-linux.sh --this-machine-is-disposable --cleanup    # after the lane, on success and on failure
#
# The lane apt-installs polkitd, pkexec and opendoas (and what they pull in) and writes /etc/doas.conf. `--record`
# saves the list of installed packages and the current /etc/doas.conf (or that there is none) in $RUNNER_TEMP.
# `--cleanup` purges exactly the packages that are installed now and were not then, never one that was there before,
# and puts /etc/doas.conf back as recorded; it does nothing when nothing was recorded. Run it after `unattended-gui-elevation.py --revert`, which restarts polkit.
set -euo pipefail
exec 2>&1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
state="${RUNNER_TEMP:?RUNNER_TEMP names where the record lives}/elevation-lane-linux"
doas_conf=/etc/doas.conf

if [[ "${1:-}" != --this-machine-is-disposable || $# -ne 2 ]]; then
    echo "usage: $0 --this-machine-is-disposable (--record | --cleanup)" >&2
    exit 2
fi
python3 "$here/unattended-gui-elevation.py" --this-machine-is-disposable --check-only

# Every installed package, one per line, sorted.
installed_packages() {
    dpkg-query -W -f='${db:Status-Status} ${binary:Package}\n' | sed -n 's/^installed //p' | sort
}

case "$2" in
--record)
    if [[ -e "$state" ]]; then
        echo "$state exists, so a record was already made (a second would save the lane's own changes)" >&2
        exit 1
    fi
    mkdir "$state"
    installed_packages >"$state/before"
    if [[ -e "$doas_conf" ]]; then
        sudo cp -p "$doas_conf" "$state/doas.conf"
    fi
    : >"$state/done"
    ;;
--cleanup)
    if [[ ! -e "$state/done" ]]; then
        echo "no complete record at $state: nothing to clean up"
        exit 0
    fi
    # What the lane installed: installed now, and not before.
    mapfile -t lane_installed < <(comm -13 "$state/before" <(installed_packages))
    if ((${#lane_installed[@]} > 0)); then
        sudo apt-get purge -y "${lane_installed[@]}"
    fi
    # The file goes back after the purge, which could otherwise remove or rewrite it.
    if [[ -e "$state/doas.conf" ]]; then
        sudo cp -p "$state/doas.conf" "$doas_conf"
    else
        sudo rm -f "$doas_conf"
    fi
    mapfile -t still_installed < <(comm -13 "$state/before" <(installed_packages))
    if ((${#still_installed[@]} > 0)); then
        echo "still installed after the cleanup: ${still_installed[*]}" >&2
        exit 1
    fi
    sudo rm -r --one-file-system -- "${state:?}"
    ;;
*)
    echo "usage: $0 --this-machine-is-disposable (--record | --cleanup)" >&2
    exit 2
    ;;
esac
