#!/usr/bin/env bash
# Records, then restores, the Linux elevation lane's package and `doas` state.
#
# Usage (every form starts with the flag):
#   elevation-lane-linux.sh --this-machine-is-disposable --record     # before the lane installs anything
#   elevation-lane-linux.sh --this-machine-is-disposable --cleanup    # after the lane, on success and on failure
#
# The lane apt-installs polkitd, pkexec and opendoas and writes /etc/doas.conf. `--record` saves which of those
# packages are installed already and the current /etc/doas.conf (or that there is none) in $RUNNER_TEMP. `--cleanup`
# purges only the packages the lane installed and puts /etc/doas.conf back as recorded; it does nothing when nothing was
# recorded. Run it after `unattended-gui-elevation.py --revert`, which restarts polkit.
set -euo pipefail
exec 2>&1

packages=(polkitd pkexec opendoas)
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
state="${RUNNER_TEMP:?RUNNER_TEMP names where the record lives}/elevation-lane-linux"
doas_conf=/etc/doas.conf

if [[ "${1:-}" != --this-machine-is-disposable || $# -ne 2 ]]; then
    echo "usage: $0 --this-machine-is-disposable (--record | --cleanup)" >&2
    exit 2
fi
python3 "$here/unattended-gui-elevation.py" --this-machine-is-disposable --check-only

installed() {
    [[ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" == installed ]]
}

case "$2" in
--record)
    if [[ -e "$state" ]]; then
        echo "$state exists, so a record was already made (a second would save the lane's own changes)" >&2
        exit 1
    fi
    mkdir "$state"
    : >"$state/preinstalled"
    for package in "${packages[@]}"; do
        if installed "$package"; then
            echo "$package" >>"$state/preinstalled"
        fi
    done
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
    if [[ -e "$state/doas.conf" ]]; then
        sudo cp -p "$state/doas.conf" "$doas_conf"
    else
        sudo rm -f "$doas_conf"
    fi
    lane_installed=()
    for package in "${packages[@]}"; do
        if installed "$package" && ! grep -qxF "$package" "$state/preinstalled"; then
            lane_installed+=("$package")
        fi
    done
    if ((${#lane_installed[@]} > 0)); then
        sudo apt-get purge -y "${lane_installed[@]}"
    fi
    for package in "${lane_installed[@]}"; do
        if installed "$package"; then
            echo "$package is still installed after the cleanup" >&2
            exit 1
        fi
    done
    rm -r -- "${state:?}"
    ;;
*)
    echo "usage: $0 --this-machine-is-disposable (--record | --cleanup)" >&2
    exit 2
    ;;
esac
