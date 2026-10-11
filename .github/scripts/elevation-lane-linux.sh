#!/usr/bin/env bash
# Records, then restores, the Linux elevation lane's package and `doas` state.
#
# Usage (every form starts with the flag):
#   elevation-lane-linux.sh --this-machine-is-disposable --record     # before the lane installs anything
#   elevation-lane-linux.sh --this-machine-is-disposable --cleanup    # after the lane, on success and on failure
#
# The lane apt-installs polkitd, pkexec and opendoas (and what they pull in), runs `apt-get update`, and writes
# /etc/doas.conf. `--record` saves, in $RUNNER_TEMP, every package whose dpkg status is not `not-installed` (so
# half-installed and `rc` packages count) with its version and status, /var/lib/apt/lists, and the current
# /etc/doas.conf (or that there is none).
#
# `--cleanup` puts all of that back:
# - it purges every package that is new, but first simulates the purge and refuses it if it would remove a package that
#   was there before;
# - it reinstalls the recorded version of a package that changed (and fails if that version is unavailable), and
#   removes, keeping its configuration, a package that was `rc` before and is installed now;
# - it restores the apt lists and /etc/doas.conf;
# - it asserts that the packages now are exactly the recorded ones, at the recorded versions and statuses.
#
# Run it after `unattended-gui-elevation.py --revert`, which restarts polkit.
set -euo pipefail
exec 2>&1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
state="${RUNNER_TEMP:?RUNNER_TEMP names where the record lives}/elevation-lane-linux"
doas_conf=/etc/doas.conf
apt_lists=/var/lib/apt/lists
# shellcheck disable=SC2016 # dpkg-query expands its own fields
query='${db:Status-Status}\t${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'

if [[ "${1:-}" != --this-machine-is-disposable || $# -ne 2 ]]; then
    echo "usage: $0 --this-machine-is-disposable (--record | --cleanup)" >&2
    exit 2
fi
python3 "$here/unattended-gui-elevation.py" --this-machine-is-disposable --check-only

# Reads `dpkg-query` output on stdin; prints `<package> <version> <status>` for every package that is not `not-installed`.
present() {
    awk -F'\t' '$1 != "not-installed" { sub(/ +$/, "", $4); print $2 " " $3 " " $4 }' | sort
}

# Sets `now` to the present packages. The query is captured first so that its failure fails the script.
snapshot() {
    local raw
    raw="$(dpkg-query -W -f="$query")"
    now="$(present <<<"$raw")"
}

case "$2" in
--record)
    if [[ -e "$state" ]]; then
        echo "$state exists, so a record was already made (a second would save the lane's own changes)" >&2
        exit 1
    fi
    mkdir "$state"
    snapshot
    printf '%s\n' "$now" >"$state/before"
    sudo cp -a "$apt_lists" "$state/lists"
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
    failed=0
    before="$(<"$state/before")"
    snapshot

    # Packages by name: the first field of each line.
    names() { awk '{ print $1 }' <<<"$1" | sort; }
    mapfile -t new_packages < <(comm -13 <(names "$before") <(names "$now"))

    if ((${#new_packages[@]} > 0)); then
        simulation="$(sudo apt-get -s purge "${new_packages[@]}")"
        # `Remv`/`Purg` lines name what apt would remove: `Purg <package> [<version>] ...`.
        mapfile -t would_remove < <(awk '$1 == "Remv" || $1 == "Purg" { print $2 }' <<<"$simulation" | sort -u)
        mapfile -t collateral < <(comm -12 <(names "$before") <(printf '%s\n' "${would_remove[@]}"))
        if ((${#collateral[@]} > 0)); then
            echo "refusing to purge ${new_packages[*]}: it would also remove packages that were here before: ${collateral[*]}" >&2
            failed=1
        elif ! sudo apt-get purge -y "${new_packages[@]}"; then
            echo "purging ${new_packages[*]} failed" >&2
            failed=1
        fi
    fi

    # Packages that were here before and are different now.
    snapshot
    while read -r name version status; do
        [[ -n "$name" ]] || continue
        current="$(awk -v name="$name" '$1 == name' <<<"$now")"
        [[ "$current" != "$name $version $status" ]] || continue
        if [[ "$status" == ii ]]; then
            if ! sudo apt-get install -y --allow-downgrades "$name=$version" </dev/null; then
                echo "could not reinstall $name=$version (now: ${current:-not installed})" >&2
                failed=1
            fi
        elif [[ "$status" == rc && "$current" == "$name $version ii" ]]; then
            if ! sudo apt-get remove -y "$name" </dev/null; then
                echo "could not remove $name back to its configuration-only state" >&2
                failed=1
            fi
        else
            echo "cannot restore $name to '$version $status' (now: ${current:-not installed})" >&2
            failed=1
        fi
    done <<<"$before"

    sudo find "$apt_lists" -mindepth 1 -delete || failed=1
    sudo cp -a "$state/lists/." "$apt_lists/" || failed=1
    # The file goes back after the purge, which could otherwise remove or rewrite it.
    if [[ -e "$state/doas.conf" ]]; then
        sudo cp -p "$state/doas.conf" "$doas_conf" || failed=1
    else
        sudo rm -f "$doas_conf" || failed=1
    fi

    snapshot
    if [[ "$now" != "$before" ]]; then
        echo "the packages differ from the record after the cleanup (< recorded, > now):" >&2
        diff <(printf '%s\n' "$before") <(printf '%s\n' "$now") >&2 || true
        failed=1
    fi
    if ((failed)); then
        exit 1
    fi
    sudo rm -r --one-file-system -- "${state:?}"
    ;;
*)
    echo "usage: $0 --this-machine-is-disposable (--record | --cleanup)" >&2
    exit 2
    ;;
esac
