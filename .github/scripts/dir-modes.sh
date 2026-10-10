#!/usr/bin/env bash
# Records the modes of paths a CI step is about to loosen, and puts exactly those back.
#
# Usage:
#   dir-modes.sh record <state file> <path>...         # the paths themselves
#   dir-modes.sh record-tree <state file> <path>...    # the paths and everything under them
#   dir-modes.sh restore <state file>                  # set every recorded mode back, read it back, remove the state file
#
# `record` refuses to run when the state file exists (a second record would save the loosened modes), and writes the
# file only once every mode is read. `restore` does nothing when there is no state file; it restores all it can, then
# fails if any mode reads back different. The state is NUL-separated `<mode> <path>` records.
set -euo pipefail

mode_of() {
    if [[ "$(uname -s)" == Darwin ]]; then
        stat -f %Lp -- "$1"
    else
        stat -c %a -- "$1"
    fi
}

# Paths must be absolute: they are passed to `chmod` and `stat` without `--`, which BSD `chmod` does not take after a mode.
command="${1:-}"
state="${2:-}"
if [[ -z "$command" || -z "$state" ]]; then
    echo "usage: $0 (record | record-tree | restore) <state file> [<path>...]" >&2
    exit 2
fi
shift 2
for path in "$@"; do
    [[ "$path" == /* ]] || { echo "not an absolute path: $path" >&2; exit 2; }
    # `chmod` follows a symlink, so a restore would set the mode of whatever it points at.
    [[ ! -L "$path" ]] || { echo "$path is a symlink; refusing to record it" >&2; exit 2; }
done

case "$command" in
record | record-tree)
    if [[ -e "$state" ]]; then
        echo "$state exists, so modes were already recorded (a second record would save the loosened modes)" >&2
        exit 1
    fi
    partial="$state.partial"
    : >"$partial"
    for path in "$@"; do
        if [[ "$command" == record-tree ]]; then
            while IFS= read -r -d '' entry; do
                printf '%s %s\0' "$(mode_of "$entry")" "$entry" >>"$partial"
            done < <(find "$path" -not -type l -print0)
        else
            printf '%s %s\0' "$(mode_of "$path")" "$path" >>"$partial"
        fi
    done
    mv -- "$partial" "$state"
    ;;
restore)
    if [[ ! -e "$state" ]]; then
        echo "no recorded modes at $state: nothing to restore"
        exit 0
    fi
    failed=0
    while IFS= read -r -d '' record; do
        mode="${record%% *}"
        path="${record#* }"
        # A path that is gone has no mode to restore.
        [[ -e "$path" ]] || continue
        # Never through a symlink: `chmod` would change its target.
        [[ ! -L "$path" ]] || continue
        if ! sudo chmod "$mode" "$path"; then
            echo "chmod $mode $path failed" >&2
            failed=1
            continue
        fi
        if [[ "$(mode_of "$path")" != "$mode" ]]; then
            echo "$path reads back $(mode_of "$path") after restoring $mode" >&2
            failed=1
        fi
    done <"$state"
    if ((failed)); then
        exit 1
    fi
    rm -- "$state"
    ;;
*)
    echo "usage: $0 (record | record-tree | restore) <state file> [<path>...]" >&2
    exit 2
    ;;
esac
