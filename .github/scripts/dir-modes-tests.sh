#!/usr/bin/env bash
# Tests of dir-modes.sh on a scratch directory of its own. `sudo` is replaced by a function that runs the command
# unprivileged, so nothing outside the scratch directory is touched.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch="$(mktemp -d)"
trap 'chmod -R u+rwx "${scratch:?}" && rm -rf -- "${scratch:?}"' EXIT
mkdir -p "$scratch/bin"
printf '#!/bin/sh\nexec "$@"\n' >"$scratch/bin/sudo"
chmod +x "$scratch/bin/sudo"
export PATH="$scratch/bin:$PATH"
script="$here/dir-modes.sh"

mode_of() { if [[ "$(uname -s)" == Darwin ]]; then stat -f %Lp -- "$1"; else stat -c %a -- "$1"; fi; }
fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$scratch/a/b" "$scratch/tree/sub"
chmod 700 "$scratch/a" "$scratch/a/b"
touch "$scratch/tree/sub/file"
chmod 604 "$scratch/tree/sub/file"
chmod 750 "$scratch/tree"
chmod 740 "$scratch/tree/sub"

# Enable then revert restores the exact prior modes, not a default.
bash "$script" record "$scratch/state" "$scratch/a" "$scratch/a/b"
bash "$script" record-tree "$scratch/state-tree" "$scratch/tree"
chmod a+x "$scratch/a" "$scratch/a/b"
chmod -R a+rX "$scratch/tree"
bash "$script" restore "$scratch/state"
bash "$script" restore "$scratch/state-tree"
[[ "$(mode_of "$scratch/a")" == 700 ]] || fail "a is $(mode_of "$scratch/a")"
[[ "$(mode_of "$scratch/a/b")" == 700 ]] || fail "a/b is $(mode_of "$scratch/a/b")"
[[ "$(mode_of "$scratch/tree")" == 750 ]] || fail "tree is $(mode_of "$scratch/tree")"
[[ "$(mode_of "$scratch/tree/sub")" == 740 ]] || fail "tree/sub is $(mode_of "$scratch/tree/sub")"
[[ "$(mode_of "$scratch/tree/sub/file")" == 604 ]] || fail "file is $(mode_of "$scratch/tree/sub/file")"
[[ ! -e "$scratch/state" ]] || fail "the state file survived a restore"

# Restore with no state does nothing.
bash "$script" restore "$scratch/none" | grep -q "nothing to restore" || fail "restore without state"

# A second record is refused while the first is unrestored.
bash "$script" record "$scratch/again" "$scratch/a"
if bash "$script" record "$scratch/again" "$scratch/a" 2>/dev/null; then fail "a second record was accepted"; fi

# A mode that does not read back fails and keeps the state.
printf '#!/bin/sh\nexit 0\n' >"$scratch/bin/sudo"
chmod 755 "$scratch/a"
if bash "$script" restore "$scratch/again" 2>/dev/null; then fail "a restore that changed nothing passed"; fi
[[ -e "$scratch/again" ]] || fail "the state file was removed after a failed restore"
echo "dir-modes tests passed"
