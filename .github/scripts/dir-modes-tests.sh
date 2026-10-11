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

# Four digits, so setuid, setgid and sticky show.
mode_of() { if [[ "$(uname -s)" == Darwin ]]; then stat -f %Mp%Lp -- "$1"; else stat -c %04a -- "$1"; fi; }
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
[[ "$(mode_of "$scratch/a")" == 0700 ]] || fail "a is $(mode_of "$scratch/a")"
[[ "$(mode_of "$scratch/a/b")" == 0700 ]] || fail "a/b is $(mode_of "$scratch/a/b")"
[[ "$(mode_of "$scratch/tree")" == 0750 ]] || fail "tree is $(mode_of "$scratch/tree")"
[[ "$(mode_of "$scratch/tree/sub")" == 0740 ]] || fail "tree/sub is $(mode_of "$scratch/tree/sub")"
[[ "$(mode_of "$scratch/tree/sub/file")" == 0604 ]] || fail "file is $(mode_of "$scratch/tree/sub/file")"
[[ ! -e "$scratch/state" ]] || fail "the state file survived a restore"

bash "$script" restore "$scratch/none" | grep -q "nothing to restore" || fail "restore without state"

# A second record is refused while the first is unrestored.
bash "$script" record "$scratch/again" "$scratch/a"
if bash "$script" record "$scratch/again" "$scratch/a" 2>/dev/null; then fail "a second record was accepted"; fi

# A mode that does not read back fails and keeps the state.
printf '#!/bin/sh\nexit 0\n' >"$scratch/bin/sudo"
chmod 755 "$scratch/a"
if bash "$script" restore "$scratch/again" 2>/dev/null; then fail "a restore that changed nothing passed"; fi
[[ -e "$scratch/again" ]] || fail "the state file was removed after a failed restore"
# A symlink is never followed: neither recorded nor restored, so its target keeps its own mode.
mkdir -p "$scratch/links/dir"
touch "$scratch/outside"
chmod 600 "$scratch/outside"
ln -s "$scratch/outside" "$scratch/links/dir/link"
chmod 750 "$scratch/links/dir"
bash "$script" record-tree "$scratch/state-links" "$scratch/links"
chmod a+rx "$scratch/links/dir"
printf '#!/bin/sh\nexec "$@"\n' >"$scratch/bin/sudo"
bash "$script" restore "$scratch/state-links"
[[ "$(mode_of "$scratch/outside")" == 0600 ]] || fail "the symlink target is $(mode_of "$scratch/outside")"
[[ "$(mode_of "$scratch/links/dir")" == 0750 ]] || fail "links/dir is $(mode_of "$scratch/links/dir")"
if bash "$script" record "$scratch/state-link-arg" "$scratch/links/dir/link" 2>/dev/null; then fail "a symlink argument was accepted"; fi
[[ ! -e "$scratch/state-link-arg" ]] || fail "a refused record left a state file"

# A recorded path that became a symlink fails the restore and its target keeps its mode.
printf '0777 %s\0' "$scratch/links/dir/link" >"$scratch/state-hand"
if bash "$script" restore "$scratch/state-hand" 2>/dev/null; then fail "a symlink in the state was accepted"; fi
[[ "$(mode_of "$scratch/outside")" == 0600 ]] || fail "a hand-written symlink record changed the target to $(mode_of "$scratch/outside")"
[[ -e "$scratch/state-hand" ]] || fail "the state file was removed after a symlink failure"

# A recorded path that is gone is named, and the rest is still restored.
mkdir -p "$scratch/gone" "$scratch/kept"
chmod 700 "$scratch/gone" "$scratch/kept"
bash "$script" record "$scratch/state-gone" "$scratch/gone" "$scratch/kept"
chmod 755 "$scratch/kept"
rmdir "$scratch/gone"
bash "$script" restore "$scratch/state-gone" 2>&1 | grep -q "$scratch/gone" || fail "a missing path was not named"
[[ "$(mode_of "$scratch/kept")" == 0700 ]] || fail "kept is $(mode_of "$scratch/kept")"
[[ ! -e "$scratch/state-gone" ]] || fail "the state file survived a restore with a missing path"

# Setuid, setgid and sticky survive a record and a restore.
mkdir -p "$scratch/sticky" "$scratch/sgid"
chmod 1777 "$scratch/sticky"
chmod 2750 "$scratch/sgid"
bash "$script" record "$scratch/state-special" "$scratch/sticky" "$scratch/sgid"
chmod 755 "$scratch/sticky" "$scratch/sgid"
bash "$script" restore "$scratch/state-special"
[[ "$(mode_of "$scratch/sticky")" == 1777 ]] || fail "sticky is $(mode_of "$scratch/sticky")"
[[ "$(mode_of "$scratch/sgid")" == 2750 ]] || fail "sgid is $(mode_of "$scratch/sgid")"

# A record that cannot read every mode publishes nothing.
[[ "$(id -u)" != 0 ]] || fail "this test needs a non-root user: root reads every directory"
if bash "$script" record "$scratch/state-missing" "$scratch/a" "$scratch/does-not-exist" 2>/dev/null; then fail "a missing path was recorded"; fi
[[ ! -e "$scratch/state-missing" && ! -e "$scratch/state-missing.partial" ]] || fail "a failed record left a state file"
if bash "$script" record-tree "$scratch/state-missing-tree" "$scratch/does-not-exist" 2>/dev/null; then fail "a missing tree was recorded"; fi
[[ ! -e "$scratch/state-missing-tree" && ! -e "$scratch/state-missing-tree.partial" ]] || fail "a failed record-tree left a state file"
mkdir -p "$scratch/locked/inner"
chmod 000 "$scratch/locked/inner"
if bash "$script" record-tree "$scratch/state-locked" "$scratch/locked" 2>/dev/null; then fail "an unreadable subdirectory was recorded"; fi
[[ ! -e "$scratch/state-locked" && ! -e "$scratch/state-locked.partial" ]] || fail "an unreadable subdirectory left a state file"
chmod 700 "$scratch/locked/inner"

mkdir -p "$scratch/with space/in side"
chmod 700 "$scratch/with space" "$scratch/with space/in side"
bash "$script" record-tree "$scratch/state-space" "$scratch/with space"
chmod -R a+rx "$scratch/with space"
bash "$script" restore "$scratch/state-space"
[[ "$(mode_of "$scratch/with space/in side")" == 0700 ]] || fail "spaces: $(mode_of "$scratch/with space/in side")"

# One failing path does not stop the others from being restored, and the run still fails.
mkdir -p "$scratch/p" "$scratch/q"
chmod 700 "$scratch/p" "$scratch/q"
bash "$script" record "$scratch/state-two" "$scratch/p" "$scratch/q"
chmod 755 "$scratch/p" "$scratch/q"
# shellcheck disable=SC2016 # the generated script expands its own arguments
printf '#!/bin/sh\n[ "$3" = "%s" ] && exit 1\nexec "$@"\n' "$scratch/p" >"$scratch/bin/sudo"
if bash "$script" restore "$scratch/state-two" 2>/dev/null; then fail "a failed chmod passed"; fi
[[ "$(mode_of "$scratch/q")" == 0700 ]] || fail "the path after the failure was not restored: $(mode_of "$scratch/q")"
[[ -e "$scratch/state-two" ]] || fail "the state file was removed after a failed restore"
echo "dir-modes tests passed"
