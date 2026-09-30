#!/usr/bin/env bash
# Fail unless the setuid helper really reaches uid 0 in this lane. Run before the setuid tests, as
# the user that runs them: a lane whose setuid bit did not take effect (a `nosuid` mount, the wrong
# owner or mode), or, on Linux, where `unshare(CLONE_NEWUSER)` is denied to the helper, would
# otherwise fail deep inside a test or, worse, exercise nothing.
#
# Usage: setuid-lane-check.sh <helper>
#   helper  a root-owned, mode u+s copy of `cosca_testbin`.
set -euo pipefail

helper="${1:?usage: setuid-lane-check.sh <helper>}"

fail() {
    echo "::error::setuid lane check failed: $*" >&2
    exit 1
}

# The caller must not be root: a root caller can signal the helper, so nothing is unsignalable.
[[ "$(id -u)" != 0 ]] || fail "the caller is uid 0; the setuid tests need an unprivileged caller"

err="$(mktemp)"
trap 'rm -f -- "${err:?}"' EXIT

case "$(uname -s)" in
Linux)
    # `n` acks only after `unshare(CLONE_NEWUSER)` succeeded. The new namespace maps no uid, so the
    # `r` after it must then fail with EINVAL and exit 3. Together with the `+N` this proves that
    # the setuid bit took effect and that the root helper may create a user namespace here.
    want="+N"
    rc=0
    out="$(printf nr | "$helper" setuid-stdin-block root 2> "$err")" || rc=$?
    [[ "$out" == "$want" ]] || fail "the helper printed '$out', expected '$want': $(cat "$err")"
    [[ "$rc" == 3 ]] || fail "the helper exited $rc, expected 3 (the setresuid after unshare must fail): $(cat "$err")"
    if ! grep -qF 'setresuid(0, 0, 0)' "$err" || ! grep -qF 'Invalid argument' "$err"; then
        fail "the helper's stderr does not name the failed setresuid(0, 0, 0) with EINVAL, so no user namespace was created: $(cat "$err")"
    fi
    ;;
Darwin)
    # Measured on macos-latest (job 109789120504): the helper reaches uid 0. This keeps measuring it.
    want="+"
    rc=0
    out="$("$helper" setuid-stdin-block root < /dev/null 2> "$err")" || rc=$?
    [[ "$out" == "$want" ]] || fail "the helper printed '$out', expected '$want': $(cat "$err")"
    [[ "$rc" == 0 ]] || fail "the helper exited nonzero ($rc): $(cat "$err")"
    ;;
*)
    fail "unsupported OS $(uname -s)"
    ;;
esac

echo "setuid lane ok: the helper reached uid 0 (printed '$out')"
