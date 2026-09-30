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
    # `n` acks only after `unshare(CLONE_NEWUSER)` succeeded, so `+N` proves both that the setuid
    # bit took effect and that the root helper may create a user namespace on this runner.
    want="+N"
    out="$(printf n | "$helper" setuid-stdin-block root 2> "$err")" || fail "'$helper setuid-stdin-block root' exited nonzero: $(cat "$err")"
    ;;
Darwin)
    # The module doc calls a setuid-root helper unreliable on macOS (SIP); this measures it.
    want="+"
    out="$("$helper" setuid-stdin-block root < /dev/null 2> "$err")" || fail "'$helper setuid-stdin-block root' exited nonzero: $(cat "$err")"
    ;;
*)
    fail "unsupported OS $(uname -s)"
    ;;
esac

[[ "$out" == "$want" ]] || fail "the helper printed '$out', expected '$want': $(cat "$err")"
echo "setuid lane ok: the helper reached uid 0 (printed '$out')"
