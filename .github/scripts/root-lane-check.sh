#!/usr/bin/env bash
# Fail unless this process holds the privilege state the root lane exists to test. Run under the
# lane's own PREFIX, so it sees what nextest will see. A lane whose setup silently did not take
# effect (a dropped `--ambient-caps`, a missing `--cap-add`) would otherwise run unprivileged and
# stay green.
#
# Environment (masks are hex capability bitmasks, as in /proc/self/status):
#   EXPECT_UID         the uid this process must have.
#   EXPECT_CAPEFF_HAS  effective bits that must all be set.
#   EXPECT_CAPEFF_LACKS effective bits that must all be clear.
#   EXPECT_CAPAMB      the exact ambient set.
#   EXPECT_USERNS      "1": must be in a non-initial user namespace.
#   FOREIGN_TMPDIR     "true": uid 65534 must not be able to list $TMPDIR.
set -euo pipefail

: "${EXPECT_UID:?}" "${EXPECT_CAPEFF_HAS:?}" "${EXPECT_CAPEFF_LACKS:?}" "${EXPECT_CAPAMB:?}"

fail() {
    echo "::error::lane precondition failed: $*" >&2
    exit 1
}

# Value of a `Cap*:` line in /proc/self/status, as a number.
cap() {
    local hex
    hex="$(awk -v key="$1:" '$1 == key { print $2 }' /proc/self/status)"
    [[ -n "$hex" ]] || fail "no $1 line in /proc/self/status"
    echo $((16#$hex))
}

uid="$(id -u)"
eff="$(cap CapEff)"
amb="$(cap CapAmb)"
printf 'uid=%s CapEff=%#x CapAmb=%#x\n' "$uid" "$eff" "$amb"

[[ "$uid" == "$EXPECT_UID" ]] || fail "uid is $uid, expected $EXPECT_UID"

has=$((EXPECT_CAPEFF_HAS))
lacks=$((EXPECT_CAPEFF_LACKS))
(((eff & has) == has)) || fail "CapEff $(printf '%#x' "$eff") lacks $(printf '%#x' "$has")"
(((eff & lacks) == 0)) || fail "CapEff $(printf '%#x' "$eff") holds a bit of $(printf '%#x' "$lacks")"
((amb == EXPECT_CAPAMB)) || fail "CapAmb is $(printf '%#x' "$amb"), expected $(printf '%#x' "$((EXPECT_CAPAMB))")"

if [[ "${EXPECT_USERNS:-}" == "1" ]]; then
    read -r inner outer count < /proc/self/uid_map
    [[ "$inner $outer $count" != "0 0 4294967295" ]] || fail "still in the initial user namespace"
fi

if [[ "${FOREIGN_TMPDIR:-}" == "true" ]]; then
    : "${TMPDIR:?}"
    if setpriv --reuid 65534 --regid 65534 --clear-groups ls "$TMPDIR" > /dev/null 2>&1; then
        fail "uid 65534 can list TMPDIR=$TMPDIR"
    fi
fi
