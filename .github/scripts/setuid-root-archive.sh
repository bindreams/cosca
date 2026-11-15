#!/usr/bin/env bash
# Archives the setuid-root process-group teardown test and makes it reachable by uid 65534.
#
# Usage: setuid-root-archive.sh <target>
# Run it as the ordinary user, from the checkout, with RUNNER_TEMP set. It writes `setuid-root.tar.zst` and
# `setuid-root-extract/` there, and the modes it loosens go to `dir-modes` there: undo it with
# `dir-modes.sh restore "$RUNNER_TEMP/dir-modes"`.
#
# The same test started as root re-executes itself as uid 65534 (see the test file's "Running as root" docs), so the
# test binary, the `cosca_testbin` path compiled into it, and the helper must all be reachable by that uid: every
# directory above the checkout and the extraction directory is made traversable and `target` readable.
# `--extract-to` is what lets nextest run an archive there: its default extraction directory is root-only.
set -euxo pipefail

cargo nextest archive --locked --target "$1" --test group_teardown_setuid --archive-file "$RUNNER_TEMP/setuid-root.tar.zst"
mkdir -m 0755 "$RUNNER_TEMP/setuid-root-extract"
# Build output of this checkout, not system policy.
chmod -R a+rX "$PWD/target"
modes=("$RUNNER_TEMP")
d="$PWD"
while [ "$d" != / ]; do modes+=("$d"); d=$(dirname "$d"); done
bash .github/scripts/dir-modes.sh record "$RUNNER_TEMP/dir-modes" "${modes[@]}"
for d in "${modes[@]}"; do sudo chmod a+x "$d"; done
