#!/usr/bin/env bash
# Usage: reap-root-group.sh <base>
#
# Kills the process group root-group.sh published under <base>, as root, and returns once its
# keeper is gone. The runner's timeout SIGKILL cannot reach root processes, so a root nextest can
# outlive its step and rewrite the shared JUnit path under a later step.
#
# The group cannot have been reused: the keeper has been a member since before the id was
# published, and only this script ends it. Nothing is signalled unless a group was published.
set -euo pipefail

base=${1:?usage: reap-root-group.sh <base>}
[[ -f $base ]] || exit 0
pgid=$(<"$base")

# Open the keeper's FIFO before the kill: this blocks only until the keeper, still alive, holds it.
exec 4<"$base.keeper"
# `sudo bash -c`: the builtin `kill` takes `-- -<pgid>` on every platform; /bin/kill does not.
sudo bash -c 'kill -KILL -- "-$0"' "$pgid"
# End of file arrives when the last writer, the keeper, has exited.
cat <&4 >/dev/null
exec 4<&-
rm -f "$base" "$base.keeper"
