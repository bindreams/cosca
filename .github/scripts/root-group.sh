#!/usr/bin/env bash
# Usage: root-group.sh <base> <command> [args...]
#
# Runs <command> as root inside a process group that stays occupied until reap-root-group.sh
# kills it, so the group id can never be reused in between. Start it through `run_forwarding`: that
# makes this script the leader of its own group, and `$$` the group id.
#
# A keeper joins the group first. It ignores INT/TERM/HUP, so only SIGKILL ends it, and it holds the
# write side of the FIFO `<base>.keeper` so that its death is observable. Once the keeper is
# running, the group id is published in `<base>`; both files are consumed by reap-root-group.sh.
set -uo pipefail

base=${1:?usage: root-group.sh <base> <command> [args...]}
shift
fifo="$base.keeper"

mkfifo -m 0644 "$fifo"
(
    trap '' INT TERM HUP
    exec 5<>"$fifo"
    read -r <&5
) &
# Opening the read side blocks until a writer exists, i.e. until the keeper holds the FIFO.
: <"$fifo"
echo "$$" >"$base"

"$@"
