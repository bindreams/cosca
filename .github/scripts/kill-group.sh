#!/usr/bin/env bash
# Usage: kill-group.sh <pidfile>
#
# SIGKILLs, as root, the process group whose id is in <pidfile> (written by the group's leader), and
# returns once the group holds no process. A missing file means the run never started.
#
# The group is killed again until the kill finds nothing to signal: a member that forked between two
# kills is caught by the next, and a refused or empty signal is the kernel's report that no live
# process is left. The group id cannot have been reused while a member lives; with none left, a new
# group of the same id would need a full wrap of the pid space.
set -euo pipefail

pidfile="${1:?usage: kill-group.sh <pidfile>}"
[[ -e "$pidfile" ]] || exit 0

pgid="$(sudo cat -- "$pidfile")"
[[ "$pgid" =~ ^[0-9]+$ ]] || { echo "::error::$pidfile does not hold a group id: $pgid"; exit 1; }
((pgid > 1)) || { echo "::error::refusing to signal group $pgid"; exit 1; }

while sudo kill -KILL -- "-$pgid" 2>/dev/null; do
    sleep 0.1
done
sudo rm -f -- "${pidfile:?}"
