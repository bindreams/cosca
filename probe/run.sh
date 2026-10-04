#!/bin/bash
# Every run: a start banner, the hashes of the exact sources, then the run, every line timestamped live.
{ echo "== run: $* ($(uname -sr), $(sw_vers -productVersion))"; shasum -a 256 probe/*.c probe/*.h probe/*.m probe/*.py probe/*.sh; "$@"; echo "== exit $?"; } 2>&1 | python3 -u probe/stamp.py
