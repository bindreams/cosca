#!/bin/bash
# One stamped run (THROWAWAY): banner, source hashes, then the command; every line timestamped as it is written.
set -o pipefail
{ echo "== run: $* ($(uname -sr), $(sw_vers -productVersion))"; shasum -a 256 probe/*.c probe/*.h probe/*.py probe/*.sh; "$@"; rc=$?; echo "== exit $rc"; exit $rc; } 2>&1 | python3 -u probe/stamp.py
