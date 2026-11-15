#!/usr/bin/env bash
# Builds `cosca_testbin` and installs a setuid-root copy of it, for the setuid group (`COSCA_TEST_SETUID`).
#
# Usage: setuid-helper.sh <target> <helper path>
#        setuid-helper.sh --remove <helper path>
# Run it as the ordinary user, from the checkout; `sudo` does the two root steps. The group needs a COPY of
# cosca_testbin that is genuinely setuid-root (owned by root, mode u+s), so a helper process can become truly
# unsignalable by this ordinary user, giving a REAL mixed process group. Only preparing the copy needs root; the tests
# run as the ordinary user. `setuid-lane-check.sh` then checks that the copy works. `--remove` deletes it.
set -euxo pipefail

if [[ "${1:-}" == --remove ]]; then
    sudo rm -f -- "${2:?usage: setuid-helper.sh --remove <helper path>}"
    exit 0
fi

BIN=$(cargo build --locked --target "$1" --bin cosca_testbin --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .target.name == "cosca_testbin") | .executable' \
    | grep -v '^null$' | grep . | head -n1)
test -x "$BIN"
HELPER="$2"
cp "$BIN" "$HELPER"
sudo chown root:root "$HELPER"
sudo chmod 4755 "$HELPER"
