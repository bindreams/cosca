#!/usr/bin/env bash
# Lets <user> run anything as root through `doas` without a password (the `Backend::Doas` test).
#
# Usage: elevation-lane-doas.sh <user>
# Run it as a user that may `sudo`. It writes /etc/doas.conf: `elevation-lane-linux.sh --cleanup` puts back what was
# there before (`--record` saves it).
set -euxo pipefail

printf 'permit nopass %s as root\n' "$1" | sudo tee /etc/doas.conf >/dev/null
doas -C /etc/doas.conf
test "$(doas -n id -u)" = 0
