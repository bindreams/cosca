# Sourced by a lane command (`devvm/README.md`) before it runs tests, so the lane sees what a CI lane sees.
#
# The groups that are off by default are off here as in CI: `.github/test-group-defaults.env`, which the CI jobs apply
# to their environment; a lane turns on its own. Then the groups whose kernel feature this guest's kernel lacks are
# turned off too, and the script says which. The floors are those of `src/test_groups.rs`; at or above one the
# variable stays unset and the group runs. Only `sudo --preserve-env` carries these into a root shell.
set -a
. "$(dirname "${BASH_SOURCE[0]}")/../.github/test-group-defaults.env"
set +a
kernel="$(uname -r)"
release="${kernel%%[-+]*}"
at_least() { [ "$(printf '%s\n%s\n' "$1" "$release" | sort -V | head -n1)" = "$1" ]; }
echo "kernel $kernel"
if ! at_least 6.9; then
    export COSCA_TEST_PIDFD_GROUP_SIGNAL=0
    echo "COSCA_TEST_PIDFD_GROUP_SIGNAL=0: the kernel is older than 6.9"
fi
if ! at_least 6.13; then
    export COSCA_TEST_PIDFD_GET_INFO=0
    echo "COSCA_TEST_PIDFD_GET_INFO=0: the kernel is older than 6.13"
fi
