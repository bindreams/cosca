# Sourced by a lane command (`devvm/README.md`) before it runs tests, so the lane sees what a CI lane sees.
#
# The system-affecting groups are off, as in the `env:` of `.github/workflows/ci.yaml`; a lane turns on its own.
# Then the groups whose kernel feature this guest's kernel lacks are turned off too, and the script says which. The
# floors are those of `src/test_groups.rs`; at or above one the variable stays unset and the group runs. Only
# `sudo --preserve-env` carries these into a root shell.
export COSCA_TEST_ROOT=0 COSCA_TEST_UID_SWITCH=0 COSCA_TEST_NAMESPACES=0 COSCA_TEST_TRACER=0 COSCA_TEST_SETUID=0
export COSCA_TEST_CGROUP=0 COSCA_TEST_ELEVATION=0 COSCA_TEST_STRAY_SIGNAL=0
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
