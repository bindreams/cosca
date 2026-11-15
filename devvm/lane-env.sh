# Sourced by a lane command (`devvm/README.md`) before it runs tests, so the lane sees what a CI lane sees.
#
# The groups that are off by default are off here as in CI: `.github/test-group-defaults.env`, which the CI jobs apply
# to their environment; a lane turns on its own. Then the groups whose kernel feature this guest's kernel lacks are
# turned off too, and the script says which. The floors are those of `src/test_groups.rs`; at or above one the
# variable stays unset and the group runs. Only `sudo --preserve-env` carries these into a root shell.
# The caller's shell keeps its allexport setting and gains no variables besides the exports. The one function it
# defines is named under the `cosca_lane_env` prefix, which no caller should own, and is removed again.
cosca_lane_env() {
    local allexport=off kernel release pair floor group
    case $- in *a*) allexport=on ;; esac
    set -a
    . "$(dirname "${BASH_SOURCE[0]}")/../.github/test-group-defaults.env"
    if [[ $allexport == off ]]; then
        set +a
    fi
    kernel="$(uname -r)"
    release="${kernel%%[-+]*}"
    echo "kernel $kernel"
    for pair in "6.9 COSCA_TEST_PIDFD_GROUP_SIGNAL" "6.13 COSCA_TEST_PIDFD_GET_INFO"; do
        floor="${pair% *}"
        group="${pair#* }"
        if [ "$(printf '%s\n%s\n' "$floor" "$release" | sort -V | head -n1)" != "$floor" ]; then
            export "$group=0"
            echo "$group=0: the kernel is older than $floor"
        fi
    done
}
cosca_lane_env
unset -f cosca_lane_env
