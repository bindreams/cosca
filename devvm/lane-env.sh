# Sourced by a lane command (`devvm/README.md`) before it runs tests, so the lane sees what a CI lane sees.
#
# The groups that are off by default are off here as in CI: `.github/test-group-defaults.env`, which the CI jobs apply
# to their environment; a lane turns on its own. Then the groups whose kernel feature this guest's kernel lacks are
# turned off too, and the script says which. The floors are those of `src/test_groups.rs`; at or above one the
# variable stays unset and the group runs. `COSCA_LANE_FLOOR_VARS` lists, comma-separated, the kernel-floor
# variables this script turned off or may turn off, for `sudo --preserve-env`. A root lane's `sudo` drops the
# default-off groups as CI's does; the lane script sets the groups it runs.
# The caller's shell keeps its allexport setting and gains no variables besides the exports.
cosca_lane_env() {
    local allexport=off kernel release pair floor group vars=
    case $- in *a*) allexport=on ;; esac
    set -a
    . "$(dirname "${BASH_SOURCE[0]}")/../.github/test-group-defaults.env"
    if [[ $allexport == off ]]; then
        set +a
    fi
    kernel="$(uname -r)"
    release="${kernel%%[-+]*}"
    echo "kernel $kernel"
    # The floors, each the row of `src/test_groups.rs` named beside it:
    #   6.9  `kernel_signals_groups_through_pidfds`
    #   6.13 `kernel_answers_pidfd_get_info`
    for pair in "6.9 COSCA_TEST_PIDFD_GROUP_SIGNAL" "6.13 COSCA_TEST_PIDFD_GET_INFO"; do
        floor="${pair% *}"
        group="${pair#* }"
        vars+="${vars:+,}$group"
        if [ "$(printf '%s\n%s\n' "$floor" "$release" | sort -V | head -n1)" != "$floor" ]; then
            export "$group=0"
            echo "$group=0: the kernel is older than $floor"
        fi
    done
    export COSCA_LANE_FLOOR_VARS="$vars"
}
cosca_lane_env
unset -f cosca_lane_env
