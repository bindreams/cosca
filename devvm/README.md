# Cosca's Linux lanes in a devvm guest

The guest is Ubuntu 24.04 with the toolchain of `.github/ci-toolchain`, `cargo-nextest`, and the git-tracked tree at
`~/cosca` ([`cosca-linux.devvm.yaml`](cosca-linux.devvm.yaml)). Each lane below runs the CI lane's scripts from
`.github/scripts/`, so a lane that passes here runs the text CI runs. It does not reproduce CI's runner or kernel: the
guest's is 6.8, and `lane-env.sh` turns off the groups that need a newer one and says which.

Every lane runs as the guest's `user`, which may `sudo` without a password; the lanes that need root call `sudo`
themselves. The guest is disposable: the elevation and setuid lanes change it.

Lanes in one guest run one at a time; for lanes at once, start one instance per lane (`--name cosca-lane-<n>`).

## Run a lane

```sh
devvm up devvm/cosca-linux.devvm.yaml --name cosca-lane        # once: about 5 minutes cold
devvm ssh cosca-lane -- bash -c "$(cat lane.sh)"               # lane.sh holds one block below
```

Git Bash on Windows rewrites any argument of `devvm` that starts with `/` or holds `=/` into a Windows path: set
`MSYS_NO_PATHCONV=1` for such a command.

After an edit to a tracked file, rerun from a fresh instance: `devvm rm cosca-lane`, then `devvm up` again. Only the
last step (`copy`) runs again, about 45 seconds; the layers above it are reused. `devvm rm cosca-lane` when done.

Each block sources `lane-env.sh`: the groups that are off by default (`.github/test-group-defaults.env`) are off, and
the lane's script turns on its own with their `_CONSENT` variable. All tests of the lane pass; skips are the groups
`lane-env.sh` printed as off.

| Lane (CI group)                           | Consent variables set by                    |
| ----------------------------------------- | ------------------------------------------- |
| elevation                                 | `elevation-lane.sh`: `ELEVATION`            |
| cgroup (`CGROUP`, `NAMESPACES`, `TRACER`) | `cgroup-lane.sh`                            |
| setuid                                    | `setuid-lane.sh`: `SETUID`                  |
| cgroup and setuid                         | `cgroup-setuid-lane.sh`: `CGROUP`, `SETUID` |
| setuid-root                               | `setuid-root-lane.sh`: `SETUID`             |
| root, uid switch (five variants)          | the block: `ROOT`, `UID_SWITCH`             |
| tracer (debug, release)                   | `tracer-lane.sh`: `TRACER`                  |
| stray signal (debug, release)             | `stray-signal-lane.sh`: `STRAY_SIGNAL`      |

The setuid lanes remove their setuid-root helper on exit, as CI's "Remove the setuid-root helper" step does.

## Elevation

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
export RUNNER_TEMP="$(mktemp -d)"
bash .github/scripts/elevation-lane.sh x86_64-unknown-linux-gnu
```

## Cgroup

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
export RUNNER_TEMP="$(mktemp -d)"
bash .github/scripts/cgroup-archive.sh "$target"
bash .github/scripts/cgroup-lane.sh "$(command -v cargo-nextest)" "$RUNNER_TEMP/cgroup.tar.zst" "$(id -u):$(id -g)"
```

## Setuid

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
export RUNNER_TEMP="$(mktemp -d)"
helper="$RUNNER_TEMP/cosca_testbin_setuid"
trap 'bash .github/scripts/setuid-helper.sh --remove "$helper"' EXIT
bash .github/scripts/setuid-helper.sh "$target" "$helper"
bash .github/scripts/setuid-lane-check.sh "$helper"
bash .github/scripts/setuid-lane.sh "$target" "$helper"
```

## Cgroup and setuid

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
export RUNNER_TEMP="$(mktemp -d)"
helper="$RUNNER_TEMP/cosca_testbin_setuid"
trap 'bash .github/scripts/setuid-helper.sh --remove "$helper"' EXIT
bash .github/scripts/setuid-helper.sh "$target" "$helper"
bash .github/scripts/setuid-lane-check.sh "$helper"
bash .github/scripts/cgroup-archive.sh "$target"
bash .github/scripts/cgroup-setuid-lane.sh "$(command -v cargo-nextest)" "$RUNNER_TEMP/cgroup.tar.zst" "$helper"
```

## Setuid-root

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
export RUNNER_TEMP="$(mktemp -d)"
helper="$RUNNER_TEMP/cosca_testbin_setuid"
# The helper is removed and the directory modes are put back on every exit.
restore() {
  status=$?
  trap - EXIT
  bash .github/scripts/setuid-helper.sh --remove "$helper" || status=1
  bash .github/scripts/dir-modes.sh restore "$RUNNER_TEMP/dir-modes" || status=1
  exit "$status"
}
trap restore EXIT
bash .github/scripts/setuid-helper.sh "$target" "$helper"
bash .github/scripts/setuid-lane-check.sh "$helper"
bash .github/scripts/setuid-root-archive.sh "$target"
bash .github/scripts/setuid-root-lane.sh "$(command -v cargo-nextest)" "$RUNNER_TEMP/setuid-root.tar.zst" "$RUNNER_TEMP/setuid-root-extract" "$helper"
```

## Root and uid switch

This block approximates CI's `.github/actions/root-lane` container with `unshare` and `setpriv`; its variant table is
taken from the root-lane steps of `ci.yaml`.

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
export RUNNER_TEMP="$(mktemp -d)"
mkdir -p target/nextest "$RUNNER_TEMP/artifacts"
cargo nextest archive --locked --target "$target" --archive-file "$RUNNER_TEMP/artifacts/root-lane.tar.zst"
# The capabilities Docker gives a container's root; a lane adds to them as its `docker run` flags do.
docker_caps=+chown,+dac_override,+fowner,+fsetid,+kill,+setgid,+setuid,+setpcap,+net_bind_service,+net_raw,+sys_chroot,+mknod,+audit_write,+setfcap
# variant <slug> <UID_SWITCH> <extra capabilities, +name each> <PREFIX> <EXPECT_UID> <has> <lacks> <ambient> <userns> <foreign TMPDIR>
variant() {
  local lane="$RUNNER_TEMP/root-lane/$1"
  mkdir -p "$lane/nextest" "$lane/junit"
  chmod 0777 "$lane/nextest" "$lane/junit"
  echo "== lane $1"
  # The mounts give root-lane.sh the container's /repo/target/nextest, /junit-out and /artifacts, in a mount
  # namespace that ends with the lane.
  sudo --preserve-env=COSCA_TEST_PIDFD_GROUP_SIGNAL,COSCA_TEST_PIDFD_GET_INFO env \
    LANE="$lane" ARTIFACTS="$RUNNER_TEMP/artifacts" CAPS="-all,$docker_caps$3" \
    COSCA_TEST_ROOT=1 COSCA_TEST_ROOT_CONSENT=1 COSCA_TEST_UID_SWITCH="$2" COSCA_TEST_UID_SWITCH_CONSENT=1 \
    PRIVILEGE_TESTS='binary(cosca) | binary(process_root)' PREFIX="$4" \
    EXPECT_UID="$5" EXPECT_CAPEFF_HAS="$6" EXPECT_CAPEFF_LACKS="$7" EXPECT_CAPAMB="$8" EXPECT_USERNS="$9" FOREIGN_TMPDIR="${10}" \
    unshare --mount --propagation private bash -c '
      mount --bind "$LANE/nextest" /repo/target/nextest
      mount --bind "$LANE/junit" /junit-out
      mount --bind "$ARTIFACTS" /artifacts
      exec setpriv --bounding-set "$CAPS" bash /repo/.github/scripts/root-lane.sh'
}
variant root 1 '' '' 0 0x2 0x4 0x0 '' ''
variant unshare 0 ,+sys_admin 'unshare -r ' 0 0x6 0x0 0x0 1 ''
variant dac-read-search 1 ,+dac_read_search '' 0 0x6 0x0 0x0 '' ''
variant foreign-tmpdir 1 '' '' 0 0x2 0x4 0x0 '' true
variant uid-1000 0 '' 'setpriv --reuid 1000 --regid 1000 --clear-groups --inh-caps +dac_override --ambient-caps +dac_override ' 1000 0x2 0x4 0x2 '' ''
```

## Tracer

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
bash .github/scripts/tracer-lane.sh "$target"
bash .github/scripts/tracer-lane.sh "$target" release
```

## Stray signal

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
bash .github/scripts/stray-signal-lane.sh "$target"
bash .github/scripts/stray-signal-lane.sh "$target" release
```
