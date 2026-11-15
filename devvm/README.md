# Cosca's Linux lanes in a devvm guest

The guest is Ubuntu 24.04 with the toolchain of `.github/ci-toolchain`, `cargo-nextest`, and the git-tracked tree at
`~/cosca` ([`cosca-linux.devvm.yaml`](cosca-linux.devvm.yaml)). Each lane below runs the CI lane's scripts from
`.github/scripts/`, so a lane that passes here runs the text CI runs. It does not reproduce CI's runner or kernel: the
guest's is 6.8, and `lane-env.sh` turns off the groups that need a newer one and says which.

Every lane runs as the guest's `user`, which may `sudo` without a password; the lanes that need root call `sudo`
themselves. Nothing runs on the host. The guest is disposable: the elevation and setuid lanes change it.

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
the block turns on its own with their `_CONSENT` variable. The lane's scripts set the ones they need themselves.

| Lane (CI group)                           | Consent variables set by         | Passes with                                  |
| ----------------------------------------- | -------------------------------- | -------------------------------------------- |
| elevation                                 | `elevation-lane.sh`: `ELEVATION` | 9 tests run: 9 passed                        |
| cgroup (`CGROUP`, `NAMESPACES`, `TRACER`) | `cgroup-lane.sh`                 | 482 tests run: 482 passed, 10 skipped        |
| setuid                                    | the block: `SETUID`              | 40 tests run: 40 passed, 1 skipped           |
| cgroup and setuid                         | the block: `CGROUP`, `SETUID`    | 1 test run: 1 passed                         |
| setuid-root                               | the block: `SETUID`              | 1 test run: 1 passed                         |
| root, uid switch (five variants)          | the block: `ROOT`, `UID_SWITCH`  | 69, 68, 69, 69, 68 passed                    |
| tracer (debug, release)                   | the block: `TRACER`              | 19 passed, 2 skipped (both)                  |
| stray signal (debug, release)             | the block: `STRAY_SIGNAL`        | 42 passed, 10 skipped; 41 passed, 10 skipped |

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
cargo nextest archive --locked --features pty,tokio --target "$target" --archive-file "$RUNNER_TEMP/cgroup.tar.zst"
python3 .github/scripts/run-nextest.py cgroup sudo --preserve-env=COSCA_TEST_PIDFD_GROUP_SIGNAL,COSCA_TEST_PIDFD_GET_INFO "$(command -v python3)" .github/scripts/forward.py bash -ux .github/scripts/cgroup-lane.sh "$(command -v cargo-nextest)" "$RUNNER_TEMP/cgroup.tar.zst" "$(id -u):$(id -g)"
```

## Setuid

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
export RUNNER_TEMP="$(mktemp -d)"
helper="$RUNNER_TEMP/cosca_testbin_setuid"
trap 'sudo rm -f -- "$helper"' EXIT
bash .github/scripts/setuid-helper.sh "$target" "$helper"
bash .github/scripts/setuid-lane-check.sh "$helper"
cargo nextest run --locked --no-run --features tokio --target "$target" --profile ci -E 'binary(cosca) | binary(group_teardown_setuid)'
COSCA_TEST_SETUID=1 COSCA_TEST_SETUID_CONSENT=1 COSCA_TESTCFG_SETUID_HELPER="$helper" SKULD_LABELS=setuid \
  python3 .github/scripts/run-nextest.py setuid cargo nextest run --locked --no-tests=fail --features tokio --target "$target" -E 'binary(cosca) | binary(group_teardown_setuid)'
```

## Cgroup and setuid

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
export RUNNER_TEMP="$(mktemp -d)"
helper="$RUNNER_TEMP/cosca_testbin_setuid"
trap 'sudo rm -f -- "$helper"' EXIT
bash .github/scripts/setuid-helper.sh "$target" "$helper"
bash .github/scripts/setuid-lane-check.sh "$helper"
cargo nextest archive --locked --features pty,tokio --target "$target" --archive-file "$RUNNER_TEMP/cgroup.tar.zst"
COSCA_TEST_CGROUP=1 COSCA_TEST_CGROUP_CONSENT=1 COSCA_TEST_SETUID=1 COSCA_TEST_SETUID_CONSENT=1 COSCA_TESTCFG_SETUID_HELPER="$helper" SKULD_LABELS='cgroup & setuid' \
  python3 .github/scripts/run-nextest.py cgroup-setuid bash -ux .github/scripts/cgroup-setuid-lane.sh "$(command -v cargo-nextest)" "$RUNNER_TEMP/cgroup.tar.zst"
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
  sudo rm -f -- "$helper" || status=1
  bash .github/scripts/dir-modes.sh restore "$RUNNER_TEMP/dir-modes" || status=1
  exit "$status"
}
trap restore EXIT
bash .github/scripts/setuid-helper.sh "$target" "$helper"
bash .github/scripts/setuid-lane-check.sh "$helper"
bash .github/scripts/setuid-root-archive.sh "$target"
COSCA_TEST_SETUID=1 COSCA_TEST_SETUID_CONSENT=1 COSCA_TESTCFG_SETUID_HELPER="$helper" SKULD_LABELS=setuid_root \
  python3 .github/scripts/run-nextest.py setuid-root sudo --preserve-env=COSCA_TEST_SETUID,COSCA_TEST_SETUID_CONSENT,COSCA_TESTCFG_SETUID_HELPER,SKULD_LABELS,COSCA_TEST_PIDFD_GROUP_SIGNAL,COSCA_TEST_PIDFD_GET_INFO "$(command -v python3)" .github/scripts/forward.py bash -eux .github/scripts/setuid-root-lane.sh "$(command -v cargo-nextest)" "$RUNNER_TEMP/setuid-root.tar.zst" "$RUNNER_TEMP/setuid-root-extract"
```

## Root and uid switch

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
export RUNNER_TEMP="$(mktemp -d)"
export COSCA_TEST_TRACER=1 COSCA_TEST_TRACER_CONSENT=1 SKULD_LABELS=tracer
python3 .github/scripts/run-nextest.py tracer cargo nextest run --locked --no-tests=fail --features tokio --target "$target" -E 'binary(cosca)'
python3 .github/scripts/run-nextest.py tracer-release cargo nextest run --locked --no-tests=fail --release --lib --features tokio --target "$target"
```

## Stray signal

```bash
set -euo pipefail
cd ~/cosca
. devvm/lane-env.sh
target=x86_64-unknown-linux-gnu
export RUNNER_TEMP="$(mktemp -d)"
export COSCA_TEST_STRAY_SIGNAL=1 COSCA_TEST_STRAY_SIGNAL_CONSENT=1 SKULD_LABELS=stray_signal
python3 .github/scripts/run-nextest.py stray-signal cargo nextest run --locked --no-tests=fail --features tokio --target "$target" -E 'binary(cosca) | binary(=process)'
python3 .github/scripts/run-nextest.py stray-signal-release cargo nextest run --locked --no-tests=fail --release --lib --features tokio --target "$target"
```
