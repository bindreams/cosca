# Cosca's sandbox lanes in a devvm guest

Two guests run the lanes that change a machine: Ubuntu 24.04 ([`cosca-linux.devvm.yaml`](cosca-linux.devvm.yaml)) and
Windows ([`cosca-windows.devvm.yaml`](cosca-windows.devvm.yaml)). Each has the toolchain of `.github/ci-toolchain`,
`cargo-nextest`, and the git-tracked tree at `~/cosca`. Each lane below runs the CI lane's scripts from
`.github/scripts/`, the scripts CI's steps call. It does not reproduce CI's runner or kernel: the Linux guest's
kernel is 6.8, and `lane-env.sh` turns off the groups that need a newer one and says which. The Windows lanes are
under [Windows](#windows).

Every Linux lane runs as the guest's `user`, which may `sudo` without a password; the lanes that need root call
`sudo` themselves. A guest is disposable: the elevation and setuid lanes change it.

Lanes in one guest run one at a time; for lanes at once, start one instance per lane (`--name cosca-lane-<n>`).

## Run a Linux lane

```sh
devvm up devvm/cosca-linux.devvm.yaml --name cosca-lane        # once: about 5 minutes cold
devvm ssh cosca-lane -- bash -c "$(cat lane.sh)"               # lane.sh holds one block below
```

Git Bash on Windows rewrites any argument of `devvm` that starts with `/` or holds `=/` into a Windows path: set
`MSYS_NO_PATHCONV=1` for such a command.

After an edit to a tracked file, rerun from a fresh instance: `devvm rm cosca-lane`, then `devvm up` again. Only the
last step (`copy`) runs again, about 45 seconds; the layers above it are reused. `devvm rm cosca-lane` when done.

Each block sources `lane-env.sh`: the groups that are off by default (`.github/test-group-defaults.env`) are off, and
the lane's script turns on its own with their `_CONSENT` variable. All tests of the lane pass. Skipped are the tests
the lane does not select (its labels and filterset), ignored tests, and those of the groups `lane-env.sh` printed as off.

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
python3 .github/scripts/run-nextest.py setuid-root bash .github/scripts/setuid-root-lane.sh "$(command -v cargo-nextest)" "$RUNNER_TEMP/setuid-root.tar.zst" "$RUNNER_TEMP/setuid-root-extract" "$helper"
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
  sudo --preserve-env="$COSCA_LANE_FLOOR_VARS" env \
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

## Windows

The guest is Windows 11 built from your own ISO, with the MSVC linker and Windows SDK (Visual Studio 2022 Build Tools),
the toolchain, `cargo-nextest`, Git Bash and Python (the lane scripts call `bash` and `python3`), and the tree at
`~/cosca`. The ISO is not in the repository: `devvm/windows-iso.local.devvm.yaml`, untracked and per checkout, names it.

```yaml
from:
  iso: C:/path/to/windows.iso
  edition: Windows 11 IoT Enterprise LTSC 2024 # only if the ISO holds several images
  product-key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX # only for a non-evaluation edition
```

Devvm's README ("Windows ISOs") says which key to use. `devvm up` without the file fails naming its path.

```sh
devvm up devvm/cosca-windows.devvm.yaml --name cosca-win-lane      # cold: about 20 minutes; with the layers cached, 2
devvm ssh --elevated cosca-win-lane -- pwsh -NoProfile -Command "$(cat lane.ps1)"   # lane.ps1 holds one block below
```

Every Windows lane runs elevated, as CI's runner does. The elevation lane's tests run as a second local administrator
that its script creates and removes, so they see an unelevated token. A lane changes the guest; `devvm rm` it when done.
A rerun after an edit to a tracked file needs a fresh instance, as on Linux (`devvm rm`, then `devvm up`; about 2
minutes). One instance runs one lane at a time.

Each block applies `.github/test-group-defaults.env` through `devvm/lane-env.ps1`; the lane's script turns on its own
group.

| Lane (CI group)                                       | Consent variables set by     | JUnit count |
| ----------------------------------------------------- | ---------------------------- | ----------- |
| elevation                                             | `elevation-lane-windows.ps1` | 5           |
| canaries (`PATH_PROBES`, `SHELL_EXECUTE`)             | `windows-canary-lane.ps1`    | 26 and 3    |
| drive mapping (`DRIVE_MAPPING`)                       | `drive-mapping-lane.ps1`     |             |
| executing probes (`SHELL_PROBES`, `ELEVATION_ROUTES`) | `shell-probes-lane.sh`       |             |

### Windows: elevation

```powershell
$ErrorActionPreference = 'Stop'
Set-Location ~/cosca
. ./devvm/lane-env.ps1
$env:RUNNER_TEMP = (New-Item -ItemType Directory (Join-Path $env:TEMP "lane-$([guid]::NewGuid())")).FullName
./.github/scripts/elevation-lane.ps1 x86_64-pc-windows-msvc
exit $LASTEXITCODE
```

### Windows: canaries

Each run is a `pwsh` of its own, as a CI step is.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location ~/cosca
. ./devvm/lane-env.ps1
$target = 'x86_64-pc-windows-msvc'
$env:RUNNER_TEMP = (New-Item -ItemType Directory (Join-Path $env:TEMP "lane-$([guid]::NewGuid())")).FullName
$env:COSCA_CANARY_MARKERS = "$env:RUNNER_TEMP/canary-markers"
$env:NEXTEST_PROFILE = 'ci-canary'
pwsh -NoProfile -File ./.github/scripts/run-nextest.ps1 canary-path pwsh -NoProfile -File ./.github/scripts/windows-canary-lane.ps1 path $target
if ($LASTEXITCODE) { exit $LASTEXITCODE }
python3 .github/scripts/check-junit.py "$env:RUNNER_TEMP/junit/canary-path.xml" --tests 26
if ($LASTEXITCODE) { exit $LASTEXITCODE }
$env:COSCA_CANARY_MARKERS = "$env:RUNNER_TEMP/elevating-markers"
$env:NEXTEST_PROFILE = 'ci-shell-execute'
pwsh -NoProfile -File ./.github/scripts/run-nextest.ps1 canary-shell-execute pwsh -NoProfile -File ./.github/scripts/windows-canary-lane.ps1 shell-execute $target
if ($LASTEXITCODE) { exit $LASTEXITCODE }
python3 .github/scripts/check-junit.py "$env:RUNNER_TEMP/junit/canary-shell-execute.xml" --tests 3
exit $LASTEXITCODE
```

### Windows: drive mapping

```powershell
$ErrorActionPreference = 'Stop'
Set-Location ~/cosca
. ./devvm/lane-env.ps1
$target = 'x86_64-pc-windows-msvc'
$env:RUNNER_TEMP = (New-Item -ItemType Directory (Join-Path $env:TEMP "lane-$([guid]::NewGuid())")).FullName
pwsh -NoProfile -File ./.github/scripts/run-nextest.ps1 drive-mapping pwsh -NoProfile -File ./.github/scripts/drive-mapping-lane.ps1 $target
exit $LASTEXITCODE
```

### Windows: executing probes

The main run, the three isolated probes each in a run of its own (after the first), and the check that a probe left a
marker, as `windows-probes.yaml` runs them.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location ~/cosca
. ./devvm/lane-env.ps1
$target = 'x86_64-pc-windows-msvc'
$env:RUNNER_TEMP = (New-Item -ItemType Directory (Join-Path $env:TEMP "lane-$([guid]::NewGuid())")).FullName
$env:COSCA_PROBE_MARKERS = "$env:RUNNER_TEMP/probe-markers"
foreach ($isolated in '', 'isolated_trailing_dot', 'isolated_pathext_precedence', 'isolated_existing_extensionless') {
    bash .github/scripts/shell-probes-lane.sh $target $isolated
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}
bash .github/scripts/shell-probes-check.sh
exit $LASTEXITCODE
```
