# Runs one of the Windows canary groups: the path-resolution canaries (`windows_path_resolution`, the `PATH_PROBES`
# group) or the elevating ShellExecuteEx probes (`windows_shell_execute`, the `SHELL_EXECUTE` group).
#
# Usage: windows-canary-lane.ps1 <path|shell-execute> <target>
# Run it from the checkout, on a machine that is a sandbox (a CI runner, a devvm guest): the group consents here.
# `COSCA_CANARY_MARKERS` names the directory each canary that passes leaves a marker in. `FILTER`, when set, is a
# test-name filter. CI runs it under `run-nextest.ps1 canary-path` and `canary-shell-execute`, with
# `NEXTEST_PROFILE` set to `ci-canary` and `ci-shell-execute`.
#
# `--no-capture`: the surveys report only through stdout, and every canary prints what it measured before asserting on
# it. `shell-execute` ELEVATES and writes one volatile App Paths key in HKLM and one in HKCU, deleting each again; a
# volatile parent key it had to create can stay behind until the next logon session. These measure an ELEVATED
# caller's launch, not the consent route cosca takes from an unelevated one. They share machine-wide state and must not
# run concurrently; `--no-capture` and the `windows-shell-execute` test group (one thread, `.config/nextest.toml`) both
# guarantee that.
$ErrorActionPreference = 'Stop'

$kind = $args[0]
$target = $args[1]
switch ($kind) {
    'path' { $group = 'PATH_PROBES'; $labels = 'path_probes'; $test = 'windows_path_resolution' }
    'shell-execute' { $group = 'SHELL_EXECUTE'; $labels = 'shell_execute'; $test = 'windows_shell_execute' }
    default { throw 'usage: windows-canary-lane.ps1 <path|shell-execute> <target>' }
}
if (-not $target) { throw 'usage: windows-canary-lane.ps1 <path|shell-execute> <target>' }
if (-not $env:COSCA_CANARY_MARKERS) { throw 'COSCA_CANARY_MARKERS names where each canary that passes leaves a marker' }

Set-Item "Env:COSCA_TEST_$group" '1'
Set-Item "Env:COSCA_TEST_${group}_CONSENT" '1'
$env:SKULD_LABELS = $labels
New-Item -ItemType Directory -Force $env:COSCA_CANARY_MARKERS | Out-Null
$filter = @(if ($env:FILTER) { $env:FILTER })
cargo nextest run --locked --target $target --test $test --no-capture --no-tests=fail @filter
exit $LASTEXITCODE
