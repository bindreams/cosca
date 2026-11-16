# The ELEVATION group's Windows lane, start to finish: the same text runs on a CI runner and in a devvm guest.
#
# Usage: elevation-lane.ps1 <target triple>
# Run it from the checkout, in an elevated pwsh, on a machine that `unattended-gui-elevation.py` accepts as disposable
# (a hosted runner or a devvm guest). `RUNNER_TEMP` names where the lane keeps the archive and the JUnit file
# (`$env:RUNNER_TEMP\junit\elevation.xml`). The tests run as a fresh local administrator:
# `elevation-lane-windows.ps1` has the explanation.
#
# The machine is disposable, so the group consents inside `elevation-lane-windows.ps1`.
#
# Every exit that runs the `finally` undoes the lane in this order, each part even if the one before it failed:
#   1. the throwaway administrator (`elevation-lane-windows.ps1 -Cleanup`), which the run's own `finally` also removes.
#   2. the unattended elevation policy (`unattended-gui-elevation.py --revert`).
# A part that fails to restore fails the lane. Each is a no-op where its setup did not run.
$ErrorActionPreference = 'Stop'

$target = $args[0]
if (-not $target) { throw 'usage: elevation-lane.ps1 <target triple>' }
if (-not $env:RUNNER_TEMP) { throw 'RUNNER_TEMP names where the lane keeps its archive and JUnit file' }
$here = $PSScriptRoot
$disposable = '--this-machine-is-disposable'
$archive = Join-Path $env:RUNNER_TEMP 'elevation.tar.zst'

# `$ErrorActionPreference` does not cover native commands.
function Invoke-Native {
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command $Arguments ended with exit code $LASTEXITCODE" }
}

Invoke-Native python @("$here\unattended-gui-elevation.py", $disposable, '--check-only')

$status = 1
try {
    Invoke-Native python @("$here\unattended-gui-elevation.py", $disposable)
    Invoke-Native cargo @('nextest', 'archive', '--locked', '--features', 'tokio', '--target', $target, '--archive-file', $archive)

    # The JUnit file is published by `run-nextest.ps1`, from the profile named here.
    $env:NEXTEST_PROFILE = 'ci-elevation'
    # In a pwsh of its own, as a CI step runs it: it leaves its job's name in the environment.
    pwsh -NoProfile -File "$here\run-nextest.ps1" elevation pwsh -NoProfile -File "$here\elevation-lane-windows.ps1" $archive (Get-Command cargo-nextest).Source
    $status = $LASTEXITCODE
    if ($status -eq 0) {
        Invoke-Native python @("$here\check-junit.py", (Join-Path $env:RUNNER_TEMP 'junit\elevation.xml'), '--tests', '5')
    }
} catch {
    Write-Host "::error::$_"
    if ($status -eq 0) { $status = 1 }
} finally {
    foreach ($restore in @(
            @{ What = 'remove the throwaway administrator'; Body = { & "$here\elevation-lane-windows.ps1" -Cleanup } },
            @{ What = 'revert the unattended elevation policy'; Body = { Invoke-Native python @("$here\unattended-gui-elevation.py", $disposable, '--revert') } })) {
        try { & $restore.Body } catch {
            Write-Host "::error::restore failed: $($restore.What): $_"
            $status = 1
        }
    }
}
exit $status
