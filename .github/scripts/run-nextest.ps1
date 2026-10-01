# Usage: run-nextest.ps1 <name> <command> [args...]
#
# The Windows counterpart of run-nextest.sh: runs a nextest command, then moves the `ci` profile's
# JUnit file to $env:RUNNER_TEMP/junit/<name>.xml. It is not bash because running the tests under
# Git bash changes what they observe (two ACL tests in `resolve_windows_tests` fail there).
# No param block: the command's own arguments (`-E`, `--profile`) must not be bound as parameters.
$ErrorActionPreference = 'Stop'

$name = $args[0]
$command = @($args[1..($args.Count - 1)])
$src = 'target/nextest/ci/junit.xml'
$dir = Join-Path $env:RUNNER_TEMP 'junit'

New-Item -ItemType Directory -Force $dir | Out-Null
if (Test-Path $src) { Remove-Item -Force $src }

& $command[0] @($command[1..($command.Count - 1)])
$status = $LASTEXITCODE

if (Test-Path $src) {
    Move-Item -Force $src (Join-Path $dir "$name.xml")
} elseif ($status -eq 0) {
    Write-Host "::error::nextest succeeded but wrote no JUnit file at $src"
    $status = 1
}
exit $status
