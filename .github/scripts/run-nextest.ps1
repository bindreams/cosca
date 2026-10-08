# Usage: run-nextest.ps1 <name> <command> [args...]
#
# The Windows counterpart of run-nextest.py: runs a nextest command, then moves the JUnit file of
# the profile in $env:NEXTEST_PROFILE (the shared `ci` when unset) to $env:RUNNER_TEMP/junit/<name>.xml. It is not bash because Git bash's MSYS runtime
# enables SeBackupPrivilege and SeRestorePrivilege in its token, and the tests inherit it (measured:
# `whoami /priv` shows them Disabled under pwsh, Enabled under bash). An enabled backup privilege
# bypasses a DACL deny, so the two ACL tests in `resolve_windows_tests` fail their precondition
# there (#495). Re-launching pwsh from bash does not help: the token is inherited.
# Unlike run-nextest.py it defaults to the shared `ci` profile and has no signal forwarding: after a failed
# or timed-out step every later step is skipped (they carry no `if:`), so a process that outlives its
# step cannot affect a published result. A killed script publishes nothing.
# No param block: the command's own arguments (`-E`, `--target`) must not be bound as parameters.
$ErrorActionPreference = 'Stop'
# A step may select its own profile (the elevation step does); the default is the shared `ci`.
if (-not $env:NEXTEST_PROFILE) { $env:NEXTEST_PROFILE = 'ci' }

$name = $args[0]
$command = @($args[1..($args.Count - 1)])
$src = "target/nextest/$($env:NEXTEST_PROFILE)/junit.xml"
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
