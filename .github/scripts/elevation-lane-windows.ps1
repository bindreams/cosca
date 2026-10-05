# Usage: elevation-lane-windows.ps1 <nextest archive> <cargo-nextest.exe>
#
# Runs the ELEVATION group's nextest run on a hosted Windows runner, as an UNELEVATED administrator. The CI
# step runs this script through run-nextest.ps1, which collects the JUnit file the run writes.
#
# The runner's own account is already elevated (a High integrity token), so `runas` would not raise
# an elevation and the tests would not exercise it. This script creates a local administrator, logs
# it on with Start-Process -Credential, and runs nextest there: that logon gets the filtered Medium
# integrity token with Administrators as deny-only, and `ShellExecuteEx(runas)` raises the elevation
# without a prompt because ConsentPromptBehaviorAdmin is 0 (`unattended-gui-elevation.py` sets it).
#
# The account cannot read the runner's profile, so it runs a copy of cargo-nextest and an extraction of the
# archive under C:\cosca-elevation-lane, and it writes its JUnit file into the workspace's `target\nextest\<profile>`.
# The script exits with nextest's exit code. It creates an account, so it refuses outside a hosted runner.
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'refusing: this creates a local administrator; it runs only on a GitHub-hosted runner (GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted)'
}

$archive = $args[0]
$nextestExe = $args[1]
foreach ($path in $archive, $nextestExe) {
    if (-not $path -or -not (Test-Path -LiteralPath $path)) {
        throw "usage: elevation-lane-windows.ps1 <nextest archive> <cargo-nextest.exe> (got '$path')"
    }
}
$workspace = (Get-Location).Path

$account = 'coscaelev'
$root = 'C:\cosca-elevation-lane'
$marker = Join-Path $root 'marker'
$work = Join-Path $root 'work'
$bin = Join-Path $root 'bin'
$extract = Join-Path $work 'extract'
$out = Join-Path $work 'out.txt'
$nextestProfile = $env:NEXTEST_PROFILE
if (-not $nextestProfile) { throw 'NEXTEST_PROFILE must name the profile whose JUnit file the caller publishes' }
$junitDir = Join-Path $workspace "target\nextest\$nextestProfile"

$password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
$password += 'aA1!'
Write-Host "::add-mask::$password"

# `$ErrorActionPreference` does not cover native commands: a failed ACL must fail the lane.
function Set-Acl-Native {
    icacls @args | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $args failed with exit code $LASTEXITCODE" }
}

New-Item -ItemType Directory -Force $marker, $work, $bin, $extract, $junitDir | Out-Null
Copy-Item -LiteralPath $archive -Destination (Join-Path $bin 'elevation.tar.zst')
Copy-Item -LiteralPath $nextestExe -Destination (Join-Path $bin 'cargo-nextest.exe')
# The marker directory is what the elevated child writes to and the unelevated test reads: only
# administrators may write it, everyone may read it.
Set-Acl-Native $marker /inheritance:r
Set-Acl-Native $marker /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
Set-Acl-Native $bin /grant '*S-1-5-32-545:(OI)(CI)RX'

New-LocalUser $account -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires | Out-Null
try {
    Add-LocalGroupMember -Group 'Administrators' -Member $account
    Set-Acl-Native $work /grant "${account}:(OI)(CI)M"
    Set-Acl-Native $junitDir /grant "${account}:(OI)(CI)M"

    $script = Join-Path $work 'run.cmd'
    @(
        'set COSCA_TEST_ELEVATION=1',
        'set COSCA_TEST_ELEVATION_CONSENT=1',
        'set COSCA_TEST_ELEVATION_EXPECT_KILL=ok',
        "set COSCA_TEST_ELEVATION_MARKER_DIR=$marker",
        'set SKULD_LABELS=elevation',
        "set NEXTEST_PROFILE=$nextestProfile",
        "`"$(Join-Path $bin 'cargo-nextest.exe')`" nextest run --archive-file `"$(Join-Path $bin 'elevation.tar.zst')`" --extract-to `"$extract`" --workspace-remap `"$workspace`" --no-tests=fail -E `"binary(=elevation)`" > `"$out`" 2>&1"
    ) | Set-Content -Path $script -Encoding ascii

    $credential = New-Object System.Management.Automation.PSCredential(
        "$env:COMPUTERNAME\$account", (ConvertTo-SecureString $password -AsPlainText -Force))
    $process = Start-Process cmd.exe -ArgumentList '/c', $script -Credential $credential `
        -LoadUserProfile -WorkingDirectory $work -Wait -PassThru
    $exitCode = $process.ExitCode
} finally {
    # Stop on a failed removal: the step fails, and no exit path leaves the account behind unnoticed.
    Remove-LocalUser $account -ErrorAction Stop
    if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { throw "the account $account is still there after its removal" }
}

Get-Content -LiteralPath $out
Write-Host "nextest exit code: $exitCode"
exit $exitCode
