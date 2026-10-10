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
#
# Everything it creates it removes, on failure too: the account (which must not exist beforehand, and is recorded in
# `$root\account` before it is created, so only that account is deleted), its profile, the ACE it was given on the
# JUnit directory, and `$root`.
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
$tmp = Join-Path $work 'tmp'
$accountRecord = Join-Path $root 'account'
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

New-Item -ItemType Directory -Force $marker, $work, $tmp, $bin, $extract, $junitDir | Out-Null
Copy-Item -LiteralPath $archive -Destination (Join-Path $bin 'elevation.tar.zst')
Copy-Item -LiteralPath $nextestExe -Destination (Join-Path $bin 'cargo-nextest.exe')
# The marker directory is what the elevated child writes to and the unelevated test reads: only
# administrators may write it, everyone may read it.
Set-Acl-Native $marker /inheritance:r
Set-Acl-Native $marker /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
Set-Acl-Native $bin /grant '*S-1-5-32-545:(OI)(CI)RX'

# The record first, then the account: a record without an account is fine for the cleanup, an account without one
# would be left behind. An account that exists already is not ours to adopt or delete.
if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { throw "the account $account already exists; refusing to adopt it" }
Set-Content -LiteralPath $accountRecord -Value $account -Encoding ascii
New-LocalUser $account -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires | Out-Null
try {
    Add-LocalGroupMember -Group 'Administrators' -Member $account
    Set-Acl-Native $work /grant "${account}:(OI)(CI)M"
    Set-Acl-Native $junitDir /grant "${account}:(OI)(CI)M"

    $script = Join-Path $work 'run.cmd'
    @(
        "set TEMP=$tmp",
        "set TMP=$tmp",
        'set COSCA_TEST_ELEVATION=1',
        'set COSCA_TEST_ELEVATION_CONSENT=1',
        'set COSCA_TEST_ELEVATION_EXPECT_KILL=ok',
        "set COSCA_TEST_ELEVATION_MARKER_DIR=$marker",
        'set SKULD_LABELS=elevation',
        "set NEXTEST_PROFILE=$nextestProfile",
        "`"$(Join-Path $bin 'cargo-nextest.exe')`" nextest run --archive-file `"$(Join-Path $bin 'elevation.tar.zst')`" --extract-to `"$extract`" --workspace-remap `"$workspace`" --no-tests=fail -E `"binary(=elevation)`" > `"$out`" 2>&1"
    ) | Set-Content -Path $script -Encoding ascii

    # The logon happens in a pwsh of its own, which is gone when the run is over: nothing of this script then holds
    # the logon session, and the account's profile hive can unload.
    $launcher = {
        param($account, $script, $work)
        $credential = New-Object System.Management.Automation.PSCredential(
            "$env:COMPUTERNAME\$account", (ConvertTo-SecureString $env:COSCA_LANE_PASSWORD -AsPlainText -Force))
        $process = Start-Process cmd.exe -ArgumentList '/c', $script -Credential $credential `
            -WorkingDirectory $work -Wait -PassThru
        exit $process.ExitCode
    }
    $env:COSCA_LANE_PASSWORD = $password
    try {
        & pwsh -NoProfile -NonInteractive -Command $launcher -args $account, $script, $work
        $exitCode = $LASTEXITCODE
    } finally {
        Remove-Item Env:COSCA_LANE_PASSWORD
    }
} finally {
    # Print what the run said before its directory goes. Each step below stops on failure: the step fails, and no
    # exit path leaves anything behind unnoticed.
    if (Test-Path -LiteralPath $out) { Get-Content -LiteralPath $out }
    if ((Test-Path -LiteralPath $accountRecord) -and ((Get-Content -LiteralPath $accountRecord -Raw).Trim() -eq $account)) {
        $existing = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
        if ($existing) {
            $sid = $existing.SID.Value
            # The ACE on the published JUnit directory names the account; without it the SID would dangle there.
            Set-Acl-Native $junitDir /remove "${account}"
            Remove-LocalUser $account -ErrorAction Stop
            # Nothing of the account may be running when its profile goes: stop what is left of its processes.
            foreach ($candidate in Get-CimInstance Win32_Process) {
                $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($owner -and $owner.User -eq $account) { Stop-Process -Id $candidate.ProcessId -Force -ErrorAction SilentlyContinue }
            }
            # Best effort: the registry hive of the logon stays loaded for minutes after everything of the run has
            # exited (measured on both hosted runners; no process of the account is left, and waiting does not
            # end it within the step's bound), and a loaded profile cannot be removed. The runner is an ephemeral VM.
            try {
                Get-CimInstance Win32_UserProfile -Filter "SID = '$sid'" | Remove-CimInstance -ErrorAction Stop
            } catch {
                Write-Host "::warning::the profile of $account is still loaded and was left behind: $_"
            }
        }
        if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { throw "the account $account is still there after its removal" }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}

Write-Host "nextest exit code: $exitCode"
exit $exitCode
