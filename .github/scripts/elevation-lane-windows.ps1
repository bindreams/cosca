# Usage: elevation-lane-windows.ps1 <nextest archive> <cargo-nextest.exe>
#        elevation-lane-windows.ps1 -Cleanup
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
# Everything it creates it removes, on failure too: the account, its profile, the ACE it was given on the JUnit
# directory, and `$root`. `$root\account` records the account as "pending" before `New-LocalUser` and as "created" after
# it, so only an account this script made is deleted; `New-LocalUser` itself fails if the account exists.
#
# `-Cleanup` does the whole teardown from that record, for a step that runs after this script was killed (a step
# timeout ends it without running its `finally`). The `finally` runs the same code.
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'refusing: this creates a local administrator; it runs only on a GitHub-hosted runner (GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted)'
}

$account = 'coscaelev'
$root = 'C:\cosca-elevation-lane'
$accountRecord = Join-Path $root 'account'
$out = Join-Path $root 'work\out.txt'

# `$ErrorActionPreference` does not cover native commands: a failed ACL must fail the lane.
function Set-Acl-Native {
    icacls @args | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $args failed with exit code $LASTEXITCODE" }
}

function Write-AccountRecord {
    param([string]$State, [string]$Nonce, [string]$JunitDir, [string]$Sid = '')
    $record = [ordered]@{ account = $account; state = $State; nonce = $Nonce; junitDir = $JunitDir; sid = $Sid }
    Set-Content -LiteralPath $accountRecord -Value (ConvertTo-Json -InputObject $record) -Encoding ascii
}

# Each cleanup step runs whatever the others did; its failure is added to `$Failures`, and they are reported together.
function Invoke-CleanupStep {
    param([System.Collections.Generic.List[string]]$Failures, [string]$What, [scriptblock]$Body)
    try { & $Body } catch {
        $Failures.Add("${What}: $_")
        Write-Host "::error::cleanup step failed: ${What}: $_"
    }
}

# The processes owned by the account with this SID. The account must still exist: the owner of a process is looked up
# by SID, which stops resolving to a name once the account is gone.
function Get-AccountProcess {
    param([string]$Sid)
    foreach ($candidate in Get-CimInstance Win32_Process) {
        try {
            $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid -ErrorAction Stop
        } catch {
            if (Get-Process -Id $candidate.ProcessId -ErrorAction SilentlyContinue) {
                Write-Host "::warning::could not read the owner of process $($candidate.ProcessId) ($($candidate.Name)): $_"
            }
            continue
        }
        if ($owner.ReturnValue -eq 0 -and $owner.Sid -eq $Sid) { $candidate }
    }
}

# Stops the account's processes, and looks again until a listing finds none that were not stopped already: a process
# can start another between two listings. A process that cannot be stopped is reported once, and not retried.
function Stop-AccountProcess {
    param([string]$Sid)
    $seen = @{}
    $unstoppable = @()
    while ($true) {
        $found = @(Get-AccountProcess $Sid | Where-Object { -not $seen.ContainsKey("$($_.ProcessId)/$($_.CreationDate.Ticks)") })
        if ($found.Count -eq 0) { break }
        foreach ($candidate in $found) {
            $seen["$($candidate.ProcessId)/$($candidate.CreationDate.Ticks)"] = $true
            $process = Get-Process -Id $candidate.ProcessId -ErrorAction SilentlyContinue
            if (-not $process) { continue }
            try {
                $process.Kill($true)
                $process.WaitForExit()
            } catch {
                if (-not $process.HasExited) { $unstoppable += "$($candidate.ProcessId) ($($candidate.Name)): $_" }
            }
        }
    }
    if ($unstoppable.Count -gt 0) { throw "could not stop: $($unstoppable -join '; ')" }
}

# The whole teardown, from the record. `$Created` says that this script created `$root` itself (the in-script `finally`);
# the `-Cleanup` mode has only the record to go by. Returns the failures.
function Invoke-LaneCleanup {
    param([bool]$Created)
    $failures = [System.Collections.Generic.List[string]]::new()
    Invoke-CleanupStep $failures 'print the run output' {
        if (Test-Path -LiteralPath $out) { Get-Content -LiteralPath $out | ForEach-Object { Write-Host $_ } }
    }
    $record = $null
    if (Test-Path -LiteralPath $accountRecord) {
        try { $record = Get-Content -LiteralPath $accountRecord -Raw | ConvertFrom-Json } catch {
            $failures.Add("read the account record: $_")
            Write-Host "::error::cleanup step failed: read the account record: $_"
        }
    }
    $existing = $null
    if ($record -and $record.account -eq $account) {
        $existing = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
        # "pending": `New-LocalUser` may have succeeded just before the record could say so. The description is the
        # nonce of this run, and `New-LocalUser` fails on an existing account, so a match means this script made it.
        if ($existing -and $record.state -ne 'created' -and $existing.Description -ne $record.nonce) { $existing = $null }
    }
    if ($existing) {
        $sid = $existing.SID.Value
        # Nothing of the account may be running when it is deleted: a process holds files, and keeps the profile and
        # `$root` from going.
        Invoke-CleanupStep $failures 'stop the account processes' { Stop-AccountProcess $sid }
        # The ACE on the published JUnit directory names the account; remove it while the name still resolves.
        Invoke-CleanupStep $failures 'remove the account from the JUnit directory ACL' {
            Set-Acl-Native $record.junitDir /remove "${account}"
        }
        Invoke-CleanupStep $failures 'delete the account' { Remove-LocalUser $account -ErrorAction Stop }
        # Best effort: the logon's registry hive stays loaded for minutes after the run (measured on hosted runners),
        # and a loaded profile cannot be removed. The runner is an ephemeral VM.
        try {
            Get-CimInstance Win32_UserProfile -Filter "SID = '$sid'" | Remove-CimInstance -ErrorAction Stop
        } catch {
            Write-Host "::warning::the profile of $account is still loaded and was left behind: $_"
        }
        Invoke-CleanupStep $failures 'confirm the account is gone' {
            if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { throw "the account $account is still there after its removal" }
        }
    }
    if ($Created -or $record) {
        if (Test-Path -LiteralPath $root) {
            Invoke-CleanupStep $failures "remove $root" { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        }
    } elseif (Test-Path -LiteralPath $root) {
        $failures.Add("$root exists with no record of this script, so it was left alone")
    }
    return , $failures
}

if ($args[0] -eq '-Cleanup') {
    $failures = Invoke-LaneCleanup $false
    if ($failures.Count -gt 0) { throw "cleanup failed: $($failures -join '; ')" }
    Write-Host 'the elevation lane left nothing behind'
    return
}

$archive = $args[0]
$nextestExe = $args[1]
foreach ($path in $archive, $nextestExe) {
    if (-not $path -or -not (Test-Path -LiteralPath $path)) {
        throw "usage: elevation-lane-windows.ps1 <nextest archive> <cargo-nextest.exe> (got '$path')"
    }
}
$workspace = (Get-Location).Path

$marker = Join-Path $root 'marker'
$work = Join-Path $root 'work'
$bin = Join-Path $root 'bin'
$extract = Join-Path $work 'extract'
$tmp = Join-Path $work 'tmp'
$nextestProfile = $env:NEXTEST_PROFILE
if (-not $nextestProfile) { throw 'NEXTEST_PROFILE must name the profile whose JUnit file the caller publishes' }
$junitDir = Join-Path $workspace "target\nextest\$nextestProfile"

$password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
$password += 'aA1!'
Write-Host "::add-mask::$password"

# Nothing is adopted: a directory that exists already is not ours to fill, or to delete. An existing account is refused
# by `New-LocalUser` below.
if (Test-Path -LiteralPath $root) { throw "$root already exists; refusing to adopt it" }

$rootCreated = $false
$laneError = $null
$exitCode = $null
try {
    New-Item -ItemType Directory $root | Out-Null
    $rootCreated = $true
    New-Item -ItemType Directory -Force $marker, $work, $tmp, $bin, $extract, $junitDir | Out-Null
    Copy-Item -LiteralPath $archive -Destination (Join-Path $bin 'elevation.tar.zst')
    Copy-Item -LiteralPath $nextestExe -Destination (Join-Path $bin 'cargo-nextest.exe')
    # The marker directory is what the elevated child writes to and the unelevated test reads: only
    # administrators may write it, everyone may read it.
    Set-Acl-Native $marker /inheritance:r
    Set-Acl-Native $marker /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
    Set-Acl-Native $bin /grant '*S-1-5-32-545:(OI)(CI)RX'

    # "pending" before the account exists and "created" after: the cleanup deletes an account only if the record says it
    # made it, and `New-LocalUser` fails when the account is already there.
    $nonce = [guid]::NewGuid().ToString()
    Write-AccountRecord 'pending' $nonce $junitDir
    $user = New-LocalUser $account -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires -Description $nonce
    Write-AccountRecord 'created' $nonce $junitDir $user.SID.Value
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

    # The logon happens in a pwsh of its own, so this script holds no logon session once the run is over.
    $launcher = {
        param($account, $script, $work)
        $credential = New-Object System.Management.Automation.PSCredential(
            "$env:COMPUTERNAME\$account", (ConvertTo-SecureString $env:COSCA_LANE_PASSWORD -AsPlainText -Force))
        # The run inherits this environment; the password must not reach it, and the tests dump whole blocks, values included, to files.
        Remove-Item Env:COSCA_LANE_PASSWORD
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
} catch {
    $laneError = $_
} finally {
    $failures = Invoke-LaneCleanup $rootCreated
}

# The lane's own error is not replaced by the cleanup's: both are reported.
if ($laneError -and $failures.Count -gt 0) {
    throw "the lane failed: $laneError`; and the cleanup failed: $($failures -join '; ')"
}
if ($laneError) { throw $laneError }
if ($failures.Count -gt 0) { throw "cleanup failed: $($failures -join '; ')" }

Write-Host "nextest exit code: $exitCode"
exit $exitCode
