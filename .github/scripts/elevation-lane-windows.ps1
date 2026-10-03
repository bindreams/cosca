# Usage: elevation-lane-windows.ps1 <path to the elevation test executable>
#
# Runs the ELEVATION group on a throwaway Windows CI runner, as an UNELEVATED administrator.
#
# The runner's own account is already elevated (a High integrity token), so `runas` would not raise
# an elevation and the tests would not exercise it. This script creates a local administrator, logs
# it on with Start-Process -Credential, and runs the tests there: that logon gets the filtered Medium
# integrity token with Administrators as deny-only, and `ShellExecuteEx(runas)` raises the elevation
# without a prompt because the runner's ConsentPromptBehaviorAdmin is 0 ("elevate without prompting").
#
# The tests run the executable directly (nextest cannot be run by that account: the runner's cargo
# home is not readable by it), with `--format json`. The script then checks the run the way the
# nextest lanes are checked: every started suite ended, tests ran, all of them passed, none ignored.
$ErrorActionPreference = 'Stop'

$testExe = $args[0]
if (-not $testExe -or -not (Test-Path -LiteralPath $testExe)) {
    throw "usage: elevation-lane-windows.ps1 <path to the elevation test executable> (got '$testExe')"
}
$testExe = (Resolve-Path -LiteralPath $testExe).Path

$account = 'coscaelev'
$root = 'C:\cosca-elevation-lane'
$marker = Join-Path $root 'marker'
$work = Join-Path $root 'work'
$out = Join-Path $work 'out.txt'

$password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
$password += 'aA1!'
Write-Host "::add-mask::$password"

New-Item -ItemType Directory -Force $marker, $work | Out-Null
# The marker directory is what the elevated child writes to and the unelevated test reads: only
# administrators may write it, everyone may read it.
icacls $marker /inheritance:r | Out-Null
icacls $marker /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
icacls $work /grant "${account}:(OI)(CI)M" | Out-Null

New-LocalUser $account -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires | Out-Null
try {
    Add-LocalGroupMember -Group 'Administrators' -Member $account
    icacls $work /grant "${account}:(OI)(CI)M" | Out-Null

    $script = Join-Path $work 'run.cmd'
    @(
        'set COSCA_TEST_ELEVATION=1',
        'set COSCA_TEST_ELEVATION_CONSENT=1',
        "set COSCA_TEST_ELEVATION_MARKER_DIR=$marker",
        "set SKULD_DB_DIR=$work",
        'set SKULD_LABELS=elevation',
        "`"$testExe`" --nocapture --format json > `"$out`" 2>&1"
    ) | Set-Content -Path $script -Encoding ascii

    $credential = New-Object System.Management.Automation.PSCredential(
        "$env:COMPUTERNAME\$account", (ConvertTo-SecureString $password -AsPlainText -Force))
    $process = Start-Process cmd.exe -ArgumentList '/c', $script -Credential $credential `
        -LoadUserProfile -WorkingDirectory $work -Wait -PassThru
    $exitCode = $process.ExitCode
} finally {
    Remove-LocalUser $account -ErrorAction Continue
}

Get-Content -LiteralPath $out
Write-Host "test executable exit code: $exitCode"

$started = 0; $ended = 0; $tests = 0; $passed = 0; $ignored = 0; $failed = 0
foreach ($line in Get-Content -LiteralPath $out) {
    if (-not $line.StartsWith('{')) { continue }
    try { $event = $line | ConvertFrom-Json } catch { continue }
    if ($event.type -ne 'suite') { continue }
    if ($event.event -eq 'started') {
        $started++; $tests += $event.test_count
    } elseif ($event.event -in 'ok', 'failed') {
        $ended++; $passed += $event.passed; $ignored += $event.ignored; $failed += $event.failed
    }
}
Write-Host "suites started=$started ended=$ended; tests=$tests passed=$passed ignored=$ignored failed=$failed"

$problems = @()
if ($exitCode -ne 0) { $problems += "the test executable exited with $exitCode" }
if ($started -lt 1 -or $started -ne $ended) { $problems += "$started suites started but $ended ended" }
if ($tests -lt 1) { $problems += 'no test was selected' }
if ($ignored -ne 0) { $problems += "$ignored tests were ignored: the group is on in this lane" }
if ($tests -ne $passed) { $problems += "$tests tests selected, but only $passed passed" }
if ($failed -ne 0) { $problems += "$failed tests failed" }
if ($problems) {
    $problems | ForEach-Object { Write-Host "::error::$_" }
    exit 1
}
