# Runs a command as the CURRENT interactive (session 1, console) logon's actual filtered
# token, at the LIMITED (non-elevated) run level — even though that account is itself an
# Administrators member. This is what devvm.py's `run --unelevated` calls into.
#
# Why this script exists at all: `devvm.py run`/`ssh` normally go over WinRM, which is a
# network logon in session 0 with (LocalAccountTokenFilterPolicy=1 on this box) a full,
# unsplit High-integrity token — so a WinRM-launched process calling
# ShellExecuteExW("runas") already has full rights and elevates trivially, measuring
# elevated-to-elevated, NOT the real desktop unelevated-user-clicks-through-UAC path this
# guest exists to probe. `schtasks /Create /IT /RL LIMITED` borrows the CURRENT interactive
# logon's token (hence windows-account-and-uac.ps1 configuring autologon — there has to be
# an active session-1 logon for /IT to borrow) and explicitly requests the filtered/standard
# run level even for an admin account, which is the closest built-in primitive to "what a
# real interactive unelevated user session would produce."
#
# Combined with the auto-consent option (ConsentPromptBehaviorAdmin=0, `devvm.py up
# --allow-elevation`), a runas child launched from the probe this runs takes the consent
# path with no click required, so it can be driven headlessly. Verify inside the guest that
# this script's own probe process reports Medium Mandatory Level (`whoami /groups`) and that
# a runas child launched from it reports High.
Param(
    [Parameter(Mandatory = $true)]
    [string]$EncodedCommand,

    # Failure bound surfaced to the caller if the probe hangs or is genuinely slow — not a
    # sync-via-time hack. Task Scheduler exposes no blocking "wait for completion" primitive
    # from PowerShell, only a pollable State property, so a bounded poll is the only
    # available mechanism; see the loop below.
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
$taskName = "DevvmUnelevatedRun-" + [Guid]::NewGuid().ToString("N")
$outputPath = "$env:TEMP\$taskName.out"
$exitCodePath = "$env:TEMP\$taskName.exitcode"
$scriptPath = "$env:TEMP\$taskName.ps1"

# The scheduled task's action: decode and run the caller's command, redirecting its combined
# output to a file (a scheduled task has no console/pipe devvm.py can read directly) and
# recording $LASTEXITCODE so the caller's actual exit status survives the task boundary.
#
# This inner wrapper is written to its own .ps1 file and run via `-File`, rather than being
# inlined into schtasks's /TR value via -Command "..." or -EncodedCommand. Both of those were
# tried and measured directly (2026-09-23) to fail for different reasons:
#   - `-Command "..."` embeds double quotes (needed here for the *> "$outputPath" redirect and
#     -FilePath "$exitCodePath") that survive into $taskAction. PowerShell's native-argument
#     auto-quoting doesn't re-wrap an argument that already contains embedded quotes, so
#     schtasks.exe's own command-line parser sees `-NoProfile` etc. as bare, space-separated
#     top-level arguments instead of part of /TR's value: "ERROR: Invalid argument/option -
#     '-NoProfile'."
#   - `-EncodedCommand <base64 of the same wrapper>` sidesteps the quoting problem (base64 has
#     no quote characters) but blows schtasks's separate, hard, undocumented-in-`/?` 261-char
#     limit on /TR's value: "ERROR: Value for '/TR' option cannot be more than 261
#     character(s)." - UTF-16LE + base64 roughly quadruples the wrapper's raw length.
# `-File $scriptPath` keeps /TR short (a fixed-form command plus one %TEMP%-rooted path, no
# embedded quotes since neither %TEMP% nor $taskName contain spaces) and puts the actual
# wrapper logic - including its own quotes - safely inside a file instead of a command line.
$taskCommand = (
    "powershell -NoProfile -NonInteractive -EncodedCommand $EncodedCommand " +
    "*> `"$outputPath`"; `$LASTEXITCODE | Out-File -FilePath `"$exitCodePath`" -Encoding ascii"
)
Set-Content -Path $scriptPath -Value $taskCommand -Encoding UTF8
$taskAction = "powershell -NoProfile -NonInteractive -File $scriptPath"

# /SC ONCE requires some /ST time-of-day, but the actual value is otherwise irrelevant here -
# `schtasks /Run` below fires the task immediately regardless of its schedule. A fixed
# "00:00" is wrong for any time after midnight: schtasks compares it against the current
# time-of-day (there's no /SD, so no date to anchor it) and, once past, writes "WARNING: Task
# may not run because /ST is earlier than current time" to stderr - which
# $ErrorActionPreference = "Stop" (above) turns into a terminating error for this script, even
# though task creation itself still succeeds. A few minutes in the future is never in the
# past relative to itself, so the warning - and the failure it was causing - can't occur;
# this isn't a sleep/timing hack since nothing waits on this value, /Run alone decides when
# the command actually executes.
$scheduledTime = (Get-Date).AddMinutes(5).ToString("HH:mm")
schtasks /Create /TN $taskName /TR $taskAction /SC ONCE /ST $scheduledTime /IT /RL LIMITED /F | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "devvm: schtasks /Create failed (exit $LASTEXITCODE) - is there an active interactive (session 1) logon for /IT to borrow? See windows-account-and-uac.ps1's autologon setup."
}

try {
    schtasks /Run /TN $taskName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "devvm: schtasks /Run failed (exit $LASTEXITCODE)"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $state = (Get-ScheduledTask -TaskName $taskName).State
    while ($state -eq "Running" -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $state = (Get-ScheduledTask -TaskName $taskName).State
    }

    if ($state -eq "Running") {
        schtasks /End /TN $taskName | Out-Null
        throw "devvm: unelevated probe did not finish within ${TimeoutSeconds}s (task still Running) - this is the failure bound, not a hang detector; pass -TimeoutSeconds explicitly if the probe is legitimately this slow."
    }

    $output = if (Test-Path $outputPath) { Get-Content -Path $outputPath -Raw } else { "" }
    $exitCode = if (Test-Path $exitCodePath) {
        [int](Get-Content -Path $exitCodePath -Raw).Trim()
    } else {
        throw "devvm: unelevated probe left no exit-code file - it may have failed to start under the scheduled task"
    }
} finally {
    schtasks /Delete /TN $taskName /F | Out-Null
    Remove-Item -Path $outputPath, $exitCodePath, $scriptPath -ErrorAction SilentlyContinue
}

if ($output) {
    Write-Output $output
}
exit $exitCode
