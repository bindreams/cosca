# Runs a command as the CURRENT interactive (session 1, console) logon's actual filtered
# token, at the LIMITED (non-elevated) run level — even though that account is itself an
# Administrators member. This is what devvm.py's `run --unelevated` calls into.
#
# Why this script exists at all: `devvm.py run`/`ssh` normally go over WinRM, which is a
# network logon in session 0 with (LocalAccountTokenFilterPolicy=1 on this box) a full,
# unsplit High-integrity token — so a WinRM-launched process calling
# ShellExecuteExW("runas") already has full rights and elevates trivially, measuring
# elevated-to-elevated, NOT the real desktop unelevated-user-clicks-through-UAC path this
# guest exists to probe. A scheduled task with an Interactive-logon principal at LIMITED run
# level (hence windows-account-and-uac.ps1 configuring autologon — there has to be an active
# session-1 logon for it to borrow) borrows the CURRENT interactive logon's token and
# explicitly requests the filtered/standard run level even for an admin account, which is the
# closest built-in primitive to "what a real interactive unelevated user session would
# produce."
#
# Combined with the auto-consent option (ConsentPromptBehaviorAdmin=0, `devvm.py up
# --allow-elevation`), a runas child launched from the probe this runs takes the consent
# path with no click required, so it can be driven headlessly. Verify inside the guest that
# this script's own probe process reports Medium Mandatory Level (`whoami /groups`) and that
# a runas child launched from it reports High.
#
# Completion is signalled over a named pipe, not a poll: the task's wrapper script writes its
# own $PID to a file first (so a timeout can kill the whole process tree, not just the
# wrapper's own root), runs the caller's command with output redirected to a file, then
# connects to a named pipe this script is already blocked reading from and writes its exit
# code before closing. This script's own wait is a single blocking read that only returns once
# the wrapper's pipe client actually connects and writes — a real completion signal, not
# `Start-Sleep` in a loop. The one timeout in this script (`-TimeoutSeconds`, below) is a
# genuine external-event failure bound: the task might never run at all (no interactive
# session to borrow) or the probe might hang, and there is no way to distinguish "still
# running" from "never started" other than waiting up to some bound before giving up.
Param(
    [Parameter(Mandatory = $true)]
    [string]$EncodedCommand,

    [int]$TimeoutSeconds = 3600
)

$ErrorActionPreference = "Stop"
$taskName = "DevvmUnelevatedRun-" + [Guid]::NewGuid().ToString("N")
$outputPath = "$env:TEMP\$taskName.out"
$exitCodePath = "$env:TEMP\$taskName.exitcode"
$scriptPath = "$env:TEMP\$taskName.ps1"
$pidPath = "$env:TEMP\$taskName.pid"

# The scheduled task's action: record the wrapper's own PID (for a full process-tree kill on
# timeout), decode and run the caller's command, redirecting its combined output to a file (a
# scheduled task has no console/pipe devvm.py can read directly) and recording $LASTEXITCODE
# so the caller's actual exit status survives the task boundary, then report that exit code
# back over a named pipe this script is already waiting on.
#
# This inner wrapper is written to its own .ps1 file and run via `-File`, rather than being
# inlined into the scheduled task's action via -Command "..." or -EncodedCommand. Both of
# those were tried and measured directly (2026-09-23, against the schtasks.exe-based
# predecessor of this script — the same argument-length/quoting limits apply to a scheduled
# task's action in general, not specifically to schtasks.exe's /TR) to fail for different
# reasons:
#   - `-Command "..."` embeds double quotes (needed here for the *> "$outputPath" redirect and
#     -FilePath "$exitCodePath") that survive into the task's action string, and got
#     misparsed by the outer command-line parser.
#   - `-EncodedCommand <base64 of the same wrapper>` sidesteps the quoting problem (base64 has
#     no quote characters) but blows past schtasks.exe's own hard, undocumented-in-`/?`
#     261-char limit on a task action's value - UTF-16LE + base64 roughly quadruples the
#     wrapper's raw length.
# `-File $scriptPath` keeps the action short (a fixed-form command plus one %TEMP%-rooted
# path, no embedded quotes since neither %TEMP% nor $taskName contain spaces) and puts the
# actual wrapper logic - including its own quotes - safely inside a file instead of a command
# line.
#
# Built from a SINGLE-quoted here-string with `__PLACEHOLDER__` tokens substituted via the
# literal `.Replace()` string method (not the `-replace` operator, whose regex/`$`-in-
# replacement semantics are a hazard here) - the here-string being single-quoted means none of
# its `$`-prefixed PowerShell variables are expanded in THIS script's scope; they stay literal
# text for the wrapper's own process to evaluate when it runs.
$wrapperTemplate = @'
$PID | Out-File -FilePath '__PID_PATH__' -Encoding ascii
powershell -NoProfile -NonInteractive -EncodedCommand __ENCODED_COMMAND__ *> '__OUTPUT_PATH__'
$exitCode = $LASTEXITCODE
$exitCode | Out-File -FilePath '__EXITCODE_PATH__' -Encoding ascii
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', '__TASK_NAME__', [System.IO.Pipes.PipeDirection]::Out)
$pipe.Connect()
$writer = New-Object System.IO.StreamWriter($pipe)
$writer.WriteLine($exitCode)
$writer.Flush()
$writer.Close()
$pipe.Close()
'@

$taskCommand = $wrapperTemplate.
    Replace('__PID_PATH__', $pidPath).
    Replace('__ENCODED_COMMAND__', $EncodedCommand).
    Replace('__OUTPUT_PATH__', $outputPath).
    Replace('__EXITCODE_PATH__', $exitCodePath).
    Replace('__TASK_NAME__', $taskName)
Set-Content -Path $scriptPath -Value $taskCommand -Encoding UTF8

# Register-ScheduledTask with NO -Trigger at all: this task is only ever fired on demand via
# Start-ScheduledTask below, so there is no time-of-day value anywhere in this path. The
# schtasks.exe-based predecessor of this script needed a `/SC ONCE /ST HH:mm` value purely to
# satisfy schtasks' own required-field validation, and a fixed "00:00" wrapped/failed for any
# invocation after midnight - Register-ScheduledTask has no such requirement, so that failure
# mode is structurally impossible here, not just less likely.
$action = New-ScheduledTaskAction -Execute "powershell" -Argument "-NoProfile -NonInteractive -File $scriptPath"
$principal = New-ScheduledTaskPrincipal -LogonType Interactive -RunLevel Limited
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
} catch {
    throw "devvm: Register-ScheduledTask failed: $($_.Exception.Message) - is there an active interactive (session 1) logon for it to borrow? See windows-account-and-uac.ps1's autologon setup."
}

$pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($taskName, [System.IO.Pipes.PipeDirection]::In)
try {
    # Start waiting for the wrapper's pipe connection BEFORE starting the task, so the
    # wrapper's client-side Connect() can never race ahead of a server that isn't listening
    # yet.
    $connectResult = $pipeServer.BeginWaitForConnection($null, $null)

    Start-ScheduledTask -TaskName $taskName

    # The one acceptable timeout in this script: a genuine external-event failure bound, not
    # a poll. The task might never run at all (no interactive session to borrow) or the probe
    # might hang; there is no primitive that distinguishes those from "still running" other
    # than waiting up to some bound.
    $signaled = $connectResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
    if (-not $signaled) {
        if (Test-Path $pidPath) {
            $taskPid = (Get-Content -Path $pidPath -Raw).Trim()
            if ($taskPid) {
                # taskkill is a native command: any stderr it writes would make PowerShell
                # 5.1 set $? to $false regardless of its own exit code, which the script-wide
                # $ErrorActionPreference = "Stop" above would otherwise escalate into a
                # terminating NativeCommandError - masking the real timeout error below with
                # an unrelated one. Scoped to "Continue" for just this call, matching the same
                # native-command-stderr hazard windows-rust.ps1 documents and works around.
                $previousEap = $ErrorActionPreference
                $ErrorActionPreference = "Continue"
                try {
                    taskkill /F /T /PID $taskPid | Out-Null
                } finally {
                    $ErrorActionPreference = $previousEap
                }
            }
        }
        throw "devvm: unelevated probe did not finish within ${TimeoutSeconds}s - killed its whole process tree. This is the failure bound, not a hang detector; pass -TimeoutSeconds explicitly if the probe is legitimately this slow."
    }

    $pipeServer.EndWaitForConnection($connectResult)
    $reader = New-Object System.IO.StreamReader($pipeServer)
    try {
        $exitCode = [int]$reader.ReadLine()
    } catch {
        throw "devvm: unelevated probe connected but sent no valid exit code - it may have failed to start under the scheduled task"
    } finally {
        $reader.Close()
    }

    $output = if (Test-Path $outputPath) { Get-Content -Path $outputPath -Raw } else { "" }
} finally {
    $pipeServer.Dispose()
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $outputPath, $exitCodePath, $scriptPath, $pidPath -ErrorAction SilentlyContinue
}

if ($output) {
    Write-Output $output
}
# Verified in-guest (2026-09-23, windows-x64): this exit code becomes powershell.exe's own
# process exit code, which reaches `vagrant winrm -c` on the host. But `vagrant winrm -c`
# itself does not forward the value - measured directly with a remote command exiting
# {0, 1, 2, 42, 255}: vagrant's own process exit code was 0 for the zero case and exactly 1
# for every nonzero case. So only the zero-vs-nonzero distinction survives to devvm.py's
# sys.exit, not the probe's actual exit code; do not rely on a specific nonzero value showing
# up in the developer's shell.
exit $exitCode
