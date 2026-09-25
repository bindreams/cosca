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
# Completion is signalled over a named pipe, not a poll, and the pipe connection's own lifetime
# is the liveness signal: the wrapper connects to a named pipe this script is already blocked
# reading from as its very first action and keeps that connection open for its whole life,
# running the caller's command with output redirected to a file, and writing its exit code to
# the still-open pipe as its very last action. If the wrapper's PROCESS goes away anywhere
# after connecting — an unhandled error, being killed, a crash — the OS tears down its end of
# the pipe the instant that happens, and the blocking read unblocks immediately with EOF,
# reported as "exited without reporting a result", rather than this script waiting out the rest
# of -TimeoutSeconds for a result that will never arrive. That is a narrower claim than "the
# wrapper always reaches its pipe write or dies": a wrapper that is merely stuck while still
# alive (see "If a run hangs" below) leaves the pipe genuinely open, and this script's
# read blocks for as long as that process does.
#
# -TimeoutSeconds bounds every blocking Task Scheduler RPC call this script itself makes
# during the probe (Register-ScheduledTask, Start-ScheduledTask — neither has a timeout of its
# own) and the pipe connect wait: a genuine external-event bound (Task Scheduler actually
# dispatching the task and its wrapper reaching Connect()), not a poll. Stop-/Unregister-
# ScheduledTask (cleanup, in the `finally` block below) is NOT bounded by -TimeoutSeconds — it
# runs after the probe either way, on its own fixed 120s budget, so a small -TimeoutSeconds
# can't cut cleanup short. That cleanup is skipped entirely, not merely bounded differently, when
# Register-/Start-ScheduledTask's own -TimeoutSeconds bound is what actually expired — see
# $setupTimedOut below for why.
# Invoke-Bounded (below) implements that bound by running each call on an in-process runspace
# via [PowerShell]::BeginInvoke()/AsyncWaitHandle.WaitOne() — the same real-completion-event
# pattern the named-pipe waits use, and no new process spawned (this guest is already
# resource-constrained under TCG emulation, so avoiding Start-Job's extra powershell.exe per
# call matters here). This script's own deadline is monotonic (QueryPerformanceCounter-backed,
# via [System.Diagnostics.Stopwatch]::GetTimestamp()/::Frequency), not wall-clock (Get-Date):
# this guest's own clock has been observed to jump by hours across an ordinary reboot (NTP
# resync), which would corrupt a Get-Date-based deadline mid-wait. GetTimestamp()/Frequency are
# static OS-level values, consistent across processes on the same machine with no intervening
# reboot, so the identical absolute tick count can cross the process boundary to the wrapper
# template below (baked in as __DEADLINE_TICKS__) — unlike a Stopwatch *instance*'s Elapsed
# state, which cannot.
#
# Once connected, this script's own read of the pipe has NO deadline of its own: it just blocks
# until the wrapper either writes a result or its end of the pipe is torn down (EOF). A second,
# independent deadline racing that from this script's side would add no real protection for the
# ordinary slow-command case — only a coin-flip between two different messages depending on
# which timer fired first — so instead of adding one, every step the wrapper takes after
# Connect() is itself kept bounded: its child process's WaitForExit() is bounded against the
# SAME __DEADLINE_TICKS__ this script uses, followed only by a fixed-30s taskkill of that child
# and a Stop-Transcript/pipe-write/close that do no further waiting. That covers the wrapper
# running slowly, or its command running long — it does NOT cover the wrapper being stuck while
# still alive (suspended, or held by a Windows Error Reporting "... has stopped working"
# dialog): the pipe stays genuinely open in that case, and nothing here can tell "still
# legitimately working" apart from "wedged forever". See "If a run hangs" below for that
# residual case, and -WindowStyle Hidden plus the wrapper's use of Add-Content instead of
# Write-Host (in the template below) for why an ordinary console can no longer be the cause of
# it.
#
# The wrapper's own pipe Connect() call (in the here-string below) is bounded too, for a case
# the above doesn't cover: a scheduled task that starts running only AFTER this script has
# already given up on the connect wait and moved on — without a bound there, that late
# wrapper's Connect() would block forever against a server pipe this script has by then
# disposed, leaking a process on the guest indefinitely.
#
# If a run hangs, Ctrl-C and clean up the guest by hand via devvm.py — see
# scripts/README.md#windows-guests for the recovery commands.
Param(
    [Parameter(Mandatory = $true)]
    [string]$EncodedCommand,

    # The domain-qualified account name (e.g. "DESKTOP-RPVSB2I\vagrant") a scheduled task
    # borrows its Interactive-logon token from. Resolved by the caller, not here - see the
    # $currentUser assignment below for why.
    [Parameter(Mandatory = $true)]
    [string]$InteractiveUser,

    [int]$TimeoutSeconds = 3600
)

$ErrorActionPreference = "Stop"

# Without this, every `throw` below (the -TimeoutSeconds bound, a wrapper crash, a failed
# Register-ScheduledTask, ...) is an UNCAUGHT terminating error, and this script never reaches
# its own `exit $exitCode` at the bottom: `vagrant winrm -c 'throw "x"; exit $LASTEXITCODE'`
# exits 0, not 1 - the throw stops execution before the trailing `exit $LASTEXITCODE`
# statement ever runs, and $LASTEXITCODE at that point is whatever it was before this script
# started (typically unset/0), not something the throw itself sets. That would make every
# failure path here - including the -TimeoutSeconds bound this script exists to provide -
# silently report success to devvm.py and its caller instead of a nonzero exit. A script-scope
# trap is the one choke point that turns every terminating error below into an explicit
# `exit 1`, regardless of which statement raised it; `finally` blocks in try/finally regions
# further down still run first during unwinding - a `try { throw } finally { ... }` nested
# inside a function, under a script-scope trap exactly like this one, runs its `finally` block
# before the trap fires, so any `finally`-based cleanup elsewhere in this script still runs
# before this trap gets a chance to catch the error.
trap {
    Write-Host "devvm: unelevated probe failed: $($_.Exception.Message)"
    exit 1
}

$taskName = "DevvmUnelevatedRun-" + [Guid]::NewGuid().ToString("N")
$outputPath = "$env:TEMP\$taskName.out"
$errorPath = "$env:TEMP\$taskName.err"
$scriptPath = "$env:TEMP\$taskName.ps1"
# Decoded from -EncodedCommand and written here (see the wrapper template below): cmd.exe caps
# its own command line at roughly 8191 characters, well under CreateProcess's general 32767 -
# an inner command whose raw text is on the order of 2600+ characters blows past that once
# base64/UTF-16LE-encoded and embedded directly in cmd's own Arguments string. A file has no
# such cap.
$innerScriptPath = "$env:TEMP\$taskName.inner.ps1"
# The wrapper is a whole separate powershell.exe process (see -File $scriptPath below), so it
# does NOT inherit this script's $ErrorActionPreference = Stop - its own default is Continue.
# It also runs with -WindowStyle Hidden (see its task action below), so it has no console at
# all to print anything to even if it tried - an error thrown before the pipe-write step (e.g.
# by something the wrapper itself does, as opposed to the caller's redirected command) would
# otherwise be lost entirely. Start-Transcript on the wrapper captures that text anyway
# (transcription doesn't need a console, only the wrapper's own host object) to a file this
# script reads back below, regardless of whether the wrapper's main body throws. The wrapper's
# own deliberate diagnostics (below) don't rely on that passive capture: they Add-Content
# directly to $logPath, a second file, instead of ever calling Write-Host - so nothing here
# depends on rendering to a console that, even before -WindowStyle Hidden, could block
# indefinitely on a paused or QuickEdit-selected window (see "If a run hangs" in the
# header above).
$transcriptPath = "$env:TEMP\$taskName.transcript.txt"
$logPath = "$env:TEMP\$taskName.log.txt"

# New-ScheduledTaskPrincipal -LogonType Interactive requires an explicit -UserId: it does not
# default to "whoever is currently logged on", so without this Register-ScheduledTask throws
# "missing mandatory parameter: UserId".
#
# Resolved by the caller (devvm.py's cmd_run, via get_windows_interactive_username), not here:
# that Python-side helper and this script used to run the identical explorer.exe-owner-via-WMI
# query independently - see get_windows_interactive_username's own docstring in devvm.py for
# the full "why explorer.exe, not Win32_ComputerSystem.UserName or
# Win32_LoggedOnUser/Win32_LogonSession" reasoning, which applies equally to both call sites.
# devvm.py already fails loudly there if nobody is logged on interactively, before this script
# ever runs.
$currentUser = $InteractiveUser
# RDP recovery guidance is threaded through to the two sites below that can surface a logon
# that was usable when devvm.py resolved it but isn't by the time this script actually needs
# it: Register-ScheduledTask (found a logon there but it's gone by now), and "no wrapper ever
# connected" (found a logon and registered the task, but nothing about running it further
# confirms the session was actually usable) - an interactive-but-RDP-redirected session can
# still leave the scheduled task unable to actually run, e.g. the session was disconnected
# (not just redirected) between one check and the next.
$rdpRecoveryNote = " If this guest was reached over RDP: the scheduled task needs vagrant's session to still be an active, connected desktop, not merely logged on - a disconnected RDP session (closed the client without logging off) can leave a LogonType 10/11 session that this check finds but the scheduled task still can't run in. From inside the guest, 'query session' lists session IDs and 'tscon <id> /dest:console' reattaches a disconnected session to the console; otherwise reboot the guest."

# Shared monotonic deadline for every blocking wait THIS script itself makes (Register-,
# Start-, the pipe connect wait) and, via __DEADLINE_TICKS__ below, for the wrapper's own waits
# too - see the header comment above for why it's Stopwatch/QPC-based and why one shared
# deadline, not a fresh one per phase or per process.
$deadlineTicks = [System.Diagnostics.Stopwatch]::GetTimestamp() + [long]($TimeoutSeconds * [System.Diagnostics.Stopwatch]::Frequency)

function Get-RemainingSeconds {
    $remaining = ($deadlineTicks - [System.Diagnostics.Stopwatch]::GetTimestamp()) / [double][System.Diagnostics.Stopwatch]::Frequency
    if ($remaining -lt 0) { return 0 }
    return [Math]::Ceiling($remaining)
}

# Best-effort: the wrapper's Start-Transcript writes incrementally and its own diagnostics are
# Add-Content'd to $logPath as they happen, so even a killed-on-timeout wrapper has usually
# left something useful in one or both files - read them whenever they exist, on both the
# success and timeout paths below, rather than only on success.
function Read-WrapperTranscript {
    $parts = @()
    if (Test-Path $logPath) {
        try { $parts += Get-Content -Path $logPath -Raw } catch {}
    }
    if (Test-Path $transcriptPath) {
        try { $parts += Get-Content -Path $transcriptPath -Raw } catch {}
    }
    return ($parts -join "`n")
}

function Get-TranscriptNote {
    # Whatever the wrapper itself printed or threw, formatted for appending to a thrown error
    # message, or "" if there's nothing to add.
    $transcript = Read-WrapperTranscript
    if (-not $transcript) { return "" }
    return "`n--- wrapper diagnostics (log file plus transcript, if either exists) ---`n$transcript"
}

function Invoke-Bounded {
    <#
      Runs $ScriptBlock on a separate in-process runspace and waits up to $TimeoutSeconds for
      it to finish, via BeginInvoke()/AsyncWaitHandle.WaitOne() — the same real-completion-
      event pattern the named-pipe wait below uses, not a poll. $ScriptBlock must be
      self-contained (only $Parameters in scope, no closures over this script's variables):
      AddScript(scriptblock) re-parses it from its string form in the new runspace.

      On timeout, stops the pipeline via BeginStop (async) and does NOT Dispose() it: "not
      signaled" means a command is still actually executing on that runspace, and Dispose()
      on a still-running pipeline blocks the calling thread until it actually stops — exactly
      the unbounded wait this function exists to avoid (Register-/Start-/Unregister-
      ScheduledTask have no timeout of their own; a wedged Task Scheduler service is the
      documented case this guards against). The abandoned $ps is left for BeginStop's own
      completion and eventual GC, off this thread.

      $TimeoutMessage is thrown as-is on timeout, with no substitution: WaitOne blocks for up
      to exactly $TimeoutSeconds, so a separately-measured "actual elapsed" value would be
      mechanically forced to be ≈ $TimeoutSeconds itself (confirmed live: a couple of seconds
      over, from `[Math]::Ceiling` rounding plus BeginStop overhead) — a second number that
      looks precise but adds no real information beyond the one budget the caller already
      knows and states in $TimeoutMessage.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [Parameter()]
        [hashtable]$Parameters = @{},
        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)]
        [string]$TimeoutMessage
    )
    if ($TimeoutSeconds -le 0) {
        throw $TimeoutMessage
    }
    $ps = [PowerShell]::Create()
    try {
        [void]$ps.AddScript($ScriptBlock)
        foreach ($key in $Parameters.Keys) {
            [void]$ps.AddParameter($key, $Parameters[$key])
        }
        $asyncResult = $ps.BeginInvoke()
    } catch {
        # Setup itself failed before there was ever a pipeline actually running - safe (and
        # necessary) to dispose here, unlike the timeout path below.
        $ps.Dispose()
        throw
    }
    $signaled = $asyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
    if (-not $signaled) {
        $ps.BeginStop($null, $null) | Out-Null
        throw $TimeoutMessage
    }
    try {
        try {
            $ps.EndInvoke($asyncResult) | Out-Null
        } catch [System.Management.Automation.MethodInvocationException] {
            # A ScriptBlock that itself throws an uncaught terminating error (e.g.
            # Register-ScheduledTask's own catch/throw below) surfaces here, not via
            # $ps.HadErrors below: EndInvoke() rethrows it wrapped in a
            # MethodInvocationException whose own message is generic ("Exception calling
            # "EndInvoke" with "1" argument(s): ..."). Unwrap to the ScriptBlock's real
            # exception so callers see the friendly message it actually threw.
            throw $_.Exception.InnerException
        }
        # Not $ps.HadErrors: PowerShell/PowerShell#4613 - HadErrors can be $true even when
        # -ErrorAction SilentlyContinue suppressed the error and nothing was actually added to
        # Streams.Error, making Streams.Error[0] below throw an index-out-of-range instead of
        # the intended exception. Streams.Error.Count is what HadErrors is documented to mean.
        if ($ps.Streams.Error.Count -gt 0) {
            throw $ps.Streams.Error[0].Exception
        }
    } finally {
        $ps.Dispose()
    }
}

# The scheduled task's action: decode and run the caller's command, redirecting its combined
# output to a file (a scheduled task has no console/pipe devvm.py can read directly, and none
# is wanted now that the task runs -WindowStyle Hidden - see below) and recording its real exit
# code, then report that exit code back over a named pipe this script is already waiting on.
#
# This inner wrapper is written to its own .ps1 file and run via `-File`, rather than being
# inlined into the scheduled task's action via -Command "..." or -EncodedCommand. Both of
# those fail for different reasons (the same argument-length/quoting limits apply to a
# scheduled task's action in general, not specifically to schtasks.exe's /TR, whose
# predecessor this script replaced):
#   - `-Command "..."` embeds double quotes (needed for the redirect targets and other
#     quoted arguments) that survive into the task's action string, and got misparsed by the
#     outer command-line parser.
#   - `-EncodedCommand <base64 of the same wrapper>` sidesteps the quoting problem (base64 has
#     no quote characters) but blows past schtasks.exe's own hard, undocumented-in-`/?`
#     261-char limit on a task action's value - UTF-16LE + base64 roughly quadruples the
#     wrapper's raw length.
# `-File $scriptPath` keeps the action short (a fixed-form command plus one %TEMP%-rooted
# path, no embedded quotes since neither %TEMP% nor $taskName contain spaces) and puts the
# actual wrapper logic - including its own quotes - safely inside a file instead of a command
# line. The wrapper's OWN nested cmd.exe invocation (running the caller's actual command, further
# down) needs the identical fix one layer deeper — see its own comment.
#
# Built from a SINGLE-quoted here-string with `__PLACEHOLDER__` tokens substituted via the
# literal `.Replace()` string method (not the `-replace` operator, whose regex/`$`-in-
# replacement semantics are a hazard here) - the here-string being single-quoted means none of
# its `$`-prefixed PowerShell variables are expanded in THIS script's scope; they stay literal
# text for the wrapper's own process to evaluate when it runs.
#
# $exitCode starts at -1 (not 0) so that if the wrapper crashes before the caller's command
# ever runs, the caller sees a nonzero/sentinel status rather than a false "succeeded".
# Connect() is bounded against __DEADLINE_TICKS__ (baked in as raw QPC ticks, not a duration -
# see the header comment above for why) for the case the header's ordering note doesn't cover:
# a task that starts running only after this script has already given up on its own connect
# wait and disposed the server pipe. Diagnostics throughout use Add-Content to __LOG_PATH__,
# never Write-Host: with the task's action now running -WindowStyle Hidden (below), there is no
# console for Write-Host to reach anyway, but writing to a file directly also means nothing
# here depends on a host/console object succeeding at all - see "If a run hangs" in the
# header above for the one thing that still isn't bounded by any of this.
$wrapperTemplate = @'
Start-Transcript -Path '__TRANSCRIPT_PATH__' | Out-Null
$logPath = '__LOG_PATH__'
function Write-Log {
    param([string]$Message)
    try { Add-Content -Path $logPath -Value $Message } catch {}
}
$exitCode = -1
$pipe = $null
$writer = $null
$deadlineTicks = [long]'__DEADLINE_TICKS__'
function Get-RemainingMs {
    $remainingMs = (($deadlineTicks - [System.Diagnostics.Stopwatch]::GetTimestamp()) / [double][System.Diagnostics.Stopwatch]::Frequency) * 1000
    if ($remainingMs -lt 1) { return 1 }
    return [int]$remainingMs
}
try {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', '__TASK_NAME__', [System.IO.Pipes.PipeDirection]::Out)
    $pipe.Connect((Get-RemainingMs))
    $writer = New-Object System.IO.StreamWriter($pipe)
    try {
        # cmd.exe caps its own command line at roughly 8191 characters (well under
        # CreateProcess's general 32767) - a raw inner command of about 2600+ characters blows
        # past that once base64/UTF-16LE-encoded and embedded directly in cmd's Arguments
        # string, and cmd.exe fails to even start the process, silently. Decoding
        # __ENCODED_COMMAND__ to its own file and running it via -File sidesteps the limit
        # entirely, the same way -File $scriptPath does one layer up for the outer script's own
        # scheduled-task action.
        $decodedInner = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('__ENCODED_COMMAND__'))
        Set-Content -Path '__INNER_SCRIPT_PATH__' -Value $decodedInner -Encoding UTF8

        # The child runs via cmd.exe's own `1>`/`2>` redirection, performed by cmd.exe itself (a
        # real OS-level file handle it opens before running its own child), NOT a PowerShell
        # redirection operator. PowerShell 5.1 parses a native child's stderr through its own
        # stream reader regardless of which operator is used (`*>`, `2>&1`, even a plain `2>`
        # alone) or -OutputFormat, and treats a `#< CLIXML` prefix (written by a nested
        # non-interactive powershell.exe with redirected output) as serialized records to
        # deserialize - throwing if what follows isn't well-formed CLIXML. cmd.exe's `1>`/`2>`
        # never goes through that PowerShell stream reader at all (see scripts/README.md).
        #
        # Launched via [System.Diagnostics.Process]::Start($psi) directly, NOT PowerShell's
        # Start-Process cmdlet: PS 5.1's Start-Process -PassThru -RedirectStandardOutput/
        # -RedirectStandardError, without -Wait, returns a Process object whose .ExitCode reads
        # back blank/$null even after WaitForExit() itself returns cleanly with no error - it
        # does not leave that object's handle in a state .ExitCode can read from afterward when
        # used this way. [System.Diagnostics.Process]::Start() is the underlying .NET API
        # Start-Process itself wraps; calling it directly returns a Process object whose
        # WaitForExit() and .ExitCode both work correctly against the real handle.
        #
        # cmd.exe is the immediate child (not the caller's command directly) so its own `1>`/`2>`
        # can perform the OS-level redirection above; `cmd /c command` exits with `command`'s own
        # exit code once `command` finishes, so $childProcess.ExitCode below is the caller's real
        # exit code, not cmd.exe's own. `/d` skips any AutoRun registry command.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = '/d /c powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "__INNER_SCRIPT_PATH__" 1>"__OUTPUT_PATH__" 2>"__ERROR_PATH__"'
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $childProcess = [System.Diagnostics.Process]::Start($psi)
        # Bounded against this wrapper's own deadline: an unbounded WaitForExit() could leave
        # this child running forever on the guest, either because the outer script already gave
        # up on a late connect (nothing left there to kill it from) or because the outer
        # script/devvm.py itself was interrupted (Ctrl-C, the whole `vagrant winrm` call dying) -
        # nothing else on the guest would ever stop it. On expiry this kills only the immediate
        # cmd.exe child's own process tree (via taskkill /F /T), not any further descendant it
        # may have already detached - the wrapper itself keeps running afterward to reach its
        # own pipe write below, which is what the outer script's unbounded read relies on.
        if ($childProcess.WaitForExit((Get-RemainingMs))) {
            $exitCode = $childProcess.ExitCode
        } else {
            Write-Log "devvm wrapper: caller's command did not finish within its deadline - killing its process tree (PID $($childProcess.Id))"
            try {
                $killPsi = New-Object System.Diagnostics.ProcessStartInfo
                $killPsi.FileName = 'taskkill.exe'
                $killPsi.Arguments = "/F /T /PID $($childProcess.Id)"
                $killPsi.UseShellExecute = $false
                $killPsi.CreateNoWindow = $true
                $killProcess = [System.Diagnostics.Process]::Start($killPsi)
                if ($killProcess.WaitForExit(30000)) {
                    Write-Log "devvm wrapper: taskkill exited with code $($killProcess.ExitCode)"
                } else {
                    Write-Log "devvm wrapper: taskkill did not finish within 30s (PID $($killProcess.Id)) - the caller's command's process tree may still be running"
                }
            } catch {
                Write-Log "devvm wrapper: taskkill of the caller's command failed: $($_.Exception.Message)"
            }
            # $exitCode stays at its -1 sentinel: the command never actually finished, so there
            # is no real exit code to report.
        }
    } catch {
        Write-Log "devvm wrapper: caught $($_.Exception.GetType().FullName): $($_.Exception.Message)"
        Write-Log $_.ScriptStackTrace
    }
} catch {
    Write-Log "devvm wrapper: pipe connect failed: $($_.Exception.Message)"
} finally {
    # Stopped BEFORE the pipe write below, not after: the outer script's read of the pipe is
    # what unblocks it to go read this transcript/log back (see Read-WrapperTranscript and its
    # call sites) - stopping the transcript first guarantees the file is fully flushed and closed
    # by the time that read can possibly happen, instead of racing it. Wrapped in its own
    # try/catch so a failing Stop-Transcript can never prevent the pipe write below - that is
    # what the outer script actually depends on for correctness.
    try {
        Stop-Transcript | Out-Null
    } catch {
        Write-Log "devvm wrapper: Stop-Transcript failed: $($_.Exception.Message)"
    }
    if ($writer) {
        try {
            $writer.WriteLine($exitCode)
            $writer.Flush()
            $writer.Close()
        } catch {
            Write-Log "devvm wrapper: pipe signal failed: $($_.Exception.Message)"
        }
    }
    if ($pipe) {
        $pipe.Close()
    }
}
'@

# Baked into the wrapper template as raw QPC ticks, not a duration - see the header comment
# above for why.
$taskCommand = $wrapperTemplate.
    Replace('__ENCODED_COMMAND__', $EncodedCommand).
    Replace('__OUTPUT_PATH__', $outputPath).
    Replace('__ERROR_PATH__', $errorPath).
    Replace('__INNER_SCRIPT_PATH__', $innerScriptPath).
    Replace('__TASK_NAME__', $taskName).
    Replace('__TRANSCRIPT_PATH__', $transcriptPath).
    Replace('__LOG_PATH__', $logPath).
    Replace('__DEADLINE_TICKS__', $deadlineTicks.ToString())
Set-Content -Path $scriptPath -Value $taskCommand -Encoding UTF8

# Register-ScheduledTask with NO -Trigger at all: this task is only ever fired on demand via
# Start-ScheduledTask below, so there is no time-of-day value anywhere in this path, and no
# midnight-wraparound failure mode to guard against.
#
# Everything from here through the pipe read below runs inside one try/finally, started right
# after $scriptPath is written to disk, so that ANY failure past this point - not just a failed
# pipe connect - still reaches the cleanup at the bottom (Unregister-ScheduledTask,
# Remove-Item): starting the try/finally any later would leak a registered task and/or
# $scriptPath on the guest if, say, the pipe's SDDL construction or the NamedPipeServerStream
# constructor itself threw in between.
#
# $setupTimedOut tracks whether Register-/Start-ScheduledTask's own Invoke-Bounded call timed
# out specifically (as opposed to the ScriptBlock inside it throwing a normal, already-complete
# error) - Invoke-Bounded's own contract on timeout is BeginStop (async) with no Dispose(), so
# the abandoned runspace may still be actually running Register-/Start-ScheduledTask when this
# script reaches its cleanup below. Unregistering the task or deleting its files in that window
# would race that still-in-flight call: it could re-create the task (Register) or leave it
# freshly started (Start) right after cleanup just removed it. The `finally` block below skips
# cleanup entirely when this is set, and warns instead - see there.
$setupTimedOut = $false
$pipeServer = $null
try {
    # The try/catch immediately below Get-RemainingSeconds exists only to notice a TIMEOUT
    # specifically (via an exact match against $registerTimeoutMessage, which Invoke-Bounded
    # throws as-is - see its own docstring) and set $setupTimedOut before rethrowing unchanged -
    # it does not re-wrap or alter the error itself. A genuine cmdlet failure (e.g. no
    # interactive session to borrow) still gets its friendly RDP-recovery wrapping purely inside
    # the ScriptBlock below (an explicit `throw`, a terminating error inside the ScriptBlock's
    # own runspace), surfacing through Invoke-Bounded's unwrapped-EndInvoke path already fully
    # formatted - not through $ps.Streams.Error[0].Exception, which only catches a ScriptBlock
    # that leaves a non-terminating error unthrown (see Invoke-Bounded's own comment).
    # $rdpRecoveryNote is passed in via -Parameters since the ScriptBlock runs on its own
    # runspace and cannot close over this script's variables.
    #
    # Bounded by whatever's left of the caller's own -TimeoutSeconds, not a budget of its own —
    # so a timeout here means -TimeoutSeconds itself ran out during this step, not that Task
    # Scheduler is stuck (see Invoke-Bounded's finally-block sibling call below for the one case
    # where that distinction doesn't apply).
    $registerBudget = Get-RemainingSeconds
    $registerTimeoutMessage = "devvm: -TimeoutSeconds ${TimeoutSeconds}s expired during Register-ScheduledTask - it had ${registerBudget}s left when this step started. If the guest is just slow, a larger -TimeoutSeconds (devvm.py's --timeout) usually fixes this."
    try {
        Invoke-Bounded -TimeoutSeconds $registerBudget `
            -TimeoutMessage $registerTimeoutMessage `
            -Parameters @{ TaskName = $taskName; ScriptPath = $scriptPath; UserId = $currentUser; RdpRecoveryNote = $rdpRecoveryNote } `
            -ScriptBlock {
            param($TaskName, $ScriptPath, $UserId, $RdpRecoveryNote)
            # -ExecutionPolicy Bypass: the LIMITED-run-level principal's own effective execution
            # policy is untested/unknown territory (a different, filtered token than the
            # High-integrity WinRM session that registers this task) - forcing Bypass for this
            # one task action removes that as a variable entirely rather than relying on
            # whatever CurrentUser/LocalMachine policy happens to be configured on the guest.
            # -WindowStyle Hidden: an Interactive-logon task otherwise opens a real, visible
            # console on vagrant's desktop - QuickEdit-mode text selection in that window (or
            # any other way of pausing it) blocks a console write indefinitely, which would
            # block the wrapper before it ever reaches taskkill or its own pipe write. See "If
            # a run hangs anyway" in the header above for the residual case even this doesn't
            # cover, and why this script deliberately does not add a second timer for it.
            $action = New-ScheduledTaskAction -Execute "powershell" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $ScriptPath"
            $principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
            # Without this, Task Scheduler applies its own default ExecutionTimeLimit (commonly
            # 72 hours) on top of -TimeoutSeconds - normally moot, but a caller passing a long
            # --timeout close to or past that would hit a second, uncoordinated limit instead of
            # the one this script actually reports and explains. Zero means unlimited: this
            # script's own deadline is the only bound that should apply.
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
            try {
                # -ErrorAction Stop: Register-ScheduledTask is CDXML-backed (a CIM cmdlet
                # generated from a Task Scheduler CDXML definition, not native .NET), and a
                # CDXML cmdlet's own failure is a NON-terminating error regardless of this
                # runspace's default $ErrorActionPreference:
                # without -ErrorAction Stop here, a forced registration failure (e.g. no
                # interactive session to borrow) writes to the error stream and returns
                # normally, so this catch never runs and the friendly RDP-recovery message
                # below never fires. Invoke-Bounded's own HadErrors check still catches that
                # case and throws $ps.Streams.Error[0].Exception, so the caller does see a
                # failure either way - just Register-ScheduledTask's own generic error, not
                # this script's friendly RDP-recovery wrapping.
                Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
            } catch {
                throw "devvm: Register-ScheduledTask failed: $($_.Exception.Message) - is there an active interactive (session 1) logon for it to borrow? See windows-account-and-uac.ps1's autologon setup.$RdpRecoveryNote"
            }
        }
    } catch {
        if ($_.Exception.Message -eq $registerTimeoutMessage) {
            $setupTimedOut = $true
        }
        throw
    }

    # The 2-arg NamedPipeServerStream(name, direction) constructor defaults to
    # PipeOptions.None (synchronous); BeginWaitForConnection() below is the async API and throws
    # "Pipe is not opened in asynchronous mode" against a stream opened that way.
    # [PipeOptions]::Asynchronous on the full 5-arg constructor is what actually enables
    # Begin/End-style calls.
    #
    # An explicit PipeSecurity is required, not optional: this script itself runs over `vagrant
    # winrm`, a High-integrity session (LocalAccountTokenFilterPolicy=1 - see cmd_run's comment), so
    # a pipe created here with no explicit security descriptor implicitly inherits a High mandatory
    # label from the creating process/token. The wrapper's client-side Connect() runs under the
    # scheduled task's LIMITED run level, i.e. a Medium-integrity token - and Windows' Mandatory
    # Integrity Control denies a lower-integrity process write access to a higher-integrity object
    # by default ("no write up"), regardless of the DACL: with no explicit security descriptor, the
    # wrapper's Connect() fails with "Access to the path is denied." The fix is to hand the pipe its
    # own explicit DACL plus a SACL mandatory label of Medium with the no-write-up flag, so a
    # Medium-integrity client is not "writing up": SYSTEM and Administrators get full control (GA)
    # for completeness, and $currentUser's own resolved SID gets read/write (GRGW) - the actual
    # access path for the LIMITED task, since a UAC-filtered/standard token's Administrators
    # membership is deny-only and won't match a DACL entry for BUILTIN\Administrators. This is the
    # specific user's SID, not the broad well-known Authenticated Users alias (AU): any other
    # authenticated principal able to run code on the guest at Medium integrity or above would
    # otherwise be able to connect to this pipe first and race the real wrapper, feeding this script
    # a fake result before the actual probe ever runs. Setting a SACL at object-creation time (as
    # opposed to modifying an existing object's SACL afterwards) does not require
    # SeSecurityPrivilege, so this needs no extra privilege grant on top of the High-integrity WinRM
    # session already in use here.
    $currentUserSid = (New-Object System.Security.Principal.NTAccount($currentUser)).
        Translate([System.Security.Principal.SecurityIdentifier]).Value
    $pipeSecuritySddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;$currentUserSid)S:(ML;;NW;;;ME)"
    $pipeSecurity = New-Object System.IO.Pipes.PipeSecurity
    $pipeSecurity.SetSecurityDescriptorSddlForm($pipeSecuritySddl)
    $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream(
        $taskName,
        [System.IO.Pipes.PipeDirection]::In,
        1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte,
        [System.IO.Pipes.PipeOptions]::Asynchronous,
        0,
        0,
        $pipeSecurity
    )

    # Start waiting for the wrapper's pipe connection BEFORE starting the task, so the
    # wrapper's client-side Connect() can never race ahead of a server that isn't listening
    # yet.
    $connectResult = $pipeServer.BeginWaitForConnection($null, $null)

    # Same reasoning as the Register-ScheduledTask call above: this budget is whatever's left
    # of the caller's own -TimeoutSeconds, not an independent one, so a timeout here means
    # -TimeoutSeconds ran out, not that Task Scheduler is stuck. Same $setupTimedOut tracking
    # too, and for the identical reason: an abandoned, still-running Start-ScheduledTask call
    # could leave the task freshly started right after cleanup below removes it.
    $startBudget = Get-RemainingSeconds
    $startTimeoutMessage = "devvm: -TimeoutSeconds ${TimeoutSeconds}s expired during Start-ScheduledTask - it had ${startBudget}s left when this step started. If the guest is just slow, a larger -TimeoutSeconds (devvm.py's --timeout) usually fixes this."
    try {
        Invoke-Bounded -TimeoutSeconds $startBudget `
            -TimeoutMessage $startTimeoutMessage `
            -Parameters @{ TaskName = $taskName } `
            -ScriptBlock {
                param($TaskName)
                Start-ScheduledTask -TaskName $TaskName
            }
    } catch {
        if ($_.Exception.Message -eq $startTimeoutMessage) {
            $setupTimedOut = $true
        }
        throw
    }

    # A genuine external-event failure bound, not a poll: the task might never run at all (no
    # interactive session to borrow) or Task Scheduler might hang before the wrapper ever gets
    # far enough to connect; there is no primitive that distinguishes those from "still
    # running" other than waiting up to some bound.
    $signaled = $connectResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds((Get-RemainingSeconds)))
    if (-not $signaled) {
        # No connection was seen before WaitOne's own deadline, so there is no wrapper process
        # known to this script to signal at all - not the stronger claim "no wrapper ever
        # connected": a wrapper could still connect in the gap between this check and the
        # Dispose() right below. Dispose the server pipe FIRST: that's what makes the wrapper's
        # own bounded Connect() (against this now-closed pipe) fail promptly if a late-dispatched
        # task tries to connect after this point, rather than blocking against a pipe still
        # nominally open. A late dispatch that hasn't even started its process yet instead finds
        # $scriptPath already gone (Remove-Item, in the shared `finally` below) and fails to
        # start at all - one that's already running is bounded by its own Connect()/child-
        # WaitForExit deadline regardless (see the wrapper template's comment above).
        $pipeServer.Dispose()
        throw "devvm: unelevated probe did not finish within ${TimeoutSeconds}s - no wrapper connection was seen before the deadline. This is the failure bound, not a hang detector; pass -TimeoutSeconds explicitly if the probe is legitimately this slow.$rdpRecoveryNote$(Get-TranscriptNote)"
    }

    $pipeServer.EndWaitForConnection($connectResult)
    $reader = New-Object System.IO.StreamReader($pipeServer)
    try {
        # No deadline of its own: ReadLine() just blocks until either a full line arrives or
        # the connection is torn down. See the header comment above for why, and for the one
        # residual case (a wrapper stuck but still alive) that isn't bounded by anything here.
        #
        # A torn-down connection can surface here as a clean EOF ($null) or, depending on OS
        # timing if the process dies while a read is already in flight, as a broken-pipe
        # IOException - both mean exactly the same thing (the wrapper is gone without having
        # written anything), so both are treated as $null below rather than as this script's
        # own error.
        try {
            $resultLine = $reader.ReadLine()
        } catch [System.IO.IOException] {
            $resultLine = $null
        }
    } finally {
        $reader.Close()
    }

    if ($null -eq $resultLine) {
        throw "devvm: unelevated probe's wrapper exited without reporting a result - it connected to the pipe but the connection was closed (crashed, was killed, or otherwise exited abnormally) before it wrote an exit code$(Get-TranscriptNote)"
    }
    try {
        $exitCode = [int]$resultLine
    } catch {
        throw "devvm: unelevated probe connected but sent no valid exit code - it may have failed to start under the scheduled task$(Get-TranscriptNote)"
    }

    $output = if (Test-Path $outputPath) { Get-Content -Path $outputPath -Raw } else { "" }
    $errorOutput = if (Test-Path $errorPath) { Get-Content -Path $errorPath -Raw } else { "" }
    if ($errorOutput) {
        # Kept as its own file/section rather than merged back into $output here: merging is
        # exactly the operation that triggers PowerShell's CLIXML-deserializing ProcessStreamReader
        # (see the wrapper template's comment above `1>`/`2>`) - re-merging as plain text after
        # both streams have already safely landed on disk as bytes is not that operation, but the
        # separation is kept anyway so a caller can tell stdout from stderr instead of the two
        # being interleaved in unpredictable order.
        $output = "$output`n--- stderr ---`n$errorOutput"
    }
    # Only appended on a nonzero exit code: on success there is normally nothing here beyond
    # PowerShell's own module-loading noise, and appending it unconditionally made every
    # successful run's output noisier for no benefit. A failing wrapper's own diagnostics (its
    # catch blocks, or Get-TranscriptNote's callers above) still need it - those are exactly
    # the nonzero-exit case.
    if ($exitCode -ne 0) {
        $transcript = Read-WrapperTranscript
        if ($transcript) {
            $output = "$output`n--- wrapper diagnostics ---`n$transcript"
        }
    }
} finally {
    if ($pipeServer) {
        $pipeServer.Dispose()
    }
    if ($setupTimedOut) {
        # Register-/Start-ScheduledTask's own Invoke-Bounded call timed out, which per its own
        # contract (BeginStop, no Dispose - see its docstring) may still be genuinely running on
        # an abandoned runspace right now. Unregistering the task or deleting its files here
        # would race that: a still-in-flight Register-ScheduledTask could re-create the task
        # right after Unregister-ScheduledTask just removed it, or a still-in-flight
        # Start-ScheduledTask could leave it freshly started right after cleanup. Skipping
        # cleanup entirely is the safe side of that race - the cost is a possibly-leaked task
        # and files, surfaced to the human below, not a resurrected task nobody is watching.
        Write-Warning "devvm: setup (Register-/Start-ScheduledTask) timed out with its call possibly still running in the background - skipping cleanup to avoid racing it. The task '$taskName' (and its per-run files under `$env:TEMP`) may be left behind; its name is GUID-suffixed and unique to THIS run, so it will not collide with a later run, but it will accumulate until removed by hand. Once you're sure the timed-out call has actually finished (give it a few minutes), remove it via devvm.py (a bare 'vagrant winrm' lacks its environment):`n`nuv run scripts/devvm.py run windows-x64 -- powershell -NoProfile -Command 'Get-ScheduledTask $taskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:`$false'"
    } else {
        try {
            # 120s, not 30s: real headroom above Stop-/Unregister-ScheduledTask's measured
            # duration on this guest, well above Register-/Start-ScheduledTask's own. A failure
            # bound surfaced to the human via the warning below, not a synchronization interval.
            Invoke-Bounded -TimeoutSeconds 120 `
                -TimeoutMessage "devvm: cleanup (Stop-/Unregister-ScheduledTask) did not complete within 120s - the task '$taskName' may be left behind, possibly still running. Its name is GUID-suffixed and unique to THIS run, so a later run's Register-ScheduledTask -Force will NOT reuse/overwrite it (-Force only overwrites a task registered under the same name) - it will accumulate until removed by hand, routed through devvm.py (a bare 'vagrant winrm' lacks its environment):`n`nuv run scripts/devvm.py run windows-x64 -- powershell -NoProfile -Command 'Get-ScheduledTask $taskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:`$false'" `
                -Parameters @{ TaskName = $taskName } `
                -ScriptBlock {
                    param($TaskName)
                    # Existence-checked first, not -ErrorAction SilentlyContinue on
                    # Unregister-ScheduledTask itself: that used to silently swallow a GENUINE
                    # Unregister failure (as opposed to "there was nothing to unregister")
                    # together with Invoke-Bounded's own (now-fixed) HadErrors bug, so a real
                    # failure never reached the Write-Warning below. Checking existence first,
                    # then using -ErrorAction Stop only once the task is confirmed present, lets
                    # a genuine failure surface through Invoke-Bounded's already-fixed
                    # EndInvoke-unwrap path instead of being swallowed twice over.
                    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                    if ($task) {
                        # Best-effort: Stop-ScheduledTask kills the wrapper's action process if
                        # it's still somehow running (e.g. a late-dispatched task that connected
                        # in the WaitOne-to-Dispose gap above, or one that connected and then
                        # hung) before its transcript/log/output files get deleted below, closing
                        # the window where a still-running wrapper could be caught mid-write to a
                        # file this script is about to remove out from under it.
                        $task | Stop-ScheduledTask -ErrorAction SilentlyContinue
                        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
                    }
                }
        } catch {
            # Best-effort cleanup only: never let a stuck/failed Stop-/Unregister-ScheduledTask
            # replace the real outcome of the probe above (success, or the timeout already
            # thrown).
            Write-Warning $_.Exception.Message
        }
        Remove-Item -Path $outputPath, $errorPath, $scriptPath, $transcriptPath, $logPath, $innerScriptPath -ErrorAction SilentlyContinue
    }
}

if ($output) {
    Write-Output $output
}
# This exit code becomes powershell.exe's own process exit code, which reaches
# `vagrant winrm -c` on the host. But `vagrant winrm -c` itself does not forward the value:
# for a remote command exiting {0, 1, 2, 42, 255}, vagrant's own process exit code is 0 for
# the zero case and exactly 1 for every nonzero case. So only the zero-vs-nonzero distinction
# survives to devvm.py's sys.exit, not the probe's actual exit code (see run_vagrant's own
# comment in devvm_common.py). The inner script that runs the caller's actual command (built
# by devvm.py's build_run_inner with direct=False, decoded to __INNER_SCRIPT_PATH__ above)
# prints the real value itself, via its "devvm: command exited N" diagnostic, whenever that
# command runs to completion and exits nonzero - so it's still visible in the developer's
# shell, just not as this process's own exit status.
exit $exitCode
