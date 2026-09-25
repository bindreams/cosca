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
# the still-open pipe as its very last action. This script (not the wrapper) captures the
# wrapper's PID once that connection is established, via GetNamedPipeClientProcessId against
# the now-connected pipe handle — a real OS query at the moment it's needed, not a value the
# wrapper writes to a file that this script would otherwise have to race to read (so a timeout
# can kill the whole process tree, not just the wrapper's own root). If the
# wrapper dies anywhere after connecting — an unhandled error, being killed, a crash — the OS
# tears down its end of the pipe the moment the process goes away, and the blocking read
# unblocks immediately with EOF, reported as "exited without reporting a result", rather than
# this script waiting out the rest of -TimeoutSeconds for a result that will never arrive.
#
# -TimeoutSeconds bounds every blocking wait in this script and the wrapper it launches, not
# just the pipe connect: Register-ScheduledTask, Start-ScheduledTask, the pipe connect wait,
# the result read that follows it, AND the wrapper's own child process (the caller's actual
# command). This script's own deadline is monotonic (QueryPerformanceCounter-backed, via
# [System.Diagnostics.Stopwatch]::GetTimestamp()/::Frequency), not wall-clock (Get-Date): this
# guest's own clock has been observed to jump by hours across an ordinary reboot (NTP resync),
# which would corrupt a Get-Date-based deadline mid-wait. GetTimestamp()/Frequency are static
# OS-level values, consistent across processes on the same machine with no intervening reboot —
# unlike a Stopwatch *instance*'s Elapsed state, which cannot cross the process boundary to the
# wrapper template below, a raw absolute tick count can: it's baked into that template
# (__DEADLINE_TICKS__) as a fixed grace margin EARLIER than this script's own deadline, not the
# identical tick count - see $WrapperGraceSeconds's own comment below for why.
#
# The result read is bounded the same way as the connect wait: a real completion event
# (ReadLineAsync()'s Task, via its AsyncWaitHandle) raced against the remaining deadline, not a
# poll — a command that deadlocks inside the wrapper (as opposed to the wrapper itself dying,
# which the pipe-EOF liveness signal above already covers) would otherwise hang this script,
# and devvm.py behind it, forever. On expiry it kills the wrapper's whole process tree via the
# PID this script captured right after EndWaitForConnection — which reliably reflects the
# actual connected wrapper process by construction, not a file this script has to hope was
# already written (see Stop-WrapperProcessTree). Because the wrapper's own deadline is earlier
# than this script's, reaching this timeout at all means the wrapper already hit its own bound
# and still didn't finish its own graceful shutdown within the grace margin — the expected case
# is the wrapper's own bound firing first, unblocking this read with a result or a clean EOF
# well before this script's later deadline is ever reached.
#
# The wrapper's own pipe Connect() call (in the here-string below) is bounded too, for a case
# neither of the above covers: a scheduled task that starts running only AFTER this script has
# already given up on the connect wait and moved on — without a bound there, that late
# wrapper's Connect() would block forever against a server pipe this script has by then
# disposed, leaking a process on the guest indefinitely. And the wrapper's own child — the
# caller's actual command, run via cmd.exe — is bounded the same way, against that same wrapper
# deadline: without that bound, that child could outlive both a late-connecting wrapper this
# script has already given up on (nothing left to taskkill it from this side) and this whole
# script being interrupted (Ctrl-C) — nothing else on the guest would ever stop it. On expiry
# the wrapper kills its own child's process tree via taskkill /F /T, the same mechanism this
# script uses on the wrapper itself.
#
# That bound has to cover every blocking Task Scheduler RPC call, not just the pipe waits:
# Register-ScheduledTask, Start-ScheduledTask, and Unregister-ScheduledTask have no timeout
# parameter of their own and can block indefinitely if the Task Scheduler service is stuck —
# a guest has wedged inside Register-ScheduledTask for the better part of an hour with no error
# and no output, because -TimeoutSeconds previously only wrapped the wait *after*
# Start-ScheduledTask fired, not the calls before it. The deadline and Invoke-Bounded (below)
# close that gap: every blocking Task Scheduler call shares the same deadline derived from
# -TimeoutSeconds, run on an in-process runspace via
# [PowerShell]::BeginInvoke()/AsyncWaitHandle.WaitOne() — the same real-completion-event
# pattern as the named-pipe waits, not a poll, and no new process spawned (this guest is
# already resource-constrained under TCG emulation, so avoiding Start-Job's extra
# powershell.exe per call matters here).
Param(
    [Parameter(Mandatory = $true)]
    [string]$EncodedCommand,

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
# No PID file: a file the wrapper writes its own $PID to is inherently racy from this script's
# side (does it exist yet? has the write actually landed?) and was, in practice, only ever
# reliably present at the read-wait timeout site below, not the connect-wait one. Instead, once
# this script's own pipe server has a connected client (EndWaitForConnection), it asks the OS
# directly which process is on the other end via GetNamedPipeClientProcessId - a real query
# against the actual connected handle, not a value some other process wrote down earlier.
Add-Type -Namespace Devvm -Name NativeMethods -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr hObject);
'@
# The wrapper is a whole separate powershell.exe process (see -File $scriptPath below), so it
# does NOT inherit this script's $ErrorActionPreference = Stop — its own default is Continue,
# and an error thrown before the pipe-write step (e.g. by something the wrapper itself does,
# as opposed to the caller's redirected command) prints to that process's own console and is
# otherwise lost: the window this task runs in is only visible in the interactive session
# devvm.py's own host can't see, and closes with the task.
# Start-Transcript on the wrapper captures everything that would have printed there — including
# red terminating/non-terminating error text — to a file this script reads back below,
# regardless of whether the wrapper's main body throws.
$transcriptPath = "$env:TEMP\$taskName.transcript.txt"

# New-ScheduledTaskPrincipal -LogonType Interactive requires an explicit -UserId: it does not
# default to "whoever is currently logged on", so without this Register-ScheduledTask throws
# "missing mandatory parameter: UserId".
#
# Not Win32_ComputerSystem.UserName (the previous check here): that property reports only the
# CONSOLE (session 1) session's owner, and goes blank the moment an RDP logon takes over that
# session - which this tool's own README recommends for interactive debugging. RDP taking over
# a client-SKU console session doesn't log the account out, it keeps driving the same
# interactive session remotely - so 'vagrant' was genuinely still logged in, but this check
# reported no logon to borrow at all (live-verified: an active RDP logon leaves
# Win32_ComputerSystem.UserName empty while Win32_LoggedOnUser/Win32_LogonSession still show
# 'vagrant', LogonType 2). devvm.py's get_windows_interactive_username runs the identical
# check, for the same reason - see its docstring.
#
# Checks two things instead, session-type-agnostic: a Win32_LogonSession linked (via
# Win32_LoggedOnUser) to the 'vagrant' account whose LogonType is Interactive (2),
# RemoteInteractive (10, i.e. RDP), or CachedInteractive (11) - the logon types an actual
# desktop session can present as - falling back to the owner of a running explorer.exe (the
# desktop shell itself) in case that association is ever incomplete for a session type this box
# hasn't been observed in. The result comes back machine-qualified (e.g.
# "DESKTOP-RPVSB2I\vagrant"), which is exactly what -UserId needs.
#
# Fail loudly, not silently substitute a guess, if nobody is logged on
# interactively - a task registered against no session-1 logon to borrow would just fail later
# with a less legible error inside Start-ScheduledTask instead.
$logonTypes = 2, 10, 11
$currentUser = Get-CimInstance -ClassName Win32_LoggedOnUser | Where-Object { $_.Antecedent.Name -eq 'vagrant' } | ForEach-Object {
    $session = Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonId='$($_.Dependent.LogonId)'"
    if ($session -and $logonTypes -contains $session.LogonType) {
        "$($_.Antecedent.Domain)\$($_.Antecedent.Name)"
    }
} | Select-Object -First 1
if (-not $currentUser) {
    $owner = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" |
        ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName GetOwner } |
        Where-Object { $_.ReturnValue -eq 0 } | Select-Object -First 1
    if ($owner) {
        $currentUser = "$($owner.Domain)\$($owner.User)"
    }
}
# RDP recovery guidance is threaded through to the two failure sites below (Register-
# ScheduledTask, and "no wrapper ever connected") where an interactive-but-RDP-redirected
# session can still leave the scheduled task unable to actually run - e.g. the session was
# disconnected (not just redirected) between this check and Start-ScheduledTask firing.
$rdpRecoveryNote = " If this guest was reached over RDP: the scheduled task needs vagrant's session to still be an active, connected desktop, not merely logged on - a disconnected RDP session (closed the client without logging off) can leave a LogonType 10/11 session that this check finds but the scheduled task still can't run in. From inside the guest, 'query session' lists session IDs and 'tscon <id> /dest:console' reattaches a disconnected session to the console; otherwise reboot the guest."
if (-not $currentUser) {
    throw "devvm: no interactive (session 1, console or RDP-redirected) logon for 'vagrant' was found, so there is no logon for a scheduled task to borrow. See windows-account-and-uac.ps1's autologon setup.$rdpRecoveryNote"
}

# Shared monotonic deadline for every blocking wait THIS script itself makes (Register-,
# Start-, the pipe connect wait, the result read — see Invoke-Bounded and the header comment
# above for why this is Stopwatch/QPC-based rather than Get-Date). One shared deadline instead
# of a fresh $TimeoutSeconds per phase bounds total worst-case runtime to ~$TimeoutSeconds, not
# some multiple of it.
$deadlineTicks = [System.Diagnostics.Stopwatch]::GetTimestamp() + [long]($TimeoutSeconds * [System.Diagnostics.Stopwatch]::Frequency)

# The wrapper (a separate process — see __DEADLINE_TICKS__ below) gets its OWN deadline, a
# fixed grace margin earlier than $deadlineTicks above, not the identical tick count. With one
# shared deadline, the outer script's own read-wait and the wrapper's internal bound (Connect,
# then its child's WaitForExit) expire at the same instant — which one actually fires first is
# a race, so an ordinary timeout could have this script taskkill the wrapper's whole process
# tree (see the read-wait timeout below) while the wrapper was already mid-way through its own
# graceful shutdown (killing its own child, flushing its transcript, writing its pipe result),
# duplicating that work and discarding whatever the wrapper's own -1-sentinel result/transcript
# would otherwise have reported. Giving the wrapper a deadline this much earlier instead makes
# its own graceful shutdown the expected outcome: by the time this script's later read-wait
# deadline could fire, the wrapper's pipe write/close (or the OS tearing the pipe down if it
# dies outright) has already unblocked that read with a result or a clean EOF. This script's
# own read-wait timeout is then reachable only if the wrapper hasn't even finished its own
# graceful shutdown within the margin below - a genuine hang, not the expected case. The margin
# has to cover the wrapper's own worst-case cleanup after its deadline hits: taskkill of its
# child (bounded 30s, see the wrapper template) plus Stop-Transcript and the pipe write/close
# (both fast) - 45s leaves real headroom above that 30s bound, not another too-tight guess.
$WrapperGraceSeconds = 45
$wrapperDeadlineTicks = $deadlineTicks - [long]($WrapperGraceSeconds * [System.Diagnostics.Stopwatch]::Frequency)

function Get-RemainingSeconds {
    $remaining = ($deadlineTicks - [System.Diagnostics.Stopwatch]::GetTimestamp()) / [double][System.Diagnostics.Stopwatch]::Frequency
    if ($remaining -lt 0) { return 0 }
    return [Math]::Ceiling($remaining)
}

# Best-effort: the wrapper's Start-Transcript writes incrementally, so even a killed-on-timeout
# wrapper has usually flushed something useful here - read it whenever it exists, on both the
# success and timeout paths below, rather than only on success.
function Read-WrapperTranscript {
    if (Test-Path $transcriptPath) {
        try { return Get-Content -Path $transcriptPath -Raw } catch { return "" }
    }
    return ""
}

function Get-TranscriptNote {
    # Whatever the wrapper itself printed or threw, formatted for appending to a thrown error
    # message, or "" if there's nothing to add.
    $transcript = Read-WrapperTranscript
    if (-not $transcript) { return "" }
    return "`n--- wrapper transcript (captures anything the wrapper itself printed or threw) ---`n$transcript"
}

function Stop-WrapperProcessTree {
    <#
      Best-effort: taskkill the wrapper's whole process tree via $TaskPid, a client PID this
      script obtained from GetNamedPipeClientProcessId against its own connected pipe server
      handle (see the call site right after EndWaitForConnection below) - not a file the
      wrapper wrote, so there is no "does the file exist yet, and is the write complete" race.
      Only called from the read-wait timeout site, which runs after EndWaitForConnection has
      already succeeded - but $TaskPid can still be 0 there if GetNamedPipeClientProcessId
      failed or the process had already exited by the time this script tried to pin it; guarded
      below, not assumed away. The connect-wait timeout site (no client ever connected) has no
      PID to give this function at all - see its own comment - so it doesn't call this function.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$TaskPid
    )
    if ($TaskPid -eq 0) {
        # GetNamedPipeClientProcessId either failed or the process had already exited by the
        # time we tried to pin it (see the OpenProcess call site below) - PID 0 is the System
        # Idle Process, never a real target.
        Write-Warning "devvm: no usable wrapper PID to taskkill - refusing to touch PID 0."
        return
    }
    # taskkill.exe via Start-Process + WaitForExit(30000): bounded (fixed 30s, independent of
    # the main deadline which has already elapsed here - this is best-effort cleanup, not a
    # new failure to report) and, launched this way rather than invoked directly, its stderr
    # goes to a file instead of into this script's own error stream - sidestepping the
    # PowerShell 5.1 hazard where ANY stderr from a directly-invoked native command sets $? to
    # $false under $ErrorActionPreference = "Stop", which would otherwise turn a successful
    # kill into a NativeCommandError masking the real timeout error thrown by the caller (the
    # same hazard windows-rust.ps1 documents and works around for a direct invocation).
    $killOutPath = "$env:TEMP\$taskName.taskkill.out"
    $killErrPath = "$env:TEMP\$taskName.taskkill.err"
    try {
        $killProcess = Start-Process -FilePath "taskkill.exe" -ArgumentList @("/F", "/T", "/PID", $TaskPid) `
            -PassThru -NoNewWindow -RedirectStandardOutput $killOutPath -RedirectStandardError $killErrPath
        if (-not $killProcess.WaitForExit(30000)) {
            $killProcess | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    } finally {
        Remove-Item -Path $killOutPath, $killErrPath -ErrorAction SilentlyContinue
    }
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
        $ps.EndInvoke($asyncResult) | Out-Null
        if ($ps.HadErrors) {
            throw $ps.Streams.Error[0].Exception
        }
    } finally {
        $ps.Dispose()
    }
}

# The scheduled task's action: decode and run the caller's command, redirecting its combined
# output to a file (a scheduled task has no console/pipe devvm.py can read directly) and
# recording its real exit code, then report that exit code back over a named pipe this script
# is already waiting on.
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
# $exitCode starts at -1 (not 0) so that if the wrapper crashes before the caller's command
# ever runs, the caller sees a nonzero/sentinel status rather than a false "succeeded". Connect()
# is the wrapper's very first action, bounded by this script's own deadline minus
# $WrapperGraceSeconds (see that constant's own comment for why it's earlier, not identical) -
# baked into this template as raw QPC ticks (__DEADLINE_TICKS__, see the header comment for why
# Stopwatch/QPC rather than wall-clock), not a millisecond duration computed once at
# Register-ScheduledTask time. A duration frozen at registration time is wrong by however long
# Task Scheduler takes to actually dispatch the task: the wrapper instead computes its own
# remaining milliseconds from this absolute tick count right when it needs it (both for
# Connect() and later for its own child's WaitForExit()), so a dispatch delay shrinks its own
# budget correctly instead of leaving it working against a stale allowance computed on this
# script's clock, at a different moment, in a different process. In the ordinary case a real
# server is already listening before Start-ScheduledTask ever fires (see that ordering below),
# so Connect() returns almost immediately. The bound exists for the case that ordering doesn't
# cover: a task that starts running only AFTER the outer script has already given up on its own
# connect wait and disposed the server pipe. An unbounded Connect() there would block forever
# against a pipe with no listener, leaking this wrapper (and Task Scheduler's record of it
# running) on the guest indefinitely; with the bound, it times out, falls into the outer catch
# below, and this process exits.
#
# The pipe connection is kept open for the wrapper's entire life and only written to once, at
# the very end - not reopened per write. That means the outer script's read of this connection
# doubles as the wrapper's liveness signal: if the wrapper dies for any reason after connecting
# (an error escaping the inner try/catch, being killed, a crash) without ever reaching the
# final WriteLine, the OS tears down this end of the pipe as the process exits, and the outer
# script's blocking read unblocks immediately with EOF - a real, immediate signal, not another
# timeout to wait out. If instead the wrapper is merely slow - its command hasn't finished, the
# pipe is still open, nothing has died - the outer script's read is bounded by that same
# remaining deadline and kills this whole process tree via taskkill /T on expiry (see
# Stop-WrapperProcessTree there). The outer try/catch here only guards the connect step itself;
# the inner try/catch/finally guards the caller's command and guarantees the pipe write happens
# exactly once for every way the inner block can end.
$wrapperTemplate = @'
Start-Transcript -Path '__TRANSCRIPT_PATH__' | Out-Null
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
        # nothing else on the guest would ever stop it. On expiry this kills only the immediate cmd.exe
        # child's own process tree (via taskkill /F /T, same as the outer script's
        # Stop-WrapperProcessTree), not any further descendant it may have already detached.
        if ($childProcess.WaitForExit((Get-RemainingMs))) {
            $exitCode = $childProcess.ExitCode
        } else {
            Write-Host "devvm wrapper: caller's command did not finish within its deadline - killing its process tree (PID $($childProcess.Id))"
            try {
                $killPsi = New-Object System.Diagnostics.ProcessStartInfo
                $killPsi.FileName = 'taskkill.exe'
                $killPsi.Arguments = "/F /T /PID $($childProcess.Id)"
                $killPsi.UseShellExecute = $false
                $killPsi.CreateNoWindow = $true
                $killProcess = [System.Diagnostics.Process]::Start($killPsi)
                $killProcess.WaitForExit(30000) | Out-Null
            } catch {
                Write-Host "devvm wrapper: taskkill of the caller's command failed: $($_.Exception.Message)"
            }
            # $exitCode stays at its -1 sentinel: the command never actually finished, so there
            # is no real exit code to report.
        }
    } catch {
        Write-Host "devvm wrapper: caught $($_.Exception.GetType().FullName): $($_.Exception.Message)"
        Write-Host $_.ScriptStackTrace
    }
} catch {
    Write-Host "devvm wrapper: pipe connect failed: $($_.Exception.Message)"
} finally {
    # Stopped BEFORE the pipe write below, not after: the outer script's read of the pipe is
    # what unblocks it to go read this transcript file back (see Read-WrapperTranscript and its
    # call sites) - stopping the transcript first guarantees the file is fully flushed and closed
    # by the time that read can possibly happen, instead of racing it. Wrapped in its own
    # try/catch so a failing Stop-Transcript can never prevent the pipe write below - that is
    # what the outer script actually depends on for correctness.
    try {
        Stop-Transcript | Out-Null
    } catch {
        Write-Host "devvm wrapper: Stop-Transcript failed: $($_.Exception.Message)"
    }
    if ($writer) {
        try {
            $writer.WriteLine($exitCode)
            $writer.Flush()
            $writer.Close()
        } catch {
            Write-Host "devvm wrapper: pipe signal failed: $($_.Exception.Message)"
        }
    }
    if ($pipe) {
        $pipe.Close()
    }
}
'@

# Baked into the wrapper template as raw QPC ticks - an absolute instant on this machine's
# monotonic clock, not a millisecond duration computed here: the wrapper is a whole separate
# process that may not start running until well after this point (the late-dispatched-task case
# described above), and a fixed duration captured now would already be stale by however long
# that dispatch delay turns out to be. The wrapper computes its OWN remaining time against this
# same tick count, via the same Stopwatch.Frequency (a machine constant, not something that
# needs to cross the process boundary) - not a value computed on this script's clock at a
# different moment in a different process.
$taskCommand = $wrapperTemplate.
    Replace('__ENCODED_COMMAND__', $EncodedCommand).
    Replace('__OUTPUT_PATH__', $outputPath).
    Replace('__ERROR_PATH__', $errorPath).
    Replace('__INNER_SCRIPT_PATH__', $innerScriptPath).
    Replace('__TASK_NAME__', $taskName).
    Replace('__TRANSCRIPT_PATH__', $transcriptPath).
    Replace('__DEADLINE_TICKS__', $wrapperDeadlineTicks.ToString())
Set-Content -Path $scriptPath -Value $taskCommand -Encoding UTF8

# Register-ScheduledTask with NO -Trigger at all: this task is only ever fired on demand via
# Start-ScheduledTask below, so there is no time-of-day value anywhere in this path, and no
# midnight-wraparound failure mode to guard against.
try {
    Invoke-Bounded -TimeoutSeconds (Get-RemainingSeconds) `
        -TimeoutMessage "devvm: Register-ScheduledTask did not complete within ${TimeoutSeconds}s - Task Scheduler may be stuck." `
        -Parameters @{ TaskName = $taskName; ScriptPath = $scriptPath; UserId = $currentUser } `
        -ScriptBlock {
            param($TaskName, $ScriptPath, $UserId)
            # -ExecutionPolicy Bypass: the LIMITED-run-level principal's own effective execution
            # policy is untested/unknown territory (a different, filtered token than the
            # High-integrity WinRM session that registers this task) - forcing Bypass for this
            # one task action removes that as a variable entirely rather than relying on
            # whatever CurrentUser/LocalMachine policy happens to be configured on the guest.
            $action = New-ScheduledTaskAction -Execute "powershell" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ScriptPath"
            $principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
            # Without this, Task Scheduler applies its own default ExecutionTimeLimit (commonly
            # 72 hours) on top of -TimeoutSeconds - normally moot, but a caller passing a long
            # --timeout close to or past that would hit a second, uncoordinated limit instead of
            # the one this script actually reports and explains. Zero means unlimited: this
            # script's own deadline is the only bound that should apply.
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
            Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        }
} catch {
    throw "devvm: Register-ScheduledTask failed: $($_.Exception.Message) - is there an active interactive (session 1) logon for it to borrow? See windows-account-and-uac.ps1's autologon setup.$rdpRecoveryNote"
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
# Holds a real OS handle to the wrapper's process object once its PID is known (see the
# EndWaitForConnection block below), so that PID number cannot be reassigned to a different,
# unrelated process by the OS for as long as this handle stays open - a kernel-level guarantee,
# not a best-effort narrowing of the race window. Declared here, not inside the try, so the
# overall finally below can always safely check/close it, including on the connect-timeout path
# where it's never assigned.
$wrapperProcessHandle = [IntPtr]::Zero
try {
    # Start waiting for the wrapper's pipe connection BEFORE starting the task, so the
    # wrapper's client-side Connect() can never race ahead of a server that isn't listening
    # yet.
    $connectResult = $pipeServer.BeginWaitForConnection($null, $null)

    Invoke-Bounded -TimeoutSeconds (Get-RemainingSeconds) `
        -TimeoutMessage "devvm: Start-ScheduledTask did not complete within ${TimeoutSeconds}s - Task Scheduler may be stuck." `
        -Parameters @{ TaskName = $taskName } `
        -ScriptBlock {
            param($TaskName)
            Start-ScheduledTask -TaskName $TaskName
        }

    # A genuine external-event failure bound, not a poll: the task might never run at all (no
    # interactive session to borrow) or Task Scheduler might hang before the wrapper ever gets
    # far enough to connect; there is no primitive that distinguishes those from "still
    # running" other than waiting up to some bound.
    $signaled = $connectResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds((Get-RemainingSeconds)))
    if (-not $signaled) {
        # No client ever connected here, so there is no PID GetNamedPipeClientProcessId could
        # give Stop-WrapperProcessTree - nothing to taskkill yet. Dispose the server pipe FIRST,
        # before doing anything else: that's what makes the wrapper's own bounded Connect()
        # (against this now-closed pipe) fail promptly if a late-dispatched task tries to connect
        # after this point, rather than racing a kill attempt against a pipe still nominally open.
        # A leftover scheduled-task process with nothing left to connect to will hit its own
        # Connect() bound (see the wrapper template's comment) and exit on its own - defense in
        # depth, not the only thing standing between this and a late dispatch reading a deleted
        # $scriptPath: the shared `finally` below also actively Stop-ScheduledTask's this task
        # by name before deleting any files, closing that race outright rather than relying on
        # this bound alone.
        $pipeServer.Dispose()
        throw "devvm: unelevated probe did not finish within ${TimeoutSeconds}s - no wrapper ever connected. This is the failure bound, not a hang detector; pass -TimeoutSeconds explicitly if the probe is legitimately this slow.$rdpRecoveryNote$(Get-TranscriptNote)"
    }

    $pipeServer.EndWaitForConnection($connectResult)
    # A real OS query against the now-connected handle, not a value some other process wrote to
    # a file this script would otherwise have to race to read - see the file-level comment above.
    # Only obtainable from here on: before EndWaitForConnection returns, no client has connected,
    # so there is nothing for this call to report (see the connect-timeout branch above).
    [uint32]$wrapperPid = 0
    $gotPid = [Devvm.NativeMethods]::GetNamedPipeClientProcessId($pipeServer.SafePipeHandle.DangerousGetHandle(), [ref]$wrapperPid)
    if ($gotPid -and $wrapperPid -ne 0) {
        # PROCESS_QUERY_LIMITED_INFORMATION (0x1000) is enough to hold the reference; taskkill
        # opens its own handle by PID when actually invoked, this one exists purely to keep
        # that PID number allocated to the right process until then (see the declaration above).
        $wrapperProcessHandle = [Devvm.NativeMethods]::OpenProcess(0x1000, $false, $wrapperPid)
        if ($wrapperProcessHandle -eq [IntPtr]::Zero) {
            # Already exited in the gap between GetNamedPipeClientProcessId and this call -
            # nothing left to pin, and nothing left to taskkill either.
            $wrapperPid = 0
        }
    } else {
        Write-Warning "devvm: GetNamedPipeClientProcessId did not return a usable PID for the connected wrapper - a later timeout would have nothing to taskkill."
        $wrapperPid = 0
    }
    $reader = New-Object System.IO.StreamReader($pipeServer)
    try {
        # ReadLineAsync() blocks until either a full line arrives or the connection is torn
        # down, same as the synchronous ReadLine() this replaced, but its returned Task
        # implements IAsyncResult, so it can be raced against the remaining deadline via
        # AsyncWaitHandle.WaitOne() - the same real-completion-event pattern used for the
        # connect wait and every Invoke-Bounded call above, not a poll. This is what actually
        # bounds a deadlocked caller command: the wrapper dying is already covered by the EOF
        # case below, but a command that just never returns needs its own bound, or this
        # script (and devvm.py behind it) would wait forever.
        $readTask = $reader.ReadLineAsync()
        $remainingForRead = Get-RemainingSeconds
        $readSignaled = $remainingForRead -gt 0 -and
            ([IAsyncResult]$readTask).AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($remainingForRead))
        if (-not $readSignaled) {
            # Unlike the connect-wait timeout above, a real PID is known here: the wrapper's
            # Connect() has already returned (that's how we got past EndWaitForConnection) and
            # this script captured its PID right then via GetNamedPipeClientProcessId, above.
            Stop-WrapperProcessTree -TaskPid $wrapperPid
            throw "devvm: unelevated probe did not finish within ${TimeoutSeconds}s - killed its whole process tree. This is the failure bound, not a hang detector; pass -TimeoutSeconds explicitly if the probe is legitimately this slow.$(Get-TranscriptNote)"
        }
        # A torn-down connection can surface here as a clean EOF ($null) or, depending on OS
        # timing if the process dies while a read is already in flight, as a broken-pipe
        # IOException - both mean exactly the same thing (the wrapper is gone without having
        # written anything), so both are treated as $null below rather than as this script's
        # own error. GetAwaiter().GetResult() (rather than .Result) surfaces that IOException
        # directly instead of wrapped in an AggregateException, so the existing typed catch
        # still matches it.
        try {
            $resultLine = $readTask.GetAwaiter().GetResult()
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
    # successful run's output noisier for no benefit. A failing wrapper's own Write-Host lines
    # (its catch blocks, or Get-TranscriptNote's callers above) still need it - those are
    # exactly the nonzero-exit case.
    if ($exitCode -ne 0) {
        $transcript = Read-WrapperTranscript
        if ($transcript) {
            $output = "$output`n--- wrapper transcript ---`n$transcript"
        }
    }
} finally {
    $pipeServer.Dispose()
    if ($wrapperProcessHandle -ne [IntPtr]::Zero) {
        [void][Devvm.NativeMethods]::CloseHandle($wrapperProcessHandle)
    }
    try {
        # Stopping BEFORE unregistering/deleting closes a race the connect-timeout path above
        # otherwise leaves open: Start-ScheduledTask having returned only means Task Scheduler
        # accepted the request, not that its process has actually reached (or even started)
        # this script's own Connect() - a late dispatch could still be about to open $scriptPath
        # after Remove-Item below has already deleted it, failing on a file-not-found instead of
        # the clean "hit its own Connect() bound" exit the no-PID case can't otherwise guarantee.
        # Stop-ScheduledTask acts on the task by name, not a PID, so it also covers that
        # connect-timeout path, where no PID was ever captured to taskkill. A no-op if nothing is
        # running (-ErrorAction SilentlyContinue swallows "task is not currently running").
        Invoke-Bounded -TimeoutSeconds 30 `
            -TimeoutMessage "devvm: Stop-ScheduledTask did not complete within 30s during cleanup - proceeding to unregister/delete anyway." `
            -Parameters @{ TaskName = $taskName } `
            -ScriptBlock {
                param($TaskName)
                Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            }
    } catch {
        # Best-effort: a stuck Stop-ScheduledTask must not block Unregister-ScheduledTask/
        # Remove-Item below from still running.
        Write-Warning $_.Exception.Message
    }
    try {
        # 120s, not 30s: Unregister-ScheduledTask on this guest routinely takes ~32s even when
        # Register-/Start-ScheduledTask for the same task each took under 3s - a fixed 30s bound
        # was clipping real, successful cleanups essentially every time, which is why plain
        # `Get-ScheduledTask` kept finding leftover DevvmUnelevatedRun-* tasks from runs that had
        # otherwise succeeded. 120s is a failure bound surfaced to the human via the warning
        # below, not a synchronization interval - real margin above the ~32s baseline, not
        # another too-tight guess.
        Invoke-Bounded -TimeoutSeconds 120 `
            -TimeoutMessage "devvm: Unregister-ScheduledTask did not complete within 120s during cleanup - the task '$taskName' is left behind. Its name is GUID-suffixed and unique to THIS run, so a later run's Register-ScheduledTask -Force will NOT reuse/overwrite it (-Force only overwrites a task registered under the same name) - it will accumulate until removed by hand: Get-ScheduledTask 'DevvmUnelevatedRun-*' | Unregister-ScheduledTask." `
            -Parameters @{ TaskName = $taskName } `
            -ScriptBlock {
                param($TaskName)
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            }
    } catch {
        # Best-effort cleanup only: never let a stuck/failed Unregister-ScheduledTask replace
        # the real outcome of the probe above (success, or the timeout already thrown).
        Write-Warning $_.Exception.Message
    }
    Remove-Item -Path $outputPath, $errorPath, $scriptPath, $transcriptPath, $innerScriptPath -ErrorAction SilentlyContinue
}

if ($output) {
    Write-Output $output
}
# This exit code becomes powershell.exe's own process exit code, which reaches
# `vagrant winrm -c` on the host. But `vagrant winrm -c` itself does not forward the value:
# for a remote command exiting {0, 1, 2, 42, 255}, vagrant's own process exit code is 0 for
# the zero case and exactly 1 for every nonzero case. So only the zero-vs-nonzero distinction
# survives to devvm.py's sys.exit, not the probe's actual exit code. The inner script that
# runs the caller's actual command (built by devvm.py's build_run_inner with direct=False,
# decoded to __INNER_SCRIPT_PATH__ above) prints the real value itself, via its
# "devvm: command exited N" diagnostic, whenever that command runs to completion and exits
# nonzero - so it's still visible in the developer's shell, just not as this process's own
# exit status.
#
# That diagnostic requires the inner script to reach its own `exit $__devvmExit` - two
# separate things can prevent that, and only one of them is what leaves $exitCode here at its
# -1 sentinel:
#   - The wrapper's own child-process wait (`$childProcess.WaitForExit(...)`, inside
#     $wrapperTemplate above) expiring: the inner script's process tree gets taskkilled mid-run,
#     never reaching its own exit line, so $exitCode stays -1 and is what reaches `exit
#     $exitCode` here. The "did not finish within its deadline" message on the wrapper's own
#     transcript is what explains that case.
#   - THIS script's own connect/read timeouts (the `throw`s above, e.g. "no wrapper ever
#     connected" / "killed its whole process tree") firing instead: those are unhandled
#     exceptions that terminate this script before it ever reaches this line at all - `exit
#     $exitCode` never runs, and the -1 sentinel is irrelevant to that path.
exit $exitCode
