# Usage: run-nextest.ps1 <name> <command> [args...]
#
# The Windows counterpart of run-nextest.py: runs a nextest command, then moves the JUnit file of
# the profile in $env:NEXTEST_PROFILE (the shared `ci` when unset) to $env:RUNNER_TEMP/junit/<name>.xml. It is not bash because Git bash's MSYS runtime
# enables SeBackupPrivilege and SeRestorePrivilege in its token, and the tests inherit it (measured:
# `whoami /priv` shows them Disabled under pwsh, Enabled under bash). An enabled backup privilege
# bypasses a DACL deny, so the two ACL tests in `resolve_windows_tests` fail their precondition
# there (#495). Re-launching pwsh from bash does not help: the token is inherited.
#
# Teardown: the command runs in a Job Object with KILL_ON_JOB_CLOSE. This script holds the job's only
# handle but is not a member; it re-runs itself, and that inner copy joins the job before it starts
# the command, so nothing the command starts can be outside it. When the command ends, or when the
# runner's timeout stops this script (the `finally` block), the job is terminated and this script
# waits until it holds no process. If the runner kills this script outright instead, the closed
# handle makes the kernel kill the job. So no process of the command outlives this script, and a
# later step finds none: not a `cosca_testbin.exe` holding its image, nor a writer of the JUnit file.
# It covers processes created inside the job; `Start-Process -Credential` (the elevation lane's
# throwaway administrator) is created by the secondary logon service, outside it. A killed script
# publishes nothing.
# No param block: the command's own arguments (`-E`, `--target`) must not be bound as parameters.
$ErrorActionPreference = 'Stop'

# Only the limit flags and the process count are used, so the two structs are raw buffers:
# JOBOBJECT_EXTENDED_LIMIT_INFORMATION is 144 bytes with LimitFlags at offset 16 (64-bit), and
# JOBOBJECT_BASIC_ACCOUNTING_INFORMATION is 48 bytes with ActiveProcesses at offset 40.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class CoscaJob
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenJobObjectW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    static void Check(bool ok, string what)
    {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), what);
    }

    public static IntPtr Create(string name)
    {
        if (!Environment.Is64BitProcess) throw new PlatformNotSupportedException("a 64-bit process is required");
        IntPtr job = CreateJobObjectW(IntPtr.Zero, name);
        Check(job != IntPtr.Zero, "CreateJobObject");
        IntPtr info = Marshal.AllocHGlobal(144);
        try
        {
            for (int i = 0; i < 144; i += 8) Marshal.WriteInt64(info, i, 0);
            Marshal.WriteInt32(info, 16, 0x2000); // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            Check(SetInformationJobObject(job, 9, info, 144), "SetInformationJobObject");
        }
        finally { Marshal.FreeHGlobal(info); }
        return job;
    }

    public static void JoinSelf(string name)
    {
        IntPtr job = OpenJobObjectW(0x1, false, name); // JOB_OBJECT_ASSIGN_PROCESS
        Check(job != IntPtr.Zero, "OpenJobObject");
        Check(AssignProcessToJobObject(job, GetCurrentProcess()), "AssignProcessToJobObject");
    }

    public static int Active(IntPtr job)
    {
        IntPtr info = Marshal.AllocHGlobal(48);
        try
        {
            Check(QueryInformationJobObject(job, 1, info, 48, IntPtr.Zero), "QueryInformationJobObject");
            return Marshal.ReadInt32(info, 40);
        }
        finally { Marshal.FreeHGlobal(info); }
    }

    public static void Terminate(IntPtr job)
    {
        Check(TerminateJobObject(job, 1), "TerminateJobObject");
    }
}
'@

if ($env:COSCA_RUN_NEXTEST_JOB) {
    # Inner copy: join the job, then run the command.
    $jobName = $env:COSCA_RUN_NEXTEST_JOB
    $argv = @(ConvertFrom-Json $env:COSCA_RUN_NEXTEST_ARGV)
    Remove-Item Env:COSCA_RUN_NEXTEST_JOB, Env:COSCA_RUN_NEXTEST_ARGV
    [CoscaJob]::JoinSelf($jobName)

    # A step may select its own profile (the elevation step does); the default is the shared `ci`.
    if (-not $env:NEXTEST_PROFILE) { $env:NEXTEST_PROFILE = 'ci' }

    $name = $argv[0]
    $command = @($argv[1..($argv.Count - 1)])
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
}

# Outer copy: own the job, run the inner copy in it, and end the job.
$env:COSCA_RUN_NEXTEST_JOB = "Local\cosca-run-nextest-$([guid]::NewGuid())"
$job = [CoscaJob]::Create($env:COSCA_RUN_NEXTEST_JOB)
$env:COSCA_RUN_NEXTEST_ARGV = ConvertTo-Json -Compress -InputObject @($args)
try {
    & ([Environment]::ProcessPath) -NoProfile -File $PSCommandPath
    $status = $LASTEXITCODE
} finally {
    [CoscaJob]::Terminate($job)
    # Terminating is asynchronous; the job holds a process until the kernel has finished with it.
    while ([CoscaJob]::Active($job) -ne 0) { Start-Sleep -Milliseconds 50 }
}
exit $status
