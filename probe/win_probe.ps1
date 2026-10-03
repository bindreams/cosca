param([string]$Mode = "outer", [string]$Out = "")
$ErrorActionPreference = "Stop"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class P {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct SEI { public int cbSize; public uint fMask; public IntPtr hwnd; public string lpVerb; public string lpFile;
    public string lpParameters; public string lpDirectory; public int nShow; public IntPtr hInstApp; public IntPtr lpIDList;
    public string lpClass; public IntPtr hkeyClass; public uint dwHotKey; public IntPtr hIcon; public IntPtr hProcess; }
  [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool ShellExecuteExW(ref SEI i);
  [DllImport("ntdll.dll")] public static extern int NtQueryObject(IntPtr h, int cls, byte[] buf, int len, out int ret);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetExitCodeProcess(IntPtr h, out uint code);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern int GetProcessId(IntPtr h);
  [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetTokenInformation(IntPtr t, int cls, out int v, int len, out int ret);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr CreateJobObjectW(IntPtr a, IntPtr n);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AssignProcessToJobObject(IntPtr j, IntPtr p);
  public static string Run(string file, string args) {
    var i = new SEI(); i.cbSize = Marshal.SizeOf(typeof(SEI)); i.fMask = 0x40 | 0x100; // NOCLOSEPROCESS | NOASYNC
    i.lpVerb = "runas"; i.lpFile = file; i.lpParameters = args; i.nShow = 0;
    if (!ShellExecuteExW(ref i)) return "ShellExecuteEx failed: " + Marshal.GetLastWin32Error();
    var b = new byte[56]; int r; int st = NtQueryObject(i.hProcess, 0, b, b.Length, out r);
    uint access = BitConverter.ToUInt32(b, 4);
    string s = String.Format("child pid {0}; NtQueryObject status 0x{1:X}; GrantedAccess 0x{2:X8} (TERMINATE bit 0x1: {3}, SYNCHRONIZE 0x100000: {4}, QUERY_LIMITED 0x1000: {5})",
      GetProcessId(i.hProcess), st, access, (access & 1) != 0, (access & 0x100000) != 0, (access & 0x1000) != 0);
    IntPtr tok; int elev = -1, ret2;
    if (OpenProcessToken(i.hProcess, 0x8, out tok)) { if (!GetTokenInformation(tok, 20, out elev, 4, out ret2)) elev = -2; }
    s += "; child TokenElevation=" + (elev == -1 ? ("OpenProcessToken failed " + Marshal.GetLastWin32Error()) : elev.ToString());
    IntPtr job = CreateJobObjectW(IntPtr.Zero, IntPtr.Zero);
    s += "; AssignProcessToJobObject -> " + (AssignProcessToJobObject(job, i.hProcess) ? "OK" : ("FAILED " + Marshal.GetLastWin32Error()));
    bool t = TerminateProcess(i.hProcess, 7); int e = Marshal.GetLastWin32Error();
    s += "; TerminateProcess -> " + (t ? "OK" : ("FAILED error " + e));
    uint w = WaitForSingleObject(i.hProcess, 30000); uint code; GetExitCodeProcess(i.hProcess, out code);
    s += String.Format("; wait {0}; exit code {1}", w, code);
    return s;
  }
}
"@
function Facts {
  $k = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  $p = Get-ItemProperty $k
  $il = (whoami /groups | Select-String "Mandatory Label") -join " | "
  "user=$(whoami) EnableLUA=$($p.EnableLUA) ConsentPromptBehaviorAdmin=$($p.ConsentPromptBehaviorAdmin) session=$([System.Diagnostics.Process]::GetCurrentProcess().SessionId) IL=[$il]"
}
$payload = "$env:SystemRoot\System32\waitfor.exe"
$payloadArgs = "/t 60 kefNeverSignalled"  # blocks on a named signal nobody sends; /t is only the failure bound
if ($Mode -eq "outer") {
  "== outer (the job's own process)"; Facts; "build: " + [Environment]::OSVersion.VersionString
  "== runas from the job's own process:"; [P]::Run($payload, $payloadArgs)
  # Elevate without a prompt, so a medium-IL caller's runas can complete unattended.
  Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ConsentPromptBehaviorAdmin 0
  # runneradmin is High already; a fresh local admin logged on with -Credential gets the filtered
  # Medium token (the shape of PR #552's elevation lane), and ConsentPromptBehaviorAdmin=0 elevates.
  $dir = "C:\kefprobe"; New-Item -ItemType Directory -Force $dir | Out-Null
  icacls $dir /grant "Everyone:(OI)(CI)F" | Out-Null
  Copy-Item $PSCommandPath "$dir\win_probe.ps1"
  $pw = (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })) + "aA1!"
  Write-Host "::add-mask::$pw"
  $sec = ConvertTo-SecureString $pw -AsPlainText -Force
  New-LocalUser kefadm -Password $sec -AccountNeverExpires | Out-Null
  Add-LocalGroupMember -Group Administrators -Member kefadm
  $out = "$dir\kef-inner.txt"
  try {
    $cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\kefadm", $sec)
    $pr = Start-Process powershell.exe -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File","$dir\win_probe.ps1","-Mode","inner","-Out",$out -Credential $cred -LoadUserProfile -WorkingDirectory $dir -Wait -PassThru
    "== runas from a fresh admin's filtered logon (kefadm), exit $($pr.ExitCode):"
    if (Test-Path $out) { Get-Content $out }
  } catch { "== inner failed: $_" } finally { Remove-LocalUser kefadm -ErrorAction Continue }
} else {
  try {
    $r = @("inner: " + (Facts)); $r += "inner runas: " + [P]::Run($payload, $payloadArgs)
  } catch { $r += "inner error: $_" }
  $r | Set-Content "$Out.tmp"
  Move-Item "$Out.tmp" $Out
}
