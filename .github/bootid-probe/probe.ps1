# Throwaway probe: which Windows values change per boot? Prints key=value lines.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File probe.ps1 [-KusdDump <path>]
param([string]$KusdDump = "")
$ErrorActionPreference = "Continue"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class BootProbe {
    [DllImport("ntdll.dll")] public static extern int NtQuerySystemInformation(int cls, byte[] buf, int len, out int ret);
    [DllImport("ntdll.dll")] public static extern int NtQueryInformationProcess(IntPtr h, int cls, byte[] buf, int len, out int ret);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr GetModuleHandleW(string name);
    [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
    [DllImport("kernel32.dll")] public static extern bool QueryUnbiasedInterruptTime(out ulong t);
    public static byte[] Kusd(int len) { byte[] b = new byte[len]; Marshal.Copy(new IntPtr(0x7FFE0000), b, 0, len); return b; }
    public static string SysInfo(int cls, int len, out byte[] buf) {
        buf = new byte[len]; int ret;
        int st = NtQuerySystemInformation(cls, buf, len, out ret);
        return "0x" + st.ToString("X8") + " ret=" + ret;
    }
    public static string ProcInfo(int cls, out byte[] buf) {
        int ret; buf = new byte[96];
        int st = NtQueryInformationProcess(GetCurrentProcess(), cls, buf, buf.Length, out ret);
        if (ret > buf.Length) { buf = new byte[ret]; st = NtQueryInformationProcess(GetCurrentProcess(), cls, buf, buf.Length, out ret); }
        return "0x" + st.ToString("X8") + " ret=" + ret;
    }
}
"@

function Out-KV($k, $v) { Write-Output ("{0}={1}" -f $k, $v) }
function FileTime($v) { try { [DateTime]::FromFileTimeUtc([long]$v).ToString("o") } catch { "invalid($v)" } }

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Out-KV "os" ("{0} {1}.{2} {3}" -f $cv.ProductName, $cv.CurrentBuild, $cv.UBR, $env:PROCESSOR_ARCHITECTURE)
Out-KV "ps_arch_64bit_process" ([Environment]::Is64BitProcess)
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
Out-KV "user" $id.Name
Out-KV "elevated" ((New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Out-KV "integrity" ((whoami /groups | Select-String 'Mandatory Label') -replace '\s+', ' ')
Out-KV "now_utc" ([DateTime]::UtcNow.ToString("o"))

# SystemBootEnvironmentInformation (90)
$b = $null; $st = [BootProbe]::SysInfo(90, 32, [ref]$b)
Out-KV "bootenv.status" $st
$g = New-Object byte[] 16; [Array]::Copy($b, 0, $g, 0, 16)
Out-KV "bootenv.BootIdentifier" ([Guid]$g)
Out-KV "bootenv.FirmwareType" ([BitConverter]::ToUInt32($b, 16))
Out-KV "bootenv.BootFlags" ("0x{0:X}" -f [BitConverter]::ToUInt64($b, 24))

# SystemTimeOfDayInformation (3)
$b = $null; $st = [BootProbe]::SysInfo(3, 48, [ref]$b)
Out-KV "tod.status" $st
Out-KV "tod.BootTime" ("{0} ({1})" -f [BitConverter]::ToInt64($b, 0), (FileTime ([BitConverter]::ToInt64($b, 0))))
Out-KV "tod.CurrentTime" (FileTime ([BitConverter]::ToInt64($b, 8)))
Out-KV "tod.BootTimeBias" ([BitConverter]::ToUInt64($b, 32))
Out-KV "tod.SleepTimeBias" ([BitConverter]::ToUInt64($b, 40))

# KUSER_SHARED_DATA
$k = [BootProbe]::Kusd(0x800)
Out-KV "kusd.InterruptTime" ([BitConverter]::ToUInt64($k, 0x8))
Out-KV "kusd.SystemTime" (FileTime ([BitConverter]::ToInt64($k, 0x14)))
Out-KV "kusd.BootId@0x2C4" ([BitConverter]::ToUInt32($k, 0x2C4))
Out-KV "kusd.Cookie@0x330" ("0x{0:X8}" -f [BitConverter]::ToUInt32($k, 0x330))
Out-KV "kusd.NtBuildNumber@0x260" ("0x{0:X8}" -f [BitConverter]::ToUInt32($k, 0x260))
if ($KusdDump) { [IO.File]::WriteAllBytes($KusdDump, $k); Out-KV "kusd.dump" $KusdDump }

# Own process: class 64 (ProcessTelemetryIdInformation) and 92 (ProcessSequenceNumber)
$b = $null; $st = [BootProbe]::ProcInfo(64, [ref]$b)
Out-KV "proc64.status" $st
if ($b.Length -ge 64) {
    Out-KV "proc64.ProcessStartKey" ("0x{0:X16}" -f [BitConverter]::ToUInt64($b, 8))
    Out-KV "proc64.ProcessSequenceNumber" ([BitConverter]::ToUInt64($b, 40))
    Out-KV "proc64.BootId" ([BitConverter]::ToUInt32($b, 60))
}

# Image bases (ASLR image bias is chosen once per boot)
foreach ($m in "ntdll.dll", "kernel32.dll", "kernelbase.dll") {
    Out-KV ("base." + $m) ("0x{0:X}" -f [BootProbe]::GetModuleHandleW($m).ToInt64())
}

$t = 0; [void][BootProbe]::QueryUnbiasedInterruptTime([ref]$t)
Out-KV "uptime.GetTickCount64_s" ([BootProbe]::GetTickCount64() / 1000)
Out-KV "uptime.UnbiasedInterruptTime_s" ($t / 1e7)

try { Out-KV "wmi.LastBootUpTime" ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("o")) } catch { Out-KV "wmi.LastBootUpTime" "ERR $_" }
try { Out-KV "wmi.InstallDate" ((Get-CimInstance Win32_OperatingSystem).InstallDate.ToUniversalTime().ToString("o")) } catch { }
try { Out-KV "smbios.UUID" ((Get-CimInstance Win32_ComputerSystemProduct).UUID) } catch { Out-KV "smbios.UUID" "ERR $_" }

$pp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
try { $p = Get-ItemProperty $pp; Out-KV "reg.PrefetchParameters.BootId" $p.BootId; Out-KV "reg.PrefetchParameters.BaseTime" ("0x{0:X}" -f $p.BaseTime) } catch { Out-KV "reg.PrefetchParameters" "ERR $_" }
try { Out-KV "reg.MachineGuid" ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid) } catch { Out-KV "reg.MachineGuid" "ERR $_" }
try {
    $seed = (Get-ItemProperty 'HKLM:\SYSTEM\RNG' -ErrorAction Stop).Seed
    $h = [Security.Cryptography.SHA256]::Create().ComputeHash([byte[]]$seed)
    Out-KV "reg.RNG.Seed.sha256_8" (([BitConverter]::ToString($h, 0, 8)) -replace '-', '')
} catch { Out-KV "reg.RNG.Seed" "ERR $($_.Exception.GetType().Name)" }

# BCD: is BootIdentifier the {current} loader object's GUID? (needs admin)
try { Out-KV "bcd.current" ((bcdedit /enum '{current}' /v 2>&1 | Select-String '^identifier') -replace '\s+', ' ') } catch { Out-KV "bcd.current" "ERR $_" }

# Measured boot logs: names are <boot counter>-<resume counter>.log
try {
    $mb = Get-ChildItem "$env:SystemRoot\Logs\MeasuredBoot" -ErrorAction Stop | Sort-Object Name | Select-Object -Last 3 -ExpandProperty Name
    Out-KV "measuredboot.last3" ($mb -join ",")
} catch { Out-KV "measuredboot" "ERR $($_.Exception.GetType().Name)" }
try { $tpm = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -ErrorAction Stop; Out-KV "tpm.present" ($null -ne $tpm) } catch { Out-KV "tpm" "ERR $($_.Exception.GetType().Name)" }

# Event log: this boot's Kernel-General 12 and Kernel-Boot events
try {
    $e = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 12 } -MaxEvents 1 -ErrorAction Stop
    $x = [xml]$e.ToXml()
    Out-KV "evt.KernelGeneral12" (($x.Event.EventData.Data | ForEach-Object { "$($_.Name):$($_.'#text')" }) -join ";")
} catch { Out-KV "evt.KernelGeneral12" "ERR $_" }
try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Boot' } -MaxEvents 40 -ErrorAction Stop
    foreach ($e in $ev) {
        $x = [xml]$e.ToXml()
        $d = ($x.Event.EventData.Data | ForEach-Object { "$($_.Name):$($_.'#text')" }) -join ";"
        Out-KV ("evt.KernelBoot." + $e.Id + "@" + $e.TimeCreated.ToUniversalTime().ToString("o")) $d
    }
} catch { Out-KV "evt.KernelBoot" "ERR $_" }
