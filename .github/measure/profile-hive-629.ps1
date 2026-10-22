# Throwaway measurement for #629. Usage: profile-hive-629.ps1 <scenario>
# Creates one local administrator, logs it on by the scenario's path, cleans up by the scenario's method, then checks
# the pass criteria right after the account is deleted. Hosted runners only.
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'hosted runners only' }
$scenario = $args[0]

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class P629 {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROFILEINFO {
        public int dwSize; public int dwFlags; public string lpUserName; public string lpProfilePath;
        public string lpDefaultPath; public string lpServerName; public string lpPolicyPath; public IntPtr hProfile;
    }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUserW(string user, string domain, string pw, int type, int provider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithLogonW(string user, string domain, string pw, int logonFlags, string app,
        StringBuilder cmd, int flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr token, int logonFlags, string app, StringBuilder cmd,
        int flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LoadUserProfileW(IntPtr token, ref PROFILEINFO pi);
    [DllImport("userenv.dll", SetLastError = true)]
    public static extern bool UnloadUserProfile(IntPtr token, IntPtr hProfile);
    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool DeleteProfileW(string sid, string path, string computer);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);

    public static string WaitAndClose(PROCESS_INFORMATION pi) {
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
        uint code; GetExitCodeProcess(pi.hProcess, out code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return "exit=" + code;
    }
    public static string Cpwl(string user, string pw, int logonFlags, string cmdline) {
        var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
        PROCESS_INFORMATION pi;
        if (!CreateProcessWithLogonW(user, ".", pw, logonFlags, null, new StringBuilder(cmdline), 0x08000000,
                IntPtr.Zero, "C:\\c629", ref si, out pi))
            return "CreateProcessWithLogonW failed: " + Marshal.GetLastWin32Error();
        return WaitAndClose(pi);
    }
    public static string Cpwt(IntPtr token, string cmdline) {
        var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
        PROCESS_INFORMATION pi;
        if (!CreateProcessWithTokenW(token, 0, null, new StringBuilder(cmdline), 0x08000000, IntPtr.Zero, "C:\\c629",
                ref si, out pi))
            return "CreateProcessWithTokenW failed: " + Marshal.GetLastWin32Error();
        return WaitAndClose(pi);
    }
    public static IntPtr Logon(string user, string pw, int type) {
        IntPtr t;
        if (!LogonUserW(user, ".", pw, type, 0, out t)) throw new Exception("LogonUserW(" + type + ") failed: " + Marshal.GetLastWin32Error());
        return t;
    }
    public static IntPtr Load(IntPtr token, string user) {
        var p = new PROFILEINFO(); p.dwSize = Marshal.SizeOf(p); p.dwFlags = 1; p.lpUserName = user;
        if (!LoadUserProfileW(token, ref p)) throw new Exception("LoadUserProfileW failed: " + Marshal.GetLastWin32Error());
        return p.hProfile;
    }
    public static string Unload(IntPtr token, IntPtr h) {
        return UnloadUserProfile(token, h) ? "ok" : "failed: " + Marshal.GetLastWin32Error();
    }
    public static string DeleteProfile(string sid) {
        return DeleteProfileW(sid, null, null) ? "ok" : "failed: " + Marshal.GetLastWin32Error();
    }
}
'@

$scenarios = 'logonuser-interactive', 'logonuser-network', 'cpwl-profile', 'cpwl-noprofile', 'cpwl-profile-l2',
    'cpwl-profile-elevate-l2', 'own-load-l2', 'own-load-elevate-l2', 'startprocess', 'startprocess-loadprofile',
    'startprocess-elevate', 'startprocess-elevate-l2', 'startprocess-elevate-m1', 'cpwl-profile-elevate-m1'
$index = [array]::IndexOf($scenarios, $scenario)
if ($index -lt 0) { throw "unknown scenario $scenario" }
$account = 'c629s{0:d2}' -f $index
$password = (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })) + 'aA1!'
Write-Host "::add-mask::$password"
$start = Get-Date
$log = [ordered]@{ scenario = $scenario; account = $account; runner = $env:RUNNER_NAME; os = [Environment]::OSVersion.VersionString; arch = $env:PROCESSOR_ARCHITECTURE; steps = @() }
function Step([string]$what, $value) { Write-Host "STEP ${what}: $value"; $log.steps += "${what}: $value" }

function State([string]$label, [string]$sid) {
    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    $pl = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    $wp = Get-CimInstance Win32_UserProfile -Filter "SID = '$sid'"
    $procs = foreach ($p in Get-CimInstance Win32_Process) {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction SilentlyContinue
        if ($o -and $o.ReturnValue -eq 0 -and $o.Sid -eq $sid) { "$($p.ProcessId) $($p.Name)" }
    }
    $sessions = @(Get-CimInstance Win32_LoggedOnUser | Where-Object { $_.Antecedent.Name -eq $account } | ForEach-Object { $_.Dependent.LogonId })
    $s = [ordered]@{
        label = $label
        hku = Test-Path -LiteralPath "Registry::HKEY_USERS\$sid"
        hkuClasses = Test-Path -LiteralPath "Registry::HKEY_USERS\${sid}_Classes"
        profileList = [bool]$pl
        profileListBak = Test-Path -LiteralPath "$key.bak"
        profileImagePath = $pl.ProfileImagePath
        profileListState = $pl.State
        profileListRefCount = $pl.RefCount
        win32UserProfile = [bool]$wp
        wupLoaded = $wp.Loaded
        wupRefCount = $wp.RefCount
        wupLocalPath = $wp.LocalPath
        dirs = @(Get-ChildItem C:\Users -Directory -Force | Where-Object Name -like "$account*" | ForEach-Object FullName)
        account = [bool](Get-LocalUser -Name $account -ErrorAction SilentlyContinue)
        processes = @($procs)
        logonSessions = $sessions
    }
    Write-Host "STATE $(ConvertTo-Json -InputObject $s -Compress)"
    $log[$label] = $s
    $s
}

# M1: every handle that names the account's SID or the account (Token handles read `<computer>\<account>:<luid>`).
function Holders([string]$label, [string]$sid) {
    $exe = @{ AMD64 = 'handle64.exe'; ARM64 = 'handle64a.exe' }[$env:PROCESSOR_ARCHITECTURE]
    $path = Join-Path C:\c629-tools $exe
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Force C:\c629-tools | Out-Null
        Invoke-WebRequest -Method Get -Uri https://download.sysinternals.com/files/Handle.zip -OutFile C:\c629-tools\Handle.zip
        Expand-Archive C:\c629-tools\Handle.zip C:\c629-tools -Force
        $sig = Get-AuthenticodeSignature $path
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*Microsoft Corporation*') { throw "handle signature: $($sig.Status) $($sig.SignerCertificate.Subject)" }
    }
    $all = & $path -accepteula -nobanner -a -u 2>&1
    $current = ''
    $hits = foreach ($line in $all) {
        if ($line -match '^\S.*pid: \d+') { $current = $line.Trim(); continue }
        if ($line -like "*$sid*" -or $line -like "*\$account*") { "$current :: $($line.Trim())" }
    }
    Write-Host "HOLDERS[$label] $($hits.Count) handles (handle.exe exit $LASTEXITCODE, $($all.Count) lines)"
    foreach ($h in $hits) { Write-Host "HOLDER[$label] $h" }
    $log["holders-$label"] = @($hits)
    foreach ($ls in Get-CimInstance Win32_LogonSession) {
        $users = @(Get-CimAssociatedInstance -InputObject $ls -Association Win32_LoggedOnUser -ErrorAction SilentlyContinue | ForEach-Object Name)
        if ($users -contains $account) { Write-Host "LOGONSESSION[$label] id=$($ls.LogonId) type=$($ls.LogonType) pkg=$($ls.AuthenticationPackage) start=$($ls.StartTime)" }
    }
}

function Events {
    $out = @()
    foreach ($f in @(
            @{ LogName = 'Application'; ProviderName = 'Microsoft-Windows-User Profiles Service'; StartTime = $start },
            @{ LogName = 'Application'; ProviderName = 'Microsoft-Windows-User Profiles General'; StartTime = $start },
            @{ LogName = 'Microsoft-Windows-User Profile Service/Operational'; StartTime = $start })) {
        $found = try { @(Get-WinEvent -FilterHashtable $f -ErrorAction Stop) } catch { Write-Host "EVENTQUERY $($f.LogName)/$($f.ProviderName): $_"; @() }
        foreach ($e in $found | Sort-Object TimeCreated) {
            $props = ($e.Properties | ForEach-Object { "$($_.Value)" }) -join ' | '
            $line = "$($e.LogName) id=$($e.Id) $($e.TimeCreated.ToString('o')) props=[$props]"
            Write-Host "EVENT $line"
            if ($e.Id -eq 1530) { Write-Host "EVENT1530XML $($e.ToXml())" }
            $out += $line
        }
    }
    $log.events = $out
}

New-Item -ItemType Directory -Force C:\c629 | Out-Null
icacls C:\c629 /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
$user = New-LocalUser $account -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires
Add-LocalGroupMember -Group Administrators -Member $account
$sid = $user.SID.Value
Step 'sid' $sid

$cmd = 'C:\Windows\System32\cmd.exe /c exit 0'
# The elevating child: the account's own filtered token asks for runas, as the lane's tests do.
$elevCmd = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -Command "$p = Start-Process C:\Windows\System32\cmd.exe -ArgumentList ''/c'',''exit 7'' -Verb RunAs -Wait -PassThru; exit $p.ExitCode"'

function StartProcessShape([string]$commandLine, [bool]$loadProfile) {
    # The lane's shape: Start-Process -Credential in a pwsh of its own.
    $env:C629_PW = $password
    $launcher = {
        param($account, $commandLine, $loadProfile)
        $c = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$account", (ConvertTo-SecureString $env:C629_PW -AsPlainText -Force))
        $exe, $rest = $commandLine -split ' ', 2
        $p = Start-Process $exe -ArgumentList $rest -Credential $c -WorkingDirectory C:\c629 -Wait -PassThru -LoadUserProfile:$loadProfile
        exit $p.ExitCode
    }
    & pwsh -NoProfile -NonInteractive -Command $launcher -args $account, $commandLine, $loadProfile
    Remove-Item Env:C629_PW
    "exit=$LASTEXITCODE"
}

# Lead L2: our own LoadUserProfile/UnloadUserProfile pair, then DeleteProfile.
function OwnLoadUnloadDelete {
    $t = [P629]::Logon($account, $password, 2)
    $h = [P629]::Load($t, $account)
    Step 'own LoadUserProfileW' "hProfile=$h"
    Step 'own UnloadUserProfile' ([P629]::Unload($t, $h))
    [void][P629]::CloseHandle($t)
    State 'after-own-unload' $sid | Out-Null
    Step 'DeleteProfileW' ([P629]::DeleteProfile($sid))
}

# The cleanup the lane and the harness do today.
function BaselineCleanup {
    try { Get-CimInstance Win32_UserProfile -Filter "SID = '$sid'" | Remove-CimInstance -ErrorAction Stop; Step 'Remove-CimInstance' 'ok' }
    catch { Step 'Remove-CimInstance' "failed: $_" }
}

try {
switch ($scenario) {
    'logonuser-interactive' {
        $t = [P629]::Logon($account, $password, 2); [void][P629]::CloseHandle($t); Step 'LogonUserW INTERACTIVE' 'ok, closed'
        State 'after-logon' $sid | Out-Null; BaselineCleanup
    }
    'logonuser-network' {
        $t = [P629]::Logon($account, $password, 3); [void][P629]::CloseHandle($t); Step 'LogonUserW NETWORK' 'ok, closed'
        State 'after-logon' $sid | Out-Null; BaselineCleanup
    }
    'cpwl-profile' {
        Step 'CreateProcessWithLogonW(LOGON_WITH_PROFILE)' ([P629]::Cpwl($account, $password, 1, $cmd))
        State 'after-logon' $sid | Out-Null; BaselineCleanup
    }
    'cpwl-noprofile' {
        Step 'CreateProcessWithLogonW(0)' ([P629]::Cpwl($account, $password, 0, $cmd))
        State 'after-logon' $sid | Out-Null; BaselineCleanup
    }
    'cpwl-profile-l2' {
        Step 'CreateProcessWithLogonW(LOGON_WITH_PROFILE)' ([P629]::Cpwl($account, $password, 1, $cmd))
        State 'after-logon' $sid | Out-Null
        Step 'DeleteProfileW before own unload' ([P629]::DeleteProfile($sid))
        OwnLoadUnloadDelete
    }
    'cpwl-profile-elevate-l2' {
        Step 'CreateProcessWithLogonW(LOGON_WITH_PROFILE), elevating child' ([P629]::Cpwl($account, $password, 1, $elevCmd))
        State 'after-logon' $sid | Out-Null
        OwnLoadUnloadDelete
    }
    'own-load-l2' {
        $t = [P629]::Logon($account, $password, 2)
        $h = [P629]::Load($t, $account)
        Step 'LoadUserProfileW' "hProfile=$h"
        Step 'CreateProcessWithTokenW(0)' ([P629]::Cpwt($t, $cmd))
        State 'after-child' $sid | Out-Null
        Step 'UnloadUserProfile' ([P629]::Unload($t, $h))
        [void][P629]::CloseHandle($t)
        State 'after-unload' $sid | Out-Null
        Step 'DeleteProfileW' ([P629]::DeleteProfile($sid))
    }
    'own-load-elevate-l2' {
        $t = [P629]::Logon($account, $password, 2)
        $h = [P629]::Load($t, $account)
        Step 'LoadUserProfileW' "hProfile=$h"
        Step 'CreateProcessWithTokenW(0), elevating child' ([P629]::Cpwt($t, $elevCmd))
        State 'after-child' $sid | Out-Null
        Step 'UnloadUserProfile' ([P629]::Unload($t, $h))
        [void][P629]::CloseHandle($t)
        State 'after-unload' $sid | Out-Null
        Step 'DeleteProfileW' ([P629]::DeleteProfile($sid))
    }
    'startprocess' {
        Step 'Start-Process -Credential' (StartProcessShape $cmd $false)
        State 'after-logon' $sid | Out-Null; BaselineCleanup
    }
    'startprocess-loadprofile' {
        Step 'Start-Process -Credential -LoadUserProfile' (StartProcessShape $cmd $true)
        State 'after-logon' $sid | Out-Null; BaselineCleanup
    }
    'startprocess-elevate' {
        Step 'Start-Process -Credential, elevating child' (StartProcessShape $elevCmd $false)
        State 'after-logon' $sid | Out-Null; BaselineCleanup
    }
    'startprocess-elevate-m1' {
        Holders 'before' $sid
        Step 'Start-Process -Credential, elevating child' (StartProcessShape $elevCmd $false)
        State 'after-logon' $sid | Out-Null
        Holders 'after-logon' $sid
        BaselineCleanup
        Holders 'after-cleanup' $sid
    }
    'cpwl-profile-elevate-m1' {
        Step 'CreateProcessWithLogonW(LOGON_WITH_PROFILE), elevating child' ([P629]::Cpwl($account, $password, 1, $elevCmd))
        State 'after-logon' $sid | Out-Null
        Holders 'after-logon' $sid
        BaselineCleanup
    }
    'startprocess-elevate-l2' {
        Step 'Start-Process -Credential, elevating child' (StartProcessShape $elevCmd $false)
        State 'after-logon' $sid | Out-Null
        Step 'DeleteProfileW before own unload' ([P629]::DeleteProfile($sid))
        OwnLoadUnloadDelete
    }
}
} catch {
    Step 'ERROR' "$_"
    $log.error = "$_"
}

try { Remove-LocalUser $account; Step 'Remove-LocalUser' 'ok' } catch { Step 'Remove-LocalUser' "failed: $_" }
$after = State 'after-delete' $sid
if ($scenario -like '*-m1') { Holders 'after-delete' $sid }
Events

$imagePath = $log['after-logon'].profileImagePath, $log['after-child'].profileImagePath | Where-Object { $_ } | Select-Object -First 1
$criteria = [ordered]@{
    profileDirGone = -not ($imagePath -and (Test-Path -LiteralPath $imagePath)) -and $after.dirs.Count -eq 0
    profileListGone = -not $after.profileList -and -not $after.profileListBak
    hiveUnloaded = -not $after.hku -and -not $after.hkuClasses
    noWin32UserProfile = -not $after.win32UserProfile
    noAccount = -not $after.account
}
$log.profileCreated = [bool]$imagePath
$log.criteria = $criteria
$log.pass = -not ($criteria.Values -contains $false)
Write-Host "CRITERIA $(ConvertTo-Json -InputObject $criteria -Compress) pass=$($log.pass) profileCreated=$($log.profileCreated)"
New-Item -ItemType Directory -Force "$env:RUNNER_TEMP\629" | Out-Null
ConvertTo-Json -InputObject $log -Depth 6 | Set-Content "$env:RUNNER_TEMP\629\$scenario.json"
