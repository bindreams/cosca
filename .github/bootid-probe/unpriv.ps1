# Re-run probe.ps1 at low integrity and as a fresh standard (non-admin) user.
$ErrorActionPreference = "Continue"
$probe = Join-Path $PSScriptRoot "probe.ps1"
$work = Join-Path $env:SystemDrive "bootid-probe-tmp"
New-Item -ItemType Directory -Force $work | Out-Null
Copy-Item $probe "$work\probe.ps1"
icacls $work /grant "*S-1-1-0:(OI)(CI)RX" | Out-Null

Write-Output "===== low integrity (admin token, IL lowered via executable label)"
$lowps = "$work\pslow.exe"
Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $lowps
icacls $lowps /setintegritylevel low | Out-Null
& $lowps -NoProfile -ExecutionPolicy Bypass -File "$work\probe.ps1" 2>&1 | ForEach-Object { "low: $_" }

Write-Output "===== standard user"
$pw = "Pw-" + [guid]::NewGuid().ToString("N").Substring(0, 16) + "!a1"
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
$name = "bootidstd"
New-LocalUser -Name $name -Password $sec -AccountNeverExpires -ErrorAction Stop | Out-Null
try {
    $cred = New-Object Management.Automation.PSCredential (".\$name", $sec)
    $out = "$work\std.out"; $err = "$work\std.err"
    New-Item -ItemType File -Force $out, $err | Out-Null
    icacls $out /grant "${name}:F" | Out-Null; icacls $err /grant "${name}:F" | Out-Null
    $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $work\probe.ps1" `
        -Credential $cred -LoadUserProfile -WorkingDirectory $work -RedirectStandardOutput $out -RedirectStandardError $err -Wait -PassThru
    Write-Output "std: exit=$($p.ExitCode)"
    Get-Content $out | ForEach-Object { "std: $_" }
    Get-Content $err | ForEach-Object { "std.err: $_" }
} finally {
    Remove-LocalUser -Name $name
}
