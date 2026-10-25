# MEASURE (throwaway). Usage: measure-sockets-run.ps1 <target>
param([Parameter(Mandatory)][string]$Target)
$ErrorActionPreference = 'Stop'
$m = './.github/scripts/measure-sockets.ps1'

Write-Host '--- ephemeral port range (tcp)'
netsh int ipv4 show dynamicport tcp
Write-Host '--- excluded port ranges (tcp)'
netsh int ipv4 show excludedportrange protocol=tcp
Write-Host '--- TcpTimedWaitDelay / MaxUserPort (absent = defaults)'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' | Select-Object TcpTimedWaitDelay, MaxUserPort | Format-List
Write-Host '--- os'
[System.Environment]::OSVersion.VersionString

& $m 'idle-10s' pwsh -NoProfile -Command 'Start-Sleep -Seconds 10'
foreach ($i in 1..3) {
    & $m "suite$i" pwsh -NoProfile -File ./.github/scripts/run-nextest.ps1 tests cargo nextest run --locked --target $Target
}

$json = cargo nextest list --locked --target $Target --message-format json 2>$null | Out-String
$suites = (ConvertFrom-Json $json).'rust-suites'
$ids = @($suites.PSObject.Properties.Name)
Write-Host "binaries: $($ids.Count)"
foreach ($id in $ids) {
    & $m "bin:$id" cargo nextest run --locked --target $Target --no-tests=pass -E "binary_id(=$id)"
}
& $m 'idle-10s-after' pwsh -NoProfile -Command 'Start-Sleep -Seconds 10'
./.github/scripts/measure-sockets-probe.ps1
