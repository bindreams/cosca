# THROWAWAY probe driver. Usage: probe.ps1 manifest|etw|order
param([Parameter(Mandatory)][string]$Mode)
$ErrorActionPreference = 'Stop'

if ($Mode -eq 'manifest') {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
        Select-Object ProductName, DisplayVersion, CurrentBuild, UBR | Format-List | Out-String | Write-Host
    $m = wevtutil gp Microsoft-Windows-Kernel-Process /ge /gm
    $m | Set-Content -Path "$env:RUNNER_TEMP\kp-manifest.txt"
    Write-Host "manifest lines: $($m.Count)"
    $m | Select-String -Pattern 'SequenceNumber|StartKey|ParentProcess' | ForEach-Object { $_.Line.Trim() } | Select-Object -Unique | Write-Host
    # Print every event version that carries ParentProcessSequenceNumber, with its template.
    $text = $m -join "`n"
    [regex]::Matches($text, '(?s)event:\s*\n\s*value:\s*(\d+)\s*\n\s*version:\s*(\d+).*?(?=event:|\z)') |
        Where-Object { $_.Value -match 'ParentProcessSequenceNumber' } |
        ForEach-Object { Write-Host "== event $($_.Groups[1].Value) v$($_.Groups[2].Value)"; Write-Host ($_.Value -split "`n" | Select-String 'data name' | Out-String) }
    exit 0
}

Add-Type -Path "$PSScriptRoot\Probe.cs"

if ($Mode -eq 'etw') {
    $etl = "$env:RUNNER_TEMP\kp.etl"
    logman start cosca-pidseq-probe -p Microsoft-Windows-Kernel-Process 0x10 0x4 -o $etl -ets | Write-Host
    try { [Probe]::Etw() } finally { logman stop cosca-pidseq-probe -ets | Write-Host }
    Get-WinEvent -Path $etl -Oldest | Where-Object { $_.Id -eq 1 -and $_.ProcessId -eq $PID } | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        Write-Host ("ETW ProcessStart v{0} headerPid={1} ProcessID={2} ProcessSequenceNumber={3} ParentProcessID={4} ParentProcessSequenceNumber={5} Image={6}" -f
            $_.Version, $_.ProcessId, $d.ProcessID, $d.ProcessSequenceNumber, $d.ParentProcessID, $d.ParentProcessSequenceNumber, $d.ImageName)
    }
    exit 0
}

if ($Mode -eq 'preempt') {
    [Probe]::Preempt(1500)
    exit 0
}

if ($Mode -eq 'order') {
    [Probe]::Order(6)
    exit 0
}
throw "unknown mode $Mode"
