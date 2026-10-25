# MEASURE (throwaway). Usage: measure-sockets.ps1 <label> <command> [args...]
# Runs the command while a thread samples the TCP table every 100 ms, then prints one MEASURE| line:
# label, wall seconds, kernel counters (delta), and peaks of the sampled table.
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Net.NetworkInformation;
using System.Threading;

public class SockSampler
{
    public int[] PeakByState = new int[13];
    public int PeakEndpoints, PeakListeners, PeakEphemeral, PeakLoopbackEstablished;
    volatile bool stop;
    Thread t;

    void Sample()
    {
        var p = IPGlobalProperties.GetIPGlobalProperties();
        var conns = p.GetActiveTcpConnections();
        var lst = p.GetActiveTcpListeners();
        var n = new int[13];
        var ports = new System.Collections.Generic.HashSet<int>();
        foreach (var c in conns)
        {
            n[(int)c.State]++;
            if (c.LocalEndPoint.Port >= 49152) ports.Add(c.LocalEndPoint.Port);
        }
        foreach (var l in lst) if (l.Port >= 49152) ports.Add(l.Port);
        for (int i = 0; i < 13; i++) if (n[i] > PeakByState[i]) PeakByState[i] = n[i];
        if (conns.Length > PeakEndpoints) PeakEndpoints = conns.Length;
        if (lst.Length > PeakListeners) PeakListeners = lst.Length;
        if (ports.Count > PeakEphemeral) PeakEphemeral = ports.Count;
    }

    public void Start()
    {
        t = new Thread(() => { while (!stop) { Sample(); Thread.Sleep(100); } });
        t.IsBackground = true;
        t.Start();
    }

    public void Stop() { stop = true; t.Join(); Sample(); }
}
'@

function Stats {
    $s = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetTcpIPv4Statistics()
    [pscustomobject]@{
        Init = $s.ConnectionsInitiated; Acc = $s.ConnectionsAccepted
        Fail = $s.FailedConnectionAttempts; Reset = $s.ResetConnections
    }
}

$label = $args[0]
$command = @($args[1..($args.Count - 1)])
$before = Stats
$sampler = New-Object SockSampler
$sampler.Start()
$sw = [Diagnostics.Stopwatch]::StartNew()
& $command[0] @($command[1..($command.Count - 1)])
$status = $LASTEXITCODE
$sw.Stop()
$sampler.Stop()
$after = Stats
$p = $sampler.PeakByState
# TcpState: Established=5, TimeWait=11
$line = 'MEASURE|{0}|exit={1}|secs={2:N1}|init={3}|acc={4}|fail={5}|reset={6}|peakEndpoints={7}|peakEstab={8}|peakTimeWait={9}|peakListeners={10}|peakEphemeralPorts={11}' -f `
    $label, $status, $sw.Elapsed.TotalSeconds, ($after.Init - $before.Init), ($after.Acc - $before.Acc), `
    ($after.Fail - $before.Fail), ($after.Reset - $before.Reset), $sampler.PeakEndpoints, $p[5], $p[11], `
    $sampler.PeakListeners, $sampler.PeakEphemeral
Write-Host $line
if ($env:GITHUB_STEP_SUMMARY) { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value ('`' + $line + '`' + "`n") }
exit 0
