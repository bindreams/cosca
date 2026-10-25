# MEASURE (throwaway). Prints how many loopback sockets this runner will give before it fails, and the error.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

public static class SockProbe
{
    // bind(127.0.0.1:0) until it fails; listeners stay open until the end.
    public static string Binds()
    {
        var held = new List<Socket>();
        try
        {
            while (true)
            {
                var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                held.Add(s);
                try { s.Bind(new IPEndPoint(IPAddress.Loopback, 0)); }
                catch (SocketException e) { return string.Format("binds={0} err={1} ({2})", held.Count - 1, e.NativeErrorCode, e.SocketErrorCode); }
            }
        }
        finally { foreach (var s in held) s.Close(); }
    }

    // connect + close (client closes first, so the client side keeps TIME_WAIT) until connect fails.
    public static string Connects()
    {
        var l = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        l.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        l.Listen(1000);
        var ep = (IPEndPoint)l.LocalEndPoint;
        int n = 0;
        try
        {
            while (true)
            {
                var c = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try { c.Connect(ep); }
                catch (SocketException e) { c.Close(); return string.Format("connects={0} err={1} ({2})", n, e.NativeErrorCode, e.SocketErrorCode); }
                var a = l.Accept();
                c.Close();
                a.Close();
                n++;
            }
        }
        finally { l.Close(); }
    }
}
'@
Write-Host ('PROBE|binds-before|' + [SockProbe]::Binds())
Write-Host ('PROBE|connects|' + [SockProbe]::Connects())
Write-Host ('PROBE|binds-after-connects|' + [SockProbe]::Binds())
