// THROWAWAY probe: does Windows allocate a process's pid no later than its SequenceNumber?
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class Probe
{
    const uint CREATE_SUSPENDED = 0x4;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000;
    const uint DUPLICATE_SAME_ACCESS = 2;
    const int ProcessBasicInformation = 0;
    const int ProcessTelemetryIdInformation = 64;
    const int ProcessSequenceNumber = 92;
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = (IntPtr)0x00020000;
    const string Exe = @"C:\Windows\System32\whoami.exe";

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO
    {
        public int cb; public IntPtr lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit,
        uint flags, IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value, IntPtr size, IntPtr prev, IntPtr retSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(IntPtr sa, UIntPtr stack, IntPtr start, IntPtr param, uint flags, out uint tid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr GetModuleHandleW(string name);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateEventW(IntPtr sa, bool manual, bool initial, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernelbase.dll")] static extern void QueryInterruptTimePrecise(out ulong t);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, out ulong v, int len, out int ret);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, byte[] buf, int len, out int ret);

    static ulong Seq(IntPtr h)
    {
        ulong v; int r;
        int st = NtQueryInformationProcess(h, ProcessSequenceNumber, out v, 8, out r);
        if (st != 0) throw new Exception("ProcessSequenceNumber status 0x" + st.ToString("x"));
        return v;
    }

    static ulong Ppid(IntPtr h)
    {
        var b = new byte[48]; int r;
        int st = NtQueryInformationProcess(h, ProcessBasicInformation, b, b.Length, out r);
        if (st != 0) throw new Exception("ProcessBasicInformation status 0x" + st.ToString("x"));
        return BitConverter.ToUInt64(b, 40);
    }

    // CreateTime, CreateInterruptTime, CreateUnbiasedInterruptTime, ProcessSequenceNumber.
    static ulong[] Telemetry(IntPtr h)
    {
        var b = new byte[65536]; int r;
        int st = NtQueryInformationProcess(h, ProcessTelemetryIdInformation, b, b.Length, out r);
        if (st < 0) throw new Exception("ProcessTelemetryIdInformation status 0x" + st.ToString("x"));
        return new[] { BitConverter.ToUInt64(b, 16), BitConverter.ToUInt64(b, 24), BitConverter.ToUInt64(b, 32), BitConverter.ToUInt64(b, 40) };
    }

    static PROCESS_INFORMATION Spawn(bool inherit, IntPtr parent)
    {
        var si = new STARTUPINFOEX();
        uint flags = CREATE_SUSPENDED;
        IntPtr list = IntPtr.Zero, val = IntPtr.Zero;
        si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        if (parent != IntPtr.Zero)
        {
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            list = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(list, 1, 0, ref size)) throw new Exception("InitializeProcThreadAttributeList " + Marshal.GetLastWin32Error());
            val = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(val, parent);
            if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, val, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Exception("UpdateProcThreadAttribute " + Marshal.GetLastWin32Error());
            si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            si.lpAttributeList = list;
            flags |= EXTENDED_STARTUPINFO_PRESENT;
        }
        PROCESS_INFORMATION pi;
        if (!CreateProcessW(Exe, new StringBuilder("whoami"), IntPtr.Zero, IntPtr.Zero, inherit, flags, IntPtr.Zero, null, ref si, out pi))
            throw new Exception("CreateProcessW " + Marshal.GetLastWin32Error());
        return pi;
    }

    static void Kill(PROCESS_INFORMATION pi)
    {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    // ETW ground truth ======================================================================

    public static void Etw()
    {
        var self = GetCurrentProcess();
        Console.WriteLine("EXPECT self pid={0} seq={1} ppid={2}", Environment.ProcessId, Seq(self), Ppid(self));
        var q = Spawn(false, IntPtr.Zero);
        Console.WriteLine("EXPECT q pid={0} seq={1} ppid={2}", q.dwProcessId, Seq(q.hProcess), Ppid(q.hProcess));
        var c1 = Spawn(false, IntPtr.Zero);
        Console.WriteLine("EXPECT c1-normal pid={0} seq={1} ppid={2}", c1.dwProcessId, Seq(c1.hProcess), Ppid(c1.hProcess));
        var c2 = Spawn(false, q.hProcess);
        Console.WriteLine("EXPECT c2-reparented-to-q pid={0} seq={1} ppid={2}", c2.dwProcessId, Seq(c2.hProcess), Ppid(c2.hProcess));
        Kill(c2); Kill(c1); Kill(q);
    }

    // Ordering experiment ===================================================================

    static IntPtr exitThread;
    static readonly List<IntPtr> drainThreads = new List<IntPtr>();
    static ulong frontier;

    static void See(ulong cid) { if (cid > frontier) frontier = cid; }

    // Consume freed CID-table entries until allocations come out fresh and increasing.
    static bool Drain(int run)
    {
        int seen = 0; long made = 0;
        while (seen < run)
        {
            uint tid;
            IntPtr h = CreateThread(IntPtr.Zero, (UIntPtr)65536, exitThread, IntPtr.Zero, CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION, out tid);
            if (h == IntPtr.Zero)
            {
                Console.WriteLine("drain: CreateThread failed after {0}: {1}", made, Marshal.GetLastWin32Error());
                return false;
            }
            drainThreads.Add(h); made++;
            if (tid > frontier) { seen++; frontier = tid; } else seen = 0;
        }
        Console.WriteLine("drain: fresh after {0} threads (total {1}), frontier={2}", made, drainThreads.Count, frontier);
        return true;
    }

    class X { public PROCESS_INFORMATION pi; public ulong seq, itBefore, itAfter; }

    static void Trial(string label, int pre, int post)
    {
        if (!Drain(512)) { Console.WriteLine("TRIAL {0} SKIPPED drain-failed", label); return; }
        ulong floor = frontier;
        var xs = new List<X>();
        var started = new ManualResetEventSlim(false);
        var preDone = new ManualResetEventSlim(false);
        int stop = 0;
        Exception helperErr = null;
        var helper = new Thread(() =>
        {
            try
            {
                started.Wait();
                int after = 0;
                while (true)
                {
                    var x = new X();
                    QueryInterruptTimePrecise(out x.itBefore);
                    x.pi = Spawn(false, IntPtr.Zero);
                    x.seq = Seq(x.pi.hProcess);
                    QueryInterruptTimePrecise(out x.itAfter);
                    xs.Add(x);
                    if (xs.Count == pre) preDone.Set();
                    if (Volatile.Read(ref stop) != 0 && ++after >= post) break;
                }
            }
            catch (Exception e) { helperErr = e; preDone.Set(); }
        });
        helper.Start();
        started.Set();
        preDone.Wait();
        PROCESS_INFORMATION n = new PROCESS_INFORMATION();
        ulong t0, t1;
        QueryInterruptTimePrecise(out t0);
        try { n = Spawn(true, IntPtr.Zero); }
        finally { QueryInterruptTimePrecise(out t1); Volatile.Write(ref stop, 1); helper.Join(); }
        if (helperErr != null) throw helperErr;

        ulong nseq = Seq(n.hProcess);
        ulong npid = n.dwProcessId;
        var tel = Telemetry(n.hProcess);
        if (tel[3] != nseq) throw new Exception("telemetry seq mismatch");

        // Fresh = allocated from never-used entries, so value order is allocation order.
        int freshX = 0, freshMono = 1;
        ulong lastFresh = 0;
        foreach (var x in xs)
        {
            if (x.pi.dwProcessId > floor)
            {
                freshX++;
                if (x.pi.dwProcessId <= lastFresh) freshMono = 0;
                lastFresh = x.pi.dwProcessId;
            }
        }
        bool nFresh = npid > floor;

        int iS = xs.FindIndex(x => x.seq > nseq);                                   // first X whose seq is after N's
        int iP = xs.FindIndex(x => x.pi.dwProcessId > floor && x.pi.dwProcessId > npid); // first fresh X whose pid is after N's
        int lastBelow = xs.FindLastIndex(x => x.pi.dwProcessId > floor && x.pi.dwProcessId < npid);
        int iCt = xs.FindIndex(x => x.itBefore > tel[1]);                          // first X started after N's CreateInterruptTime
        int iTid = xs.FindIndex(x => x.pi.dwProcessId > floor && x.pi.dwProcessId > n.dwThreadId);

        string verdict;
        if (!nFresh || freshMono == 0) verdict = "UNPOSITIONED";
        else if (iS >= 0 && lastBelow > iS) verdict = "REFUTED(seq-before-pid)";
        else if (iP >= 0 && (iS < 0 ? xs.Count : iS) >= iP + 2) verdict = "PID-BEFORE-SEQ(observed gap)";
        else verdict = "UNRESOLVED(adjacent)";

        int nWin = xs.FindAll(x => x.itBefore >= t0 && x.itAfter <= t1).Count;
        Console.WriteLine(
            "TRIAL {0} verdict={1} xs={2} freshX={3} freshMono={4} xsInsideWindow={5} windowMs={6:F1} " +
            "N.pid={7} N.tid={8} N.seq={9} floor={10} iSeq={11} iPid={12} lastFreshPidBelowN={13} iTid={14} iCreateInterruptTime={15} " +
            "seqRange=[{16},{17}]",
            label, verdict, xs.Count, freshX, freshMono, nWin, (t1 - t0) / 10000.0,
            npid, n.dwThreadId, nseq, floor, iS, iP, lastBelow, iTid, iCt,
            xs[0].seq, xs[xs.Count - 1].seq);

        See(npid); See(n.dwThreadId);
        foreach (var x in xs) { See(x.pi.dwProcessId); See(x.pi.dwThreadId); }
        Kill(n);
        foreach (var x in xs) Kill(x.pi);
    }

    public static void Order(int trialsPerVariant)
    {
        exitThread = GetProcAddress(GetModuleHandleW("kernel32.dll"), "ExitThread");
        IntPtr evt = CreateEventW(IntPtr.Zero, true, false, null);
        IntPtr me = GetCurrentProcess();
        long have = 0;
        foreach (long want in new long[] { 0, 1L << 18, 1L << 21 })
        {
            for (; have < want; have++)
            {
                IntPtr d;
                if (!DuplicateHandle(me, evt, me, out d, 0, true, DUPLICATE_SAME_ACCESS))
                    throw new Exception("DuplicateHandle " + Marshal.GetLastWin32Error() + " at " + have);
            }
            for (int t = 0; t < trialsPerVariant; t++)
                Trial(string.Format("handles={0}#{1}", want, t), 3, 3);
        }
    }
}
