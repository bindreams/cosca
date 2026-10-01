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

    // Preemption experiment =================================================================
    // N's creator shares CPU 0 with a higher-priority load thread that alternates busy and idle
    // phases, so N's creation is preempted at arbitrary points for longer than one X creation.
    // Timing only shapes where preemption lands; every verdict rests on CID and seq order.

    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern UIntPtr SetThreadAffinityMask(IntPtr h, UIntPtr mask);
    [DllImport("kernel32.dll")] static extern bool SetThreadPriority(IntPtr h, int prio);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateWaitableTimerExW(IntPtr sa, IntPtr name, uint flags, uint access);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetWaitableTimer(IntPtr h, ref long due, int period, IntPtr cb, IntPtr arg, bool resume);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateThread(IntPtr h, uint code);

    static void Pin(ulong mask, int prio)
    {
        if (SetThreadAffinityMask(GetCurrentThread(), (UIntPtr)mask) == UIntPtr.Zero) throw new Exception("SetThreadAffinityMask");
        if (!SetThreadPriority(GetCurrentThread(), prio)) throw new Exception("SetThreadPriority");
    }

    static void FreeDrain()
    {
        foreach (var h in drainThreads) { TerminateThread(h, 0); WaitForSingleObject(h, 0xFFFFFFFF); CloseHandle(h); }
        drainThreads.Clear();
    }

    static readonly Dictionary<string, int> tally = new Dictionary<string, int>();
    static void Count(string k) { int v; tally.TryGetValue(k, out v); tally[k] = v + 1; }

    static void TrialP(int t, ulong helperMask)
    {
        FreeDrain();
        if (!Drain(32)) throw new Exception("drain failed");
        ulong floor = frontier;
        var xs = new List<X>();
        var preDone = new ManualResetEventSlim(false);
        int stop = 0;
        Exception helperErr = null;
        var helper = new Thread(() =>
        {
            try
            {
                Pin(helperMask, 0);
                int after = 0;
                while (true)
                {
                    var x = new X();
                    x.pi = Spawn(false, IntPtr.Zero);
                    x.seq = Seq(x.pi.hProcess);
                    xs.Add(x);
                    if (xs.Count == 2) preDone.Set();
                    if (Volatile.Read(ref stop) != 0 && ++after >= 2) break;
                }
            }
            catch (Exception e) { helperErr = e; preDone.Set(); }
        });
        helper.Start();
        preDone.Wait();
        PROCESS_INFORMATION n = new PROCESS_INFORMATION();
        try { n = Spawn(false, IntPtr.Zero); }
        finally { Volatile.Write(ref stop, 1); helper.Join(); }
        if (helperErr != null) throw helperErr;

        ulong nseq = Seq(n.hProcess), npid = n.dwProcessId, ntid = n.dwThreadId;
        Func<X, bool> fresh = x => x.pi.dwProcessId > floor;
        bool mono = true; ulong last = 0;
        foreach (var x in xs) if (fresh(x)) { if (x.pi.dwProcessId <= last) mono = false; last = x.pi.dwProcessId; }

        if (npid <= floor || ntid <= floor || !mono) Count("UNPOSITIONED");
        else
        {
            int iS = xs.FindIndex(x => x.seq > nseq);
            int lastBelowPid = xs.FindLastIndex(x => fresh(x) && x.pi.dwProcessId < npid);
            int lastBelowTid = xs.FindLastIndex(x => fresh(x) && x.pi.dwProcessId < ntid);
            int iP = xs.FindIndex(x => fresh(x) && x.pi.dwProcessId > npid);
            int seqEnd = iS < 0 ? xs.Count : iS;
            bool refuted = iS >= 0 && lastBelowPid > iS;          // s_N < s_X(iS) < a_X(j>iS) < a_N
            bool pidFirst = iP >= 0 && seqEnd >= iP + 2;          // a_N < a_X(iP) < s_X(j>iP) < s_N
            bool pidTidGap = xs.Exists(x => fresh(x) && x.pi.dwProcessId > npid && x.pi.dwProcessId < ntid);
            bool seqTidGap = iS >= 0 && lastBelowTid > iS;        // s_N < s_X(iS) < a_X(j>iS) < a_tid(N)
            Count("positioned");
            if (refuted) { Count("REFUTED(seq-before-pid)"); Console.WriteLine("REFUTED trial {0}: N.pid={1} N.tid={2} N.seq={3}", t, npid, ntid, nseq); }
            if (pidFirst) Count("PID-BEFORE-SEQ(observed gap)");
            if (!refuted && !pidFirst) Count("UNRESOLVED(adjacent)");
            if (pidTidGap) Count("control: X pid between N.pid and N.tid");
            if (seqTidGap) Count("control: X created between N.seq and N.tid");
            if (refuted || pidFirst || t < 3)
            {
                var sb = new StringBuilder();
                foreach (var x in xs) sb.AppendFormat(" [{0}{1} seq={2}]", x.pi.dwProcessId, fresh(x) ? "" : "(old)", x.seq);
                Console.WriteLine("trial {0}: N pid={1} tid={2} seq={3} floor={4} X:{5}", t, npid, ntid, nseq, floor, sb);
            }
        }
        See(npid); See(ntid);
        foreach (var x in xs) { See(x.pi.dwProcessId); See(x.pi.dwThreadId); }
        Kill(n);
        foreach (var x in xs) Kill(x.pi);
    }

    public static void Preempt(int trials)
    {
        exitThread = GetProcAddress(GetModuleHandleW("kernel32.dll"), "ExitThread");
        int cpus = Environment.ProcessorCount;
        Console.WriteLine("cpus={0} trials={1}", cpus, trials);
        if (cpus < 2) throw new Exception("needs at least 2 CPUs");
        ulong helperMask = ((cpus >= 64) ? ulong.MaxValue : ((1UL << cpus) - 1)) & ~1UL;
        int stopLoad = 0;
        Exception err = null;
        var load = new Thread(() =>
        {
            Pin(1, 15);
            IntPtr timer = CreateWaitableTimerExW(IntPtr.Zero, IntPtr.Zero, 2 /*HIGH_RESOLUTION*/, 0x1F0003);
            if (timer == IntPtr.Zero) throw new Exception("CreateWaitableTimerExW " + Marshal.GetLastWin32Error());
            var rng = new Random(12345);
            while (Volatile.Read(ref stopLoad) == 0)
            {
                long due = -rng.Next(1000, 8000);             // idle 0.1-0.8 ms (100 ns units)
                SetWaitableTimer(timer, ref due, 0, IntPtr.Zero, IntPtr.Zero, false);
                WaitForSingleObject(timer, 0xFFFFFFFF);
                ulong now, end;
                QueryInterruptTimePrecise(out now);
                end = now + (ulong)rng.Next(20000, 50000);     // busy 2-5 ms
                while (now < end && Volatile.Read(ref stopLoad) == 0) QueryInterruptTimePrecise(out now);
            }
            CloseHandle(timer);
        });
        var main = new Thread(() =>
        {
            try
            {
                Pin(1, 0);
                for (int t = 0; t < trials; t++) TrialP(t, helperMask);
            }
            catch (Exception e) { err = e; }
            finally { Volatile.Write(ref stopLoad, 1); }
        });
        load.Start();
        main.Start();
        main.Join();
        load.Join();
        FreeDrain();
        foreach (var kv in tally) Console.WriteLine("TALLY {0} = {1}", kv.Key, kv.Value);
        if (err != null) throw err;
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
