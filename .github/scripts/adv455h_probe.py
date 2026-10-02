#!/usr/bin/env python3
"""Throwaway probe for the PR #455 review (round h). macOS CI only.

A: a process blocked in `signal.sigwait`, stopped, then sent two waited signals and SIGCONT.
B: the real forward.py, stopped in sigwait while its command exits, then `kill %job`'s TERM+CONT.
"""

import collections
import ctypes
import ctypes.util
import json
import os
import select
import signal
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FORWARD = os.path.join(HERE, "forward.py")
N = int(os.environ.get("PROBE_N", "40"))
S = signal.Signals

libproc = ctypes.CDLL(ctypes.util.find_library("proc"))


class ThreadInfo(ctypes.Structure):
    _fields_ = [
        ("user", ctypes.c_uint64), ("system", ctypes.c_uint64), ("cpu", ctypes.c_int32),
        ("policy", ctypes.c_int32), ("run_state", ctypes.c_int32), ("flags", ctypes.c_int32),
        ("sleep", ctypes.c_int32), ("curpri", ctypes.c_int32), ("pri", ctypes.c_int32),
        ("maxpri", ctypes.c_int32), ("name", ctypes.c_char * 64),
    ]


def thread_states(pid):
    ids = (ctypes.c_uint64 * 64)()
    n = libproc.proc_pidinfo(pid, 6, 0, ids, ctypes.sizeof(ids)) // 8  # PROC_PIDLISTTHREADS
    states = []
    for i in range(n):
        info = ThreadInfo()
        if libproc.proc_pidinfo(pid, 5, ctypes.c_uint64(ids[i]), ctypes.byref(info), ctypes.sizeof(info)) > 0:
            states.append(info.run_state)  # 1 running, 2 stopped, 3 waiting, 4 uninterruptible
    return states


def wait_all_waiting(pid):
    polls = 0
    while True:
        s = thread_states(pid)
        if s and all(x == 3 for x in s):
            return
        polls += 1
        if polls == 2000:
            print(f"    still not waiting after 2000 polls: {s}", flush=True)


def ps_stat(pid):
    return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()


WAITER = r"""
import json, os, signal, sys
W = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGCHLD)
signal.pthread_sigmask(signal.SIG_BLOCK, W)
signal.signal(signal.SIGCHLD, lambda *_: None)
if sys.argv[1] == "catch":
    for s in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, lambda *_: None)
sys.stdout.write("r\n"); sys.stdout.flush()
n = signal.sigwait(W)
print(json.dumps({"n": n, "pending": sorted(int(s) for s in signal.sigpending())}), flush=True)
"""


def readline_bounded(stream, bound):
    ready, _, _ = select.select([stream], [], [], bound)  # probe-only failure bound
    return stream.readline() if ready else None


def part_a(first, second, mode):
    results = collections.Counter()
    for _ in range(N):
        p = subprocess.Popen([sys.executable, "-c", WAITER, mode], stdout=subprocess.PIPE, text=True)
        assert p.stdout.readline() == "r\n"
        wait_all_waiting(p.pid)
        os.kill(p.pid, signal.SIGSTOP)
        os.waitpid(p.pid, os.WUNTRACED)
        os.kill(p.pid, first)
        os.kill(p.pid, second)
        stat_before_cont = ps_stat(p.pid)
        os.kill(p.pid, signal.SIGCONT)
        line = readline_bounded(p.stdout, 5)
        note = ""
        if line is None:
            note = f"STUCK stat={ps_stat(p.pid)} threads={thread_states(p.pid)}"
            os.kill(p.pid, signal.SIGCONT)
            line = readline_bounded(p.stdout, 2)
            note += " second CONT: " + ("revived" if line else f"still stuck stat={ps_stat(p.pid)}")
            if line is None:
                os.kill(p.pid, signal.SIGKILL)
        status = p.wait()
        r = json.loads(line) if line else {"n": None, "pending": []}
        results[(r["n"], tuple(r["pending"]), status, stat_before_cont, note)] += 1
    print(f"A stopped in sigwait ({mode} TERM/HUP), {S(first).name} then {S(second).name}, then CONT: n={N}")
    for key, count in results.most_common():
        print(f"    {count:3d}  sigwait->{key[0]!r} pending={key[1]!r} status={key[2]} stat-before-CONT={key[3]!r} {key[4]}")


COMMAND = r"""
import os
os.write(1, str(os.getpid()).encode() + b"\n")
os.read(0, 1)
os._exit(7)
"""


def part_b():
    results = collections.Counter()
    for _ in range(N):
        f = subprocess.Popen([sys.executable, FORWARD, sys.executable, "-c", COMMAND],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = int(f.stdout.readline())
        q = select.kqueue()
        q.control([select.kevent(command, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 0, 0)
        wait_all_waiting(f.pid)
        os.kill(f.pid, signal.SIGSTOP)  # ^Z
        os.waitpid(f.pid, os.WUNTRACED)
        f.stdin.write(b"x"); f.stdin.flush()  # the command exits while the forwarder is stopped
        q.control(None, 1, None)
        while ps_stat(command)[:1] != "Z":
            pass
        os.kill(f.pid, signal.SIGTERM)  # bash `kill %1` on a stopped job: TERM, then CONT
        os.kill(f.pid, signal.SIGCONT)
        try:
            status = f.wait(timeout=5)  # probe-only failure bound
            note = ""
        except subprocess.TimeoutExpired:
            status = "stuck"
            note = f"stat={ps_stat(f.pid)} threads={thread_states(f.pid)}"
            os.kill(f.pid, signal.SIGKILL)
            f.wait()
        q.close()
        err = f.stderr.read().decode().strip().replace("\n", " / ")
        results[(status, note[:40], err[:160])] += 1
        f.stdin.close(); f.stdout.close(); f.stderr.close()
    print(f"B forward.py stopped in sigwait, command exits, then TERM+CONT: n={N}")
    for key, count in results.most_common():
        print(f"    {count:3d}  status={key[0]} {key[1]} log={key[2]!r}")


if __name__ == "__main__":
    print(sys.version, os.uname(), flush=True)
    for mode in ("default", "catch"):
        for pair in [(signal.SIGCHLD, signal.SIGTERM), (signal.SIGTERM, signal.SIGCHLD), (signal.SIGCHLD, signal.SIGHUP), (signal.SIGCHLD, signal.SIGINT)]:
            part_a(*pair, mode)
    part_b()
