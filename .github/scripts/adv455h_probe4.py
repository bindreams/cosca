#!/usr/bin/env python3
"""Throwaway probe v4 for the PR #455 review (round h). macOS CI only."""

import collections
import os
import select
import signal
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adv455h_probe import FORWARD, N, S, ps_stat, readline_bounded, thread_states, wait_all_waiting  # noqa: E402

W_SRC = "W = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGCHLD)\nsignal.pthread_sigmask(signal.SIG_BLOCK, W)\nsignal.signal(signal.SIGCHLD, lambda *_: None)\n"

SIGWAIT = "import os, signal, sys\n" + W_SRC + "print('r', flush=True)\nn = signal.sigwait(W)\nprint(n, sorted(int(s) for s in signal.sigpending()), flush=True)\n"

KQUEUE = (
    "import os, select, signal, sys\n" + W_SRC
    + "q = select.kqueue()\n"
    + "q.control([select.kevent(s, select.KQ_FILTER_SIGNAL, select.KQ_EV_ADD) for s in W], 0, 0)\n"
    + "print('r', flush=True)\n"
    + "seen = []\n"
    + "while len(seen) < 2:\n"
    + "    seen += [(e.ident, e.data) for e in q.control(None, 4, None)]\n"
    + "print(seen, sorted(int(s) for s in signal.sigpending()), flush=True)\n"
)


def stopped_burst(src, signals):
    """Stop the waiter in its wait, send `signals` and SIGCONT back to back, then see if it resumes."""
    results = collections.Counter()
    for _ in range(N):
        p = subprocess.Popen([sys.executable, "-c", src], stdout=subprocess.PIPE, text=True)
        assert p.stdout.readline() == "r\n"
        wait_all_waiting(p.pid)
        os.kill(p.pid, signal.SIGSTOP)
        os.waitpid(p.pid, os.WUNTRACED)
        for s in signals:
            os.kill(p.pid, s)
        os.kill(p.pid, signal.SIGCONT)
        line = readline_bounded(p.stdout, 5)  # probe-only failure bound
        if line is None:
            stat = ps_stat(p.pid)
            os.kill(p.pid, signal.SIGCONT)
            again = readline_bounded(p.stdout, 5)
            key = f"STUCK (stat {stat}); a second SIGCONT " + ("resumed it: " + again.strip() if again else "did not")
            if again is None:
                os.kill(p.pid, signal.SIGKILL)
        else:
            key = "resumed: " + (line.strip() if "seen" in src or "[(" in line else ("garbage" if int(line.split()[0]) not in (1, 2, 15, 20) else line.split()[0]) + " pending " + line.split(" ", 1)[1].strip())
        p.wait()
        results[key] += 1
    names = "+".join(S(s).name for s in signals)
    kind = "kqueue" if "kqueue" in src else "sigwait"
    print(f"{kind}: stopped, {names}+SIGCONT back to back: n={N}")
    for key, count in results.most_common():
        print(f"    {count:3d}  {key}")


COMMAND = "import os, signal\nsignal.signal(signal.SIGTERM, lambda *_: os._exit(9))\nos.write(1, str(os.getpid()).encode() + b'\\n')\nos.read(0, 1)\nos._exit(7)\n"


def forward_case(label, act):
    results = collections.Counter()
    for _ in range(N):
        f = subprocess.Popen([sys.executable, FORWARD, sys.executable, "-c", COMMAND],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = int(f.stdout.readline())
        wait_all_waiting(f.pid)
        act(f, command)
        try:
            status = f.wait(timeout=5)  # probe-only failure bound
        except subprocess.TimeoutExpired:
            status = f"stuck (stat {ps_stat(f.pid)})"
            os.kill(f.pid, signal.SIGKILL)
            f.wait()
        try:
            os.kill(command, signal.SIGKILL)
        except OSError:
            pass
        err = f.stderr.read().decode()
        kind = "ValueError" if "ValueError" in err else ""
        lines = [l for l in err.splitlines() if l.startswith("forward.py")]
        results[(status, kind, " / ".join(l.split(":", 1)[1].split(" (")[0].strip() for l in lines))] += 1
        for s in (f.stdin, f.stdout, f.stderr):
            s.close()
    print(f"forward.py: {label}: n={N}")
    for key, count in results.most_common():
        print(f"    {count:3d}  status={key[0]} {key[1]} log={key[2]!r}")


def exit_race(f, command):
    """The shape of forward_tests' exit-race test: stop, the command exits, TERM and CONT at once."""
    q = select.kqueue()
    q.control([select.kevent(command, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 0, 0)
    os.kill(f.pid, signal.SIGSTOP)
    os.waitpid(f.pid, os.WUNTRACED)
    f.stdin.write(b"x"); f.stdin.flush()
    q.control(None, 1, None)
    q.close()
    os.kill(f.pid, signal.SIGTERM)
    os.kill(f.pid, signal.SIGCONT)


def burst(*signals):
    def act(f, command):
        for s in signals:
            os.kill(f.pid, s)
    return act


if __name__ == "__main__":
    print(sys.version, os.uname().release, flush=True)
    stopped_burst(SIGWAIT, (signal.SIGCHLD, signal.SIGTERM))
    stopped_burst(SIGWAIT, (signal.SIGTERM, signal.SIGCHLD))
    stopped_burst(KQUEUE, (signal.SIGCHLD, signal.SIGTERM))
    stopped_burst(KQUEUE, (signal.SIGTERM, signal.SIGCHLD))
    forward_case("stopped, its command exits, then TERM+CONT at once (the exit-race test)", exit_race)
    forward_case("running, live command, TERM then CHLD back to back", burst(signal.SIGTERM, signal.SIGCHLD))
    forward_case("running, live command, TERM then HUP back to back", burst(signal.SIGTERM, signal.SIGHUP))
