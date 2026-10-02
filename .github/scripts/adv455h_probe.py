#!/usr/bin/env python3
"""Throwaway probe for the PR #455 review (round h). macOS CI only.

A: two different waited signals sent back to back to a process blocked in `signal.sigwait`.
B: the same against the real forward.py, whose command records a relayed TERM.
"""

import collections
import json
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FORWARD = os.path.join(HERE, "forward.py")
N = int(os.environ.get("PROBE_N", "150"))
S = signal.Signals

WAITER = r"""
import json, os, signal, sys
W = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGCHLD)
signal.pthread_sigmask(signal.SIG_BLOCK, W)
signal.signal(signal.SIGCHLD, lambda *_: None)
sys.stdout.write("r\n"); sys.stdout.flush()
n = signal.sigwait(W)
print(json.dumps({"n": n, "pending": sorted(int(s) for s in signal.sigpending())}), flush=True)
"""

COMMAND = r"""
import os, signal, sys
def term(*_):
    os.write(1, b"term\n")
    os._exit(9)
signal.signal(signal.SIGTERM, term)
os.write(1, b"up\n")
os.read(0, 1)
os._exit(7)
"""


def wchan(pid):
    out = subprocess.run(["ps", "-o", "wchan=", "-p", str(pid)], capture_output=True, text=True).stdout
    return out.strip()


def wait_pause(pid):
    seen = collections.Counter()
    while True:
        w = wchan(pid)
        seen[w] += 1
        if w == "pause":
            return seen
        if sum(seen.values()) % 200 == 0:
            st = subprocess.run(["ps", "-o", "pid,stat,wchan,command", "-p", str(pid)], capture_output=True, text=True).stdout
            print(f"    still waiting for 'pause': {dict(seen)} {st!r}", flush=True)


def part_a(first, second):
    results = collections.Counter()
    wchans = collections.Counter()
    for _ in range(N):
        p = subprocess.Popen([sys.executable, "-c", WAITER], stdout=subprocess.PIPE, text=True)
        assert p.stdout.readline() == "r\n"
        wchans.update(wait_pause(p.pid))
        os.kill(p.pid, first)
        os.kill(p.pid, second)
        line = p.stdout.readline()
        status = p.wait()
        if not line:
            results[("died", status)] += 1
            continue
        r = json.loads(line)
        results[(r["n"], tuple(r["pending"]), status)] += 1
    print(f"A {S(first).name} then {S(second).name}: n={N}")
    for key, count in results.most_common():
        print(f"    {count:4d}  sigwait->{key[0]!r} pending={key[1]!r} status={key[2]!r}" if key[0] != "died" else f"    {count:4d}  died status={key[1]}")
    print(f"    wchan polls: {dict(wchans)}")
    sys.stdout.flush()


def part_b(first, second):
    results = collections.Counter()
    samples = {}
    for _ in range(N):
        f = subprocess.Popen(
            [sys.executable, FORWARD, sys.executable, "-c", COMMAND],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert f.stdout.readline() == b"up\n"
        wait_pause(f.pid)
        os.kill(f.pid, first)
        os.kill(f.pid, second)
        try:
            status = f.wait(timeout=10)  # probe-only failure bound
            out = f.stdout.read()
        except subprocess.TimeoutExpired:
            status = "stuck"
            os.kill(f.pid, signal.SIGTERM)  # a second TERM, so the run ends
            f.wait()
            out = f.stdout.read()
        f.stdin.close()
        err = f.stderr.read().decode()
        kind = "ValueError" if "ValueError" in err else ("traceback" if "Traceback" in err else "")
        key = (status, b"term" in out, kind, "still running" in err, "relayed" in err)
        results[key] += 1
        samples.setdefault(key, err[-600:])
    print(f"B forward.py, {S(first).name} then {S(second).name}: n={N}")
    print("    key = (status, command got TERM, traceback, logged 'still running', logged 'relayed')")
    for key, count in results.most_common():
        print(f"    {count:4d}  {key}")
    for key, err in samples.items():
        print(f"    sample stderr for {key}:\n" + "\n".join("        " + l for l in err.splitlines()))
    sys.stdout.flush()


if __name__ == "__main__":
    print(sys.version, os.uname(), flush=True)
    t = time.monotonic()
    for pair in [
        (signal.SIGCHLD, signal.SIGTERM),
        (signal.SIGTERM, signal.SIGCHLD),
        (signal.SIGTERM, signal.SIGINT),
        (signal.SIGTERM, signal.SIGHUP),
    ]:
        part_a(*pair)
    for pair in [
        (signal.SIGTERM, signal.SIGCHLD),
        (signal.SIGCHLD, signal.SIGTERM),
        (signal.SIGTERM, signal.SIGINT),
    ]:
        part_b(*pair)
    print(f"total {time.monotonic() - t:.1f}s")
