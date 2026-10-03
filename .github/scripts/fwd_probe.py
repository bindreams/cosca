#!/usr/bin/env python3
"""THROWAWAY probe: test_a_command_that_is_stopped_does_not_hold_up_a_signal, instrumented.

Same sequence as the test. Adds a NOTE_EXIT watch on the command (registered while it is alive and
blocked), timestamps for each phase, and on a stall: ps/sample snapshots, a long observation window
(slowness check), then recovery attempts that tell which side is wedged.

Usage: fwd_probe.py <iterations> <tag>
"""

import json
import os
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FORWARD = str(HERE / "forward.py")
STALL = float(os.environ.get("PROBE_STALL", "30"))
OBSERVE = float(os.environ.get("PROBE_OBSERVE", "90"))
JITTER_NS = int(float(os.environ.get("PROBE_JITTER_US", "0")) * 1000)
import random

CMD = (
    "import os, signal, sys\n"
    "work = sys.argv[1]\n"
    "signal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
    "os.write(os.open(work + '/up', os.O_RDWR), str(os.getpid()).encode() + b'\\n')\n"
    "os.read(os.open(work + '/release', os.O_RDWR), 1)\n"
    "sys.exit(7)\n"
)


class _PidFd:
    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd

    def close(self):
        os.close(self.fd)


def exit_kq(pid):
    if hasattr(os, "pidfd_open"):
        return _PidFd(os.pidfd_open(pid))
    q = select.kqueue()
    q.control([select.kevent(pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 0, 0)
    return q


def fired(q, timeout=0):
    return bool(select.select([q], [], [], timeout)[0])


def sh(*argv, timeout=60):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:  # noqa: BLE001
        return f"<{argv[0]} failed: {e}>"


class Reader:
    def __init__(self, proc):
        self.fd = proc.stderr.fileno()
        self.buf = b""

    def until(self, text, ended, bound):
        deadline = time.monotonic() + bound
        while text.encode() not in self.buf:
            rem = deadline - time.monotonic()
            if rem <= 0:
                return False
            r = select.select([self.fd, ended], [], [], rem)[0]
            if self.fd in r:
                chunk = os.read(self.fd, 65536)
                if not chunk:
                    return False
                self.buf += chunk
            elif r:
                return False
        return True

    def drain(self):
        while select.select([self.fd], [], [], 0)[0]:
            chunk = os.read(self.fd, 65536)
            if not chunk:
                break
            self.buf += chunk
        return self.buf.decode(errors="replace")


def snapshot(label, pids):
    out = [f"--- {label} @ {time.monotonic():.3f}"]
    pidlist = ",".join(str(p) for p in pids)
    out.append(sh("ps", "-o", "pid,ppid,pgid,stat,wchan,sig,sigmask,sigignore,sigcatch,etime,command", "-p", pidlist))
    return "\n".join(out)


def one(i, tag, results):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        os.mkfifo(work / "up")
        os.mkfifo(work / "release")
        up = os.open(work / "up", os.O_RDWR)
        release = os.open(work / "release", os.O_RDWR)
        rec = {"i": i, "tag": tag}
        t = {}
        proc = subprocess.Popen([sys.executable, FORWARD, sys.executable, "-c", CMD, str(work)], stderr=subprocess.PIPE)
        f_exit = exit_kq(proc.pid)
        rd = Reader(proc)
        cmd = None
        c_exit = None
        try:
            if not rd.until("started the command", f_exit, STALL):
                rec["error"] = "no start line"
                return rec
            if JITTER_NS:
                # Spin on `up` so the stop can land microseconds after the command's write, then sweep.
                os.set_blocking(up, False)
                give_up = time.monotonic() + STALL
                data = b""
                while not data.endswith(b"\n") and time.monotonic() < give_up:
                    try:
                        data += os.read(up, 32)
                    except BlockingIOError:
                        pass
                if not data.endswith(b"\n"):
                    rec["error"] = "no up"
                    return rec
                cmd = int(data)
                spin = time.perf_counter_ns() + random.randrange(JITTER_NS)
                while time.perf_counter_ns() < spin:
                    pass
                t["stop"] = time.monotonic()
                os.kill(cmd, signal.SIGSTOP)
                c_exit = exit_kq(cmd)  # the command cannot exit while stopped and unreleased
            else:
                if not select.select([up, f_exit], [], [], STALL)[0]:
                    rec["error"] = "no up"
                    return rec
                cmd = int(os.read(up, 32))
                c_exit = exit_kq(cmd)
                t["stop"] = time.monotonic()
                os.kill(cmd, signal.SIGSTOP)
            if not rd.until("is still running", f_exit, STALL):
                rec["error"] = "no still-running"
                rec["log"] = rd.drain()
                return rec
            t["still"] = time.monotonic()
            proc.send_signal(signal.SIGTERM)
            if not rd.until("relayed SIGTERM", f_exit, STALL):
                rec["error"] = "no relay"
                rec["log"] = rd.drain()
                return rec
            t["relayed"] = time.monotonic()
            os.kill(cmd, signal.SIGCONT)
            t["cont"] = time.monotonic()
            # Wait for the command's exit and the forwarder's exit separately.
            deadline = t["cont"] + STALL
            c_done = f_done = False
            while not (c_done and f_done):
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                waitset = [q for q, d in ((c_exit, c_done), (f_exit, f_done)) if not d]
                r = select.select(waitset, [], [], rem)[0]
                now = time.monotonic()
                if c_exit in r and not c_done:
                    c_done = True
                    t["c_exit"] = now
                if f_exit in r and not f_done:
                    f_done = True
                    t["f_exit"] = now
            if f_done:
                rec["status"] = proc.wait()
                rec["ok"] = rec["status"] == 9
                rec["t"] = {k: round(v - t["stop"], 6) for k, v in t.items()}
                return rec
            # Stall.
            rec["stall"] = True
            rec["t"] = {k: round(v - t["stop"], 6) for k, v in t.items()}
            rec["c_exited_within_bound"] = c_done
            diag = [snapshot("at stall", [proc.pid, cmd])]
            diag.append("sample C:\n" + sh("sample", str(cmd), "1", "-mayDie"))
            diag.append("sample F:\n" + sh("sample", str(proc.pid), "1", "-mayDie"))
            # Slowness check: does it end on its own?
            obs_deadline = time.monotonic() + OBSERVE
            while not (c_done and f_done) and time.monotonic() < obs_deadline:
                waitset = [q for q, d in ((c_exit, c_done), (f_exit, f_done)) if not d]
                r = select.select(waitset, [], [], max(0, obs_deadline - time.monotonic()))[0]
                now = time.monotonic()
                if c_exit in r and not c_done:
                    c_done = True
                    t["c_exit_late"] = now
                if f_exit in r and not f_done:
                    f_done = True
                    t["f_exit_late"] = now
            rec["after_observe"] = {"c_exited": c_done, "f_exited": f_done}
            if not f_done:
                diag.append(snapshot("after observe", [proc.pid, cmd]))
                # Recovery 1: a second SIGCONT to the command.
                if not c_done:
                    os.kill(cmd, signal.SIGCONT)
                    c_done = fired(c_exit, 10)
                    rec["second_cont_made_c_exit"] = c_done
                    diag.append(snapshot("after second CONT", [proc.pid, cmd]))
                if c_done:
                    f_done = fired(f_exit, 10)
                    rec["f_exited_after_c"] = f_done
                if not c_done:
                    # Recovery 2: TERM straight to the command.
                    os.kill(cmd, signal.SIGTERM)
                    c_done = fired(c_exit, 10)
                    rec["direct_term_made_c_exit"] = c_done
                    if c_done:
                        f_done = fired(f_exit, 10)
                        rec["f_exited_after_c"] = f_done
                if c_done and not f_done:
                    # Recovery 3: a spurious CHLD-free wake: HUP to the forwarder.
                    proc.send_signal(signal.SIGHUP)
                    f_done = fired(f_exit, 10)
                    rec["hup_woke_f"] = f_done
                    diag.append(snapshot("after HUP to F", [proc.pid, cmd]))
            rec["t"] = {k: round(v - t["stop"], 6) for k, v in t.items()}
            rec["log"] = rd.drain()
            rec["diag"] = "\n".join(diag)
            return rec
        finally:
            if cmd is not None and c_exit is not None and not fired(c_exit):
                try:
                    os.killpg(cmd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stderr.close()
            f_exit.close()
            if c_exit is not None:
                c_exit.close()
            os.write(release, b"x")
            os.close(up)
            os.close(release)


def main():
    n, tag = int(sys.argv[1]), sys.argv[2]
    out = Path(os.environ.get("PROBE_OUT", ".")) / f"probe-{tag}.jsonl"
    stalls = 0
    with open(out, "w") as fh:
        for i in range(n):
            rec = one(i, tag, None)
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            if rec.get("stall") or rec.get("error") or not rec.get("ok", False):
                stalls += 1
                print(json.dumps({k: v for k, v in rec.items() if k != "diag"}), flush=True)
                print(rec.get("diag", ""), flush=True)
            if i % 500 == 0:
                print(f"[{tag}] {i} done, {stalls} bad", flush=True)
    print(f"[{tag}] finished {n}, {stalls} bad", flush=True)


if __name__ == "__main__":
    main()
