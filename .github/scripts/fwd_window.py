#!/usr/bin/env python3
"""THROWAWAY: deterministic reproduction of the stall in Waiting.test_a_command_that_is_stopped_does_not_hold_up_a_signal.

The test's command catches TERM with a Python handler and then blocks in os.read. CPython runs a Python
handler only at an eval-breaker check; if the C-level trampoline runs after the last check and before
read(2) is entered, the read blocks and the handler never runs. The test's SIGSTOP can freeze the command
anywhere between its write to `up` and the blocking read; on SIGCONT the pending TERM is delivered there.

Scenarios (each through the real forward.py, with the test's own sequence: stopped -> "still running"
-> TERM to the forwarder -> "relayed" -> CONT to the command -> wait):
  window   the command stops itself inside a native call that then reads: the stop point is pinned
           between the last eval-breaker check and read(2).
  pycheck  the command stops itself with os.kill and then calls os.read: an eval-breaker check runs
           between the two.
  default  as `window`, but TERM is left at its default action (the proposed fix).
Usage: fwd_window.py <runs-per-scenario>
"""
import ctypes, os, select, signal, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FORWARD = str(HERE / "forward.py")
BOUND = 10.0

HELPER_C = r"""
#include <signal.h>
#include <unistd.h>
long stop_then_read(int fd) { char c; raise(SIGSTOP); return (long)read(fd, &c, 1); }
"""

def build(tmp):
    src, lib = Path(tmp) / "h.c", Path(tmp) / "libh.so"
    src.write_text(HELPER_C)
    subprocess.run(["cc", "-shared", "-fPIC", "-o", str(lib), str(src)], check=True)
    return str(lib)

def command(kind, lib):
    head = "import ctypes, os, signal, sys\nwork = sys.argv[1]\n"
    if kind != "default":
        head += "signal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
    head += "os.write(os.open(work + '/up', os.O_RDWR), str(os.getpid()).encode() + b'\\n')\n"
    head += "fd = os.open(work + '/release', os.O_RDWR)\n"
    if kind == "pycheck":
        head += "os.kill(os.getpid(), signal.SIGSTOP)\nos.read(fd, 1)\n"
    else:
        head += f"ctypes.CDLL({lib!r}).stop_then_read(fd)\n"
    return head + "sys.exit(7)\n"

def exit_watch(pid):
    if hasattr(os, "pidfd_open"):
        fd = os.pidfd_open(pid)
        class W:
            def fileno(self): return fd
            def close(self): os.close(fd)
        return W()
    q = select.kqueue()
    q.control([select.kevent(pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 0, 0)
    return q

def read_until(fd, text, buf, bound):
    deadline = time.monotonic() + bound
    while text not in buf[0]:
        rem = deadline - time.monotonic()
        if rem <= 0 or not select.select([fd], [], [], rem)[0]:
            return False
        chunk = os.read(fd, 65536)
        if not chunk:
            return False
        buf[0] += chunk
    return True

def proc_state(pid):
    try:
        return subprocess.run(["ps", "-o", "stat=,wchan=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        try:
            return Path(f"/proc/{pid}/stat").read_text().split()[2] + " " + Path(f"/proc/{pid}/wchan").read_text()
        except OSError as e:
            return str(e)

def one(kind, lib):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        os.mkfifo(work / "up"); os.mkfifo(work / "release")
        up = os.open(work / "up", os.O_RDWR); release = os.open(work / "release", os.O_RDWR)
        proc = subprocess.Popen([sys.executable, FORWARD, sys.executable, "-c", command(kind, lib), str(work)], stderr=subprocess.PIPE)
        err, buf, cmd = proc.stderr.fileno(), [b""], None
        try:
            if not select.select([up], [], [], BOUND)[0]:
                return "no up"
            cmd = int(os.read(up, 32))
            c_exit = exit_watch(cmd)
            if not read_until(err, b"is still running", buf, BOUND):
                return "no still-running: " + buf[0].decode()
            proc.send_signal(signal.SIGTERM)
            if not read_until(err, b"relayed SIGTERM", buf, BOUND):
                return "no relay: " + buf[0].decode()
            os.kill(cmd, signal.SIGCONT)
            try:
                status = proc.wait(timeout=BOUND)
                return f"exit {status}"
            except subprocess.TimeoutExpired:
                c_gone = bool(select.select([c_exit], [], [], 0)[0])
                state = proc_state(cmd)
                # The TERM was consumed: a second TERM straight to the command unblocks it.
                os.kill(cmd, signal.SIGTERM)
                try:
                    status = proc.wait(timeout=BOUND)
                    after = f"a direct TERM to the command then gave exit {status}"
                except subprocess.TimeoutExpired:
                    after = "still stuck after a direct TERM"
                return f"STUCK {BOUND:.0f}s (command exited: {c_gone}, command state: {state!r}); {after}"
        finally:
            if cmd is not None:
                try: os.killpg(cmd, signal.SIGKILL)
                except (ProcessLookupError, PermissionError): pass
            if proc.poll() is None: proc.kill()
            proc.wait(); proc.stderr.close()
            os.write(release, b"x"); os.close(up); os.close(release)

def main():
    n = int(sys.argv[1])
    with tempfile.TemporaryDirectory() as tmp:
        lib = build(tmp)
        for kind in ("window", "pycheck", "default"):
            outcomes = {}
            for _ in range(n):
                o = one(kind, lib)
                outcomes[o] = outcomes.get(o, 0) + 1
            for o, c in outcomes.items():
                print(f"{kind:8s} {c}/{n}: {o}", flush=True)

if __name__ == "__main__":
    main()
