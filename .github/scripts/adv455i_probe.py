"""Throwaway macOS probe for the adversarial review of #455 (round i). CI only."""
import os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
F = "forward.py"
MUTANTS = {
    "baseline": [],
    "always-sigwait": [(F, 'return _kqueue_waiter() if hasattr(select, "kqueue") else _sigwait_waiter()', "return _sigwait_waiter()")],
    "no-ignore": [(F, "    for number in RELAYED:\n        signal.signal(number, signal.SIG_IGN)\n", "")],
    "no-chld-kevent": [(F, "for number in BLOCKED],\n        0,", "for number in RELAYED],\n        0,")],
    "no-early": [(F, "    early = [int(number) for number in BLOCKED if number in pending]", "    early = []")],
    "ignore-before-register": [(F, "    signal.pthread_sigmask(signal.SIG_BLOCK, BLOCKED)\n    queue = select.kqueue()", "    for number in RELAYED:\n        signal.signal(number, signal.SIG_IGN)\n    queue = select.kqueue()")],
    "oneshot": [(F, "select.KQ_EV_ADD | select.KQ_EV_CLEAR", "select.KQ_EV_ADD | select.KQ_EV_ONESHOT")],
    "no-unblock": [(F, "    signal.pthread_sigmask(signal.SIG_UNBLOCK, BLOCKED)\n", "")],
    "relay-after-reap": [(F, "    child.returncode = 0  # reaped here", "    try:\n        kill(-child.pid, signal.SIGTERM)\n    except OSError:\n        pass\n    child.returncode = 0  # reaped here")],
    "block-after-popen": [(F, "    wait = make_wait()\n    try:\n        child = popen(argv, start_new_session=True, close_fds=False, preexec_fn=_child_setup)\n", "    try:\n        child = popen(argv, start_new_session=True, close_fds=False, preexec_fn=_child_setup)\n        wait = make_wait()\n")],
    "no-disposition-reset": [(F, "        signal.signal(number, signal.SIG_DFL)", "        pass")],
}
SUITES = [
    ["-m", "unittest", "-f", "forward_tests", "run_nextest_tests"],
] + [["-m", "unittest", "-f", "forward_tests.Waiting", "forward_tests.Relay", "forward_tests.SpawnWindow"]] * 10


def run_mutant(name):
    work = tempfile.mkdtemp()
    dst = os.path.join(work, "s")
    shutil.copytree(HERE, dst)
    for f, old, new in MUTANTS[name]:
        p = os.path.join(dst, f)
        text = open(p).read()
        assert text.count(old) == 1, (name, old)
        open(p, "w").write(text.replace(old, new))
    t = time.monotonic()
    for i, suite in enumerate(SUITES):
        log = open(os.path.join(work, "log"), "w+")
        try:
            r = subprocess.run([sys.executable, *suite], cwd=dst, stdout=log, stderr=log, timeout=200, start_new_session=True)
        except subprocess.TimeoutExpired:
            print(f"MUTANT {name}: HANG >200s in run {i} [{time.monotonic()-t:.1f}s]", flush=True)
            return
        if r.returncode:
            log.seek(0)
            fails = [l for l in log.read().splitlines() if l.startswith(("FAIL:", "ERROR:", "AssertionError", "Traceback"))][:3]
            print(f"MUTANT {name}: FAILS in run {i}: {fails} [{time.monotonic()-t:.1f}s]", flush=True)
            return
    print(f"MUTANT {name}: SURVIVES {len(SUITES)} runs [{time.monotonic()-t:.1f}s]", flush=True)


DOUBLE = r'''
import os, select, signal, sys
sys.path.insert(0, os.getcwd())
import forward
real = select.kqueue
class KQ:
    def __init__(self):
        self.q, self.n = real(), 0
    def control(self, *a):
        r = self.q.control(*a)
        self.n += 1
        if self.n == 1:  # the registration has just happened; sigpending() is next
            os.kill(os.getpid(), signal.SIGTERM)
        return r
select.kqueue = KQ
r, w = os.pipe()
os.set_inheritable(r, True)
kills = []
def kill(pid, number):
    kills.append(number)
    if len(kills) == 2:
        os.write(w, b"x")  # the command ends once a second relay has happened
command = [sys.executable, "-c", f"import os; os.read({r}, 1)"]
status = forward.run(command, kill=kill, log=lambda m: print(m, flush=True))
print("one TERM sent; relays:", kills, "status:", status, flush=True)
'''


def double_count():
    try:
        r = subprocess.run([sys.executable, "-c", DOUBLE], cwd=HERE, capture_output=True, timeout=20)
        print("DOUBLE-COUNT:", r.returncode, r.stdout.decode().strip().replace("\n", " / "), r.stderr.decode().strip()[-300:], flush=True)
    except subprocess.TimeoutExpired:
        print("DOUBLE-COUNT: no second relay within 20s (single count)", flush=True)


def ignored_chld():
    cases = {
        "python sets SIG_IGN then execs forward.py": [sys.executable, "-c", "import os,signal,sys; signal.signal(signal.SIGCHLD, signal.SIG_IGN); os.execv(sys.executable, [sys.executable, 'forward.py', 'sh', '-c', 'exit 7'])"],
        "bash trap '' CHLD; exec forward.py": ["bash", "-c", f"trap '' CHLD; exec {sys.executable} forward.py sh -c 'exit 7'"],
        "SIG_IGN set in a parent, forward.py forked from it": [sys.executable, "-c", "import os,signal,subprocess,sys; signal.signal(signal.SIGCHLD, signal.SIG_IGN); sys.exit(subprocess.call([sys.executable, 'forward.py', 'sh', '-c', 'exit 7']))"],
        "default": [sys.executable, "forward.py", "sh", "-c", "exit 7"],
    }
    for name, argv in cases.items():
        p = subprocess.Popen(argv, cwd=HERE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            _, err = p.communicate(timeout=20)
            print(f"IGNORED-CHLD [{name}]: status {p.returncode} (expected 7) {err.decode().strip()[-200:]}", flush=True)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            print(f"IGNORED-CHLD [{name}]: STUCK, no exit within 20s (expected 7)", flush=True)


import signal
print(sys.version, os.uname().release, flush=True)
double_count()
ignored_chld()
for name in sys.argv[1:] or MUTANTS:
    run_mutant(name)
