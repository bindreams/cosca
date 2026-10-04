"""Plan F start-protocol interleavings, revision 5 (THROWAWAY). Usage: scenarios.py <name>...

Every wait is on an event: a FIFO line or EOF, an acceptor event (or the *next* one), a process exit,
a pidfd/kqueue. No sleeps, no timeouts; the runner's per-scenario bound reports HANG as a failure."""
import errno, os, queue, resource, select, signal, socket, stat, struct, subprocess, sys, tempfile, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cosca_proto as cp
from cosca_proto import ShimLink, ElevatedChild, ShimLost, NotStarted, LIVE, REFUSED, PENDING, MACOS, identity, Unsupported, check_shim_mode

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM = os.environ.get("SHIM", os.path.join(HERE, "shim9"))
PY = sys.executable
PROG = os.path.join(HERE, "prog.py")
RESULTS = []
SUDO = ["sudo", "-n"]
PW = ["sudo", "-S", "-k", "-p", ""]


def result(name, ok, detail):
    RESULTS.append(ok)
    print("RESULT %-44s %s  %s" % (name, "PASS" if ok else "FAIL", detail), flush=True)


class Fifo:
    def __init__(self, d, name):
        self.path = os.path.join(d, name)
        os.mkfifo(self.path, 0o666); os.chmod(self.path, 0o666)
        self.lines, self.done, self.cv = [], False, threading.Condition()
        self.t = threading.Thread(target=self._run, daemon=True); self.t.start()

    def _run(self):
        with open(self.path, "rb") as f:
            for line in f:
                with self.cv:
                    self.lines.append(line.decode(errors="replace").rstrip()); self.cv.notify_all()
        with self.cv:
            self.done = True; self.cv.notify_all()

    def wait_for(self, pred):
        with self.cv:
            while not pred(self.lines) and not self.done:
                self.cv.wait()
            return pred(self.lines)

    def has(self, sub):
        return self.wait_for(lambda ls: any(sub in l for l in ls))

    def count(self, line):
        return sum(1 for l in self.lines if l == line)

    def eof(self):
        with self.cv:
            while not self.done:
                self.cv.wait()
        return list(self.lines)

    def unblock_if_never_opened(self):
        if self.t.is_alive():
            try:
                os.close(os.open(self.path, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
        return self.eof()


class Gate:
    def __init__(self, d, name):
        self.path = os.path.join(d, name)
        os.mkfifo(self.path, 0o666); os.chmod(self.path, 0o666)

    def open(self):
        with open(self.path, "wb") as f:
            f.write(b"g")


class Pinger:
    def __init__(self, d):
        self.req, self.rep = os.path.join(d, "req"), os.path.join(d, "rep")
        for p in (self.req, self.rep):
            os.mkfifo(p, 0o666); os.chmod(p, 0o666)

    def connect(self):
        self.w = open(self.req, "wb", buffering=0)
        self.r = open(self.rep, "rb", buffering=0)

    def alive(self):
        try:
            self.w.write(b"?\n")
        except BrokenPipeError:
            return False
        return self.r.readline() == b"alive\n"

    def quit_and_wait_exit(self):
        self.w.write(b"q\n")
        return self.r.readline() == b""


def workdir():
    d = tempfile.mkdtemp(prefix="sc-"); os.chmod(d, 0o755); return d


def setup(front, d=None, mode="block", gate=False, hold=False, start_acceptor=True, acceptor_gate=None, extra=None,
          prog_exe=None, link_kw=None, seams_extra=None, prog_args=None):
    d = d or workdir()
    ev = queue.Queue()
    shimlog, siglog = Fifo(d, "shimlog"), Fifo(d, "siglog")
    ready = os.path.join(d, "ready"); os.mkfifo(ready, 0o666); os.chmod(ready, 0o666)
    seams = {"SHIM_LOG": shimlog.path}
    seams.update(seams_extra or {})
    g = h = rel = pinger = None
    if gate:
        g = Gate(d, "gate"); seams["SHIM_GATE"] = g.path
    if hold:
        h = Gate(d, "hold"); seams["SHIM_HOLD"] = h.path
    prog = [prog_exe or PY, PROG, siglog.path]
    if mode in ("block", "plain"):
        prog += [mode, ready]
    elif mode == "release":
        rel = Gate(d, "rel"); prog += ["release", ready, rel.path, "42"]
    elif mode.startswith("ping"):
        pinger = Pinger(d); prog += ["ping", ready, pinger.req, pinger.rep] + (["drop"] if mode == "ping-drop" else [])
    elif mode == "argv":
        prog += ["argv"] + list(prog_args)
    else:
        prog += ["exit", mode]
    link = ShimLink(start_acceptor=start_acceptor, events=ev, gate=acceptor_gate, **(link_kw or {}))
    c = ElevatedChild(front, SHIM, prog, link, seams=seams, **(extra or {}))
    c.d, c.ev, c.shimlog, c.siglog, c.gate, c.hold, c.ready, c.rel, c.pinger = d, ev, shimlog, siglog, g, h, ready, rel, pinger
    return c


def ev_until(q, kind):
    while True:
        e = q.get()
        if e[0] == kind or e[0] == "exited":
            return e


def read_ready(c):
    with open(c.ready) as f:
        parts = f.readline().split()
    if c.pinger:
        c.pinger.connect()
    return int(parts[1])


def shim_pid(c):
    c.shimlog.wait_for(lambda ls: len(ls) > 0)
    return int(c.shimlog.lines[0].split("pid=")[1].split()[0])


def never_ran(c):
    # the shim's own record: the status pipe's EOF is the only way the program can have begun (revision 9)
    started = any(l.startswith("status pipe: EOF") for l in c.shimlog.unblock_if_never_opened())
    return not started and not any(l.startswith("ran") for l in c.siglog.unblock_if_never_opened())


def as_root(code):
    return subprocess.run(SUDO + [PY, "-c", code], stdout=subprocess.PIPE, check=True).stdout.decode()


def outcome(f):
    """('program', status) | ('not-started', front, connected) | ('shim-lost', msg) | ('acceptor-failed', msg)"""
    try:
        return f()
    except NotStarted as e:
        return ("not-started", e.front, e.connected)
    except ShimLost as e:
        return ("shim-lost", str(e))
    except cp.AcceptorFailed as e:
        return ("acceptor-failed", str(e))
    except cp.SupervisionLost as e:
        return ("lost", e.status)
    except cp.StatusLost as e:
        return ("status-lost", str(e))
    except Exception as e:  # any other error is an outcome the assertion then rejects
        return ("exception", repr(e))


def refusal(log):
    return [l for l in log if l.startswith("refused")]


# --- start protocol --------------------------------------------------------------------------------
def s_connect_after_accept():
    c = setup(SUDO, gate=True)
    ev_until(c.ev, "polling")
    c.gate.open()
    ev_until(c.ev, "listener-ready")
    a = c.ev.get()  # the very next event must be the accept (an acceptor that never steps emits "polling")
    if a[0] == "accepted":
        a = ev_until(c.ev, "answered")
    if a[0] != "answered":
        result("connect-after-accept", False, f"next acceptor event after listener-ready: {a}")
        c.link.kill(c.p.pid); c.p.wait(); c.link.release(False); c.shimlog.eof(); return
    read_ready(c)
    k = c.kill(); w = outcome(c.wait); out = c.link.release(False)
    result("connect-after-accept", a[1] == "A" and k == "sent" and w == ("program", 9) and out == "removed", f"{a[1]} {k} {w} {out}")


def s_connect_before_accept():
    c = setup(SUDO, mode="plain", start_acceptor=False)
    p = select.poll(); p.register(c.link.listener.fileno(), select.POLLIN); p.poll()
    c.link.start_acceptor()
    a = ev_until(c.ev, "answered"); read_ready(c)
    t = c.terminate(); w = outcome(c.wait); out = c.link.release(False)
    result("connect-before-accept", a[1] == "A" and t == "sent" and w == ("program", 15), f"{a[1]} {t} {w} {out}")


def s_refuse_wins():
    g = threading.Event()
    c = setup(SUDO, mode="42", acceptor_gate=g)
    ev_until(c.ev, "listener-ready")
    k = c.kill()
    g.set(); a = ev_until(c.ev, "answered")
    if a[0] == "exited":
        result("refuse-then-connection", False, "acceptor thread exited before answering"); return
    log = c.shimlog.eof(); w = outcome(c.wait); out = c.link.release(False)
    result("refuse-then-connection", a[1] == "N" and k.startswith("refused") and never_ran(c) and w[0] == "not-started" and w[2] is True,
           f"{k} answer={a[1]} {w} shim={refusal(log)}")


def s_connect_wins():
    g = threading.Event()
    c = setup(SUDO, mode="ping", acceptor_gate=g)
    ev_until(c.ev, "listener-ready"); g.set()
    a = ev_until(c.ev, "answered"); read_ready(c)
    k = c.kill()
    c.front_status = c.p.wait()
    if c.pinger.alive():
        result("connection-then-kill", False, f"{a[1]} {k}: program alive after the front exited")
        c.pinger.quit_and_wait_exit(); c.link.release(False); return
    w = outcome(c.wait); c.link.release(False)
    result("connection-then-kill", a[1] == "A" and k == "sent" and w == ("program", 9), f"{a[1]} {k} {w}")


def s_wiring():
    """T3, revised: the answer is read BEFORE anything is dropped, after the acceptor's own 'answered' event."""
    link = ShimLink(expected_euid=os.geteuid(), events=queue.Queue())
    ev_until(link.events, "polling")
    s = socket.socket(socket.AF_UNIX); s.connect(os.path.join(link.path, "s")); s.send(b"H")
    ev_until(link.events, "listener-ready")
    e = link.events.get()  # T5: the very next event must be the accept; a non-stepping acceptor emits "polling"
    if e[0] == "accepted":
        e = ev_until(link.events, "answered")
    s.setblocking(False)
    try:
        got = s.recv(1)
    except BlockingIOError:
        got = "EAGAIN"
    except ConnectionResetError:
        got = "ECONNRESET"
    out = link.release(False)
    result("acceptor wiring (answer before drop)", e[0] == "answered" and got == b"A", f"event={e} recv={got!r} {out}")


def s_no_front_real_link():
    """The real ShimLink against the real shim, no front, same uid (expected-euid seam)."""
    c = setup([], link_kw={"expected_euid": os.geteuid()})
    a = ev_until(c.ev, "answered"); read_ready(c)
    k = c.kill(); w = outcome(c.wait); c.link.release(False)
    result("real ShimLink vs real shim, no front", a[1] == "A" and k == "sent" and w == ("program", 9), f"{a[1]} {k} {w}")


def s_second_root_peer():
    c = setup(SUDO)
    ev_until(c.ev, "answered"); read_ready(c)
    got = as_root("import socket; s=socket.socket(socket.AF_UNIX); s.connect(%r); s.send(b'H'); print(len(s.recv(1)))" % os.path.join(c.link.path, "s")).strip()
    e = ev_until(c.ev, "answered")
    c.kill(); w = outcome(c.wait); c.link.release(False)
    warned = any(l == "warn" and "second root peer" in m for l, m in cp.LOG)
    result("second root peer while Live", e[1] == "closed-second" and got == "0" and w == ("program", 9) and warned, f"second peer read {got} bytes; warn logged={warned}; {w}")


# --- kill() honesty --------------------------------------------------------------------------------
def s_kill_after_shim_death():
    """Item 1: the shim is SIGKILLed with no S frame; the (setgid) program survives; kill() must not be Ok."""
    c = setup(SUDO, mode="ping", prog_exe=None if MACOS else "/proto/pysetgid")  # macOS: no PDEATHSIG at all
    ev_until(c.ev, "answered"); read_ready(c)
    as_root("import os; os.kill(%d, 9)" % shim_pid(c)); c.shimlog.eof()
    k = outcome(c.kill)
    alive = c.pinger.alive()
    if alive:
        c.pinger.quit_and_wait_exit()
    c.p.wait(); c.link.release(False)
    result("kill() after the shim died without S", k[0] == "shim-lost" and alive, f"kill -> {k}; program alive={alive}")


def s_kill_after_clean_exit():
    """The shim sent S and exited; K meets a closed peer, from a process whose SIGPIPE is SIG_DFL. Ok, no signal.
    The whole scenario runs in a child process so a SIGPIPE ends only the child."""
    pid = os.fork()
    if pid == 0:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        c = setup(SUDO, mode="42")
        ev_until(c.ev, "answered")
        c.front_status = c.p.wait()
        k = c.link.kill(-1)
        w = outcome(c.wait); c.link.release(False)
        os._exit(0 if k == "already-exited" and w == ("program", 42 << 8) else 3)
    _, st = os.waitpid(pid, 0)
    ok = os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0
    result("K to an exited shim (S buffered), SIGPIPE default", ok, ("child exit %d" % os.WEXITSTATUS(st)) if os.WIFEXITED(st) else "child killed by signal %d" % os.WTERMSIG(st))


def s_nosigpipe_getsockopt():
    """macOS: SO_NOSIGPIPE is set on both ends (read back), since the SIGPIPE path itself did not reproduce."""
    c = setup(SUDO, mode="42")
    ev_until(c.ev, "answered")
    mine = c.link.conn.getsockopt(socket.SOL_SOCKET, cp.SO_NOSIGPIPE)
    log = c.shimlog.eof(); outcome(c.wait); c.link.release(False)
    result("SO_NOSIGPIPE on both ends (getsockopt)", mine == 1 and "nosigpipe=1" in log, f"cosca end={mine} shim end={[l for l in log if l.startswith('nosigpipe')]}")


# --- authentication, owner watch -----------------------------------------------------------------
def s_wrong_identity():
    """Item 2: argv carries an identity the listener does not have: refused 122 before hello, so cosca never
    answers -> exactly NotStarted(shim_connected=false). The shim is held after connect until cosca has
    accepted it, so the acceptor's view does not depend on how fast the shim exits."""
    d = workdir(); g = Gate(d, "before_id")
    c = setup(SUDO, d=d, mode="42", extra={"ident": "12345" if not MACOS else "12345:1"}, seams_extra={"SHIM_GATE_BEFORE_ID": g.path})
    ev_until(c.ev, "accepted")
    g.open()
    log = c.shimlog.eof(); w = outcome(c.wait); c.link.release(False)
    result("listener identity mismatch refused", "refused 122" in " ".join(refusal(log)) and never_ran(c) and w[0] == "not-started" and w[2] is False,
           f"{refusal(log)} {w}")

def s_owner_rebind():
    """Item 2: cosca dies leaving its socket; a same-uid process on cosca's reused pid rebinds the path and
    answers A. Needs ns_last_pid (privileged container)."""
    d = workdir()
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # 'cosca': binds, spawns the gated shim, reports, then is SIGKILLed (no Drop)
        os.close(r)
        c = setup(SUDO, d=d, mode="42", gate=True)
        c.shimlog.has("shim pid=")
        os.write(w, ("%s %d %d\n" % (c.link.path, os.getpid(), c.p.pid)).encode())
        signal.pause()
    os.close(w)
    path, cosca, front = os.read(r, 4096).decode().split()
    cosca, front = int(cosca), int(front)
    logfd = os.open(os.path.join(d, "shimlog"), os.O_RDONLY | os.O_NONBLOCK)  # readers before the owner's go away
    os.set_blocking(logfd, True)
    sigfd = os.open(os.path.join(d, "siglog"), os.O_RDONLY | os.O_NONBLOCK)  # so a wrongly started program can run
    os.kill(cosca, signal.SIGKILL); os.waitpid(cosca, 0)  # the stale socket stays; cosca's pid is free
    # a same-uid impostor forked onto cosca's old pid: root sets ns_last_pid, the child drops to our uid
    imp = subprocess.Popen(SUDO + [PY, "-c",
        "import os,socket,sys\nopen('/proc/sys/kernel/ns_last_pid','w').write(str(%d-1))\npid=os.fork()\n"
        "if pid==0:\n  os.setgid(%d); os.setuid(%d)\n  os.unlink(%r)\n  l=socket.socket(socket.AF_UNIX); l.bind(%r); l.listen(1)\n"
        "  print('bound', os.getpid(), flush=True)\n  c,_=l.accept(); c.send(b'A'); c.recv(1)\n  os._exit(0)\n"
        "os.waitpid(pid,0)" % (cosca, os.getgid(), os.getuid(), path + "/s", path + "/s")], stdout=subprocess.PIPE)
    line = imp.stdout.readline().decode().split()
    open(os.path.join(d, "gate"), "wb").write(b"g")
    f = os.fdopen(logfd, "rb")
    lines = []
    for l in f:  # T5: stop at the decision, which comes with or without the identity check
        lines.append(l.decode().rstrip())
        if lines[-1].startswith("refused") or lines[-1].startswith("program pid="):
            break
    ran = any(l.startswith("program pid=") for l in lines)
    for l in f:  # drain to the shim's exit (the program, if started, exits 42 on its own)
        pass
    f.close(); os.close(sigfd)
    if not ran:  # let the impostor finish
        try:
            s = socket.socket(socket.AF_UNIX); s.connect(path + "/s"); s.close()
        except OSError:
            pass
    imp.wait()
    result("stale socket rebound by a reused-pid impostor", line[1] == str(cosca) and not ran and any("refused 122" in l for l in lines),
           f"impostor pid {line[1]} (cosca was {cosca}); shim: {refusal(lines)}; program started={ran}")
    as_root("import shutil; shutil.rmtree(%r, ignore_errors=True)" % path)


def s_owner_fork_copy():
    """Item 2: a fork copy holding the connection outlives the owner. The copy then sends a test-only 'P'
    ping after the owner is reaped; the shim handles owner exit before control bytes in a round, so
    'owner exited' must precede 'pong' (rule T5: 'pong' arrives with or without the owner watch)."""
    d = workdir()
    r, w = os.pipe()
    go_r, go_w = os.pipe()
    pid = os.fork()
    if pid == 0:  # 'cosca'
        os.close(r); os.close(go_w)
        c = setup(SUDO, d=d, mode="ping")
        ev_until(c.ev, "answered"); read_ready(c)
        copy = os.fork()
        if copy == 0:  # the fork copy: keeps every fd; pings the shim when told
            os.read(go_r, 1)
            c.link.conn.send(b"P")
            signal.pause()
        os.write(w, ("%d\n" % copy).encode())
        signal.pause()
    os.close(w); os.close(go_r)
    copy = int(os.read(r, 64))
    lfd = os.open(os.path.join(d, "shimlog"), os.O_RDONLY | os.O_NONBLOCK); os.set_blocking(lfd, True)
    log = os.fdopen(lfd, "rb")  # a second reader, opened while the owner's reader still exists
    os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
    os.write(go_w, b"g")
    lines = []
    for line in log:
        lines.append(line.decode().rstrip())
        if lines[-1] == "pong":
            break
    owner_seen = any(l.startswith("owner exited") for l in lines)
    if owner_seen:  # the kill follows in the same round: read on to the reap
        for line in log:
            lines.append(line.decode().rstrip())
            if lines[-1].startswith("reaped"):
                break
    try:
        os.kill(copy, 0); copy_alive = True  # a grandchild: not ours to wait for
    except ProcessLookupError:
        copy_alive = False
    os.kill(copy, signal.SIGKILL)
    result("fork copy outlives the owner: owner exit acted on", copy_alive and owner_seen and "reaped status 9" in lines,
           f"copy alive={copy_alive}; shim lines after owner death: {lines}")


def s_leaked_listener():
    """Item 3: a foreign process holds a copy of the listener; a drop while Pending must not leave a late
    shim waiting in the leaked listener's backlog."""
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    rd, wr = os.pipe()
    leak = os.fork()
    if leak == 0:  # stands in for a non-cosca spawn that inherited the listener
        os.close(rd)
        p = select.poll(); p.register(c.link.listener.fileno(), select.POLLIN)
        os.write(wr, b"armed\n")
        p.poll()
        os.write(wr, b"CONNECTION-ARRIVED-IN-LEAK\n")
        os._exit(0)
    os.close(wr)
    os.read(rd, 16)
    out = c.link.release(False)  # drop while Pending
    c.gate.open()
    log = c.shimlog.eof()
    os.kill(leak, signal.SIGKILL); os.waitpid(leak, 0)
    os.set_blocking(rd, False)
    try:
        extra = os.read(rd, 64)
    except BlockingIOError:
        extra = b""
    w = outcome(c.wait)
    result("leaked listener copy: late shim never waits in it", extra == b"" and never_ran(c) and any("refused 124" in l for l in log),
           f"{out}; leak saw={extra!r}; shim {refusal(log)}; {w}")


# --- front death, wait_started, NotStarted -----------------------------------------------------------
def s_wait_started_front_exit():
    """Item 4: the front exits without a shim ever connecting; wait_started returns NotStarted."""
    c = setup(["/bin/sh", "-c", "exit 1", "front-that-fails"], mode="42")  # a front that exits before running the shim
    w = outcome(c.wait_started); c.link.release(False)
    result("wait_started: front exits without connecting", w[0] == "not-started" and w[1] == 1 and w[2] is False, f"{w}")


def s_wait_started_live():
    c = setup(SUDO)
    w = outcome(c.wait_started); read_ready(c)
    c.kill(); x = outcome(c.wait); c.link.release(False)
    result("wait_started: Live", w == "live" and x == ("program", 9), f"{w} {x}")


def s_auth_failure_not_started():
    c = setup(PW, mode="42", extra={"stdin": subprocess.PIPE, "stderr": subprocess.DEVNULL})
    c.p.stdin.write(b"bad\nbad\nbad\n"); c.p.stdin.close(); c.p.stdin = None
    w = outcome(c.wait); c.link.release(False)
    result("wrong password -> NotStarted", w[0] == "not-started" and w[1] == 1 and w[2] is False and never_ran(c), f"{w}")


def s_front_death_prestart():
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    os.kill(c.p.pid, signal.SIGKILL)
    w = outcome(c.wait)
    c.gate.open(); log = c.shimlog.eof(); c.link.release(False)
    result("front-death-before-start", w[0] == "not-started" and w[1] == -9 and never_ran(c) and any("refused 125" in l for l in log), f"{w}; shim {refusal(log)}")


def s_front_death_live():
    c = setup(SUDO, mode="release")
    read_ready(c)
    os.kill(c.p.pid, signal.SIGKILL); c.front_status = c.p.wait()
    tw = outcome(c.try_wait); k = c.kill(); w = outcome(c.wait); c.link.release(False)
    result("front-death-after-start", tw is None and k == "sent" and w == ("program", 9), f"try_wait={tw} kill={k} wait={w}")


def s_shim_death_setid():
    c = setup(SUDO, mode="ping", prog_exe="/proto/pysetgid")
    read_ready(c)
    as_root("import os; os.kill(%d, 9)" % shim_pid(c)); c.shimlog.eof()
    w = outcome(c.wait)
    alive = c.pinger.alive()
    if alive:
        c.pinger.quit_and_wait_exit()
    c.link.release(False)
    result("shim death: setgid program survives, ShimLost", w[0] == "shim-lost" and alive, f"{w[0]}; program alive={alive}")


def s_shim_death_backlog():
    g = threading.Event()
    c = setup(SUDO, mode="42", acceptor_gate=g)
    ev_until(c.ev, "listener-ready")
    as_root("import os; os.kill(%d, 9)" % shim_pid(c)); c.shimlog.eof()
    g.set()
    while True:
        a = c.ev.get()
        if a[0] in ("answered", "closed-unreadable", "exited"):
            break
    w = outcome(c.wait); c.link.release(False)
    result("shim-death-before-answer", a[0] != "exited" and w[0] == "not-started" and never_ran(c), f"acceptor={a} {w}")


def s_exit_races_kill():
    c = setup(SUDO, mode="ping", hold=True)
    read_ready(c)
    exited = c.pinger.quit_and_wait_exit()
    k = c.kill()
    c.hold.open(); w = outcome(c.wait); c.link.release(False)
    result("program-exit-races-kill", exited and k == "sent" and w == ("program", 42 << 8), f"{w}")


def s_fail_fork():
    """Item 7: the shim got A but could not start the program: F frame -> NotStarted, never a fabricated status."""
    c = setup(SUDO, mode="42", seams_extra={"SHIM_FAIL_FORK": "1"})
    w = outcome(c.wait); log = c.shimlog.eof(); c.link.release(False)
    result("start failure after A -> NotStarted (F frame)", w[0] == "not-started" and w[2] is True and any("refused 117" in l for l in log), f"{w} {refusal(log)}")


def fake_shim_frame(name, payload):
    """A same-uid fake shim sends a malformed frame: ShimLost, never a status."""
    link = ShimLink(expected_euid=os.geteuid(), events=queue.Queue())
    s = socket.socket(socket.AF_UNIX); s.connect(os.path.join(link.path, "s")); s.send(b"H")
    ev_until(link.events, "answered")
    s.recv(1); s.send(payload); s.close()
    w = outcome(lambda: link.front_exited(0, block=True))
    link.release(False)
    result(name, w[0] == "shim-lost", str(w))


def s_frames():
    fake_shim_frame("truncated frame -> ShimLost", b"S\x00\x01")
    fake_shim_frame("garbled tag -> ShimLost", b"X\x00\x00\x00\x00")


def s_u_frame():
    """Item 3: a 'U' frame is StatusLost for wait, and kill() after it is Ok (the program is gone)."""
    link = ShimLink(expected_euid=os.geteuid(), events=queue.Queue())
    s = socket.socket(socket.AF_UNIX); s.connect(os.path.join(link.path, "s")); s.send(b"H")
    ev_until(link.events, "answered")
    s.recv(1); s.send(b"U\x00\x00\x00\x00"); s.close()
    k = outcome(lambda: link.kill(-1))
    w = outcome(lambda: link.front_exited(0, block=True))
    link.release(False)
    result("U frame: StatusLost, kill Ok", w[0] == "status-lost" and k == "already-exited", f"wait={w} kill={k}")


def s_accept_emfile():
    """Item 5: accept fails with EMFILE (real, via RLIMIT_NOFILE): fail closed, never spin, never hang."""
    g = threading.Event()
    c = setup(SUDO, mode="42", acceptor_gate=g)
    ev_until(c.ev, "listener-ready")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    top = max(int(f) for f in os.listdir("/dev/fd"))
    resource.setrlimit(resource.RLIMIT_NOFILE, (top + 1, hard))
    try:
        fds = []
        while True:  # fill every free slot below the limit so accept() has none (bounded by the limit itself)
            try:
                fds.append(os.open("/dev/null", os.O_RDONLY))
            except OSError:
                break
        g.set()
        e = c.ev.get()
        while e[0] == "polling":  # not reached unless the next event is wrong; recorded below
            break
    finally:
        for f in fds:
            os.close(f)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    log = c.shimlog.eof(); w = outcome(c.wait); c.link.release(False)
    result("accept EMFILE fails closed", e[0] == "accept-failed" and w[0] == "not-started" and never_ran(c) and any("refused 124" in l for l in log),
           f"next event={e} wait={w} shim={refusal(log)}")


def s_refusal_codes():
    """Item 6: distinct refusal codes with a stderr line, run directly (no front)."""
    d = workdir()
    def run(argv, env=None):
        p = subprocess.run(argv, stderr=subprocess.PIPE, env=env)
        return p.returncode, p.stderr.decode().strip()
    v = run([SHIM, "--cosca-elevation-shim=2", d, "1", "1", "0", "--", "/bin/true", "x"])
    n = run([SHIM, "--cosca-elevation-shim=1", d, "1", "1", "0", "--", "/bin/true", "x"])
    setgid = os.path.join(d, "shim-setgid")
    as_root("import shutil,os; shutil.copy(%r,%r); os.chown(%r,0,%d); os.chmod(%r,0o2755)" % (SHIM, setgid, setgid, 1002 if not MACOS else 1, setgid))
    sid = run([setgid, "--cosca-elevation-shim=1", d, "1", "1", "0", "--", "/bin/true", "x"])
    as_root("import os; os.unlink(%r)" % setgid)
    ok = v[0] == 120 and n[0] == 124 and sid[0] == 121 and all("cosca-elevation-shim:" in x[1] for x in (v, n, sid))
    result("shim refusal codes and stderr", ok, f"version={v} no-listener={n} set-id={sid}")


# --- teardown, dir, ownership --------------------------------------------------------------------
def s_drop_eperm_pending():
    """Item 7: sync Drop while Pending with an unsignallable front (pkexec) does not wait; the start is refused."""
    c = setup(["pkexec"], mode="42", gate=True)
    c.shimlog.has("shim pid=")
    out = c.drop(kill_on_drop=True)
    warned = any(l == "warn" and "left unreaped" in m for l, m in cp.LOG)
    c.gate.open(); log = c.shimlog.eof(); rc = c.p.wait()
    result("sync Drop, Pending, front EPERM: no wait, refused", warned and never_ran(c) and rc == 124, f"{out}; warn={warned}; front later exited {rc}; shim {refusal(log)}")


def s_detach_refuses():
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    out = c.link.release(True)
    c.gate.open(); log = c.shimlog.eof(); rc = c.p.wait()
    result("drop while Pending refuses (interim)", out == "removed" and never_ran(c) and rc == 124, f"{out}; front={rc}")


def s_detach_live():
    c = setup(SUDO, mode="release")
    read_ready(c)
    out = c.link.release(True)
    c.shimlog.has("EOF (armed=0)")
    c.rel.open(); rc = c.p.wait(); log = c.shimlog.eof()
    result("detach while live", rc == 42 and "disarmed" in log, f"{out}; front={rc}")


def s_fork_owner():
    c = setup(SUDO, gate=True)
    c.shimlog.has("shim pid=")
    pid = os.fork()
    if pid == 0:
        c.link.release(False)
        os._exit(0)
    os.waitpid(pid, 0)
    c.gate.open()
    a = ev_until(c.ev, "answered")
    if a[0] != "answered":
        result("fork copy drop leaves the owner intact", False, f"acceptor: {a}"); c.p.wait(); return
    read_ready(c); c.kill(); w = outcome(c.wait); out = c.link.release(False)
    result("fork copy drop leaves the owner intact", a[1] == "A" and w == ("program", 9) and out == "removed", f"{a[1]} {w} {out}")


def s_impostor_peer():
    link = ShimLink(events=queue.Queue())
    s = socket.socket(socket.AF_UNIX); s.connect(os.path.join(link.path, "s"))
    e = ev_until(link.events, "closed-non-root")
    got = s.recv(1); out = link.release(False)
    warned = any(l == "warn" and "non-root peer" in m for l, m in cp.LOG)
    result("non-root peer closed, warned", got == b"" and link.state == REFUSED and warned, f"{e} recv={got!r} {out}")


def s_symlink_swap():
    link = ShimLink(expected_euid=os.geteuid())
    d = link.path; moved = d + ".moved"
    os.rename(d, moved); os.mkdir(d)
    out = link.release(False)
    warned = any(l == "warn" and "no longer our directory" in m for l, m in cp.LOG)
    result("cleanup ignores a swapped name, warns", out == "name no longer ours; left alone" and os.path.isdir(d) and warned, out)
    os.rmdir(d); os.rmdir(moved)


def s_not_empty():
    link = ShimLink(expected_euid=os.geteuid())
    open(os.path.join(link.path, "leftover"), "w").close()
    out = link.release(False)
    warned = any(l == "warn" and "left" in m and link.path in m for l, m in cp.LOG)
    result("leftover file: dir left, warned", out.startswith("left") and warned, out)
    os.unlink(os.path.join(link.path, "leftover")); os.rmdir(link.path)


def s_tmpdir():
    base = workdir()
    ww = os.path.join(base, "ww"); os.mkdir(ww); os.chmod(ww, 0o777)
    gw = os.path.join(base, "gw"); os.mkdir(gw); os.chmod(gw, 0o770)
    own = os.path.join(base, "own"); os.mkdir(own); os.chmod(own, 0o700)
    sticky_other = os.path.join(base, "sticky-other"); os.mkdir(sticky_other); os.chmod(sticky_other, 0o1777)
    as_root("import os; os.chown(%r, %d, -1)" % (sticky_other, 1002 if not MACOS else 4294967294))
    got = {}
    for name, p in (("world-writable", ww), ("group-writable", gw), ("own 0700", own), ("sticky, other owner", sticky_other), ("system temp", tempfile.gettempdir())):
        try:
            ShimLink(expected_euid=os.geteuid(), start_acceptor=False, tmp=p).release(False); got[name] = "accepted"
        except PermissionError:
            got[name] = "refused"
    want = {"world-writable": "refused", "group-writable": "refused", "own 0700": "accepted", "sticky, other owner": "refused", "system temp": "accepted"}
    result("TMPDIR accept and refuse", got == want, str(got))
    as_root("import shutil; shutil.rmtree(%r)" % base)


def s_d2_symlink():
    rootsock = "/var/tmp/f-proto-rootsock-%d" % os.getpid()
    r = subprocess.Popen(SUDO + [PY, "-c", "import socket,os\nl=socket.socket(socket.AF_UNIX); l.bind(%r); l.listen(1); print('up', flush=True)\n"
                                 "c,_=l.accept(); n=0\nwhile True:\n  d=c.recv(64)\n  if not d: break\n  n+=len(d)\nprint('bytes', n, flush=True); os.unlink(%r)" % (rootsock, rootsock)],
                         stdout=subprocess.PIPE)
    r.stdout.readline()
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    os.unlink(os.path.join(c.link.path, "s")); os.symlink(rootsock, os.path.join(c.link.path, "s"))
    c.gate.open(); log = c.shimlog.eof()
    got = r.stdout.readline().decode().strip(); r.wait()
    w = outcome(c.wait); c.link.release(False)
    result("D2: symlinked socket gets no bytes", got == "bytes 0" and any("refused 122" in l for l in log) and never_ran(c), f"root listener: {got}; {w}")


# --- argv round trip ---------------------------------------------------------------------------------
ADVERSARIAL = ["a b", "it's", 'q"q', "back\\slash", "nl\nline", "$(id)", "`id`", "-dash", "", "tab\tx", "%s", "\\\"", os.fsdecode(b"\xff\xfe-not-utf8")]


def roundtrip(name, front):
    c = setup(front, mode="argv", prog_args=ADVERSARIAL)
    w = outcome(c.wait); sig = c.siglog.eof(); c.link.release(False)
    got = [bytes.fromhex(l[3:].strip()) for l in sig if l == "arg" or l.startswith("arg ")]  # rstrip eats an empty arg's space
    want = [os.fsencode(a) for a in ADVERSARIAL]
    bad = [(i, want[i], got[i] if i < len(got) else None) for i in range(len(want)) if i >= len(got) or got[i] != want[i]]
    result(name, w == ("program", 0) and not bad and len(got) == len(want), f"{w}; mismatches={bad}")


def s_argv_sudo():
    roundtrip("adversarial argv through sudo", SUDO)


def s_argv_osascript():
    roundtrip("adversarial argv through sudo osascript", "OSA")


def s_osascript():
    c = setup("OSA"); read_ready(c); k = c.kill(); w = outcome(c.wait); c.link.release(False)
    result("sudo osascript live kill", k == "sent" and w == ("program", 9) and c.front_status == 1, f"{k} {w} osascript exit={c.front_status}")


def s_pkexec_eperm():
    c = setup(["pkexec"], mode="42", gate=True)
    c.shimlog.has("shim pid=")
    k = c.kill()
    c.gate.open(); log = c.shimlog.eof(); w = outcome(c.wait); c.link.release(False)
    result("pkexec EPERM -> NotStarted", k == "refused+front-EPERM" and never_ran(c) and w[0] == "not-started" and w[1] == 125, f"{k} {w}")


def s_direct_exec():
    c = setup(SUDO, mode="42", gate=True)
    same = shim_pid(c) == c.p.pid
    k = c.kill()
    c.gate.open(); c.shimlog.eof(); w = outcome(c.wait); c.link.release(False)
    result("sudo direct exec: pre-start kill", same and k == "refused+front-EPERM" and never_ran(c) and w[0] == "not-started" and w[1] == 125, f"front is shim={same}; {k} {w}")


def s_doas_live():
    c = setup(["doas"]); read_ready(c); k = c.kill(); w = outcome(c.wait); c.link.release(False)
    result("doas live kill", k == "sent" and w == ("program", 9), f"{k} {w}")


# --- revision 6 ------------------------------------------------------------------------------------
def s_exec_failure():
    """Item 5: a program that cannot be executed is NotStarted (exec errno), never an exit 127."""
    c = setup(SUDO, mode="42", prog_exe="/nonexistent/program")
    w = outcome(c.wait); log = c.shimlog.eof(); c.link.release(False)
    result("exec failure -> NotStarted, not 127", w[0] == "not-started" and any("refused 117" in l for l in log), f"{w} {refusal(log)}")


def s_fail_pidfd():
    """Item 1: pidfd_open fails after exec was confirmed: the program ran, so 'L' (lost) with its real status."""
    c = setup(SUDO, mode="ping", seams_extra={"SHIM_FAIL_PIDFD": "1"})
    w = outcome(c.wait); log = c.shimlog.eof(); c.link.release(False)
    result("pidfd failure after fork -> possibly-started, lost (L)", w == ("lost", 9), f"{w}")


def s_fail_loop():
    """Item 1: supervision fails while the program runs: 'L' with the real status, never NotStarted."""
    d = workdir()
    fail = os.path.join(d, "fail"); os.mkfifo(fail, 0o666); os.chmod(fail, 0o666)
    c = setup(SUDO, d=d, mode="ping", seams_extra={"SHIM_FAIL_LOOP": fail})
    c.shimlog.has("program pid=")
    rd = os.open(fail, os.O_RDONLY | os.O_NONBLOCK)  # keep a reader so the writer open does not block
    wfd = os.open(fail, os.O_WRONLY); os.write(wfd, b"x")
    w = outcome(c.wait); os.close(wfd); os.close(rd); c.link.release(False)
    result("supervision failure while running -> ran-then-lost", w == ("lost", 9), f"{w}")


def fork_cosca(d, ready_after, **kw):
    """Run 'cosca' in a child process (so it can die without Drop). ready_after(c) runs in the child and
    returns a string sent to the parent. Returns (cosca pid, front pid, message)."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        c = setup(SUDO, d=d, **kw)
        msg = ready_after(c)
        os.write(w, ("%d %s\n" % (c.p.pid, msg)).encode())
        signal.pause()
    os.close(w)
    front, msg = os.read(r, 4096).decode().strip().split(" ", 1)
    return pid, int(front), msg


def shim_log_reader(d):
    fd = os.open(os.path.join(d, "shimlog"), os.O_RDONLY | os.O_NONBLOCK); os.set_blocking(fd, True)
    return os.fdopen(fd, "rb")


def read_until(f, pred):
    lines = []
    for l in f:
        lines.append(l.decode().rstrip())
        if pred(lines[-1]):
            break
    return lines


def s_code_123_before_answer():
    """Item 9: cosca dies before answering while a fork copy keeps its listener (so no EOF/reset reaches the
    shim): only the owner watch can tell. The copy then closes the listener, which ends the wait either way
    (T5): 123 if the owner watch acted, 124 if it did not."""
    d = workdir()
    r, w = os.pipe(); go_r, go_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        c = setup(SUDO, d=d, mode="42", acceptor_gate=threading.Event())
        c.shimlog.has("owner verified")
        copy = os.fork()
        if copy == 0:
            os.read(go_r, 1)
            os._exit(0)  # closes its copy of the listener
        os.write(w, b"%d\n" % copy)
        signal.pause()
    os.close(w)
    copy = int(os.read(r, 64))
    f = shim_log_reader(d); sfd = os.open(os.path.join(d, "siglog"), os.O_RDONLY | os.O_NONBLOCK)
    os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
    os.write(go_w, b"x")
    lines = read_until(f, lambda l: l.startswith("refused") or l.startswith("program pid="))
    os.close(sfd)
    result("123: cosca exits before answering (listener copy alive)", any("refused 123" in l for l in lines), f"{lines[-1:]}")


def s_code_123_after_a():
    """Item 9: 'A' is buffered, then cosca dies before the shim acts on it: re-checked, never started."""
    d = workdir()
    gate = Gate(d, "after_a")
    def ready(c):
        ev_until(c.ev, "answered")
        return "ok"
    pid, front, _ = fork_cosca(d, ready, mode="42", seams_extra={"SHIM_GATE_AFTER_A": gate.path})
    f = shim_log_reader(d); sfd = os.open(os.path.join(d, "siglog"), os.O_RDONLY | os.O_NONBLOCK)
    os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
    gate.open()
    lines = read_until(f, lambda l: l.startswith("refused") or l.startswith("program pid="))
    os.close(sfd)
    result("123: owner dead after A was buffered", any("refused 123" in l for l in lines) and not any(l.startswith("program pid=") for l in lines), f"{lines[-1:]}")


def s_code_119():
    """Item 9: the shim dies between fork and the child's PDEATHSIG; the child never execs (119)."""
    d = workdir()
    cg = Gate(d, "child")
    c = setup(SUDO, d=d, mode="42", seams_extra={"SHIM_DIE_AFTER_FORK": "1", "SHIM_CHILD_GATE": cg.path})
    c.shimlog.has("seam: shim exits after fork")
    c.p.wait()  # the shim (and its front) are gone; the child waits at its gate
    cg.open()
    log = c.shimlog.eof()  # EOF: the child exited or exec'd (it held the log until then)
    c.link.release(False)
    result("119: child logs 119 after the shim died", any("exit 119" in l for l in log), f"{[l for l in log if 'child' in l]}")


def s_code_116():
    """Item 5: SO_PEERPIDFD fails with a real EMFILE (RLIMIT_NOFILE in the shim): 116, not 122."""
    if MACOS:
        result("116 (Linux only)", True, "skipped on macOS: no SO_PEERPIDFD"); return
    c = setup(SUDO, mode="42", seams_extra={"SHIM_RLIMIT_NOFILE": "5"})
    w = outcome(c.wait); log = c.shimlog.unblock_if_never_opened(); c.link.release(False)
    result("116: owner watch setup failure (EMFILE)", any("refused 116" in l for l in log) and w[0] == "not-started" and w[2] is False and never_ran(c), f"{refusal(log)} {w}")


def s_wrong_euid():
    """Item 2: the listener's uid must be argv's euid (run the shim with a wrong euid against a real link)."""
    d = workdir()
    link = ShimLink(events=queue.Queue())
    shimlog = Fifo(d, "shimlog")
    p = subprocess.Popen(SUDO + ["/usr/bin/env", "SHIM_LOG=" + shimlog.path, SHIM, "--cosca-elevation-shim=1", link.path,
                                str(os.getpid()), str(identity()), "4242", "--", "/bin/true"], stderr=subprocess.DEVNULL)
    p.wait(); log = shimlog.unblock_if_never_opened(); link.release(False)
    want = "token is not cosca's" if MACOS else "pid or euid"
    result("listener uid must be argv's euid", any("refused 122" in l and want in l for l in log), str(refusal(log)))


def leaked_answer_case(name, accept_first):
    """A process holding a copy of cosca's listener accepts the shim and answers A. accept_first: the leak
    accepts before the shim reads the listener's identity (shim held at a seam); otherwise after the shim
    has verified the identity and waits for its first byte."""
    g = threading.Event()
    d = workdir()
    before = Gate(d, "before_id")
    c = setup(SUDO, d=d, mode="42", acceptor_gate=g, seams_extra={"SHIM_GATE_BEFORE_ID": before.path})
    go_r, go_w = os.pipe(); done_r, done_w = os.pipe()
    leak = os.fork()
    if leak == 0:
        try:
            os.read(go_r, 1)
            p = select.poll(); p.register(c.link.listener.fileno(), select.POLLIN); p.poll()
            conn, _ = c.link.listener.accept()
            conn.setblocking(True)
            os.write(done_w, b"a")
            os.read(go_r, 1)
            conn.send(b"A")
            conn.recv(1)
        except BaseException:
            pass
        os._exit(0)
    if accept_first:
        c.shimlog.has("shim pid=")  # connected or about to: the leak accepts while the shim is held
        os.write(go_w, b"1"); os.read(done_r, 1)
        before.open()
        c.shimlog.wait_for(lambda ls: any(l.startswith("owner verified") or l.startswith("refused") for l in ls))
        os.write(go_w, b"2")
    else:
        before.open()
        c.shimlog.has("owner verified")  # identity read and passed; the shim now waits for its first byte
        os.write(go_w, b"1"); os.read(done_r, 1); os.write(go_w, b"2")
    log = c.shimlog.eof(); os.waitpid(leak, 0); g.set()
    ran = any(l.startswith("program pid=") for l in log)
    outcome(c.wait); c.link.release(False)
    return ran, refusal(log)


def s_leaked_listener_answers():
    """Items 2/6, Linux: refused in both orders (SCM_CREDENTIALS on the first byte)."""
    for order in (True, False):
        ran, ref = leaked_answer_case("", order)
        result("leaked listener answers A (%s)" % ("accept before identity read" if order else "accept after identity read"),
               not ran and any("122" in r for r in ref), f"program started={ran}; {ref}")


def s_leaked_listener_answers_macos():
    """Items 2/6, macOS: measure both orders; report what happens (the residual of owner question [6/6])."""
    for order in (True, False):
        ran, ref = leaked_answer_case("", order)
        result("macOS leaked listener answers A (%s): MEASURED %s" % ("accept before identity read" if order else "accept after identity read",
               "STARTED" if ran else "refused"), True, f"program started={ran}; {ref}")


def s_reverse_rebind():
    """Item 2: a dead process's listener (kept by a helper H), with cosca now on that pid (ns_last_pid, own pid
    namespace). Behaviour, not a message: the shim must write nothing at all to that listener."""
    atk = workdir()
    r, w = os.pipe()
    hr, hw = os.pipe()  # H reports how many bytes the shim wrote to it
    x = os.fork()
    if x == 0:  # X: creates the listener, hands it to H, exits
        l = socket.socket(socket.AF_UNIX); l.bind(os.path.join(atk, "s")); l.listen(4)
        h = os.fork()
        if h == 0:  # H: answers A to a hello, counts every byte until the shim closes
            conn, _ = l.accept()
            got = b""
            try:
                while True:
                    d = conn.recv(64)
                    if not d:
                        break
                    if got == b"" and d.startswith(b"H"):
                        conn.send(b"A")
                    got += d
            except OSError:
                pass
            os.write(hw, b"%d\n" % len(got))
            os._exit(0)
        os.write(w, b"%d %d\n" % (os.getpid(), h)); os._exit(0)
    os.close(w); os.close(hw)
    n, hpid = map(int, os.read(r, 64).split()); os.waitpid(x, 0)
    as_root("open('/proc/sys/kernel/ns_last_pid','w').write(str(%d-1))" % n)
    d = workdir()
    r2, w2 = os.pipe()
    cosca = os.fork()
    if cosca == 0:  # cosca, on the dead creator's pid; it stays alive and reports the shim's decision
        os.close(r2)
        c = setup(SUDO, d=d, mode="42", gate=True)
        c.shimlog.has("shim pid=")
        os.write(w2, (c.link.path + "\n").encode())
        c.shimlog.wait_for(lambda ls: any(l.startswith("refused") or l.startswith("program pid=") for l in ls))
        dec = [l for l in c.shimlog.lines if l.startswith("refused") or l.startswith("program pid=")]
        os.write(w2, (dec[0] + "\n").encode())
        signal.pause()
    os.close(w2)
    rf = os.fdopen(r2, "rb")
    path = rf.readline().decode().strip()
    os.rename(os.path.join(atk, "s"), os.path.join(path, "s"))  # same uid: replace cosca's socket
    open(os.path.join(d, "gate"), "wb").write(b"g")
    lines = [rf.readline().decode().strip()]
    written = int(os.read(hr, 64))  # after the shim closed its connection
    os.kill(cosca, signal.SIGKILL); os.waitpid(cosca, 0)
    ran = any(l.startswith("program pid=") for l in lines)
    result("reverse rebind: dead process's listener, cosca on its pid", cosca == n and not ran and written == 0 and any("refused 122" in l for l in lines),
           f"cosca pid {cosca} (dead listener's creator {n}); bytes the shim wrote to it: {written}; {lines[-1:]}")

def s_accept_fail_live():
    """Item 3: the acceptor fails while Live: the running program stays controlled and its status reported."""
    armed = {"on": False}
    def hook():
        if armed["on"]:
            raise OSError(errno.EMFILE, os.strerror(errno.EMFILE))
    c = setup(SUDO, link_kw={"accept_hook": hook})
    ev_until(c.ev, "answered"); read_ready(c)
    armed["on"] = True
    as_root("import socket\ns=socket.socket(socket.AF_UNIX)\ntry:\n  s.connect(%r); s.recv(1)\nexcept OSError: pass" % os.path.join(c.link.path, "s"))
    e = ev_until(c.ev, "accept-failed")
    k = c.kill(); w = outcome(c.wait); c.link.release(False)
    warned = any(l == "warn" and "while Live" in m for l, m in cp.LOG)
    result("accept failure while Live: program still controlled", e[0] == "accept-failed" and k == "sent" and w == ("program", 9) and warned, f"{k} {w} warn={warned}")


def s_wait_started_late_shim():
    """Item 4: the front dies, wait_started reports NotStarted, then the still-alive shim connects: told N."""
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    os.kill(c.p.pid, signal.SIGKILL)
    os.waitid(os.P_PID, c.p.pid, os.WEXITED | os.WNOWAIT)  # the front is a zombie now: macOS registration gives ESRCH
    w = outcome(c.wait_started)
    c.gate.open()
    log = c.shimlog.eof()
    c.link.release(False)
    result("wait_started NotStarted, then a late shim is told N", w[0] == "not-started" and any("refused 125" in l for l in log) and never_ran(c), f"{w} {refusal(log)}")


def s_tmpdir_ancestor():
    """Item 2/D14: an ancestor of TMPDIR writable by others is refused."""
    base = workdir()
    ww = os.path.join(base, "ww"); os.mkdir(ww); os.chmod(ww, 0o777)
    sub = os.path.join(ww, "sub"); os.mkdir(sub); os.chmod(sub, 0o700)
    try:
        ShimLink(expected_euid=os.geteuid(), start_acceptor=False, tmp=sub).release(False); got = "accepted"
    except PermissionError as e:
        got = "refused: " + str(e)
    result("TMPDIR ancestor writable by others is refused", got.startswith("refused") and ww in got, got)


def s_wrong_identity_parts():
    """macOS: the token's pidversion and the process's p_uniqueid are each checked (one wrong at a time)."""
    uniq, ver = identity().split(":")
    for name, ident in (("pidversion", "%s:%d" % (uniq, int(ver) + 1)), ("uniqueid", "%d:%s" % (int(uniq) + 1, ver))):
        c = setup(SUDO, mode="42", extra={"ident": ident})
        log = c.shimlog.eof(); outcome(c.wait); c.link.release(False)
        result("macOS identity: wrong %s refused" % name, any("refused 122" in l for l in log) and never_ran(c), str(refusal(log)))


# --- revision 7 ------------------------------------------------------------------------------------
def s_pidfs_required():
    """Item 1: below pidfs (Linux < 6.9) shim mode is Unsupported in cosca, and the shim refuses 115."""
    if MACOS:
        result("pidfs required (Linux only)", True, "macOS: not applicable"); return
    os.environ["COSCA_FAKE_NO_PIDFS"] = "1"
    try:
        try:
            identity(); got = "accepted"
        except Unsupported as e:
            got = "Unsupported: %s" % e
    finally:
        del os.environ["COSCA_FAKE_NO_PIDFS"]
    c = setup(SUDO, mode="42", seams_extra={"SHIM_FAKE_NO_PIDFS": "1"})
    w = outcome(c.wait); log = c.shimlog.unblock_if_never_opened(); c.link.release(False)
    result("pidfs required: cosca Unsupported, shim 115", got.startswith("Unsupported") and w == ("not-started", 115, False) and never_ran(c), f"{got}; shim -> {w}")


def s_ruid_ne_euid():
    """Item 3: a cosca whose real uid differs from its effective uid (run under setpriv --ruid mallory --euid tester)."""
    c = setup(SUDO)
    ev_until(c.ev, "answered")
    c.shimlog.wait_for(lambda ls: any(l.startswith("program pid=") or l.startswith("refused") for l in ls))  # T6
    if any(l.startswith("program pid=") for l in c.shimlog.lines):
        read_ready(c)
    k = c.kill(); w = outcome(c.wait); c.link.release(False)
    result("cosca with ruid %d != euid %d starts and is killed" % (os.getuid(), os.geteuid()), os.getuid() != os.geteuid() and w == ("program", 9), f"{k} {w}")


def s_preexec_sigkill():
    """Item 1: the child is SIGKILLed before exec. Nothing proves it did not exec, so it is reported as the
    possibly-started program's status (9) -- never NotStarted from an absence."""
    d = workdir(); cg = Gate(d, "child")
    c = setup(SUDO, d=d, mode="42", seams_extra={"SHIM_CHILD_GATE": cg.path})
    c.shimlog.has("child: waiting at gate")
    child = int([l for l in c.shimlog.lines if l.startswith("forked child pid=")][0].split("=")[1])
    as_root("import os; os.kill(%d, 9)" % child)
    w = outcome(c.wait); c.link.release(False)
    result("pre-exec SIGKILL -> the possibly-started program's status 9", w == ("program", 9), f"{w}")


def s_preexec_sigint():
    """Item 2: a termination signal (SIGINT) before exec is recorded; the child does not exec and reports it on
    the status pipe -- positive evidence -- so the outcome is NotStarted, never a program that runs anyway."""
    d = workdir(); cg = Gate(d, "child")
    c = setup(SUDO, d=d, mode="42", seams_extra={"SHIM_CHILD_GATE": cg.path})
    c.shimlog.has("child: waiting at gate")
    child = int([l for l in c.shimlog.lines if l.startswith("forked child pid=")][0].split("=")[1])
    as_root("import os; os.kill(%d, 2)" % child)
    opener = threading.Thread(target=cg.open, daemon=True); opener.start()  # completes only for a live child
    w = outcome(c.wait); c.link.release(False)
    result("pre-exec SIGINT -> NotStarted (terminated before exec)", w[0] == "not-started" and w[2] is True and never_ran(c), f"{w}")

def s_status_stolen():
    """Item 4: someone else reaps the program: 'U', never a fabricated S(0)."""
    c = setup(SUDO, mode="42", seams_extra={"SHIM_STEAL_REAP": "1"})
    w = outcome(c.wait)
    k = c.kill()  # the program is gone: kill() after 'U' is Ok
    c.link.release(False)
    result("stolen status -> StatusLost, kill Ok", w[0] == "status-lost" and k in ("already-exited", "sent"), f"{w} kill={k}")


def s_threads_refused():
    """Item 5. Linux: a host thread that reaps (wait()) does not break the shim -- the status is honestly lost
    and nothing was signalled by a bare pid. macOS: a multithreaded shim process is refused (114)."""
    c = setup(SUDO, mode="42", seams_extra={"SHIM_SPAWN_THREAD": "1"})
    w = outcome(c.wait); log = c.shimlog.unblock_if_never_opened(); c.link.release(False)
    if MACOS:
        result("macOS: multithreaded shim refused (114)", w[0] == "not-started" and any("refused 114" in l for l in log) and never_ran(c), f"{w} {refusal(log)}")
    else:
        result("Linux: a reaping host thread -> StatusLost", w[0] == "status-lost", f"{w}")


def s_code_119_subreaper():
    """Item 6: code 119 checked by reaping the orphaned child ourselves (PR_SET_CHILD_SUBREAPER)."""
    if MACOS:
        result("119 via subreaper (Linux only)", True, "macOS: no subreaper; the log line is the witness"); return
    import ctypes
    ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
    d = workdir(); cg = Gate(d, "child")
    c = setup(SUDO, d=d, mode="42", seams_extra={"SHIM_DIE_AFTER_FORK": "1", "SHIM_CHILD_GATE": cg.path})
    c.shimlog.has("forked child pid=")
    child = int([l for l in c.shimlog.lines if l.startswith("forked child pid=")][0].split("=")[1])
    c.p.wait()  # shim and front gone: the child is now ours (subreaper)
    cg.open()
    _, st = os.waitpid(child, 0)
    c.link.release(False)
    code = os.WEXITSTATUS(st) if os.WIFEXITED(st) else -os.WTERMSIG(st)
    result("119: orphaned child exits 119 and never execs", code == 119, f"child exit {code}")


def s_program_sets_marker_comm():
    """Item 1(c): a program that names itself "cosca-preexec" (prctl PR_SET_NAME) still runs, is killed, and
    reports its status: nothing reads comm any more."""
    if MACOS:
        result("marker comm (Linux only)", True, "n/a"); return
    d = workdir()
    script = os.path.join(d, "named.py")
    open(script, "w").write("import ctypes,os,sys\nctypes.CDLL(None).prctl(15, b'cosca-preexec', 0, 0, 0)\n"
                            "open(sys.argv[1],'w').write('READY %d 0 0\\n' % os.getpid())\nimport signal\nwhile True: signal.pause()\n")
    os.chmod(d, 0o755); os.chmod(script, 0o644)
    ready = os.path.join(d, "r2"); os.mkfifo(ready, 0o666); os.chmod(ready, 0o666)
    link = ShimLink(events=queue.Queue())
    c = ElevatedChild(SUDO, SHIM, [PY, script, ready], link)
    st = outcome(c.wait_started)
    if st == "live":  # Live does not wait for the program; READY does, and the program writes it at once
        with open(ready) as f:  # written after the program renamed itself
            f.readline()
    k = c.kill(); w = outcome(c.wait); link.release(False)
    result("program named cosca-preexec runs and is killed", k == "sent" and w == ("program", 9), f"{k} {w}")


def s_foreign_proc():
    """Item 1(a,b): the shim sees a /proc of another pid namespace, or none at all; it neither reads nor needs
    it. Run under PROCMODE (set by the privileged lane): the program runs and is killed."""
    c = setup([], link_kw={"expected_euid": os.geteuid()})  # no front: sudo itself wants /proc
    st = outcome(c.wait_started)  # T5: returns whether the shim started the program or exited first
    if st != "live":
        c.link.release(False)
        result("shim with %s: program runs and is killed" % os.environ.get("PROCMODE", "normal /proc"), False, f"never started: {st}"); return
    read_ready(c)
    k = c.kill(); w = outcome(c.wait); c.link.release(False)
    result("shim with %s: program runs and is killed" % os.environ.get("PROCMODE", "normal /proc"), k == "sent" and w == ("program", 9), f"{k} {w}")


# --- revision 9 ------------------------------------------------------------------------------------
def s_t_before_exec():
    """Item 2: wait_started() returns at A, before the fork; terminate() then reaches the child before exec. The
    child records it, does not exec, and reports it: NotStarted -- never a program that runs un-warned."""
    d = workdir(); cg = Gate(d, "child")
    c = setup(SUDO, d=d, mode="42", seams_extra={"SHIM_CHILD_GATE": cg.path})
    st = outcome(c.wait_started)
    c.shimlog.has("child: waiting at gate")
    t = c.terminate()
    c.shimlog.has("control: signal 15")  # sent through the child's handle before the gate opens
    opener = threading.Thread(target=cg.open, daemon=True); opener.start()
    w = outcome(c.wait); c.link.release(False)
    result("terminate() before exec -> NotStarted, program never ran", st == "live" and t == "sent" and w[0] == "not-started" and never_ran(c), f"{st} {t} {w}")


def s_exec_failure_stolen():
    """Item 3: exec fails and a host thread reaps the child: the drained errno still gives F (NotStarted), not U."""
    if MACOS:
        result("exec failure + stolen reap (Linux only; macOS refuses threads)", True, "n/a"); return
    c = setup(SUDO, mode="42", prog_exe="/nonexistent/program", seams_extra={"SHIM_SPAWN_THREAD": "1"})
    w = outcome(c.wait); log = c.shimlog.eof(); c.link.release(False)
    result("exec failure + stolen reap -> NotStarted", w[0] == "not-started" and any("host thread: reaped" in l for l in log), f"{w}")


def s_reaper_race():
    """Item 1: the child exits, a host thread reaps it, a stranger takes its pid (ns_last_pid, own pid namespace);
    then the shim proceeds and cosca sends K. The shim must touch only its own child's handle: the stranger lives."""
    d = workdir(); hold = Gate(d, "hold")
    c = setup(SUDO, d=d, mode="42", prog_exe="/nonexistent/program",
              seams_extra={"SHIM_SPAWN_THREAD": "1", "SHIM_HOLD_AFTER_FORK": hold.path})
    c.shimlog.has("host thread: reaped pid")
    dead = int([l for l in c.shimlog.lines if l.startswith("host thread: reaped pid")][0].split()[-1])
    sd = workdir(); sp = Pinger(sd); sready = os.path.join(sd, "ready"); os.mkfifo(sready, 0o666); os.chmod(sready, 0o666)
    slog = os.path.join(sd, "slog"); open(slog, "w").close(); os.chmod(slog, 0o666)
    as_root("import os\nopen('/proc/sys/kernel/ns_last_pid','w').write(str(%d-1))\nif os.fork()==0:\n  n=os.open('/dev/null',os.O_RDWR); os.dup2(n,0); os.dup2(n,1); os.dup2(n,2)\n  os.execv(%r,[%r,%r,%r,'ping',%r,%r,%r])\n"
            % (dead, PY, PY, PROG, slog, sready, sp.req, sp.rep))
    with open(sready) as f:
        stranger = int(f.readline().split()[1])
    sp.connect()
    hold.open()
    k = c.kill(); w = outcome(c.wait)
    alive = sp.alive()
    if alive:
        sp.quit_and_wait_exit()
    c.link.release(False)
    result("reaped child's pid reused: the stranger is untouched", stranger == dead and alive and w[0] == "not-started", f"stranger pid {stranger} (dead child {dead}); stranger alive={alive}; kill={k}; {w}")


def s_garbled_then_kill():
    """Item 6: after a garbled frame, wait() is ShimLost, and kill() does not claim the program is gone."""
    link = ShimLink(expected_euid=os.geteuid(), events=queue.Queue())
    s = socket.socket(socket.AF_UNIX); s.connect(os.path.join(link.path, "s")); s.send(b"H")
    ev_until(link.events, "answered")
    s.recv(1); s.send(b"X\x00\x00\x00\x00")
    w = outcome(lambda: link.front_exited(0, block=True))
    k = outcome(lambda: link.kill(-1))
    s.close(); link.release(False)
    result("garbled frame: ShimLost, and kill() is not Ok-gone", w[0] == "shim-lost" and k != "already-exited", f"wait={w} kill={k}")


def s_host_executable_macos():
    """Item 5: HostExecutable is Unsupported on macOS (D13)."""
    try:
        got = check_shim_mode("host-executable")
    except Unsupported as e:
        got = "Unsupported: %s" % e
    want_unsupported = MACOS
    result("HostExecutable on this platform", got.startswith("Unsupported") == want_unsupported, got)


def s_threads_r114():
    """Item 5: macOS surfaces the 114 reason to the caller (R after hello), not only on stderr."""
    if not MACOS:
        result("114 reason surfaced (macOS only)", True, "n/a"); return
    # The answer is held until the shim's decision line: it either awaits the answer (114 checked after A) or
    # has already refused (checked before A). A refusal before A could then never reach cosca as a frame.
    started = threading.Event(); box = {}
    def answer_hook():
        started.wait()
        box["c"].shimlog.wait_for(lambda ls: any("awaiting the answer" in l or "refused 114" in l for l in ls))
    c = setup(SUDO, mode="42", seams_extra={"SHIM_SPAWN_THREAD": "1"}, link_kw={"answer_hook": answer_hook})
    box["c"] = c; started.set()
    try:
        got = ("returned", c.wait())
    except NotStarted as e:
        got = ("not-started", e.connected, e.cause)
    except Exception as e:
        got = ("other", repr(e))
    c.link.release(False)
    result("macOS: 114 reaches the caller as NotStarted(code 114)", got[0] == "not-started" and got[1] is True and "code 114" in got[2], f"{got}")


ALL = {k[2:]: v for k, v in list(globals().items()) if k.startswith("s_")}
if __name__ == "__main__":
    for n in sys.argv[1:]:
        cp.LOG.clear()
        try:
            ALL[n]()
        except Exception as e:
            import traceback; traceback.print_exc()
            result(n, False, "exception: %r" % e)
    sys.stdout.flush()
    os._exit(0 if all(RESULTS) else 1)
