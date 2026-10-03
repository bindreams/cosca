"""Plan F start-protocol interleavings, revision 4 (THROWAWAY). Usage: scenarios.py <name>...

Every wait is on an event: a FIFO line, a FIFO EOF (all writers gone), a queue item from the acceptor
seam, the next acceptor event, or a process exit. No sleeps, no timeouts; the runner's per-scenario
bound is the only one, and it reports HANG as a failure."""
import os, queue, select, signal, socket, stat, subprocess, sys, tempfile, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cosca_proto import ShimLink, ElevatedChild, ShimLost, LIVE, REFUSED, DETACHED, PENDING, MACOS, check_parent

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM = os.environ.get("SHIM", os.path.join(HERE, "shim4"))
PY = sys.executable
PROG = os.path.join(HERE, "prog.py")
RESULTS = []
SUDO = ["sudo", "-n"]
PW = ["sudo", "-S", "-k", "-p", ""]


def result(name, ok, detail):
    RESULTS.append(ok)
    print("RESULT %-38s %s  %s" % (name, "PASS" if ok else "FAIL", detail), flush=True)


class Fifo:
    """A FIFO and a reader thread: lines as they come; EOF once every writer closed."""

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
    """Liveness of a 'ping' program without a pidfd (works for root programs on macOS too)."""

    def __init__(self, d):
        self.req, self.rep = os.path.join(d, "req"), os.path.join(d, "rep")
        for p in (self.req, self.rep):
            os.mkfifo(p, 0o666); os.chmod(p, 0o666)

    def connect(self):  # same order as the program: req, then rep
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
        return self.r.readline() == b""  # EOF: the program's fds are closed, it has exited


def workdir():
    d = tempfile.mkdtemp(prefix="sc-"); os.chmod(d, 0o755); return d


def setup(front, d=None, mode="block", gate=False, hold=False, start_acceptor=True, acceptor_gate=None, extra=None, prog_exe=None, link_kw=None):
    d = d or workdir()
    ev = queue.Queue()
    shimlog, siglog = Fifo(d, "shimlog"), Fifo(d, "siglog")
    ready = os.path.join(d, "ready"); os.mkfifo(ready, 0o666); os.chmod(ready, 0o666)
    seams = {"SHIM_LOG": shimlog.path}
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
    """The shim's own record decides; the program's 'ran' line is the second witness (rule T2)."""
    started = any(l.startswith("program pid=") or l.startswith("unsupervised exec") for l in c.shimlog.eof())
    return not started and not any(l.startswith("ran") for l in c.siglog.unblock_if_never_opened())


def as_root(code):
    """Run python code as root; returns its stdout."""
    return subprocess.run(SUDO + [PY, "-c", code], stdout=subprocess.PIPE, check=True).stdout.decode()


# --- start protocol ---------------------------------------------------------------------------------
def s_connect_after_accept():
    c = setup(SUDO, gate=True)
    ev_until(c.ev, "polling")
    c.gate.open()
    ev_until(c.ev, "listener-ready")
    a = c.ev.get()  # the very next event must be the answer (an acceptor that never steps emits "polling")
    if a[0] != "answered":
        result("connect-after-accept", False, f"next acceptor event after listener-ready: {a}")
        c.link.kill(c.p.pid); c.p.wait(); c.shimlog.eof(); c.link.release(False); return
    read_ready(c)
    k = c.kill(); w = c.wait(); out = c.link.release(False)
    result("connect-after-accept", a[1] == "A" and k == "sent" and w == ("program", 9) and out == "removed", f"{a[1]} {k} {w} {out}")


def s_connect_before_accept():
    c = setup(SUDO, mode="plain", start_acceptor=False)
    p = select.poll(); p.register(c.link.listener.fileno(), select.POLLIN); p.poll()
    c.link.start_acceptor()
    a = ev_until(c.ev, "answered"); read_ready(c)
    t = c.terminate(); w = c.wait(); out = c.link.release(False)
    result("connect-before-accept", a[1] == "A" and t == "sent" and w == ("program", 15) and out == "removed", f"{a[1]} {t} {w} {out}")


def s_refuse_wins():
    g = threading.Event()
    c = setup(SUDO, mode="42", acceptor_gate=g)
    ev_until(c.ev, "listener-ready")
    k = c.kill()
    g.set(); a = ev_until(c.ev, "answered")
    if a[0] == "exited":
        result("refuse-then-connection", False, "acceptor thread exited before answering"); return
    log = c.shimlog.eof(); w = c.wait(); out = c.link.release(False)
    front = -9
    result("refuse-then-connection", a[1] == "N" and k.startswith("refused") and "first byte: N" in log and never_ran(c) and w == ("front", front),
           f"{k} answer={a[1]} {w} {out}")


def s_connect_wins():
    """Rule T6: after kill() and the front's exit, check the program is gone before the blocking wait()."""
    g = threading.Event()
    c = setup(SUDO, mode="ping", acceptor_gate=g)
    ev_until(c.ev, "listener-ready"); g.set()
    a = ev_until(c.ev, "answered"); read_ready(c)
    k = c.kill()
    c.front_status = c.p.wait()
    if c.pinger.alive():
        result("connection-then-kill", False, f"{a[1]} {k}: program alive after the front exited")
        c.pinger.quit_and_wait_exit(); c.link.release(False); return
    w = c.wait(); c.link.release(False)
    result("connection-then-kill", a[1] == "A" and k == "sent" and w == ("program", 9), f"{a[1]} {k} {w}; program gone before the front exited")


def s_second_root_peer():
    c = setup(SUDO)
    a = ev_until(c.ev, "answered"); read_ready(c)
    got = as_root("import socket; s=socket.socket(socket.AF_UNIX); s.connect(%r); print(len(s.recv(1)))" % os.path.join(c.link.path, "s")).strip()
    e = ev_until(c.ev, "answered")
    k = c.kill(); w = c.wait(); c.link.release(False)
    result("second root peer while Live", e[1] == "closed-second" and got == "0" and w == ("program", 9), f"second peer read {got} bytes; {e[1]}; first still controls: {w}")


def s_kill_before_auth():
    c = setup(PW, extra={"stdin": subprocess.PIPE})
    k = c.kill(); w = c.wait()
    try:
        c.p.stdin.write(b"pw\n"); c.p.stdin.flush(); pw = "password accepted by a reader?!"
    except BrokenPipeError:
        pw = "password pipe broken (front dead before reading it)"
    c.p.stdin = None
    out = c.link.release(False)
    shim = c.shimlog.unblock_if_never_opened()
    result("kill-before-auth", k == "refused+front-killed" and w == ("front", -9) and not shim and never_ran(c), f"{k} {w}; {pw}; {out}")
    c2 = setup(PW, extra={"stdin": subprocess.PIPE})
    c2.p.stdin.write(b"pw\n"); c2.p.stdin.flush()
    pid = read_ready(c2); c2.kill(); w2 = c2.wait(); c2.link.release(False)
    result("kill-before-auth/control", w2 == ("program", 9), f"program {pid} started; {w2}")


def s_kill_during_auth():
    c = setup(PW, mode="42", gate=True, extra={"stdin": subprocess.PIPE})
    c.p.stdin.write(b"pw\n"); c.p.stdin.flush()
    c.shimlog.has("shim pid=")
    k = c.kill(); w = c.wait()
    c.gate.open(); log = c.shimlog.eof(); out = c.link.release(False)
    result("kill-during-auth", k == "refused+front-killed" and w == ("front", -9) and "first byte: N" in log and never_ran(c), f"{k} {w} {out}")


def s_kill_after_auth():
    c = setup(PW, extra={"stdin": subprocess.PIPE})
    c.p.stdin.write(b"pw\n"); c.p.stdin.flush()
    read_ready(c); k = c.kill(); w = c.wait(); out = c.link.release(False)
    result("kill-after-auth", k == "sent" and w == ("program", 9), f"{k} {w} {out}")


def s_front_death_prestart():
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    os.kill(c.p.pid, signal.SIGKILL)
    w = c.wait()
    c.gate.open(); log = c.shimlog.eof(); c.link.release(False)
    result("front-death-before-start", w == ("front", -9) and "first byte: N" in log and never_ran(c), f"{w}; late shim told N")


def s_front_death_live():
    c = setup(SUDO, mode="release")
    read_ready(c)
    os.kill(c.p.pid, signal.SIGKILL); c.front_status = c.p.wait()
    tw = c.try_wait(); k = c.kill(); w = c.wait(); c.link.release(False)
    result("front-death-after-start/kill", tw is None and k == "sent" and w == ("program", 9), f"try_wait={tw} kill={k} wait={w}")
    c = setup(SUDO, mode="release")
    read_ready(c); os.kill(c.p.pid, signal.SIGKILL); c.front_status = c.p.wait()
    c.rel.open(); w = c.wait(); c.link.release(False)
    result("front-death-after-start/exit", w == ("program", 42 << 8), f"wait read the frame: {w}")


def shim_death_case(name, mode, prog_exe=None, expect_alive=False):
    c = setup(SUDO, mode=mode, prog_exe=prog_exe)
    read_ready(c)
    sp = shim_pid(c)
    as_root("import os; os.kill(%d, 9)" % sp)
    c.shimlog.eof()  # the shim has exited (its log writer closed)
    try:
        w = c.wait(); err = None
    except ShimLost as e:
        w, err = None, str(e)
    alive = c.pinger.alive()
    if alive:
        c.pinger.quit_and_wait_exit()
    c.link.release(False)
    result(name, err is not None and alive == expect_alive, f"wait -> ShimLost={err is not None}; program alive after the shim died: {alive}")


def s_shim_death():
    shim_death_case("shim death: plain program", "ping", expect_alive=MACOS)  # Linux: PDEATHSIG; macOS: none


def s_pdeathsig_setid():
    shim_death_case("shim death: setgid program", "ping", prog_exe="/proto/pysetgid", expect_alive=True)
    shim_death_case("shim death: program drops privileges", "ping-drop", expect_alive=True)


def s_shim_death_backlog():
    g = threading.Event()
    c = setup(SUDO, mode="42", acceptor_gate=g)
    ev_until(c.ev, "listener-ready")
    as_root("import os; os.kill(%d, 9)" % shim_pid(c))
    c.shimlog.eof()
    g.set(); a = ev_until(c.ev, "answered")
    w = c.wait(); c.link.release(False)
    result("shim-death-before-answer", a[1] == "peer-gone" and c.link.state == REFUSED and never_ran(c), f"answer={a[1]} state={c.link.state} wait={w}")


def s_exit_races_kill():
    c = setup(SUDO, mode="ping", hold=True)
    read_ready(c)
    exited = c.pinger.quit_and_wait_exit()  # program exited; the held shim has not reaped it
    k = c.kill()
    c.hold.open(); w = c.wait(); log = c.shimlog.eof(); c.link.release(False)
    ctl = [l for l in log if l.startswith("control") or l.startswith("reaped")]
    result("program-exit-races-kill", exited and k == "sent" and w == ("program", 42 << 8), f"{w} shim: {ctl}")


# --- detach and the marker ---------------------------------------------------------------------------
def s_detach_pending():
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    path = c.link.path
    out = c.link.release(True)
    c.gate.open(); log = c.shimlog.eof()
    rc = c.p.wait(); ran = any(l.startswith("ran") for l in c.siglog.eof())
    left = sorted(os.listdir(path))
    result("marker: drop while Pending runs later", ran and rc == 42 and any("marker: present" in l for l in log) and left == ["start"], f"{out}; front={rc}; dir={left}")
    os.unlink(os.path.join(path, "start")); os.rmdir(path)


def s_detach_refuses():
    """Owner question B option (a): a drop/detach while Pending refuses the start, like kill()."""
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    out = c.link.release(True, marker=False)
    c.gate.open(); log = c.shimlog.eof(); rc = c.p.wait()
    result("B(a): drop while Pending refuses", out == "removed" and "not started" in log and never_ran(c) and rc == 125, f"{out}; front={rc}")


def s_kill_then_detach():
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    k = c.kill(); out = c.link.release(True)
    c.gate.open(); log = c.shimlog.eof()
    result("kill_on_drop(false)+kill()+drop", k.startswith("refused") and out == "removed" and "not started" in log and never_ran(c), f"{k}; {out}")


def marker_tamper(name, tamper):
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    path = c.link.path
    c.link.release(True)  # marker created
    tamper(path)
    c.gate.open(); log = c.shimlog.eof(); rc = c.p.wait()
    m = [l for l in log if l.startswith("marker")]
    result(name, never_ran(c) and rc == 125, f"{m} front={rc}")
    as_root("import shutil; shutil.rmtree(%r)" % path)


def s_marker_checks():
    marker_tamper("marker rejected: dir mode 0755", lambda p: os.chmod(p, 0o755))
    marker_tamper("marker rejected: marker owned by root", lambda p: as_root("import os; os.chown(%r, 0, 0)" % os.path.join(p, "start")))


def s_marker_other_owner():
    """Our dir removed after kill(); another user recreates the path with a marker."""
    c = setup(SUDO, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    path = c.link.path
    c.kill(); c.link.release(True)
    subprocess.run(["sudo", "-n", "-u", "mallory", "/bin/sh", "-c", "umask 077; mkdir %s && touch %s/start" % (path, path)], check=True)
    c.gate.open(); log = c.shimlog.eof()
    m = [l for l in log if l.startswith("marker")]
    result("marker rejected: dir owned by another user", never_ran(c), str(m))
    as_root("import shutil; shutil.rmtree(%r)" % path)


def s_detach_backlog():
    g = threading.Event()
    c = setup(SUDO, mode="42", acceptor_gate=g)
    ev_until(c.ev, "listener-ready")
    path = c.link.path
    t = threading.Thread(target=lambda: setattr(c, "out", c.link.release(True))); t.start()
    ev_until(c.ev, "detached"); g.set(); a = ev_until(c.ev, "answered"); t.join()
    rc = c.p.wait(); ran = any(l.startswith("ran") for l in c.siglog.eof())
    result("detach with shim in backlog", a[1] == "R" and ran and rc == 42, f"answer={a[1]} front={rc}")
    os.unlink(os.path.join(path, "start")); os.rmdir(path)


def s_detach_live():
    c = setup(SUDO, mode="release")
    read_ready(c)
    out = c.link.release(True)
    c.shimlog.has("EOF (armed=0)")
    c.rel.open(); rc = c.p.wait(); log = c.shimlog.eof()
    result("detach while live", rc == 42 and "disarmed" in log, f"{out}; program outlived the handle, front={rc}")


# --- fronts ----------------------------------------------------------------------------------------
def s_pkexec_eperm():
    c = setup(["pkexec"], mode="42", gate=True)
    c.shimlog.has("shim pid=")
    k = c.kill()
    c.gate.open(); log = c.shimlog.eof(); w = c.wait(); c.link.release(False)
    result("pkexec EPERM", k == "refused+front-EPERM" and "first byte: N" in log and never_ran(c) and w == ("front", 125), f"{k} {w}")


def s_direct_exec():
    """sudo with !use_pty !pam_session !pam_setcred execs the command in place: the front IS the shim."""
    c = setup(SUDO, mode="42", gate=True)
    same = shim_pid(c) == c.p.pid
    k = c.kill()
    c.gate.open(); log = c.shimlog.eof(); w = c.wait(); c.link.release(False)
    result("sudo direct exec: pre-start kill", same and k == "refused+front-EPERM" and never_ran(c) and w == ("front", 125), f"front is shim={same}; {k} {w}")
    c = setup(SUDO)
    read_ready(c); same = shim_pid(c) == c.p.pid
    k = c.kill(); w = c.wait(); c.link.release(False)
    result("sudo direct exec: live kill", same and k == "sent" and w == ("program", 9), f"front is shim={same}; {k} {w}")


def s_pkexec_live():
    c = setup(["pkexec"]); read_ready(c); k = c.kill(); w = c.wait(); c.link.release(False)
    result("pkexec live kill", k == "sent" and w == ("program", 9), f"{k} {w}")


def s_doas_live():
    c = setup(["doas"]); read_ready(c); k = c.kill(); w = c.wait(); c.link.release(False)
    result("doas live kill", k == "sent" and w == ("program", 9), f"{k} {w}")


def s_osascript():
    c = setup("OSA"); read_ready(c); k = c.kill(); w = c.wait(); c.link.release(False)
    result("sudo osascript live kill", k == "sent" and w == ("program", 9) and c.front_status == 1, f"{k} {w} osascript exit={c.front_status}")
    c = setup("OSA", mode="42"); w = c.wait(); c.link.release(False)
    result("sudo osascript exit 42", w == ("program", 42 << 8), f"{w} osascript exit={c.front_status}")


# --- channel and directory -------------------------------------------------------------------------
def s_impostor_peer():
    link = ShimLink(events=queue.Queue())
    s = socket.socket(socket.AF_UNIX); s.connect(os.path.join(link.path, "s"))
    e = ev_until(link.events, "closed-non-root")
    got = s.recv(1); out = link.release(False)
    result("non-root peer closed", got == b"" and link.state == PENDING, f"{e} recv={got!r} {out}")


def s_wiring():
    link = ShimLink(expected_euid=os.geteuid(), events=queue.Queue())
    ev_until(link.events, "polling")
    s = socket.socket(socket.AF_UNIX); s.connect(os.path.join(link.path, "s"))
    out = link.release(False)
    s.setblocking(False)
    try:
        got = s.recv(1)
    except BlockingIOError:
        got = "EAGAIN"
    except ConnectionResetError:
        got = "ECONNRESET"
    result("acceptor wiring", got == b"A", f"recv={got!r} {out}")


def s_symlink_swap():
    link = ShimLink(expected_euid=os.geteuid())
    d = link.path; moved = d + ".moved"
    os.rename(d, moved); os.mkdir(d)
    out = link.release(False)
    ok = os.path.isdir(d) and os.path.isdir(moved)
    result("cleanup ignores a swapped name", out == "name no longer ours; left alone" and ok, f"{out}; victim kept={os.path.isdir(d)}")
    os.rmdir(d); os.rmdir(moved)


def s_tmpdir_refusal():
    base = workdir()
    ww = os.path.join(base, "ww"); os.mkdir(ww); os.chmod(ww, 0o777)
    sticky_other = os.path.join(base, "sticky-other"); os.mkdir(sticky_other); os.chmod(sticky_other, 0o1777)
    as_root("import os; os.chown(%r, %d, -1)" % (sticky_other, 1002 if not MACOS else 4294967294))
    outcomes = {}
    for name, p in (("world-writable", ww), ("sticky, other owner", sticky_other), ("system temp", tempfile.gettempdir())):
        try:
            ShimLink(expected_euid=os.geteuid(), start_acceptor=False, tmp=p).release(False); outcomes[name] = "accepted"
        except PermissionError:
            outcomes[name] = "refused"
    ok = outcomes == {"world-writable": "refused", "sticky, other owner": "refused", "system temp": "accepted"}
    result("TMPDIR refusal", ok, str(outcomes))
    as_root("import shutil; shutil.rmtree(%r)" % base)


def s_d2_symlink():
    """A symlink planted at <dir>/s to a root-owned listener: the shim connects, refuses the pid, writes nothing."""
    c_dir = workdir()
    rootsock = "/var/tmp/f-proto-rootsock-%d" % os.getpid()
    r = subprocess.Popen(SUDO + [PY, "-c", "import socket,sys,os\nl=socket.socket(socket.AF_UNIX); l.bind(%r); l.listen(1); print('up', flush=True)\n"
                                 "c,_=l.accept(); n=0\nwhile True:\n  d=c.recv(64)\n  if not d: break\n  n+=len(d)\nprint('bytes', n, flush=True); os.unlink(%r)" % (rootsock, rootsock)],
                         stdout=subprocess.PIPE)
    r.stdout.readline()
    c = setup(SUDO, d=c_dir, mode="42", gate=True)
    c.shimlog.has("shim pid=")
    os.unlink(os.path.join(c.link.path, "s")); os.symlink(rootsock, os.path.join(c.link.path, "s"))
    c.gate.open(); log = c.shimlog.eof()
    got = r.stdout.readline().decode().strip(); r.wait()
    w = c.wait(); c.link.release(False)
    result("D2: symlinked socket gets no bytes", got == "bytes 0" and any("refused, nothing written" in l for l in log) and never_ran(c), f"root listener: {got}; front={w}")


def s_fork_owner():
    """A fork-without-exec copy that drops the link must not stop the owner's acceptor or remove its dir."""
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
    read_ready(c); k = c.kill(); w = c.wait(); out = c.link.release(False)
    result("fork copy drop leaves the owner intact", a[1] == "A" and w == ("program", 9) and out == "removed", f"{a[1]} {k} {w} {out}")


def s_sigpipe():
    """K to a shim that already exited, from a host whose SIGPIPE is SIG_DFL."""
    c = setup(SUDO, mode="42")
    ev_until(c.ev, "answered")
    c.front_status = c.p.wait()  # shim and program are gone; the frame sits unread
    pid = os.fork()
    if pid == 0:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        try:
            c.link.conn.recv(5)  # consume the frame so the next send meets a closed peer
            r = c.link.kill(-1)
            os._exit(0 if r == "shim-gone" else 3)
        except BaseException:
            os._exit(4)
    _, st = os.waitpid(pid, 0)
    c.link.release(False)
    result("K to an exited shim, SIGPIPE default", os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0,
           "child " + ("exit %d" % os.WEXITSTATUS(st) if os.WIFEXITED(st) else "killed by signal %d" % os.WTERMSIG(st)))


# --- signal relay (Linux) --------------------------------------------------------------------------
def relay_case(name, front, sender, expect, preexec=None):
    c = setup(front, extra={"preexec": preexec} if preexec else None)
    read_ready(c)
    src = sender(c)
    c.shimlog.wait_for(lambda ls: any(l.startswith("sig ") and (" from %d:" % src) in l for l in ls))
    if expect == "RELAY":
        c.siglog.wait_for(lambda ls: any(l.startswith("sig") for l in ls))
    c.kill()
    try:
        w = c.wait()
    except ShimLost:
        w = "ShimLost"
    log = c.shimlog.eof(); sig = c.siglog.eof(); c.link.release(False)
    recs = [l for l in log if l.startswith("sig ")]
    mine = [l for l in recs if (" from %d:" % src) in l]
    result(name, len(mine) == 1 and expect in mine[0], f"shim records={recs} program received={[l for l in sig if l.startswith('sig')]} wait={w}")


def s_relay_sudo_kill():
    relay_case("relay: kill(sudo,TERM) no tty", SUDO, lambda c: (os.kill(c.p.pid, signal.SIGTERM), c.p.pid)[1], "RELAY")


def s_relay_sudo_killpg():
    def send(c):
        return int(as_root("import os; print(os.getpid(), flush=True); os.killpg(%d, 15)" % c.p.pid))
    relay_case("relay: root killpg(front group,TERM)", SUDO, send, "DROP (not from parent)", preexec=lambda: os.setpgid(0, 0))


def s_relay_doas():
    relay_case("relay: kill(doas,TERM)", ["doas"], lambda c: (os.kill(c.p.pid, signal.SIGTERM), c.p.pid)[1], "RELAY")


def s_relay_direct():
    def send(c):
        return int(as_root("import os; print(os.getpid(), flush=True); os.kill(%d, 15)" % shim_pid(c)))
    relay_case("relay: root kill(shim,TERM)", SUDO, send, "DROP (not from parent)")


def s_count():
    """Deterministic receipt count. Python runs pending handlers in signal-number order, so once the
    program logs the TERM barrier, every HUP relayed before the barrier was sent has been logged."""
    c = setup(SUDO)
    read_ready(c)
    os.kill(c.p.pid, signal.SIGHUP)  # 1: sudo relays it, the shim relays it: one receipt
    c.siglog.wait_for(lambda ls: ls.count("sig 1") >= 1)
    sender = int(as_root("import os; print(os.getpid(), flush=True); os.kill(%d, 1)" % shim_pid(c)))  # 2: root to the shim: none
    c.shimlog.wait_for(lambda ls: any((" from %d:" % sender) in l for l in ls))
    os.kill(c.p.pid, signal.SIGTERM)  # 3: barrier through the relay
    c.siglog.wait_for(lambda ls: "sig 15" in ls)
    hup, term = c.siglog.count("sig 1"), c.siglog.count("sig 15")
    c.kill(); c.wait(); c.link.release(False)
    result("relay: exact receipt count", hup == 1 and term == 1, f"program received HUP x{hup}, TERM x{term} (expected 1, 1)")


def s_stale_parent():
    """The front dies and is reaped; a root process reusing its pid signals the shim (needs CAP_SYS_ADMIN
    in the container's pid namespace for ns_last_pid)."""
    c = setup(SUDO)
    read_ready(c)
    old = c.p.pid
    os.kill(old, signal.SIGKILL); c.front_status = c.p.wait()  # cosca reaps the front: its pid is free
    code = ("import os\nopen('/proc/sys/kernel/ns_last_pid','w').write(str(%d-1))\npid=os.fork()\n"
            "if pid==0:\n  os.kill(%d,1); os._exit(0)\nos.waitpid(pid,0); print(pid, flush=True)") % (old, shim_pid(c))
    reused = int(as_root(code))
    c.shimlog.wait_for(lambda ls: any((" from %d:" % reused) in l for l in ls))
    k = c.kill(); w = c.wait(); log = c.shimlog.eof(); sig = c.siglog.eof(); c.link.release(False)
    rec = [l for l in log if (" from %d:" % reused) in l]
    result("relay: reused parent pid", reused == old and len(rec) == 1 and "DROP (parent had exited)" in rec[0] and "sig 1" not in sig,
           f"impostor pid {reused} (front was {old}); {rec}; program received {[l for l in sig if l.startswith('sig')]}")


def tty_inner(kind):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    c = setup(SUDO)
    read_ready(c)
    print("GO", flush=True)
    if kind == "pty-kill":
        os.kill(c.p.pid, signal.SIGTERM)
    c.shimlog.wait_for(lambda ls: any(l.startswith("sig ") for l in ls))
    c.siglog.wait_for(lambda ls: any(l.startswith("sig") for l in ls))
    c.kill()
    try:
        w = c.wait()
    except ShimLost:
        w = "ShimLost"
    log = c.shimlog.eof(); sig = c.siglog.eof(); c.link.release(False)
    dec = [l for l in log if l.startswith("sig ") or l.startswith("relay_from")]
    print("INNER decisions=%s program=%s wait=%s" % (dec, [l for l in sig if l.startswith("sig")], w), flush=True)


def tty_case(name, user, kind, expect):
    p = subprocess.Popen(["script", "-qfec", f"setpriv --reuid={user} --regid={user} --init-groups {PY} {__file__} tty_inner_{kind}", "/dev/null"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    seen = False
    for line in p.stdout:
        line = line.decode(errors="replace").strip()
        if line == "GO" and kind == "intr":
            p.stdin.write(b"\x03"); p.stdin.flush()
        if "INNER" in line:
            result(name, all(e in line for e in expect) and line.count("RELAY") == 0, line); seen = True
    p.stdin.close(); rc = p.wait()
    if not seen:
        result(name, False, "no INNER line; script rc=%s" % rc)


# --- macOS ------------------------------------------------------------------------------------------
def s_mac_term_swallowed():
    """macOS, owner question A option (a): the shim ignores a TERM sudo relays, and still supervises."""
    c = setup(SUDO)
    read_ready(c)
    os.kill(c.p.pid, signal.SIGTERM)  # sudo relays TERM to the shim, which records and swallows it
    c.shimlog.wait_for(lambda ls: any(l.startswith("sig 15") for l in ls))
    k = c.kill(); w = c.wait(); sig = c.siglog.eof(); c.link.release(False)
    got = [l for l in sig if l.startswith("sig")]
    result("macOS: relayed TERM swallowed, shim still supervises", w == ("program", 9) and got == [], f"{k} {w} program received={got}")


ALL = {k[2:]: v for k, v in list(globals().items()) if k.startswith("s_")}
if __name__ == "__main__":
    for n in sys.argv[1:]:
        if n.startswith("tty_inner_"):
            tty_inner(n[len("tty_inner_"):])
        elif n == "tty_intr_nopty":
            tty_case("relay: ^C on a tty, sudo !use_pty", "ptyless", "intr", ["DROP (not process-sent)", "'sig 2'"])
        elif n == "tty_intr_pty":
            tty_case("relay: ^C on a tty, sudo use_pty", "tester", "intr", ["DROP (not process-sent)", "'sig 2'"])
        elif n == "tty_kill_pty":
            tty_case("relay: kill(sudo,TERM), use_pty", "tester", "pty-kill", ["DROP (parent not in my pgrp)", "'sig 15'"])
        else:
            try:
                ALL[n]()
            except Exception as e:
                import traceback; traceback.print_exc()
                result(n, False, "exception: %r" % e)
    sys.exit(0 if all(RESULTS) else 1)
