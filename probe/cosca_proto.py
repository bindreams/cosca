"""Plan F prototype of cosca's side, revision 4 (THROWAWAY). Linux and macOS.

ShimLink: private dir (fd-based cleanup), listener, acceptor thread, StartState, optional detach
marker; teardown is owned by the pid that bound it (a fork-without-exec copy only closes its fds).
ElevatedChild: kill/terminate/wait/try_wait routing. Test seams are explicit constructor arguments."""
import os, queue, secrets, select, signal, socket, stat, struct, sys, tempfile, threading

PENDING, LIVE, REFUSED, DETACHED = "Pending", "Live", "Refused", "Detached"
NOSIG = getattr(socket, "MSG_NOSIGNAL", 0)
MACOS = sys.platform == "darwin"


class ShimLost(Exception):
    """The shim's connection closed without a status: the program may still be running."""


def peer_cred(c):
    if MACOS:  # LOCAL_PEERCRED (struct xucred: version, uid, ...) and LOCAL_PEERPID, at SOL_LOCAL = 0
        uid = struct.unpack_from("2I", c.getsockopt(0, 0x001, 76))[1]  # sizeof(struct xucred) = 76
        pid = struct.unpack("i", c.getsockopt(0, 0x002, 4))[0]
        return pid, uid
    pid, uid, _ = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return pid, uid


def nosigpipe(c):
    if MACOS:
        c.setsockopt(socket.SOL_SOCKET, 0x1022, 1)  # SO_NOSIGPIPE


def check_parent(st):
    """Only our uid or root may rename entries: the owner is us or root, and the dir is sticky or not
    writable by group/other. (Revision 4: the sticky branch checks the owner too.)"""
    owner_ok = st.st_uid in (0, os.geteuid())
    return owner_ok and bool(st.st_mode & stat.S_ISVTX or not st.st_mode & 0o022)


class ShimLink:
    def __init__(self, expected_euid=0, start_acceptor=True, events=None, gate=None, tmp=None, sigpipe_safe=True):
        self.expected_euid, self.events, self.gate, self.sigpipe_safe = expected_euid, events, gate, sigpipe_safe
        self.owner_pid = os.getpid()
        tmp = tmp or tempfile.gettempdir()
        self.parent_fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        if not check_parent(os.fstat(self.parent_fd)):
            os.close(self.parent_fd)
            raise PermissionError("TMPDIR %s lets another user rename entries in it" % tmp)
        while True:  # EEXIST is someone else's entry: retry with a fresh name
            self.name = "cosca-elev-" + secrets.token_hex(8)
            try:
                os.mkdir(self.name, 0o700, dir_fd=self.parent_fd)
                break
            except FileExistsError:
                continue
        self.dir_fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent_fd)
        st = os.fstat(self.dir_fd)
        assert st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700
        self.dir_id = (st.st_dev, st.st_ino)
        self.path = os.path.join(tmp, self.name)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(os.path.join(self.path, "s"))
        self.listener.listen(8)
        self.listener.setblocking(False)
        assert stat.S_ISSOCK(os.stat("s", dir_fd=self.dir_fd, follow_symlinks=False).st_mode)
        self.lock = threading.Lock()
        self.state, self.conn, self.peer_pid = PENDING, None, None
        self.wake_r, self.wake_w = os.pipe()
        for fd in (self.wake_r, self.wake_w):
            os.set_blocking(fd, False); os.set_inheritable(fd, False)
        self.thread = None
        if start_acceptor:
            self.start_acceptor()

    def ev(self, *e):
        if self.events is not None:
            self.events.put(e)

    # The acceptor ------------------------------------------------------------------------------
    def start_acceptor(self):
        self.thread = threading.Thread(target=self._run, daemon=False)
        self.thread.start()

    def _run(self):
        try:
            self._loop()
        finally:
            self.ev("exited")  # a dead acceptor ends every wait on its events (rule T5)

    def _loop(self):
        p = select.poll()
        p.register(self.listener.fileno(), select.POLLIN)
        p.register(self.wake_r, select.POLLIN)
        while True:
            self.ev("polling")
            ready = dict(p.poll())
            if ready.get(self.listener.fileno()):  # the listener before the stop byte (rule T3)
                self.ev("listener-ready")
                if self.gate is not None:
                    self.gate.wait()
                self.step()
            if ready.get(self.wake_r):
                if b"x" in os.read(self.wake_r, 64):
                    return

    def step(self):
        """Answer every connection in the backlog. Never blocks."""
        while True:
            try:
                c, _ = self.listener.accept()
            except BlockingIOError:
                return
            if self.sigpipe_safe:
                nosigpipe(c)
            pid, uid = peer_cred(c)
            if uid != self.expected_euid:
                self.ev("closed-non-root", pid, uid)
                c.close()
                continue
            with self.lock:
                byte = {PENDING: b"A", REFUSED: b"N", DETACHED: b"R"}.get(self.state)
                if byte is None:
                    c.close(); ans = "closed-second"
                else:
                    try:
                        c.send(byte, NOSIG)
                        ans = byte.decode()
                    except (BrokenPipeError, ConnectionResetError):
                        ans, byte = "peer-gone", None
                        if self.state == PENDING:
                            self.state = REFUSED
                    if byte == b"A":
                        self.conn, self.state, self.peer_pid = c, LIVE, pid
                    else:
                        c.close()
            self.ev("answered", ans, pid)

    # cosca's operations --------------------------------------------------------------------------
    def kill(self, front_pid, byte=b"K"):
        assert front_pid > 0 or self.state == LIVE
        with self.lock:
            if self.state == LIVE:
                try:
                    self.conn.send(byte, NOSIG)
                    return "sent"
                except (BrokenPipeError, ConnectionResetError):
                    return "shim-gone"
            if self.state == PENDING:
                self.state = REFUSED
            assert self.state != DETACHED, "detach consumes the handle"
            try:
                os.kill(front_pid, signal.SIGKILL)
                return "refused+front-killed"
            except PermissionError:
                return "refused+front-EPERM"
            except ProcessLookupError:
                return "refused+front-gone"

    def front_exited(self, block):
        with self.lock:
            if self.state == PENDING:
                self.state = REFUSED
            if self.state != LIVE:
                return ("front", None)
            conn = self.conn
        conn.setblocking(block)
        buf = b""
        while len(buf) < 5:
            try:
                d = conn.recv(5 - len(buf))
            except BlockingIOError:
                return None
            if not d:
                raise ShimLost("the shim closed its connection without a status: the program may still be running")
            buf += d
        assert buf[0:1] == b"S"
        return ("program", struct.unpack("<i", buf[1:])[0])

    def release(self, detached, marker=True):
        """Drop of the handle. detached: kill_on_drop(false) or detach(). marker=False is owner
        question B option (a): a detach while Pending refuses the start, like kill()."""
        if os.getpid() != self.owner_pid:  # a fork-without-exec copy: close our fds, touch nothing shared
            for fd in (self.dir_fd, self.parent_fd, self.wake_r, self.wake_w):
                os.close(fd)
            self.listener.close()
            if self.conn is not None:
                self.conn.detach()  # forget the fd without shutdown(); close() alone would be fine too
            return "not the owner: closed fds only"
        with self.lock:
            if detached and self.state == PENDING:
                if marker:
                    fd = os.open("start", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.dir_fd)
                    os.close(fd)
                    self.state = DETACHED
                else:
                    self.state = REFUSED
                self.ev("detached")
            elif detached and self.state == LIVE:
                self.conn.send(b"D", NOSIG)
        os.write(self.wake_w, b"x")
        if self.thread is not None:
            self.thread.join()
        self.listener.close()
        if self.conn is not None:
            self.conn.close()
        os.unlink("s", dir_fd=self.dir_fd)
        if self.state == DETACHED:
            outcome = "left dir with marker for a late shim"
        else:
            try:
                os.unlink("start", dir_fd=self.dir_fd)
            except FileNotFoundError:
                pass
            st = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            if (st.st_dev, st.st_ino) == self.dir_id and stat.S_ISDIR(st.st_mode):
                try:
                    os.rmdir(self.name, dir_fd=self.parent_fd)
                    outcome = "removed"
                except OSError as e:
                    outcome = "left (%s)" % e.strerror
            else:
                outcome = "name no longer ours; left alone"
        os.close(self.dir_fd); os.close(self.parent_fd); os.close(self.wake_r); os.close(self.wake_w)
        return outcome


def osascript_front(argv):
    import shlex
    cmd = "exec " + " ".join(shlex.quote(a) for a in argv)
    esc = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return ["sudo", "-n", "/usr/bin/osascript", "-e", 'do shell script "%s" with administrator privileges' % esc]


class ElevatedChild:
    def __init__(self, front, shim, prog, link, seams=None, stdin=None, preexec=None):
        import subprocess
        self.link = link
        wrap = ["/usr/bin/env"] + ["%s=%s" % kv for kv in (seams or {}).items()]  # fronts drop the caller's env
        inner = wrap + [shim, "--cosca-elevation-shim=1", link.path, str(os.getpid()), str(os.geteuid()), "--"] + prog
        argv = osascript_front(inner) if front == "OSA" else front + inner
        self.p = subprocess.Popen(argv, stdin=stdin, preexec_fn=preexec)
        self.front_status = None

    def kill(self):
        if self.front_status is not None:
            return self.link.kill(-1) if self.link.state == LIVE else "front-reaped"
        return self.link.kill(self.p.pid)

    def terminate(self):
        return self.link.kill(self.p.pid, b"T")

    def wait(self):
        if self.front_status is None:
            self.front_status = self.p.wait()
        r = self.link.front_exited(block=True)
        return r if r[0] == "program" else ("front", self.front_status)

    def try_wait(self):
        if self.front_status is None:
            rc = self.p.poll()
            if rc is None:
                return None
            self.front_status = rc
        r = self.link.front_exited(block=False)
        if r is None:
            return None
        return r if r[0] == "program" else ("front", self.front_status)
