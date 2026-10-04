"""Plan F prototype of cosca's side, revision 5 (THROWAWAY). Linux and macOS.

ShimLink: private dir (fd cleanup), listener, acceptor thread, StartState (Pending/Live/Refused),
fail-closed acceptor, state-change notification for wait_started, teardown that unlinks the socket
before the final drain, ownership by the binding pid. ElevatedChild: kill/terminate/wait/try_wait/
wait_started/drop routing with NotStarted and ShimLost outcomes."""
import ctypes, errno, os, queue, secrets, select, signal, socket, stat, struct, sys, tempfile, threading

PENDING, LIVE, REFUSED = "Pending", "Live", "Refused"
NOSIG = getattr(socket, "MSG_NOSIGNAL", 0)
MACOS = sys.platform == "darwin"
LOG = []  # (level, message): the prototype's stand-in for `log`


def log(level, msg):
    LOG.append((level, msg))


class ShimLost(Exception):
    """The shim's connection ended without a valid status: the program may still be running."""


def decode_not_executed(val):
    """F's value: kind in bits 16-23, errno or signal in bits 0-15. None if malformed (then ShimLost)."""
    kind, n = (val >> 16) & 0xff, val & 0xffff
    if val <= 0 or val >> 24 or n == 0:
        return None
    if kind == 1:
        return "ForkFailed(%s)" % os.strerror(n)
    if kind == 2:
        return "ExecFailed(%s)" % os.strerror(n)
    if kind == 3:
        return "SetupFailed(%s)" % os.strerror(n)
    if kind == 4:
        return "TerminatedBeforeExec(%d)" % n
    return None


class NotStarted(Exception):
    """The program never started. .front is the front's status; .connected says whether a shim reached cosca."""

    def __init__(self, front, connected, cause):
        super().__init__("the elevated program was not started (%s); front status %r" % (cause, front))
        self.front, self.connected, self.cause = front, connected, cause


class AcceptorFailed(Exception):
    pass


class StatusLost(Exception):
    """The program ran (or may have) and has exited, but someone else reaped it: its status is unknown."""


class SupervisionLost(Exception):
    """The program ran; the shim's supervision failed, so it killed and reaped it. .status is the real status."""

    def __init__(self, status):
        super().__init__("the elevated program ran, but its supervision failed and it was killed (status %d)" % status)
        self.status = status


class Unsupported(Exception):
    pass


PIDFS_MAGIC = 0x50494446


def has_pidfs():
    """Linux: pidfds live on pidfs (6.9+), so their inode numbers identify a process for good."""
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.pidfd_open(os.getpid())
    try:
        buf = ctypes.create_string_buffer(128)
        if libc.fstatfs(fd, buf) != 0:
            return False
        return struct.unpack_from("l", buf.raw, 0)[0] == PIDFS_MAGIC and not os.environ.get("COSCA_FAKE_NO_PIDFS")
    finally:
        os.close(fd)


def check_shim_mode(mode):
    """D13, revision 12: every mode on every platform (HostExecutable included on macOS)."""
    return mode


def identity():
    """cosca's own process identity. Revision 12: Linux carries none ("-"; pid and euid only, the owner pidfd is
    confirmed by the answer's credentials); macOS p_uniqueid:p_idversion."""
    if not MACOS:
        return "-"
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    buf = ctypes.create_string_buffer(56)
    n = libproc.proc_pidinfo(os.getpid(), 17, ctypes.c_uint64(0), buf, 56)
    assert n == 56, n
    return "%d:%d" % (struct.unpack_from("<Q", buf.raw, 16)[0], struct.unpack_from("<i", buf.raw, 32)[0] & 0xffffffff)


def peer_cred(c):
    if MACOS:
        uid = struct.unpack_from("2I", c.getsockopt(0, 0x001, 76))[1]
        pid = struct.unpack("i", c.getsockopt(0, 0x002, 4))[0]
        return pid, uid
    pid, uid, _ = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return pid, uid


SO_NOSIGPIPE = 0x1022


def nosigpipe(c):
    if MACOS:
        c.setsockopt(socket.SOL_SOCKET, SO_NOSIGPIPE, 1)


def check_parent(st):
    return st.st_uid in (0, os.geteuid()) and bool(st.st_mode & stat.S_ISVTX or not st.st_mode & 0o022)


def check_tmpdir(tmp):
    """TMPDIR and every ancestor of its real path: owned by us or root, and sticky or not group/other-writable,
    so no other user can rename any component on the way to our directory."""
    real = os.path.realpath(tmp)
    parts = real.split("/")
    for i in range(len(parts), 0, -1):
        path = "/".join(parts[:i]) or "/"
        if not check_parent(os.lstat(path)):
            return path
    return None


RETRY_ACCEPT = (errno.EINTR, errno.ECONNABORTED)


class ShimLink:
    def __init__(self, expected_euid=0, start_acceptor=True, events=None, gate=None, tmp=None, sigpipe_safe=True, accept_hook=None, answer_hook=None):
        self.expected_euid, self.events, self.gate, self.sigpipe_safe = expected_euid, events, gate, sigpipe_safe
        self.accept_hook = accept_hook  # seam: called before each accept (may raise OSError)
        self.answer_hook = answer_hook  # seam: called after a hello, before the answer (an acceptor gate)
        self.owner_pid = os.getpid()
        tmp = tmp or tempfile.gettempdir()
        bad = check_tmpdir(tmp)
        if bad:
            raise PermissionError("TMPDIR %s: %s lets another user rename entries on the way" % (tmp, bad))
        self.parent_fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        if not check_parent(os.fstat(self.parent_fd)):
            os.close(self.parent_fd)
            raise PermissionError("TMPDIR %s lets another user rename entries in it" % tmp)
        while True:
            self.name = "cosca-elev-" + secrets.token_hex(8)
            try:
                os.mkdir(self.name, 0o700, dir_fd=self.parent_fd)
                break
            except FileExistsError:
                continue
        self.dir_fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent_fd)
        st = os.fstat(self.dir_fd)
        self.dir_id = (st.st_dev, st.st_ino)
        self.path = os.path.join(tmp, self.name)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(os.path.join(self.path, "s"))
        self.listener.listen(8)
        self.listener.setblocking(False)
        self.lock = threading.Lock()
        self.state, self.conn, self.connected, self.error = PENDING, None, False, None
        self.socket_unlinked = False
        self.wake_r, self.wake_w = os.pipe()
        self.note_r, self.note_w = os.pipe()  # one byte per state change: wait_started's wake-up
        for fd in (self.wake_r, self.wake_w, self.note_r, self.note_w):
            os.set_blocking(fd, False); os.set_inheritable(fd, False)
        self.thread = None
        if start_acceptor:
            self.start_acceptor()

    def ev(self, *e):
        if self.events is not None:
            self.events.put(e)

    def _set(self, state):  # under the lock
        self.state = state
        os.write(self.note_w, b"!")

    def _unlink_socket(self):
        if not self.socket_unlinked:
            self.socket_unlinked = True
            try:
                os.unlink("s", dir_fd=self.dir_fd)
            except FileNotFoundError:
                log("debug", "socket already gone in %s" % self.path)
            except OSError as e:
                log("warn", "could not remove %s/s: %s" % (self.path, e.strerror))

    # The acceptor ------------------------------------------------------------------------------
    def start_acceptor(self):
        self.thread = threading.Thread(target=self._run, daemon=False)
        self.thread.start()

    def _run(self):
        try:
            self._loop()
        except BaseException as e:  # the stand-in for a panic: fail closed, never leave shims unanswered
            self._fail_closed("acceptor thread died: %r" % e)
            raise
        finally:
            self.ev("exited")

    def _fail_closed(self, why):
        with self.lock:
            live = self.state == LIVE
            if not live:  # Pending/Refused: nothing can start any more, and every caller is told why
                self.error = why
                if self.state == PENDING:
                    self._set(REFUSED)
        if live:  # Live: the listener only turned away extra peers; the running program is unaffected
            log("warn", "acceptor stopped while Live (%s); the running program is still controlled" % why)
        self._unlink_socket()
        try:
            self.listener.close()  # queued connections are reset: those shims exit 124
        except OSError:
            pass
        log("error", why)
        self.ev("accept-failed", why)

    def _loop(self):
        p = select.poll()
        p.register(self.listener.fileno(), select.POLLIN)
        p.register(self.wake_r, select.POLLIN)
        self.waiting = {}  # fd -> (conn, pid): accepted root peers that have not said hello yet
        while True:
            self.ev("polling")
            ready = dict(p.poll())
            if ready.get(self.listener.fileno()):
                self.ev("listener-ready")
                if self.gate is not None:
                    self.gate.wait()
                if not self.step(p):
                    return
            for fd in [f for f in ready if f in self.waiting]:
                self.hello(p, fd)
            if ready.get(self.wake_r):
                if b"x" in os.read(self.wake_r, 64):
                    self.step(p)
                    for fd in list(self.waiting):  # final drain: whoever already said hello is answered
                        self.hello(p, fd, final=True)
                    return

    def step(self, p):
        """Accept the backlog; root peers wait for their hello. Never blocks. False: failed closed."""
        while True:
            try:
                if self.accept_hook:
                    self.accept_hook()
                c, _ = self.listener.accept()
            except BlockingIOError:
                return True
            except OSError as e:
                if e.errno in RETRY_ACCEPT:
                    log("debug", "accept: %s, retrying" % e.strerror)
                    continue
                self._fail_closed("accept failed: %s" % e.strerror)
                return False
            try:
                pid, uid = peer_cred(c)
                if self.sigpipe_safe:
                    nosigpipe(c)
            except OSError as e:
                log("debug", "peer unreadable (%s): closed unanswered" % e.strerror)
                self.ev("closed-unreadable", e.errno); c.close(); continue
            if uid != self.expected_euid:
                log("warn", "non-root peer pid %d uid %d on %s: closed" % (pid, uid, self.path))
                self.ev("closed-non-root", pid, uid); c.close(); continue
            c.setblocking(False)
            self.waiting[c.fileno()] = (c, pid)
            p.register(c.fileno(), select.POLLIN)
            self.ev("accepted", pid)

    def _answer(self, c, byte):
        if MACOS:
            c.send(byte, NOSIG)
        else:  # explicit credentials with the euid: the shim compares them with SO_PEERCRED's euid
            creds = struct.pack("3i", os.getpid(), os.geteuid(), os.getegid())
            c.sendmsg([byte], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, creds)], NOSIG)

    def hello(self, p, fd, final=False):
        c, pid = self.waiting[fd]
        try:
            h = c.recv(1)
        except BlockingIOError:
            if final:  # no hello by teardown: closed unanswered; the shim exits 124 and never starts
                del self.waiting[fd]; p.unregister(fd); c.close()
            return
        except OSError:
            h = b""
        del self.waiting[fd]; p.unregister(fd)
        if h != b"H":
            log("debug", "peer pid %d closed before hello" % pid)
            c.close(); self.ev("answered", "no-hello", pid); return
        c.setblocking(True)
        if self.answer_hook:
            self.answer_hook()
        with self.lock:
            self.connected = True
            byte = {PENDING: b"A", REFUSED: b"N"}.get(self.state)
            if byte is None:
                log("warn", "second root peer pid %d while Live: closed" % pid)
                c.close(); ans = "closed-second"
            else:
                try:
                    self._answer(c, byte); ans = byte.decode()
                except OSError as e:
                    log("debug", "answer to pid %d failed: %s" % (pid, e.strerror))
                    ans, byte = "peer-gone", None
                    if self.state == PENDING:
                        self._set(REFUSED)
                if byte == b"A":
                    self.conn = c; self._set(LIVE)
                else:
                    c.close()
        self.ev("answered", ans, pid)

    # cosca's operations --------------------------------------------------------------------------
    def _owned(self):
        if os.getpid() != self.owner_pid:
            raise PermissionError("Unsupported: this ShimLink belongs to pid %d" % self.owner_pid)

    def _frame_now(self, conn):
        """Non-blocking: ('S', status) | ('F', errno) | 'none' (nothing yet) | 'eof' | ('bad', bytes)."""
        conn.setblocking(False)
        try:
            data = conn.recv(5, socket.MSG_PEEK)
        except BlockingIOError:
            return "none"
        except OSError:
            return "eof"
        if not data:
            return "eof"
        if len(data) < 5:
            return "none" if data[0:1] in (b"S", b"F", b"L", b"R", b"U") else ("bad", data)
        tag = data[0:1]
        if tag not in (b"S", b"F", b"L", b"R", b"U"):
            return ("bad", data)
        return (tag.decode(), struct.unpack("<i", data[1:5])[0])

    def refuse_if_pending(self):
        with self.lock:
            if self.state == PENDING:
                self._set(REFUSED)
            return self.state

    def kill(self, front_pid, byte=b"K"):
        self._owned()
        with self.lock:
            if getattr(self, "final", None) is not None:
                return "already-exited"
            if self.state == LIVE:
                while True:
                    try:
                        self.conn.send(byte, NOSIG)
                        return "sent"
                    except InterruptedError:
                        continue
                    except OSError as e:
                        if e.errno in (errno.EAGAIN, errno.ENOBUFS):
                            raise ShimLost("Unkillable: control channel full (%s): the shim is not reading" % e.strerror)
                        f = self._frame_now(self.conn)  # EPIPE/ECONNRESET/ENOTCONN: did the program exit?
                        if isinstance(f, tuple) and f[0] in ("S", "F", "L", "R", "U"):
                            return "already-exited"
                        raise ShimLost("K could not be delivered (%s) and no status was sent: the program may still be running" % e.strerror)
            if self.state == PENDING:
                self._set(REFUSED)
            if self.error:
                pass  # the acceptor already failed closed; nothing can start
            try:
                os.kill(front_pid, signal.SIGKILL)
                return "refused+front-killed"
            except PermissionError:
                return "refused+front-EPERM"
            except ProcessLookupError:
                return "refused+front-gone"

    def front_exited(self, front_status, block):
        """After the front was reaped: ('program', status) | None (try_wait: still running); raises NotStarted / ShimLost."""
        self._owned()
        with self.lock:
            if self.state == PENDING:
                self._set(REFUSED)
            if self.state != LIVE:
                cause = self.error or ("refused" if self.connected else "no shim reached cosca")
                raise NotStarted(front_status, self.connected, cause)
            conn = self.conn
        conn.setblocking(block)
        buf = b""
        while len(buf) < 5:
            try:
                d = conn.recv(5 - len(buf))
            except BlockingIOError:
                return None
            except OSError as e:
                raise ShimLost("status read failed (%s)" % e.strerror)
            if not d:
                cause = "truncated frame %r" % buf if buf else "connection closed without a status"
                raise ShimLost(cause + ": the program may still be running")
            buf += d
        tag, val = buf[0:1], struct.unpack("<i", buf[1:])[0]
        f_cause = decode_not_executed(val) if tag == b"F" else None
        if tag in (b"S", b"L", b"R", b"U") or f_cause:
            self.final = tag  # a valid frame: the program has ended (or never ran); kill() is then a no-op
        if tag == b"S":
            return ("program", val)
        if tag == b"F" and f_cause:
            raise NotStarted(front_status, True, f_cause)
        if tag == b"L":
            raise SupervisionLost(val)
        if tag == b"R":
            raise NotStarted(front_status, True, "the shim refused the start (code %d)" % val)
        if tag == b"U":
            raise StatusLost("the program has exited, but its status was collected by someone else")
        raise ShimLost("garbled frame %r: the program may still be running" % buf)

    def release(self, detached):
        """Drop of the handle. A fork copy only closes its fds. The socket path is unlinked before the
        acceptor's final drain, so no shim can connect after the last answer."""
        if os.getpid() != self.owner_pid:
            for fd in (self.dir_fd, self.parent_fd, self.wake_r, self.wake_w, self.note_r, self.note_w):
                os.close(fd)
            self.listener.close()
            if self.conn is not None:
                self.conn.detach()
            return "not the owner: closed fds only"
        with self.lock:
            if self.state == PENDING:
                if detached:
                    log("warn", "detached before the elevated program started: the start was refused")
                self._set(REFUSED)
            elif self.state == LIVE and detached:
                try:
                    self.conn.send(b"D", NOSIG)
                except OSError as e:
                    log("warn", "could not disarm the shim (%s)" % e.strerror)
        self._unlink_socket()
        os.write(self.wake_w, b"x")
        if self.thread is not None:
            self.thread.join()
        try:
            self.listener.close()
        except OSError:
            pass
        if self.conn is not None:
            self.conn.close()
        st = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        if (st.st_dev, st.st_ino) == self.dir_id and stat.S_ISDIR(st.st_mode):
            try:
                os.rmdir(self.name, dir_fd=self.parent_fd); outcome = "removed"
            except OSError as e:
                outcome = "left (%s)" % e.strerror; log("warn", "private dir %s left: %s" % (self.path, e.strerror))
        else:
            outcome = "name no longer ours; left alone"; log("warn", "%s is no longer our directory; left alone" % self.path)
        for fd in (self.dir_fd, self.parent_fd, self.wake_r, self.wake_w, self.note_r, self.note_w):
            os.close(fd)
        return outcome


def osascript_front(argv):
    import shlex
    cmd = "exec " + " ".join(shlex.quote(a) for a in argv)
    esc = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return ["sudo", "-n", "/usr/bin/osascript", "-e", 'do shell script "%s" with administrator privileges' % esc]


class ElevatedChild:
    def __init__(self, front, shim, prog, link, seams=None, stdin=None, preexec=None, ident=None, stderr=None, cosca_pid=None):
        import subprocess
        self.link = link
        wrap = ["/usr/bin/env"] + ["%s=%s" % kv for kv in (seams or {}).items()]
        if ident is None and not MACOS and os.path.basename(shim).startswith("shim10"):  # revision 10/11 shims: pidfs inode
            fd = os.pidfd_open(os.getpid()); ident = os.fstat(fd).st_ino; os.close(fd)
        rest = [link.path, str(cosca_pid or os.getpid()), str(ident if ident is not None else identity()), str(os.geteuid()), "--"] + prog
        if front == "OSA":  # the AppleScript text must stay ASCII: hex every argument after the flag
            hexed = [a if a == "--" else os.fsencode(a).hex() for a in rest]
            argv = osascript_front(wrap + [shim, "--cosca-elevation-shim=1x"] + hexed)
        else:
            argv = front + wrap + [shim, "--cosca-elevation-shim=1"] + rest
        self.p = subprocess.Popen(argv, stdin=stdin, preexec_fn=preexec, stderr=stderr)
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
        return self.link.front_exited(self.front_status, block=True)

    def try_wait(self):
        if self.front_status is None:
            rc = self.p.poll()
            if rc is None:
                return None
            self.front_status = rc
        return self.link.front_exited(self.front_status, block=False)

    def wait_started(self):
        """Block until Live, or until the front exits first (then NotStarted). Events only."""
        if MACOS:
            kq = select.kqueue()
            kq.control([select.kevent(self.link.note_r, select.KQ_FILTER_READ, select.KQ_EV_ADD)], 0)
            try:  # ESRCH: the front is already past exit (a zombie) -- the await_reapable peek's rule (D18)
                kq.control([select.kevent(self.p.pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD, select.KQ_NOTE_EXIT)], 0)
                watch = lambda: kq.control(None, 2)
            except ProcessLookupError:
                watch = lambda: None
        else:
            pfd = os.pidfd_open(self.p.pid)
            p = select.poll(); p.register(pfd, select.POLLIN); p.register(self.link.note_r, select.POLLIN)
            watch = lambda: p.poll()
        while True:
            with self.link.lock:
                if self.link.state == LIVE:
                    return "live"
            if self.link.state == REFUSED and self.link.error:
                raise AcceptorFailed(self.link.error)
            if self.p.poll() is not None:  # the front exited: reap it (done by poll), then refuse any late shim
                self.front_status = self.p.returncode
                if self.link.refuse_if_pending() == LIVE:
                    return "live"
                raise NotStarted(self.front_status, self.link.connected, self.link.error or "the front exited before the program started")
            watch()
            try:
                os.read(self.link.note_r, 64)
            except BlockingIOError:
                pass

    def drop(self, kill_on_drop=True):
        """Sync Drop. A front cosca could not signal while Pending is not waited for (it may be
        a human authenticating): the start is refused, the front left unreaped, and a warn names it."""
        if not kill_on_drop:
            return self.link.release(detached=True)
        k = self.kill()
        if k == "refused+front-EPERM":
            log("warn", "elevated front %d could not be signalled before its program started; left unreaped, its program will not start" % self.p.pid)
            return self.link.release(detached=False)
        try:
            self.wait()
        except (ShimLost, NotStarted) as e:
            if isinstance(e, ShimLost):
                log("warn", str(e))
        return self.link.release(detached=False)
