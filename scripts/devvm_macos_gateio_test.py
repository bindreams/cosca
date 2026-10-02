"""SignalGate.run and SignalGate.flock against real child processes and real flocks. No timers.

A broken wait would block on a live child or a held lock, so these run after the hang-free gate tests."""

from __future__ import annotations

import fcntl
import os
import signal
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from scripts import devvm_macos as m
from scripts.devvm_macos_testlib import forbid_blocking_flock

SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def kill_self(sig: int = signal.SIGTERM) -> None:
    os.kill(os.getpid(), sig)


def on_blocked(sig: int = signal.SIGTERM):
    return mock.patch.object(m.SignalGate, "on_blocked", staticmethod(lambda: kill_self(sig)))


class GateCase(unittest.TestCase):
    def setUp(self) -> None:
        for sig in SIGNALS:
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))
        # Whatever a test holds that a wait would block on (a lock, a child's stdin) is released the moment
        # the code under test is about to block in select. A correct run was already cancelled and never
        # gets there; a broken wait is released, returns normally and fails the test at once.
        self.releases: list = []
        real_select = m.select.select

        def select(*a):
            while self.releases:
                self.releases.pop()()
            return real_select(*a)

        patch = mock.patch.object(m.select, "select", select)
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def close_quietly(fd) -> None:
        try:
            os.close(fd) if isinstance(fd, int) else fd.close()
        except OSError:
            pass


class RunTests(GateCase):
    def test_run_returns_output_and_the_exit_code(self) -> None:
        with m.SignalGate() as gate:
            done = gate.run(["sh", "-c", "echo out; echo err >&2; exit 3"], capture_output=True, text=True)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (3, "out\n", "err\n"))

    def run_cancelled(self, argv, *, stdin=None, release=None):
        """Run `argv` through the gate with a signal already recorded. Returns (pid, kills)."""
        started, kills = [], []
        real_popen, real_kill = subprocess.Popen, os.kill

        def popen(*a, **kw):
            p = real_popen(*a, **kw)
            started.append(p)
            return p

        def kill(pid, sig):
            if pid != os.getpid():
                kills.append((pid, sig, self.is_ours_unreaped(pid)))
            return real_kill(pid, sig)

        with m.SignalGate() as gate, mock.patch.object(m.subprocess, "Popen", popen), mock.patch.object(
            m.os, "kill", kill
        ):
            kill_self()  # recorded before the run starts: it cancels at the first wait
            if release:
                release()
            with self.assertRaises(m.Cancelled):
                gate.run(argv, stdin=stdin, capture_output=True)
        return started[0].pid, kills

    @staticmethod
    def is_ours_unreaped(pid: int) -> bool:
        """True while `pid` is still our child (alive or a zombie): a signal to it can reach nobody else."""
        try:
            os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return False
        return True

    def test_a_signal_kills_and_reaps_the_child_before_cancelling(self) -> None:
        # `cat` blocks reading r. Right after the signal the test closes the write end too, so a `run`
        # that ignores the signal sees `cat` finish and returns normally: it fails at once.
        r, w = os.pipe()
        with os.fdopen(r, "rb") as stdin:
            pid, kills = self.run_cancelled(["cat"], stdin=stdin, release=lambda: os.close(w))
        self.assertEqual([(p, s) for p, s, _ours in kills], [(pid, signal.SIGKILL)], "the child was not killed")
        self.assertFalse(self.is_ours_unreaped(pid), "the child was not reaped")

    def test_run_waits_before_it_joins_the_output_readers(self) -> None:
        # `cat` keeps its output open while it blocks on stdin. Any join releases it, so a `run` that joins the
        # readers before it waits returns normally instead of blocking; the order of events then fails the test.
        r, w = os.pipe()
        order = []
        real_join = threading.Thread.join
        open_w = [w]

        def close_w() -> None:  # once: a closed fd number may already belong to something else
            while open_w:
                os.close(open_w.pop())

        def join(thread, *a, **kw):
            order.append("join")
            close_w()
            return real_join(thread, *a, **kw)

        self.releases.append(close_w)
        with os.fdopen(r, "rb") as stdin, m.SignalGate() as gate:
            kill_self()  # recorded first: the first wait cancels
            with self.assertRaises(m.Cancelled):
                gate.check()  # ...and proves it was recorded (else `cat` would block the run below)
            with mock.patch.object(threading.Thread, "join", join), mock.patch.object(
                m.SignalGate, "on_blocked", staticmethod(lambda: order.append("wait"))
            ):
                with self.assertRaises(m.Cancelled):
                    gate.run(["cat"], stdin=stdin, capture_output=True)
        close_w()
        self.assertEqual(order[0], "wait", "the output readers were joined before the wait")

    def test_the_child_is_never_signalled_after_it_was_reaped(self) -> None:
        # Forced ordering: the child has exited, and the exit has been observed, before the cancel is decided.
        # Whoever reaped it, no signal may go to its pid afterwards: the pid could belong to someone else by then.
        for _ in range(25):
            holder = []

            def exited_first() -> None:
                os.waitid(os.P_PID, holder[0].pid, os.WEXITED | os.WNOWAIT)  # the exit is observed
                kill_self()

            started = []
            real_popen = subprocess.Popen

            def popen(*a, started=started, holder=holder, **kw):
                p = real_popen(*a, **kw)
                started.append(p)
                holder.append(p)
                return p

            kills = []
            real_kill = os.kill

            def kill(pid, sig, kills=kills, real_kill=real_kill):
                if pid == os.getpid():
                    return real_kill(pid, sig)
                ours = self.is_ours_unreaped(pid)
                kills.append((pid, sig, ours))
                if ours:  # never forward a signal to a pid that is no longer ours
                    return real_kill(pid, sig)

            with m.SignalGate() as gate, mock.patch.object(m.subprocess, "Popen", popen), mock.patch.object(
                m.os, "kill", kill
            ), mock.patch.object(m.SignalGate, "on_blocked", staticmethod(exited_first)):
                with self.assertRaises(m.Cancelled):
                    gate.run(["true"], capture_output=True)
            self.assertEqual([k for k in kills if not k[2]], [], "a signal was sent to a pid that had been reaped")
            self.assertFalse(self.is_ours_unreaped(started[0].pid), "the child was left unreaped")


class LockTests(GateCase):
    def open_locked(self, tmp_name: str):
        f = open(tmp_name, "w")
        self.addCleanup(f.close)
        fcntl.flock(f, fcntl.LOCK_EX)
        self.releases.append(lambda: self.close_quietly(f))
        return f

    def lock_is_free(self, path) -> bool:
        with open(path, "w") as probe:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            return True

    def setUp(self) -> None:
        super().setUp()
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "lock")
        forbid_blocking_flock(self)

    def record(self, gate: m.SignalGate, sig: int = signal.SIGTERM) -> None:
        """Deliver a signal and check it was recorded: the test then cancels at the first wait.
        If recording were broken the cancelling tests below would block on a held lock, so fail here."""
        kill_self(sig)
        with self.assertRaises(m.Cancelled):
            gate.check()

    def test_gate_flock_takes_the_lock_and_the_caller_releases_it_by_closing(self) -> None:
        with m.SignalGate() as gate:
            f = open(self.path, "w")
            gate.flock(f)
            self.assertFalse(self.lock_is_free(self.path))
            f.close()
        self.assertTrue(self.lock_is_free(self.path))

    def test_flock_hands_the_file_to_the_gate_on_cancel_and_does_not_close_it_itself(self) -> None:
        holder = self.open_locked(self.path)
        opened = []
        real_open = open
        waiter_may_close = []

        class Guarded:
            """A lock file whose close() fails the test if the caller closes it while the waiter owns it."""

            def __init__(self, f):
                self._f = f

            def fileno(self):
                return self._f.fileno()

            @property
            def closed(self):
                return self._f.closed

            def close(self):
                if threading.current_thread() is threading.main_thread() and not waiter_may_close:
                    raise AssertionError("closed by the caller while the abandoned waiter still blocks on it")
                self._f.close()

        def spy_open(path, *a, **kw):
            f = real_open(path, *a, **kw)
            if str(path) == self.path:
                f = Guarded(f)
                opened.append(f)
            return f

        from pathlib import Path

        with m.SignalGate() as gate, mock.patch("builtins.open", spy_open):
            self.record(gate)
            with self.assertRaises(m.Cancelled):
                with m._flock(Path(self.path), "the test lock", gate):
                    self.fail("the lock was not contended")
            (mine,) = opened[-1:]
            self.assertFalse(mine.closed)
            holder.close()  # let the waiter finish
            waiter_may_close.append(True)
            gate.abandoned[0].join()
            self.assertTrue(mine.closed)

    def test_a_cancelled_flock_wait_does_not_join_its_waiter(self) -> None:
        # The holder is released from inside any join of the waiter, so a wait that joins it returns
        # normally instead of blocking, and fails the Cancelled assertion at once.
        holder = self.open_locked(self.path)
        joined = []
        real_join = threading.Thread.join

        def join(thread, *a, **kw):
            joined.append(thread)
            holder.close()
            return real_join(thread, *a, **kw)

        with m.SignalGate() as gate:
            self.record(gate)
            f = open(self.path, "w")
            with mock.patch.object(threading.Thread, "join", join):
                with self.assertRaises(m.Cancelled):
                    gate.flock(f)
            self.assertEqual(joined, [], "the cancelled wait joined its waiter")
            holder.close()
            gate.abandoned[0].join()

    def test_a_failing_flock_raises_its_error_and_closes_the_file(self) -> None:
        def flock(_f, _op):
            raise OSError("flock failed")

        with m.SignalGate() as gate, mock.patch.object(m.fcntl, "flock", flock):
            f = open(self.path, "w")
            with self.assertRaises(OSError):
                gate.flock(f)
            self.assertTrue(f.closed)

    def test_a_cancelled_wait_leaves_a_waiter_that_drops_the_lock_it_later_acquires(self) -> None:
        holder = self.open_locked(self.path)
        with m.SignalGate() as gate:
            self.record(gate)  # recorded first: the wait is cancelled before it can block
            f = open(self.path, "w")
            with self.assertRaises(m.Cancelled):
                gate.flock(f)
            self.assertEqual(len(gate.abandoned), 1)
            holder.close()  # the lock becomes available: the abandoned waiter takes it, then closes it
            gate.abandoned[0].join()
        self.assertTrue(self.lock_is_free(self.path), "a late-acquired lock leaked")

    def test_a_lock_acquired_just_as_the_wait_is_cancelled_is_released(self) -> None:
        acquired = threading.Event()
        real_flock = fcntl.flock

        def flock(f, op):
            result = real_flock(f, op)
            acquired.set()
            return result

        def after_acquired() -> None:
            acquired.wait()  # the waiter holds the lock; now the signal arrives
            kill_self()

        with m.SignalGate() as gate, mock.patch.object(m.fcntl, "flock", flock), mock.patch.object(
            m.SignalGate, "on_blocked", staticmethod(after_acquired)
        ):
            f = open(self.path, "w")
            with self.assertRaises(m.Cancelled):
                gate.flock(f)
            for waiter in gate.abandoned:
                waiter.join()
        self.assertTrue(self.lock_is_free(self.path), "the lock acquired during the cancel leaked")


if __name__ == "__main__":
    unittest.main()
