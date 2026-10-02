"""SignalGate and its waits against real signals, real child processes and real flocks. No timers."""

from __future__ import annotations

import fcntl
import os
import signal
import subprocess
import threading
import unittest
from unittest import mock

from scripts import devvm_macos as m

SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def kill_self(sig: int = signal.SIGTERM) -> None:
    os.kill(os.getpid(), sig)


def on_blocked(sig: int = signal.SIGTERM):
    return mock.patch.object(m.SignalGate, "on_blocked", staticmethod(lambda: kill_self(sig)))


class GateCase(unittest.TestCase):
    def setUp(self) -> None:
        for sig in SIGNALS:
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))


class RecordingTests(GateCase):
    def test_a_signal_is_recorded_and_not_raised(self) -> None:
        with m.SignalGate() as gate:
            kill_self(signal.SIGTERM)
            kill_self(signal.SIGHUP)
            with self.assertRaises(m.Cancelled) as ctx:
                gate.check()
            self.assertEqual(ctx.exception.signo, signal.SIGTERM)
            self.assertEqual(gate.pending, [signal.SIGTERM, signal.SIGHUP])

    def test_a_signal_inside_library_code_does_not_unwind_it(self) -> None:
        """The handler raises nothing, so subprocess internals run to completion whenever the signal lands."""
        real_poll, real_exec = subprocess.Popen._internal_poll, subprocess.Popen._execute_child

        def poll(self, *a, **kw):
            kill_self(signal.SIGINT)
            return real_poll(self, *a, **kw)

        def execute_child(self, *a, **kw):
            kill_self(signal.SIGTERM)
            return real_exec(self, *a, **kw)

        with m.SignalGate() as gate, mock.patch.object(subprocess.Popen, "_internal_poll", poll), mock.patch.object(
            subprocess.Popen, "_execute_child", execute_child
        ):
            with subprocess.Popen(["true"]) as proc:
                proc.wait()
                self.assertEqual(proc.poll(), 0)
        self.assertEqual(set(gate.pending), {signal.SIGINT, signal.SIGTERM})
        self.assertFalse(proc._waitpid_lock.locked())

    def test_signals_recorded_before_exit_are_all_in_pending_after_it(self) -> None:
        with m.SignalGate() as gate:
            kill_self(signal.SIGHUP)  # never checked or waited on
        self.assertEqual(gate.pending, [signal.SIGHUP])

    def test_the_handlers_and_wakeup_fd_are_restored(self) -> None:
        before = {s: signal.getsignal(s) for s in SIGNALS}
        wakeup = signal.set_wakeup_fd(-1)
        signal.set_wakeup_fd(wakeup)
        with m.SignalGate():
            current = signal.set_wakeup_fd(-1)
            signal.set_wakeup_fd(current)
            self.assertNotEqual(current, wakeup, "the gate did not install its wakeup fd")
        self.assertEqual({s: signal.getsignal(s) for s in SIGNALS}, before)
        self.assertEqual(signal.set_wakeup_fd(wakeup), wakeup)


class WaitTests(GateCase):
    def test_a_wait_multiplexes_on_the_wakeup_pipe_and_returns_ready_fds(self) -> None:
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        os.write(w, b"x")
        real = m.select.select
        seen = []

        def spy(rlist, *a):
            seen.append(list(rlist))
            return real(rlist, *a)

        with m.SignalGate() as gate, mock.patch.object(m.select, "select", spy):
            self.assertEqual(gate.wait_for([r]), [r])
        self.assertIn(gate._r, seen[0], "the wait does not watch the signal pipe")

    def test_a_signal_ends_a_wait_with_nothing_else_ready(self) -> None:
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        with m.SignalGate() as gate, on_blocked():
            with self.assertRaises(m.Cancelled):
                gate.wait_for([r])  # nothing is ever written to r

    def test_a_wait_that_starts_with_a_signal_already_recorded_does_not_block(self) -> None:
        with m.SignalGate() as gate:
            kill_self()
            with self.assertRaises(m.Cancelled):
                gate.check()  # drains the pipe: the signal is now only in `pending`
            with mock.patch.object(m.select, "select", side_effect=AssertionError("blocked in select")):
                with self.assertRaises(m.Cancelled):
                    gate.wait_for([])

    def test_sleep_with_no_signal_returns_when_the_timeout_passes(self) -> None:
        with m.SignalGate() as gate:
            gate.sleep(0)

    def test_sleep_is_ended_by_a_signal(self) -> None:
        with m.SignalGate() as gate, on_blocked(signal.SIGHUP):
            with self.assertRaises(m.Cancelled) as ctx:
                gate.sleep(3600)
        self.assertEqual(ctx.exception.signo, signal.SIGHUP)


class RunTests(GateCase):
    def test_run_returns_output_and_the_exit_code(self) -> None:
        with m.SignalGate() as gate:
            done = gate.run(["sh", "-c", "echo out; echo err >&2; exit 3"], capture_output=True, text=True)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (3, "out\n", "err\n"))

    def test_a_signal_kills_and_reaps_the_child_before_cancelling(self) -> None:
        r, w = os.pipe()  # `cat` blocks reading r until the write end closes
        self.addCleanup(os.close, w)
        started = []
        real_popen = subprocess.Popen

        def popen(*a, **kw):
            p = real_popen(*a, **kw)
            started.append(p)
            return p

        with os.fdopen(r, "rb") as stdin, m.SignalGate() as gate, mock.patch.object(m.subprocess, "Popen", popen):
            with on_blocked(), self.assertRaises(m.Cancelled):
                gate.run(["cat"], stdin=stdin, capture_output=True)
        (proc,) = started
        self.assertIsNotNone(proc.returncode, "the child was not reaped")
        with self.assertRaises(ProcessLookupError):
            os.kill(proc.pid, 0)  # a zombie would still answer
        self.assertFalse(proc._waitpid_lock.locked())


class LockTests(GateCase):
    def open_locked(self, tmp_name: str):
        f = open(tmp_name, "w")
        self.addCleanup(f.close)
        fcntl.flock(f, fcntl.LOCK_EX)
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

    def test_gate_flock_takes_the_lock_and_the_caller_releases_it_by_closing(self) -> None:
        with m.SignalGate() as gate:
            f = open(self.path, "w")
            gate.flock(f)
            self.assertFalse(self.lock_is_free(self.path))
            f.close()
        self.assertTrue(self.lock_is_free(self.path))

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
        with m.SignalGate() as gate, on_blocked():
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
