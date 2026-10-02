"""SignalGate recording and waiting against real signals. No timers, no children, no locks: hang-free."""

from __future__ import annotations

import os
import signal
import subprocess
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


def select_that_needs_a_timeout():
    """A select spy that fails at once if a wait with a timeout calls select without one."""
    real = m.select.select

    def select(rlist, wlist, xlist, timeout=None):
        if timeout is None:
            raise AssertionError("select without the timeout: the wait could block forever")
        return real(rlist, wlist, xlist, timeout)

    return mock.patch.object(m.select, "select", select)


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

    def test_a_signal_wins_over_a_ready_fd(self) -> None:
        # `r` is readable too, so a wait that ignores the signal pipe returns normally and fails this at once
        # (instead of blocking forever, as it would with nothing ever written).
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        os.write(w, b"x")
        with m.SignalGate() as gate, on_blocked():
            with self.assertRaises(m.Cancelled):
                gate.wait_for([r])

    def test_a_signal_landing_as_the_wait_begins_cancels_it(self) -> None:
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        os.write(w, b"x")
        real_select = m.select.select

        def select(rlist, *a):
            kill_self()  # after the pre-check, as the select starts
            return real_select(rlist, *a)

        with m.SignalGate() as gate, mock.patch.object(m.select, "select", select):
            with self.assertRaises(m.Cancelled):
                gate.wait_for([r])

    def test_the_blocked_hook_runs_before_each_blocking_select(self) -> None:
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        os.write(w, b"x")
        order = []
        real_select = m.select.select

        def select(rlist, *a):
            order.append("select")
            return real_select(rlist, *a)

        with m.SignalGate() as gate, mock.patch.object(m.select, "select", select), mock.patch.object(
            m.SignalGate, "on_blocked", staticmethod(lambda: order.append("hook"))
        ):
            gate.wait_for([r])
        self.assertEqual(order, ["hook", "select"])

    def test_a_wait_without_a_signal_returns_the_ready_fd(self) -> None:
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        os.write(w, b"x")
        with m.SignalGate() as gate:
            self.assertEqual(gate.wait_for([r]), [r])

    def test_a_wait_that_starts_with_a_signal_already_recorded_does_not_block(self) -> None:
        with m.SignalGate() as gate:
            kill_self()
            with self.assertRaises(m.Cancelled):
                gate.check()  # drains the pipe: the signal is now only in `pending`
            with mock.patch.object(m.select, "select", side_effect=AssertionError("blocked in select")):
                with self.assertRaises(m.Cancelled):
                    gate.wait_for([])

    def test_sleep_with_no_signal_returns_when_the_timeout_passes(self) -> None:
        with m.SignalGate() as gate, select_that_needs_a_timeout():
            gate.sleep(0)

    def test_a_wait_with_a_timeout_returns_nothing_when_nothing_is_ready(self) -> None:
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        with m.SignalGate() as gate, select_that_needs_a_timeout():
            self.assertEqual(gate.wait_for([r], timeout=0), [])

    def test_sleep_is_ended_by_a_signal(self) -> None:
        with m.SignalGate() as gate, on_blocked(signal.SIGHUP):
            with self.assertRaises(m.Cancelled) as ctx:
                gate.sleep(0)
        self.assertEqual(ctx.exception.signo, signal.SIGHUP)


if __name__ == "__main__":
    unittest.main()
