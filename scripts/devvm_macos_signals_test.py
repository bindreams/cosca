"""Signal handling of `up` and `destroy`: a signal at any step, in any blocking wait, once or twice,
ends with no VM, no `tart run` child, no claim and a message.

Real signals are delivered with os.kill to this process.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import signal
import subprocess
import sys
import threading
import unittest
from unittest import mock

from scripts import devvm_macos as m
from scripts.devvm_macos_testlib import Env, captured

SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
OUR_SIGNALS = tuple(SIGNALS)


def kill_self(*sigs: int) -> None:
    for sig in sigs:
        os.kill(os.getpid(), sig)


class SignalCase(unittest.TestCase):
    def setUp(self) -> None:
        sleeper = mock.patch.object(m.time, "sleep", lambda _s: None)
        sleeper.start()
        self.addCleanup(sleeper.stop)
        for sig in OUR_SIGNALS:
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))

    def fire_at_checkpoint(self, env: Env, label: str, *sigs: int) -> None:
        real = env.backend._checkpoint

        def checkpoint(name: str) -> None:
            if name == label:
                kill_self(*sigs)
            real(name)

        env.backend._checkpoint = checkpoint

    def fire_at_event(self, env: Env, event: str, *sigs: int, nth: int = 1) -> None:
        seen = []

        def hook() -> None:
            seen.append(True)
            if len(seen) == nth:
                kill_self(*sigs)

        env.tart.hooks[event] = hook

    def up_exit(self, env: Env, **kw):
        """Run `up`; return (exit code or None, stderr)."""
        with captured() as err:
            try:
                env.up(**kw)
            except SystemExit as e:
                return e.code, err.getvalue()
        return None, err.getvalue()

    def assert_cancelled_clean(self, env: Env, code, err: str, sig: int) -> None:
        self.assertEqual(code, 128 + sig, err)
        self.assertIn("interrupted by", err)
        env.assert_nothing_leaked(self)


def blocking_until_signalled(sig: int):
    """A hook that blocks like a long `tart exec` would, while a signal is sent from another thread.

    Returns (hook, state); state["woken_by_bound"] is True if the wait ended only because of the
    harness's own failure bound, i.e. the signal did not interrupt it.
    """
    state = {"woken_by_bound": False}

    def hook() -> None:
        r, w = os.pipe()

        def bound() -> None:
            state["woken_by_bound"] = True
            os.write(w, b"x")

        timer = threading.Timer(5, bound)
        timer.start()
        threading.Thread(target=lambda: os.kill(os.getpid(), sig)).start()
        try:
            os.read(r, 1)
        finally:
            timer.cancel()
            os.close(r)
            os.close(w)

    return hook, state


class CheckpointTests(SignalCase):
    def test_every_checkpoint_is_reached_by_a_successful_up(self) -> None:
        env = Env(self)
        seen, real = [], env.backend._checkpoint
        env.backend._checkpoint = lambda label: (seen.append(label), real(label))[1]
        with captured():
            env.up()
        self.assertEqual(seen, list(m.CHECKPOINTS))

    def test_a_signal_at_each_checkpoint_cancels_cleanly(self) -> None:
        for label in m.CHECKPOINTS:
            for sig in SIGNALS:
                with self.subTest(at=label, sig=signal.Signals(sig).name):
                    env = Env(self)
                    self.fire_at_checkpoint(env, label, sig)
                    code, err = self.up_exit(env)
                    self.assert_cancelled_clean(env, code, err, sig)

    def test_two_signals_in_a_row_at_each_checkpoint_cancel_cleanly(self) -> None:
        for label in m.CHECKPOINTS:
            for pair in ((signal.SIGINT, signal.SIGINT), (signal.SIGTERM, signal.SIGINT)):
                with self.subTest(at=label, sigs=[signal.Signals(s).name for s in pair]):
                    env = Env(self)
                    self.fire_at_checkpoint(env, label, *pair)
                    code, err = self.up_exit(env)
                    self.assert_cancelled_clean(env, code, err, pair[0])


class BlockingWaitTests(SignalCase):
    def test_a_signal_during_each_tart_call_of_a_normal_up_cancels_cleanly(self) -> None:
        for event, nth in (("vms", 2), ("clone", 1), ("start", 1), ("exec:true", 1), ("exec:stage", 1)):
            for sig in SIGNALS:
                with self.subTest(at=event, sig=signal.Signals(sig).name):
                    env = Env(self)
                    self.fire_at_event(env, event, sig, nth=nth)
                    code, err = self.up_exit(env)
                    self.assert_cancelled_clean(env, code, err, sig)

    def test_a_signal_interrupts_a_long_blocking_exec_instead_of_waiting_for_it(self) -> None:
        for event, nth in (("exec:true", 1), ("exec:stage", 1), ("exec:stage", 2)):
            with self.subTest(at=event, nth=nth):
                env = Env(self)
                hook, state = blocking_until_signalled(signal.SIGTERM)
                seen = []

                def nth_only(hook=hook, nth=nth, seen=seen):
                    seen.append(True)
                    if len(seen) == nth:
                        hook()

                env.tart.hooks[event] = nth_only
                code, err = self.up_exit(env)
                self.assertFalse(state["woken_by_bound"], "the wait was not interrupted by the signal")
                self.assert_cancelled_clean(env, code, err, signal.SIGTERM)

    def test_a_cancelled_staging_leaves_no_git_archive_child_behind(self) -> None:
        env = Env(self)
        started = []
        real_popen = subprocess.Popen

        def popen(*a, **kw):
            p = real_popen(*a, **kw)
            if a and a[0][:1] == ["git"]:
                started.append(p)
            return p

        hook, _state = blocking_until_signalled(signal.SIGTERM)
        env.tart.hooks["exec:stage"] = hook
        with mock.patch.object(m.subprocess, "Popen", popen):
            self.up_exit(env)
        self.assertTrue(started)
        self.assertEqual([p.returncode is None for p in started], [False] * len(started), "git archive was not reaped")

    def hold_lock_then_signal(self, env: Env, lock_name: str, sig: int):
        """Make the backend's first blocking acquisition of `lock_name` wait, and deliver sig during the wait."""
        real, state = fcntl.flock, {"nb": 0}

        def flock(f, op):
            from_backend = sys._getframe(1).f_code.co_filename.endswith("devvm_macos.py")
            if from_backend and f.name.endswith(lock_name):
                if op & fcntl.LOCK_NB and not state["nb"]:
                    state["nb"] = 1
                    raise BlockingIOError
                if not op & fcntl.LOCK_NB and state["nb"] == 1:
                    state["nb"] = 2
                    os.kill(os.getpid(), sig)  # lands while "blocked"
            return real(f, op)

        return mock.patch.object(m.fcntl, "flock", flock)

    def test_a_signal_while_waiting_for_the_cap_lock_cancels_cleanly(self) -> None:
        for sig in SIGNALS:
            with self.subTest(sig=signal.Signals(sig).name):
                env = Env(self)
                with self.hold_lock_then_signal(env, "devvm-cap.lock", sig):
                    code, err = self.up_exit(env)
                self.assert_cancelled_clean(env, code, err, sig)

    def test_a_signal_while_waiting_for_the_worktree_lock_cancels_cleanly(self) -> None:
        for sig in SIGNALS:
            with self.subTest(sig=signal.Signals(sig).name):
                env = Env(self)
                with self.hold_lock_then_signal(env, "/lock", sig):
                    code, err = self.up_exit(env)
                self.assert_cancelled_clean(env, code, err, sig)


class TeardownIsUninterruptibleTests(SignalCase):
    def failing_env(self, path: str, step: str, *sigs: int, nth: int = 1) -> Env:
        env = Env(self)
        armed = []
        fails = ["true"] if path == "boot" else ["sh", "-c"]

        def exec_rc(args):
            if args[: len(fails)] == fails:
                armed.append(True)  # teardown starts after this
                return 1
            return 0

        seen = []

        def hook() -> None:
            if armed:
                seen.append(True)
                if len(seen) == nth:
                    kill_self(*sigs)

        env.tart.exec_rc = exec_rc
        env.tart.hooks[step] = hook
        return env

    def up_failing(self, env: Env):
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            return self.up_exit(env)

    def test_a_signal_during_each_teardown_step_does_not_stop_the_cleanup(self) -> None:
        for path in ("stage", "boot"):
            for sig in SIGNALS:
                for step in ("vms", "stop", "terminate", "delete"):
                    with self.subTest(failure=path, sig=signal.Signals(sig).name, step=step):
                        env = self.failing_env(path, step, sig)
                        code, err = self.up_failing(env)
                        env.assert_nothing_leaked(self)
                        self.assertEqual(code, 128 + sig, err)
                        self.assertIn("removed VM", err)

    def test_two_signals_during_teardown_do_not_stop_the_cleanup(self) -> None:
        for path in ("stage", "boot"):
            with self.subTest(failure=path):
                env = self.failing_env(path, "stop", signal.SIGINT, signal.SIGINT)
                code, err = self.up_failing(env)
                env.assert_nothing_leaked(self)
                self.assertIn("removed VM", err)

    def test_the_original_error_is_still_reported_when_a_signal_arrives_during_cleanup(self) -> None:
        env = self.failing_env("stage", "stop", signal.SIGTERM)
        _code, err = self.up_failing(env)
        self.assertIn("git archive", err)

    def test_teardown_waits_for_the_cap_lock_even_if_a_signal_lands_meanwhile(self) -> None:
        for sig in SIGNALS:
            with self.subTest(sig=signal.Signals(sig).name):
                env = Env(self)
                env.tart.exec_rc = lambda args: 1 if args[:2] == ["sh", "-c"] else 0
                real, acquisitions = fcntl.flock, []

                def flock(f, op, sig=sig):
                    from_backend = sys._getframe(1).f_code.co_filename.endswith("devvm_macos.py")
                    if from_backend and f.name.endswith("devvm-cap.lock"):
                        acquisitions.append(op)
                        if len(acquisitions) == 2 and op & fcntl.LOCK_NB:  # teardown finds it held
                            raise BlockingIOError
                        if len(acquisitions) == 3:  # ...and a signal lands while it waits
                            os.kill(os.getpid(), sig)
                    return real(f, op)

                with mock.patch.object(m.fcntl, "flock", flock):
                    code, err = self.up_exit(env)
                env.assert_nothing_leaked(self)
                self.assertEqual(code, 128 + sig, err)


class DispositionTests(SignalCase):
    def test_an_inherited_sig_ign_is_respected(self) -> None:
        for sig in SIGNALS:
            with self.subTest(sig=signal.Signals(sig).name):
                signal.signal(sig, signal.SIG_IGN)
                env = Env(self)
                self.fire_at_checkpoint(env, "booted", sig)
                code, err = self.up_exit(env)
                self.assertIsNone(code, err)
                self.assertEqual(len(env.tart.local_names()), 1)
                self.assertEqual(signal.getsignal(sig), signal.SIG_IGN)

    def test_handlers_are_restored_after_success_and_after_cancellation(self) -> None:
        before = {s: signal.getsignal(s) for s in OUR_SIGNALS}
        env = Env(self)
        with captured():
            env.up()
        self.assertEqual({s: signal.getsignal(s) for s in OUR_SIGNALS}, before)
        env = Env(self)
        self.fire_at_checkpoint(env, "booted", signal.SIGTERM)
        self.up_exit(env)
        self.assertEqual({s: signal.getsignal(s) for s in OUR_SIGNALS}, before)


class GateTests(SignalCase):
    def test_a_signal_outside_an_interruptible_region_is_only_recorded(self) -> None:
        with m.SignalGate() as gate:
            kill_self(signal.SIGTERM)
            self.assertEqual(gate.pending, [signal.SIGTERM])
            with self.assertRaises(m.Cancelled) as ctx:
                gate.check()
            self.assertEqual(ctx.exception.signo, signal.SIGTERM)

    def test_a_signal_inside_an_interruptible_region_raises_once(self) -> None:
        with m.SignalGate() as gate:
            with self.assertRaises(m.Cancelled):
                with gate.interruptible():
                    kill_self(signal.SIGINT)
                    self.fail("the region was not interrupted")
            kill_self(signal.SIGINT)  # outside again: recorded, not raised
            self.assertEqual(gate.pending, [signal.SIGINT, signal.SIGINT])

    def test_a_second_signal_while_unwinding_the_region_is_only_recorded(self) -> None:
        with m.SignalGate() as gate:
            with gate.interruptible():
                try:
                    kill_self(signal.SIGINT)
                except m.Cancelled:
                    kill_self(signal.SIGTERM)  # still in the region's body: must not raise again
            self.assertEqual(gate.pending, [signal.SIGINT, signal.SIGTERM])

    def test_entering_a_region_with_a_signal_already_pending_raises_before_blocking(self) -> None:
        with m.SignalGate() as gate:
            kill_self(signal.SIGHUP)
            with self.assertRaises(m.Cancelled):
                with gate.interruptible():
                    self.fail("blocked despite a pending signal")


class DestroySignalTests(SignalCase):
    def setUp(self) -> None:
        super().setUp()
        self.env = Env(self)
        with captured():
            self.env.up()

    def destroy_exit(self):
        with captured() as err:
            try:
                self.env.destroy()
            except SystemExit as e:
                return e.code, err.getvalue()
        return None, err.getvalue()

    def test_a_signal_during_destroy_does_not_leave_it_half_done(self) -> None:
        for step in ("stop", "delete", "vms"):
            with self.subTest(step=step):
                self.setUp()
                self.fire_at_event(self.env, step, signal.SIGINT, signal.SIGTERM, nth=2 if step == "vms" else 1)
                code, err = self.destroy_exit()
                self.assertEqual(code, 128 + signal.SIGINT, err)
                self.env.assert_nothing_leaked(self, procs=False)

    def test_a_signal_while_waiting_for_the_worktree_lock_cancels_without_touching_the_vm(self) -> None:
        real, state = fcntl.flock, {"nb": 0}

        def flock(f, op):
            from_backend = sys._getframe(1).f_code.co_filename.endswith("devvm_macos.py")
            if from_backend and f.name.endswith("/lock"):
                if op & fcntl.LOCK_NB and not state["nb"]:
                    state["nb"] = 1
                    raise BlockingIOError
                if not op & fcntl.LOCK_NB and state["nb"] == 1:
                    state["nb"] = 2
                    os.kill(os.getpid(), signal.SIGTERM)
            return real(f, op)

        with mock.patch.object(m.fcntl, "flock", flock):
            code, _err = self.destroy_exit()
        self.assertEqual(code, 128 + signal.SIGTERM)
        self.assertEqual(len(self.env.tart.local_names()), 1)


if __name__ == "__main__":
    unittest.main()
