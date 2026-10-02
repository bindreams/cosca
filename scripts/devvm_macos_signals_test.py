"""Signal handling of `up` and `destroy` against the fake tart: a signal at any step, in any wait, once or
twice, ends with no VM, no `tart run` child, no claim and a message.

Real signals are delivered with os.kill to this process. Nothing here waits on a timer: signals are sent
from inside the code under test, at a named step or just before a wait blocks (SignalGate.on_blocked).
"""

from __future__ import annotations

import fcntl
import os
import signal
import unittest
from unittest import mock

from scripts import devvm_macos as m
from scripts.devvm_macos_testlib import Env, captured

SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def kill_self(*sigs: int) -> None:
    for sig in sigs:
        os.kill(os.getpid(), sig)


class SignalCase(unittest.TestCase):
    def setUp(self) -> None:
        for sig in SIGNALS:
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

    def fire_when_blocking(self, *sigs: int, nth: int = 1):
        """Patch SignalGate so the nth blocking wait sends `sigs` just before it blocks."""
        seen = []

        def on_blocked() -> None:
            seen.append(True)
            if len(seen) == nth:
                kill_self(*sigs)

        return mock.patch.object(m.SignalGate, "on_blocked", staticmethod(on_blocked))

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


class TartCallTests(SignalCase):
    def test_a_signal_during_each_tart_call_of_a_normal_up_cancels_cleanly(self) -> None:
        for event, nth in (("vms", 2), ("clone", 1), ("start", 1), ("exec:true", 1), ("exec:stage", 1), ("exec:stage", 2)):
            for sig in SIGNALS:
                with self.subTest(at=event, nth=nth, sig=signal.Signals(sig).name):
                    env = Env(self)
                    self.fire_at_event(env, event, sig, nth=nth)
                    code, err = self.up_exit(env)
                    self.assert_cancelled_clean(env, code, err, sig)

    def test_a_signal_while_the_guest_is_still_booting_ends_the_pause_between_tries(self) -> None:
        for sig in SIGNALS:
            with self.subTest(sig=signal.Signals(sig).name):
                env = Env(self)
                env.tart.exec_rc = lambda args: 1 if args == ["true"] else 0  # the agent is not up yet
                self.fire_at_event(env, "exec:true", sig)
                code, err = self.up_exit(env)
                self.assert_cancelled_clean(env, code, err, sig)


class LockWaitTests(SignalCase):
    """A real contended lock, held through a second file description in this process."""

    def hold(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        f = open(path, "w")
        fcntl.flock(f, fcntl.LOCK_EX)
        return f

    def release_and_settle(self, env: Env, holder) -> None:
        """Let the abandoned waiter acquire and drop the lock, then check nothing still holds it."""
        holder.close()
        for waiter in env.backend.last_gate.abandoned:
            waiter.join()  # ends once the lock is free, which the release above made so

    def test_a_signal_while_waiting_for_the_cap_lock_cancels_cleanly(self) -> None:
        for sig in SIGNALS:
            with self.subTest(sig=signal.Signals(sig).name):
                env = Env(self)
                holder = self.hold(env.tart.home / "devvm-cap.lock")
                with self.fire_when_blocking(sig):
                    code, err = self.up_exit(env)
                self.assertIn("waiting for the host-wide", err)
                self.assertEqual(len(env.backend.last_gate.abandoned), 1)
                self.release_and_settle(env, holder)
                self.assert_cancelled_clean(env, code, err, sig)  # includes: the cap lock is free

    def test_a_signal_while_waiting_for_the_worktree_lock_cancels_cleanly(self) -> None:
        for sig in SIGNALS:
            with self.subTest(sig=signal.Signals(sig).name):
                env = Env(self)
                holder = self.hold(env.sdir / "lock")
                with self.fire_when_blocking(sig):
                    code, err = self.up_exit(env)
                self.assertIn("waiting for another devvm command", err)
                self.release_and_settle(env, holder)
                self.assert_cancelled_clean(env, code, err, sig)

    def test_teardown_waits_for_the_cap_lock_and_is_not_cut_short_by_a_signal(self) -> None:
        # Staging fails while another `up` holds the cap lock again. The cleanup waits for it
        # (uninterruptibly); a signal lands during the wait; the holder then lets go.
        for sig in SIGNALS:
            with self.subTest(sig=signal.Signals(sig).name):
                env = Env(self)
                holder = []
                env.tart.exec_rc = lambda args: 1 if args[:2] == ["sh", "-c"] else 0
                real_exec = env.tart.exec

                def exec_(name, args, holder=holder, env=env, real_exec=real_exec, **kw):
                    if args[:2] == ["sh", "-c"]:  # staging starts: another `up` takes the cap lock
                        holder.append(self.hold(env.tart.home / "devvm-cap.lock"))
                    return real_exec(name, args, **kw)

                env.tart.exec = exec_
                real_say = m._say

                def say(message, **kw):
                    real_say(message, **kw)
                    if "waiting for the host-wide" in message:  # the cleanup is now waiting
                        kill_self(sig)
                        holder[0].close()  # ...and the other `up` finishes

                with mock.patch.object(m, "_say", say):
                    code, err = self.up_exit(env)
                env.assert_nothing_leaked(self)
                self.assertEqual(code, 128 + sig, err)
                self.assertIn("removed VM", err)


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


class LateSignalTests(SignalCase):
    """A signal recorded after the last check is never dropped: the exit code says so."""

    def kill_before_gate_exit(self, sig: int):
        real_exit = m.SignalGate.__exit__

        def exit_(gate, *a):
            kill_self(sig)
            return real_exit(gate, *a)

        return mock.patch.object(m.SignalGate, "__exit__", exit_)

    def test_up_that_succeeded_exits_with_the_late_signal(self) -> None:
        env = Env(self)
        with self.kill_before_gate_exit(signal.SIGTERM):
            code, err = self.up_exit(env)
        self.assertEqual(code, 128 + signal.SIGTERM, err)
        self.assertEqual(len(env.tart.local_names()), 1, "the VM that was brought up stays")

    def test_up_that_failed_exits_with_the_late_signal(self) -> None:
        env = Env(self)
        env.tart.exec_rc = lambda args: 1 if args[:2] == ["bash", "-c"] else 0
        with self.kill_before_gate_exit(signal.SIGTERM):
            code, err = self.up_exit(env)
        self.assertEqual(code, 128 + signal.SIGTERM, err)
        self.assertIn("provisioning failed", err)

    def test_destroy_exits_with_the_late_signal(self) -> None:
        env = Env(self)
        with captured():
            env.up()
        with self.kill_before_gate_exit(signal.SIGTERM), captured():
            with self.assertRaises(SystemExit) as ctx:
                env.destroy()
        self.assertEqual(ctx.exception.code, 128 + signal.SIGTERM)
        env.assert_nothing_leaked(self, procs=False)

    def test_a_refused_destroy_also_exits_with_the_late_signal(self) -> None:
        env = Env(self)
        with captured():
            env.up()
        (env.sdir / "identity.json").unlink()
        with self.kill_before_gate_exit(signal.SIGHUP), captured():
            with self.assertRaises(SystemExit) as ctx:
                env.destroy()
        self.assertEqual(ctx.exception.code, 128 + signal.SIGHUP)


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

    def test_handlers_and_the_wakeup_fd_are_restored_after_success_and_after_cancellation(self) -> None:
        before = {s: signal.getsignal(s) for s in SIGNALS}
        wakeup = signal.set_wakeup_fd(-1)
        signal.set_wakeup_fd(wakeup)
        for cancel in (False, True):
            env = Env(self)
            if cancel:
                self.fire_at_checkpoint(env, "booted", signal.SIGTERM)
            self.up_exit(env)
            self.assertEqual({s: signal.getsignal(s) for s in SIGNALS}, before)
            self.assertEqual(signal.set_wakeup_fd(wakeup), wakeup)


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
        other = open(self.env.sdir / "lock", "w")
        self.addCleanup(other.close)
        fcntl.flock(other, fcntl.LOCK_EX)
        with self.fire_when_blocking(signal.SIGTERM):
            code, _err = self.destroy_exit()
        self.assertEqual(code, 128 + signal.SIGTERM)
        self.assertEqual(len(self.env.tart.local_names()), 1)

    def fire_when_blocking(self, *sigs):
        return mock.patch.object(m.SignalGate, "on_blocked", staticmethod(lambda: kill_self(*sigs)))


if __name__ == "__main__":
    unittest.main()
