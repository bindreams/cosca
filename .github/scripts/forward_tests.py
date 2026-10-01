#!/usr/bin/env python3
"""Tests for forward.py. Linux and macOS.

Synchronisation. Every wait is on something the test does, or on an event that the code under test
produces whichever way it is wrong: the log line of a relay, the end of a process (a pidfd on Linux,
a kqueue `NOTE_EXIT` on macOS), a FIFO the test holds open for reading and writing. Parties that
must finish are released in advance or in cleanup, so nothing waits for a peer that a regression
could remove. The only timed waits are `BOUND`, a failure bound on an event that takes microseconds
when the code is right: a regression that leaves the forwarder stuck is reported after `BOUND`
seconds instead of hanging the run. It never orders anything.
"""

import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forward  # noqa: E402

FORWARD = str(HERE / "forward.py")
BOUND = 30


def python(code, *args):
    return [sys.executable, "-c", code, *args]


def exit_event(pid):
    """An object `select` can wait on that becomes readable when process `pid` exits, as a zombie or
    reaped, whoever its parent is. Register it before the process can exit."""
    if hasattr(os, "pidfd_open"):
        return _PidFd(os.pidfd_open(pid))
    queue = select.kqueue()
    queue.control(
        [select.kevent(pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 0, 0
    )
    return queue


class _PidFd:
    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd

    def close(self):
        os.close(self.fd)


def run_bounded(test, argv, **kwargs):
    """`subprocess.run` that fails the test, rather than hanging, if the process does not end."""
    try:
        return subprocess.run(argv, timeout=BOUND, **kwargs)
    except subprocess.TimeoutExpired:
        test.fail(f"{argv[1] if len(argv) > 1 else argv[0]} did not end within {BOUND}s")


class Workdir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = Path(self._tmp.name)
        self.fds = []
        self.events = []
        self.procs = []
        self.addCleanup(self._close)

    def _close(self):
        for process in self.procs:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
        for event in self.events:
            event.close()
        for fd in self.fds:
            os.close(fd)

    def fifo(self, name):
        """A FIFO this test holds open for reading and writing: nothing blocks on a missing peer."""
        path = self.work / name
        os.mkfifo(path)
        fd = os.open(path, os.O_RDWR)
        self.fds.append(fd)
        return path, fd

    def exit_event(self, pid):
        event = exit_event(pid)
        self.events.append(event)
        return event

    def start(self, argv, **kwargs):
        process = subprocess.Popen([sys.executable, FORWARD, *argv], stderr=subprocess.PIPE, **kwargs)
        self.procs.append(process)
        return process

    def ended(self, process):
        if not hasattr(process, "_ended"):
            process._ended = self.exit_event(process.pid)
        return process._ended

    def read_until(self, process, fd):
        """Wait for `fd` to be readable or for the forwarder to end, and say which."""
        ready, _, _ = select.select([fd, self.ended(process)], [], [], BOUND)
        if not ready:
            self.fail(f"nothing happened for {BOUND}s: the forwarder is stuck")
        return "fd" if fd in ready else "ended"

    def log_line(self, process, text, unwanted=()):
        """Read the forwarder's stderr up to a line holding `text`; fail if it ends or sticks first,
        or if a line holding one of `unwanted` comes first."""
        seen = b""
        stderr = process.stderr.fileno()
        while True:
            ready, _, _ = select.select([stderr, self.ended(process)], [], [], BOUND)
            if not ready:
                self.fail(f"no {text!r} line for {BOUND}s, the forwarder is stuck: {seen.decode()}")
            if stderr in ready:
                chunk = os.read(stderr, 4096)
                seen += chunk
                for bad in unwanted:
                    if bad.encode() in seen:
                        self.fail(f"the forwarder logged {bad!r}: {seen.decode()}")
                if text.encode() in seen:
                    return seen.decode()
                if not chunk:
                    self.fail(f"the forwarder's stderr closed without {text!r}: {seen.decode()}")
            else:
                self.fail(f"the forwarder ended without {text!r}: {seen.decode()}")

    def wait_relayed(self, process):
        return self.log_line(process, "relayed SIGTERM", unwanted=("nothing left to signal",))

    def exits(self, process):
        """The status of the forwarder once it has ended; a failure if it is stuck."""
        try:
            return process.wait(timeout=BOUND)
        except subprocess.TimeoutExpired:
            seen = b""
            while select.select([process.stderr], [], [], 0)[0]:
                chunk = os.read(process.stderr.fileno(), 4096)
                if not chunk:
                    break
                seen += chunk
            self.fail(f"the forwarder did not exit within {BOUND}s; its log: {seen.decode()!r}")


class Status(unittest.TestCase):
    def run_forward(self, code):
        return run_bounded(self, [sys.executable, FORWARD, *python(code)], stderr=subprocess.DEVNULL).returncode

    def test_the_exit_status_of_the_command_is_returned(self):
        for status in (0, 1, 3, 127, 200, 255):
            self.assertEqual(self.run_forward(f"import sys; sys.exit({status})"), status, f"status {status}")

    def test_a_command_killed_by_a_signal_gives_128_plus_the_signal(self):
        for number in (signal.SIGKILL, signal.SIGSEGV, signal.SIGTERM):
            code = f"import os; os.kill(os.getpid(), {int(number)})"
            self.assertEqual(self.run_forward(code), 128 + int(number), number.name)

    def test_a_command_that_cannot_run_gives_127(self):
        self.assertEqual(run_bounded(self, [sys.executable, FORWARD, "/nonexistent/command"], stderr=subprocess.DEVNULL).returncode, 127)


class Environment(Workdir):
    def test_the_command_leads_a_session_of_its_own_with_clean_signals(self):
        code = (
            "import json, os, signal; "
            "print(json.dumps({'sid': os.getsid(0) == os.getpid(), 'pgid': os.getpgrp() == os.getpid(), "
            "'mask': sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, [])), "
            "'hup': signal.getsignal(signal.SIGHUP) == signal.SIG_DFL, "
            "'term': signal.getsignal(signal.SIGTERM) == signal.SIG_DFL}))"
        )

        def hostile():  # a runner that ignores some signals and blocks others, as a background shell does
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})

        process = self.start(python(code), stdout=subprocess.PIPE, preexec_fn=hostile)
        try:
            out, _ = process.communicate(timeout=BOUND)
        except subprocess.TimeoutExpired:
            self.fail(f"the forwarder did not end within {BOUND}s")
        self.assertEqual(json.loads(out), {"sid": True, "pgid": True, "mask": [], "hup": True, "term": True})


class ChildSetup(unittest.TestCase):
    def test_a_signal_pending_in_the_child_meets_the_default_action_not_the_inherited_handler(self):
        # The child of a spawn is in the group of the forwarder until its `setsid`; a signal sent to
        # that group then is pending in it, blocked. Here: INT pending, then the child setup runs.
        code = (
            "import os, signal, sys\n"
            f"sys.path.insert(0, {str(HERE)!r})\n"
            "import forward\n"
            "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})\n"
            "os.kill(os.getpid(), signal.SIGINT)\n"
            "forward._child_setup()\n"
            "print('survived')\n"
        )
        result = subprocess.run([sys.executable, "-c", code], capture_output=True)
        self.assertEqual(result.returncode, -signal.SIGINT, result.stderr.decode())


    def test_the_dispositions_are_reset_before_the_mask_is_opened(self):
        calls = []
        real_signal, real_mask = signal.signal, signal.pthread_sigmask
        signal.signal = lambda number, handler: calls.append(("disposition", number, handler))
        signal.pthread_sigmask = lambda how, mask: calls.append(("mask", how, set(mask)))
        try:
            forward._child_setup()
        finally:
            signal.signal, signal.pthread_sigmask = real_signal, real_mask
        kinds = [call[0] for call in calls]
        self.assertEqual(kinds, ["disposition"] * len(forward.BLOCKED) + ["mask"], "dispositions first, then the mask")
        self.assertTrue(all(call[2] == signal.SIG_DFL for call in calls[:-1]))


class Relay(Workdir):
    """A command and a grandchild that note which signals reach them, and wait for a release."""

    def start_tree(self):
        self.up_path, self.up = self.fifo("up")
        self.done_path, self.done = self.fifo("done")
        self.release_path, self.release = self.fifo("release")
        self.addCleanup(os.write, self.release, b"xx")  # whatever a failed test left waiting ends
        script = self.work / "tree.py"
        script.write_text(
            "import os, signal, subprocess, sys\n"
            "work = sys.argv[1]\n"
            "def finish(name, how):\n"
            "    open(f'{work}/{name}', 'w').write(how)\n"
            "    if name == 'grandchild':\n"
            "        os.write(os.open(f'{work}/done', os.O_RDWR), b'x')\n"
            "def hold(name):\n"
            "    def handler(*_):\n"
            "        finish(name, 'term')\n"
            "        os._exit(9)\n"
            "    signal.signal(signal.SIGTERM, handler)\n"
            "    os.write(os.open(f'{work}/up', os.O_RDWR), b'x')\n"
            "    os.read(os.open(f'{work}/release', os.O_RDWR), 1)\n"
            "    finish(name, 'released')\n"
            "if len(sys.argv) > 2:\n"
            "    hold('grandchild')\n"
            "    sys.exit(0)\n"
            "child = subprocess.Popen([sys.executable, __file__, work, 'grandchild'])\n"
            "hold('command')\n"
            "child.wait()\n"
        )
        process = self.start([sys.executable, str(script), str(self.work)])
        for _ in range(2):  # both announce themselves; if the tree cannot start, the forwarder ends
            if self.read_until(process, self.up) == "ended":
                self.fail("the forwarder ended before the command was up")
            os.read(self.up, 1)
        return process

    def test_a_signal_reaches_the_whole_tree_of_the_command(self):
        process = self.start_tree()
        process.send_signal(signal.SIGTERM)
        self.wait_relayed(process)
        os.write(self.release, b"xx")  # frees whoever the signal missed
        self.assertEqual(self.exits(process), 9)
        # The grandchild reports when it is done, whether the signal reached it or the release did.
        ready, _, _ = select.select([self.done], [], [], BOUND)
        self.assertTrue(ready, "the grandchild never finished")
        self.assertEqual((self.work / "command").read_text(), "term")
        self.assertEqual((self.work / "grandchild").read_text(), "term")

    def relayed_as_term(self, number):
        process = self.start_tree()
        process.send_signal(number)
        self.wait_relayed(process)
        os.write(self.release, b"xx")
        self.assertEqual(self.exits(process), 9)
        self.assertEqual((self.work / "command").read_text(), "term")

    def test_int_is_relayed_as_term(self):
        self.relayed_as_term(signal.SIGINT)

    def test_hup_is_relayed_as_term(self):
        self.relayed_as_term(signal.SIGHUP)

    def test_the_other_stage_of_a_pipeline_is_not_signalled(self):
        reader = self.work / "reader.py"
        reader.write_text(
            "import os, signal, sys\n"
            "def note(*_):\n"
            "    open(sys.argv[1] + '/reader', 'w').write('term')\n"
            "    os._exit(0)\n"
            "signal.signal(signal.SIGTERM, note)\n"
            "os.write(os.open(sys.argv[1] + '/reader-up', os.O_RDWR), b'x')\n"
            "sys.stdin.read()\n"
        )
        _, reader_up = self.fifo("reader-up")
        up_path, up = self.fifo("up")
        release_path, release = self.fifo("release")
        self.addCleanup(os.write, release, b"x")
        command = python(
            "import os, signal, sys\n"
            "work = sys.argv[1]\n"
            "signal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
            "os.write(os.open(work + '/up', os.O_RDWR), b'x')\n"
            "os.read(os.open(work + '/release', os.O_RDWR), 1)\n",
            str(self.work),
        )
        first = subprocess.Popen([sys.executable, FORWARD, *command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=lambda: os.setpgid(0, 0))
        self.procs.append(first)
        second = subprocess.Popen([sys.executable, str(reader), str(self.work)], stdin=first.stdout, preexec_fn=lambda: os.setpgid(0, first.pid))
        self.procs.append(second)
        first.stdout.close()
        os.read(reader_up, 1)
        self.assertEqual(self.read_until(first, up), "fd")
        self.assertEqual(os.getpgid(second.pid), os.getpgid(first.pid), "the stages share a group")
        first.send_signal(signal.SIGTERM)
        self.wait_relayed(first)
        os.write(release, b"x")
        self.assertEqual(self.exits(first), 9)
        self.assertEqual(self.exits(second), 0)
        self.assertFalse((self.work / "reader").exists(), "the other stage was signalled")


class Waiting(Workdir):
    """A command that announces its pid, waits for a release, and exits with 7 (or on TERM, with 9)."""

    def start_command(self):
        self.up_path, self.up = self.fifo("up")
        self.release_path, self.release = self.fifo("release")
        self.addCleanup(os.write, self.release, b"x")
        process = self.start(
            python(
                "import os, signal, sys\n"
                "work = sys.argv[1]\n"
                "signal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
                "os.write(os.open(work + '/up', os.O_RDWR), str(os.getpid()).encode() + b'\\n')\n"
                "os.read(os.open(work + '/release', os.O_RDWR), 1)\n"
                "sys.exit(7)\n",
                str(self.work),
            )
        )
        self.assertEqual(self.read_until(process, self.up), "fd")
        return process, int(os.read(self.up, 32))

    def stop(self, process):
        process.send_signal(signal.SIGSTOP)
        os.waitpid(process.pid, os.WUNTRACED)  # stopped for certain: it cannot act until continued

    def test_a_signal_that_arrives_as_the_command_exits_leaves_its_status_alone(self):
        process, command = self.start_command()
        exited = self.exit_event(command)  # registered before it can exit
        self.stop(process)
        os.write(self.release, b"x")
        ready, _, _ = select.select([exited], [], [], BOUND)  # exited, and unreaped: the forwarder is stopped
        self.assertTrue(ready, "the command did not exit")
        process.send_signal(signal.SIGTERM)
        process.send_signal(signal.SIGCONT)
        # With the signal and the exit both pending, the signal is relayed first, to the group of the
        # unreaped command (which macOS refuses, a group of zombies, and Linux accepts), and the
        # status is still the command's own.
        self.assertEqual(self.exits(process), 7)

    def back_to_back(self, first, second):
        # On macOS `sigwait` loses the first of two different signals that arrive within a wake-up
        # of each other and returns an uninitialised number, which crashed the forwarder.
        process, command = self.start_command()
        process.send_signal(first)
        process.send_signal(second)
        # The command may exit on the first relay before the second signal is relayed to what is
        # left of its group: that is the "nothing left to signal" outcome, and not an error.
        log = self.log_line(process, "relayed SIGTERM", unwanted=("Traceback",))
        os.write(self.release, b"x")
        self.assertEqual(self.exits(process), 9, log)

    def test_term_then_hup_back_to_back(self):
        self.back_to_back(signal.SIGTERM, signal.SIGHUP)

    def test_hup_then_term_back_to_back(self):
        self.back_to_back(signal.SIGHUP, signal.SIGTERM)

    def test_term_then_int_back_to_back(self):
        self.back_to_back(signal.SIGTERM, signal.SIGINT)

    def test_an_exit_and_a_signal_back_to_back_leave_the_status_alone(self):
        process, command = self.start_command()
        exited = self.exit_event(command)
        os.write(self.release, b"x")  # the command exits with 7 ...
        ready, _, _ = select.select([exited], [], [], BOUND)
        self.assertTrue(ready, "the command did not exit")
        process.send_signal(signal.SIGTERM)  # ... and the forwarder is signalled as it learns of it
        self.assertEqual(self.exits(process), 7)

    def test_an_exit_while_the_forwarder_is_stopped_is_noticed_when_it_resumes(self):
        process, command = self.start_command()
        exited = self.exit_event(command)
        self.stop(process)
        os.write(self.release, b"x")
        ready, _, _ = select.select([exited], [], [], BOUND)
        self.assertTrue(ready, "the command did not exit")
        process.send_signal(signal.SIGCONT)  # no signal but the exit: SIGCHLD has waited, blocked, until now
        self.assertEqual(self.exits(process), 7)

    def test_a_command_that_is_stopped_does_not_hold_up_a_signal(self):
        process, command = self.start_command()
        os.kill(command, signal.SIGSTOP)
        # The forwarder takes the SIGCHLD of the stop and logs that the command still runs; only then
        # does the signal arrive, so a forwarder that waits for the command to exit would be stuck.
        self.log_line(process, "is still running")
        process.send_signal(signal.SIGTERM)
        self.wait_relayed(process)
        os.kill(command, signal.SIGCONT)  # the stopped command now meets the pending TERM
        self.assertEqual(self.exits(process), 9)


class SpawnWindow(Workdir):
    def test_a_signal_during_the_spawn_is_relayed_not_acted_on(self):
        # The signals are blocked before the command exists: one that arrives while it is being
        # spawned waits, and is relayed once the group exists, instead of taking its default action
        # on the forwarder and leaving the command running unsignalled.
        release_path, release = self.fifo("release")
        self.addCleanup(os.write, release, b"x")
        command = (
            "import os, signal\n"
            "signal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
            f"os.read(os.open({str(release_path)!r}, os.O_RDWR), 1)\n"
        )
        script = (
            "import os, signal, subprocess, sys\n"
            f"sys.path.insert(0, {str(HERE)!r})\n"
            "import forward\n"
            "def spawn(*args, **kwargs):\n"
            "    os.kill(os.getpid(), signal.SIGTERM)  # lands before the child exists\n"
            "    return subprocess.Popen(*args, **kwargs)\n"
            f"status, signalled = forward.run([sys.executable, '-c', {command!r}], popen=spawn, log=lambda _: None)\n"
            "print(status, signalled)\n"
        )
        result = run_bounded(self, [sys.executable, "-c", script], capture_output=True, preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, set()))
        self.assertEqual(result.returncode, 0, f"the forwarder was killed by the signal: {result.returncode}")
        status, signalled = result.stdout.decode().split()
        self.assertEqual(signalled, "True")
        self.assertIn(status, ("9", "143"))  # the command's handler, or its default action if the signal came first


class Ordering(unittest.TestCase):
    """`forward.run` against a scripted OS: a signal, then the SIGCHLD that comes with the exit. Whatever `forward.run` does after the reap is a signal sent to a pid
    that may already belong to someone else."""

    class Child:
        pid = 4242
        returncode = None

    def setUp(self):
        # `forward.run` blocks signals and installs a SIGCHLD handler in this very process; put them
        # back, or every process this test run starts afterwards inherits the blocked signals.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        handler = signal.getsignal(signal.SIGCHLD)
        self.addCleanup(signal.pthread_sigmask, signal.SIG_SETMASK, mask)
        self.addCleanup(signal.signal, signal.SIGCHLD, handler)

    def run_script(self, events, waits, kill):
        waits = iter(waits)
        return forward.run(
            ["command"],
            popen=lambda argv, **kwargs: self.Child(),
            make_wait=lambda: (lambda: [events.pop(0)]),
            kill=kill,
            waitpid=lambda pid, flags: next(waits),
            log=lambda _: None,
        )

    def test_a_signal_is_relayed_once_to_the_group_and_never_after_the_reap(self):
        events = [signal.SIGTERM, signal.SIGCHLD]
        kills = []
        reaped = []

        def kill(pid, number):
            kills.append((pid, number, bool(reaped)))

        waits = [(0, 0), (0, 0), (4242, 7 << 8)]

        def waitpid_marking():
            for result in waits:
                if result[0]:
                    reaped.append(True)
                yield result

        result = self.run_script(events, waitpid_marking(), kill)
        self.assertEqual(result, (7, True))
        self.assertEqual(kills, [(-4242, signal.SIGTERM, False)], "once, to the group, before the reap")

    def test_a_relay_that_fails_never_changes_the_status(self):
        # macOS refuses to signal a group of zombies with EPERM; a group that is gone gives ESRCH.
        for error in (PermissionError(1, "Operation not permitted"), ProcessLookupError(3, "No such process")):
            with self.subTest(error=type(error).__name__):

                def kill(pid, number):
                    raise error

                result = self.run_script([signal.SIGTERM], [(0, 0), (4242, 7 << 8)], kill)
                self.assertEqual(result, (7, True))


if __name__ == "__main__":
    unittest.main()
