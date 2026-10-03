#!/usr/bin/env python3
"""Tests for forward.py. Linux and macOS.

Synchronisation. Every wait is on something the test does, or on an event that the code under test
produces whichever way it is wrong: the log line of a relay, the end of a process (a pidfd on Linux,
a kqueue `NOTE_EXIT` on macOS), a FIFO the test holds open for reading and writing. Parties that
must finish are released in advance or in cleanup, so nothing waits for a peer that a regression
could remove. The only timed waits are `BOUND`, a failure bound on an event that takes microseconds
when the code is right: a regression that leaves the forwarder stuck, or flooding its log, is reported after `BOUND`
seconds in all, instead of hanging the run. It never orders anything.
"""

import json
import os
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forward  # noqa: E402

FORWARD = str(HERE / "forward.py")
BOUND = 30
TAIL = 65536  # bytes of a forwarder's log that a failure message keeps

# Prologue for test commands that catch TERM in Python and then block. A TERM landing between
# CPython's last signal check and the read(2) in `os.read` is consumed without running the handler,
# and the read blocks forever. The wakeup fd is written by the C-level handler, so `select` on it
# returns. Install before `signal.signal`; block with `WAIT.format(path)`, never `os.read`.
WAKEUP = (
    "import os, select, signal\n"
    "_wake, _wake_w = os.pipe()\n"
    "os.set_blocking(_wake_w, False)\n"
    "signal.set_wakeup_fd(_wake_w)\n"
)
WAIT = "select.select([os.open({}, os.O_RDWR), _wake], [], [])\n"


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


class LogScan:
    """Looks for `text`, and for any of `unwanted`, in a log that arrives in chunks. Only the last
    `TAIL` bytes are kept, so a log that floods costs time, not memory; the new chunk is searched
    together with those bytes before they are trimmed, so a match split across the boundary of two
    chunks is found."""

    def __init__(self, text, unwanted=()):
        self.text = text.encode()
        self.unwanted = [bad.encode() for bad in unwanted]
        self.seen = b""
        assert TAIL >= max([len(self.text)] + [len(bad) for bad in self.unwanted])

    def feed(self, chunk):
        """None, or `"found"`, or the unwanted text that came up."""
        window = self.seen + chunk
        self.seen = window[-TAIL:]
        for bad in self.unwanted:
            if bad in window:
                return bad.decode()
        if self.text in window:
            return "found"
        return None

    def tail(self):
        return self.seen.decode(errors="replace")


class Workdir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = Path(self._tmp.name)
        self.fds = []
        self.events = []
        self.procs = []
        self._tracked = []
        self.addCleanup(self._close)

    def _close(self):
        # Whatever a test leaves running is killed, so that nothing keeps its stdout open and a run
        # captured by `$(...)` ends: the whole group of every command a forwarder started, while
        # the exit event, registered when it started, says it has not exited (its pid is then ours).
        for process, command, exited in self._tracked:
            if not select.select([exited], [], [], 0)[0]:
                try:
                    os.killpg(command, signal.SIGKILL)
                except ProcessLookupError:
                    pass
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
        self.track(process)
        return process

    def track(self, process):
        """Read the first log line of a forwarder, which names the command it started, and register
        an exit event for that command, so that cleanup can kill what the test leaves running. If
        the forwarder ends or says nothing within `BOUND`, there is nothing to track."""
        line = b""
        stderr = process.stderr.fileno()
        deadline = time.monotonic() + BOUND
        while not line.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            ready = select.select([stderr, self.ended(process)], [], [], remaining)[0] if remaining > 0 else []
            if stderr not in ready:
                return
            chunk = os.read(stderr, 1)
            if not chunk:
                return
            line += chunk
        match = re.search(rb"started the command (\d+)", line)
        if match:
            command = int(match.group(1))
            self._tracked.append((process, command, self.exit_event(command)))

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
        """Read the forwarder's stderr up to a line holding `text`. A failure if the forwarder ends,
        or logs a line holding one of `unwanted`, first, or if `BOUND` seconds pass in all, however
        much it logs meanwhile."""
        scan = LogScan(text, unwanted)
        stderr = process.stderr.fileno()
        deadline = time.monotonic() + BOUND
        while True:
            remaining = deadline - time.monotonic()
            ready = select.select([stderr, self.ended(process)], [], [], remaining)[0] if remaining > 0 else []
            if not ready:
                self.fail(f"no {text!r} line within {BOUND}s, the forwarder is stuck: {scan.tail()}")
            if stderr in ready:
                chunk = os.read(stderr, 65536)
                verdict = scan.feed(chunk)
                if verdict == "found":
                    return scan.tail()
                if verdict:
                    self.fail(f"the forwarder logged {verdict!r}: {scan.tail()}")
                if not chunk:
                    self.fail(f"the forwarder's stderr closed without {text!r}: {scan.tail()}")
            else:
                self.fail(f"the forwarder ended without {text!r}: {scan.tail()}")

    def wait_relayed(self, process):
        return self.log_line(process, "relayed SIGTERM", unwanted=("nothing left to signal",))

    def exits(self, process):
        """The status of the forwarder once it has ended; a failure if it is stuck."""
        try:
            return process.wait(timeout=BOUND)
        except subprocess.TimeoutExpired:
            seen = b""
            deadline = time.monotonic() + BOUND
            while time.monotonic() < deadline and select.select([process.stderr], [], [], 0)[0]:
                chunk = os.read(process.stderr.fileno(), 65536)
                if not chunk:
                    break
                seen = (seen + chunk)[-TAIL:]
            self.fail(f"the forwarder did not exit within {BOUND}s; the end of its log: {seen.decode(errors='replace')!r}")


class LogScanTests(unittest.TestCase):
    """The second chunk is as big as the kept tail, so a scan that trims before it searches loses the
    first half of a match that straddles the two chunks."""

    def test_a_match_split_across_two_chunks_is_found(self):
        scan = LogScan("relayed SIGTERM")
        self.assertIsNone(scan.feed(b"noise relayed SIG"))
        self.assertEqual(scan.feed(b"TERM to the group" + b"x" * TAIL), "found")

    def test_an_unwanted_text_split_across_two_chunks_is_found(self):
        scan = LogScan("relayed", unwanted=("Traceback",))
        self.assertIsNone(scan.feed(b"noise Trace"))
        self.assertEqual(scan.feed(b"back (most recent call last)" + b"y" * TAIL), "Traceback")

    def test_a_flood_without_the_text_keeps_only_the_tail(self):
        scan = LogScan("never")
        for _ in range(8):
            scan.feed(b"z" * TAIL)
        self.assertEqual(len(scan.seen), TAIL)


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

    def test_an_ignored_sigchld_inherited_from_the_caller_does_not_stick_the_forwarder(self):
        # With SIGCHLD ignored, Linux reaps the command itself and sends no SIGCHLD.
        result = run_bounded(
            self,
            [sys.executable, FORWARD, *python("import sys; sys.exit(7)")],
            stderr=subprocess.DEVNULL,
            preexec_fn=lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN),
        )
        self.assertEqual(result.returncode, 7)

    def test_a_command_that_cannot_run_gives_127(self):
        self.assertEqual(run_bounded(self, [sys.executable, FORWARD, "/nonexistent/command"], stderr=subprocess.DEVNULL).returncode, 127)


class Environment(Workdir):
    def test_the_command_leads_a_session_of_its_own_with_clean_signals(self):
        code = (
            "import json, os, signal; "
            "print(json.dumps({'sid': os.getsid(0) == os.getpid(), 'pgid': os.getpgrp() == os.getpid(), "
            "'mask': sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, [])), "
            "'hup': signal.getsignal(signal.SIGHUP) == signal.SIG_DFL, "
            "'chld': signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "
            "'term': signal.getsignal(signal.SIGTERM) == signal.SIG_DFL}))"
        )

        def hostile():  # a runner that ignores some signals and blocks others, as a background shell does
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})

        process = self.start(python(code), stdout=subprocess.PIPE, preexec_fn=hostile)
        try:
            out, _ = process.communicate(timeout=BOUND)
        except subprocess.TimeoutExpired:
            self.fail(f"the forwarder did not end within {BOUND}s")
        self.assertEqual(json.loads(out), {"sid": True, "pgid": True, "mask": [], "hup": True, "chld": True, "term": True})


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
            WAKEUP
            + "import subprocess, sys\n"
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
            "    " + WAIT.format("f'{work}/release'")
            + "    finish(name, 'released')\n"
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
            WAKEUP
            + "import sys\n"
            "def note(*_):\n"
            "    open(sys.argv[1] + '/reader', 'w').write('term')\n"
            "    os._exit(0)\n"
            "signal.signal(signal.SIGTERM, note)\n"
            "os.write(os.open(sys.argv[1] + '/reader-up', os.O_RDWR), b'x')\n"
            "while True:  # until EOF\n"
            "    select.select([0, _wake], [], [])\n"
            "    if not os.read(0, 65536):\n"
            "        break\n"
        )
        _, reader_up = self.fifo("reader-up")
        up_path, up = self.fifo("up")
        release_path, release = self.fifo("release")
        self.addCleanup(os.write, release, b"x")
        command = python(
            WAKEUP
            + "import sys\n"
            "work = sys.argv[1]\n"
            "signal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
            "os.write(os.open(work + '/up', os.O_RDWR), b'x')\n"
            + WAIT.format("work + '/release'"),
            str(self.work),
        )
        first = subprocess.Popen([sys.executable, FORWARD, *command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=lambda: os.setpgid(0, 0))
        self.procs.append(first)
        self.track(first)
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
                WAKEUP
                + "import sys\n"
                "work = sys.argv[1]\n"
                "signal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
                "os.write(os.open(work + '/up', os.O_RDWR), str(os.getpid()).encode() + b'\\n')\n"
                + WAIT.format("work + '/release'")
                + "sys.exit(7)\n",
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
        # With the signal and the exit both pending, Linux relays the signal first, to the group of the
        # unreaped command, and macOS reports the exit first, so the command is reaped and nothing is
        # relayed. Either way the status is the command's own.
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
        process.send_signal(signal.SIGCONT)  # no signal but the exit, held by the OS until the forwarder resumes
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
        # The signals cannot act on the forwarder before the command exists (blocked on Linux, ignored
        # and watched by a kqueue on macOS): one that arrives while it is being spawned waits, and is
        # relayed once the group exists, instead of taking its default action on the forwarder and
        # leaving the command running unsignalled.
        release_path, release = self.fifo("release")
        self.addCleanup(os.write, release, b"x")
        command = (
            WAKEUP
            + "signal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
            + WAIT.format(repr(str(release_path)))
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


FAKE_KQUEUE = r"""
import json, os, signal, sys
sys.path.insert(0, {here!r})
import forward

class Empty(Exception):
    pass

class Event:
    def __init__(self, ident, *args):
        self.ident = ident

class Queue:
    def __init__(self, kq):
        self.kq, self.registered, self.events = kq, False, []
    def deliver(self, number):
        os.kill(os.getpid(), number)  # the process, which has the signal blocked: pending
        if self.registered:
            self.events.append(Event(number))  # and, once registered, reported by the queue
    def control(self, changes, count, timeout=None):
        if changes:
            self.kq.before_register(self)  # after `kqueue()` returned, before the registration
            self.registered = True
            self.kq.after_register(self)
            return []
        taken, self.events = self.events[:count], self.events[count:]
        if not taken and timeout is None:
            raise Empty
        return taken

class Kq:
    KQ_FILTER_SIGNAL, KQ_EV_ADD, KQ_EV_CLEAR = -6, 1, 32
    kevent = Event
    def __init__(self, before_register=None, after_register=None, before_pending=None, after_pending=None):
        none = lambda queue: None
        self.before_register = before_register or none
        self.after_register = after_register or none
        self.before_pending = before_pending or none
        self.after_pending = after_pending or none
        self.queue = None
    def kqueue(self):
        self.queue = Queue(self)
        return self.queue

real_sigpending = signal.sigpending
def sigpending():
    kq.before_pending(kq.queue)
    pending = real_sigpending()
    kq.after_pending(kq.queue)
    return pending
signal.sigpending = sigpending

{scenario}

wait = forward._kqueue_waiter(kq)
first = [int(n) for n in wait()]
try:
    wait()
    second = "reported again"
except Empty:
    second = "nothing more"
print(json.dumps({{"first": first, "second": second, "term": signal.getsignal(signal.SIGTERM) == signal.SIG_IGN}}))
"""


class KqueueWaiter(unittest.TestCase):
    """The macOS waiter against a stand-in kqueue that raises a signal at a chosen moment. The stand-in
    has the properties of the real one that matter here: it reports a signal only once it is
    registered, and then even if the signal is blocked or ignored."""

    def scenario(self, text):
        code = FAKE_KQUEUE.format(here=str(HERE), scenario=text)
        result = run_bounded(self, [sys.executable, "-c", code], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def test_a_signal_between_the_registration_and_the_pending_set_is_reported_once(self):
        got = self.scenario("kq = Kq(after_register=lambda queue: queue.deliver(signal.SIGTERM))")
        self.assertEqual(got["first"], [int(signal.SIGTERM)])
        self.assertEqual(got["second"], "nothing more", "one signal was reported twice")
        self.assertTrue(got["term"])

    def test_a_signal_just_before_the_pending_set_is_read_is_reported_once(self):
        # Pending and queued at once: the two sources must be merged, whatever the order of reading.
        got = self.scenario("kq = Kq(before_pending=lambda queue: queue.deliver(signal.SIGTERM))")
        self.assertEqual(got["first"], [int(signal.SIGTERM)])
        self.assertEqual(got["second"], "nothing more", "one signal was reported twice")

    def test_a_signal_just_after_the_pending_set_is_read_is_reported_once(self):
        # Not in the pending snapshot, but queued: it must not be lost to the signals being ignored.
        got = self.scenario("kq = Kq(after_pending=lambda queue: queue.deliver(signal.SIGTERM))")
        self.assertEqual(got["first"], [int(signal.SIGTERM)])
        self.assertEqual(got["second"], "nothing more")

    def test_a_signal_before_the_registration_is_found_in_the_pending_set(self):
        # Raised after the queue exists and before it is registered, which the queue cannot report:
        # only `sigpending()` knows of it.
        got = self.scenario("kq = Kq(before_register=lambda queue: queue.deliver(signal.SIGTERM))")
        self.assertEqual(got["first"], [int(signal.SIGTERM)])
        self.assertEqual(got["second"], "nothing more")


class Ordering(unittest.TestCase):
    """`forward.run` against a scripted OS: a signal, then the SIGCHLD that comes with the exit. Whatever `forward.run` does after the reap is a signal sent to a pid
    that may already belong to someone else."""

    class Child:
        pid = 4242
        returncode = None

    def setUp(self):
        # `forward.run` changes the signal state of this very process (the SIGCHLD disposition and, with
        # a real wait, the mask); put it back, or every process this test run starts afterwards
        # inherits it.
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
