#!/usr/bin/env python3
"""Pid-reuse test for forward.py. Linux, as root: it re-runs itself in a fresh PID namespace and sets
the next pid through /proc/sys/kernel/ns_last_pid, so reuse is forced, not hoped for.

Run it as: sudo python3 forward_reuse_tests.py

While the forwarder holds an unreaped command, nothing else can get that pid, so a signal relayed to
the group of the command cannot reach a stranger. Once the command is reaped the pid is free, and
the control shows that the setup really can hand it to a stranger.
"""

import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FORWARD = str(HERE / "forward.py")

if os.environ.get("FORWARD_REUSE_TESTS_INNER") != "1":
    if os.geteuid() != 0:
        sys.exit("forward_reuse_tests.py needs root: sudo python3 forward_reuse_tests.py")
    os.execvpe(
        "unshare",
        ["unshare", "--pid", "--fork", "--mount-proc", sys.executable, __file__, *sys.argv[1:]],
        {**os.environ, "FORWARD_REUSE_TESTS_INNER": "1"},
    )

BOUND = 5  # seconds: a failure bound on the end of a process, which takes microseconds when the code is right

ANNOUNCE = (
    "import os, sys\n"
    "work = sys.argv[1]\n"
    "os.write(os.open(work + '/' + sys.argv[2] + '-up', os.O_RDWR), str(os.getpid()).encode() + b'\\n')\n"
    "os.read(os.open(work + '/' + sys.argv[2] + '-release', os.O_RDWR), 1)\n"
    "sys.exit(7)\n"
)


class Reuse(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = Path(self._tmp.name)
        self.fds = {}
        self.procs = []
        self.addCleanup(self._close)

    def _close(self):
        for name in [n for n in self.fds if n.endswith("-release")]:
            os.write(self.fds[name], b"x")  # whoever is still waiting ends
        for process in self.procs:
            if process.poll() is None:
                process.kill()
            process.wait()
        for fd in self.fds.values():
            os.close(fd)

    def fifo(self, name):
        os.mkfifo(self.work / name)
        self.fds[name] = os.open(self.work / name, os.O_RDWR)

    def announced_pid(self, name, process):
        ready, _, _ = select.select([self.fds[f"{name}-up"], pidfd(process)], [], [], BOUND)
        self.assertIn(self.fds[f"{name}-up"], ready, f"{name} ended before it was up")
        return int(os.read(self.fds[f"{name}-up"], 32))

    def spawn(self, name, *, forwarded):
        self.fifo(f"{name}-up")
        self.fifo(f"{name}-release")
        argv = [sys.executable, "-c", ANNOUNCE, str(self.work), name]
        if forwarded:
            argv = [sys.executable, FORWARD, *argv]
        process = subprocess.Popen(argv, start_new_session=not forwarded, stderr=subprocess.DEVNULL)
        self.procs.append(process)
        return process

    def exits(self, process):
        try:
            return process.wait(timeout=BOUND)
        except subprocess.TimeoutExpired:
            self.fail(f"the forwarder did not exit within {BOUND}s")

    def take_pid(self, number, name):
        """Start a process in a session of its own whose pid is `number` if that pid is free."""
        with open("/proc/sys/kernel/ns_last_pid", "w") as last:
            last.write(str(number - 1))
        process = self.spawn(name, forwarded=False)
        return process, self.announced_pid(name, process)

    def test_the_pid_of_an_unreaped_command_cannot_be_taken_and_the_signal_misses_the_stranger(self):
        forwarder = self.spawn("command", forwarded=True)
        command = self.announced_pid("command", forwarder)
        forwarder.send_signal(signal.SIGSTOP)
        os.waitid(os.P_PID, forwarder.pid, os.WSTOPPED)
        command_fd = os.pidfd_open(command)
        self.addCleanup(os.close, command_fd)
        os.write(self.fds["command-release"], b"x")
        ready, _, _ = select.select([command_fd], [], [], BOUND)  # exited, and unreaped while the forwarder is stopped
        self.assertTrue(ready, "the command did not exit")

        stranger, stranger_pid = self.take_pid(command, "stranger")
        self.assertNotEqual(stranger_pid, command, "a stranger took the pid of an unreaped command")

        forwarder.send_signal(signal.SIGTERM)  # relayed to the group of the zombie, not to the stranger
        forwarder.send_signal(signal.SIGCONT)
        self.assertEqual(self.exits(forwarder), 7)
        self.assertIsNone(stranger.poll(), "the relayed signal reached the stranger")

    def test_control_after_the_reap_the_pid_is_free_to_be_taken(self):
        forwarder = self.spawn("command", forwarded=True)
        command = self.announced_pid("command", forwarder)
        os.write(self.fds["command-release"], b"x")
        self.assertEqual(self.exits(forwarder), 7)
        _, stranger_pid = self.take_pid(command, "stranger")
        self.assertEqual(stranger_pid, command)


def pidfd(process):
    if not hasattr(process, "_pidfd"):
        process._pidfd = os.pidfd_open(process.pid)
    return process._pidfd


if __name__ == "__main__":
    unittest.main()
