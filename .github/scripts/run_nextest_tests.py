#!/usr/bin/env python3
"""Tests for run-nextest.py, with stand-in commands that write (or do not write) the JUnit file of the
profile they were given. Linux and macOS. The synchronisation rules of forward_tests.py apply."""

import os
import select
import signal
import subprocess
import sys
import unittest
from pathlib import Path

from forward_tests import BOUND, Workdir, run_bounded

HERE = Path(__file__).resolve().parent
RUN_NEXTEST = str(HERE / "run-nextest.py")

WRITES = (
    "import os\n"
    "p = 'target/nextest/' + os.environ['NEXTEST_PROFILE']\n"
    "os.makedirs(p, exist_ok=True)\n"
    "open(p + '/junit.xml', 'w').write(os.environ['NEXTEST_PROFILE'])\n"
)


class Step(Workdir):
    def setUp(self):
        super().setUp()
        self.ws = self.work / "ws"
        (self.ws / "target").mkdir(parents=True)
        (self.ws / "temp").mkdir()

    def env(self):
        return {**os.environ, "RUNNER_TEMP": str(self.ws / "temp")}

    def step(self, name, *command):
        return run_bounded(self, [sys.executable, RUN_NEXTEST, name, *command], cwd=self.ws, env=self.env(), capture_output=True)

    def start_step(self, name, *command):
        process = subprocess.Popen(
            [sys.executable, RUN_NEXTEST, name, *command], cwd=self.ws, env=self.env(), stderr=subprocess.PIPE, stdout=subprocess.DEVNULL
        )
        self.procs.append(process)
        self.track(process)
        return process

    def published(self, name):
        path = self.ws / "temp" / "junit" / f"{name}.xml"
        return path.read_text() if path.exists() else None


class Publishing(Step):
    def test_a_run_that_wrote_a_file_has_it_published_under_its_name_and_moved(self):
        result = self.step("tests", sys.executable, "-c", WRITES)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.published("tests"), "ci-tests")
        self.assertFalse((self.ws / "target/nextest/ci-tests/junit.xml").exists())

    def test_the_profile_directory_exists_before_the_run(self):
        code = "import os; open('target/nextest/' + os.environ['NEXTEST_PROFILE'] + '/junit.xml', 'w').write('ok')"
        self.assertEqual(self.step("tests", sys.executable, "-c", code).returncode, 0)
        self.assertEqual(self.published("tests"), "ok")

    def test_success_without_a_file_fails_the_step(self):
        self.assertEqual(self.step("tests", "true").returncode, 1)

    def test_a_failing_run_keeps_its_status_and_its_file_is_published(self):
        result = self.step("tests", sys.executable, "-c", WRITES + "raise SystemExit(5)")
        self.assertEqual(result.returncode, 5)
        self.assertEqual(self.published("tests"), "ci-tests")

    def test_a_failing_run_without_a_file_keeps_its_status(self):
        self.assertEqual(self.step("tests", sys.executable, "-c", "raise SystemExit(6)").returncode, 6)

    def test_a_stale_file_never_stands_in_for_this_runs(self):
        stale = self.ws / "target/nextest/ci-tests"
        stale.mkdir(parents=True)
        (stale / "junit.xml").write_text("stale")
        self.assertEqual(self.step("tests", "true").returncode, 1)
        self.assertIsNone(self.published("tests"))

    def test_a_failed_move_fails_the_step(self):
        # The destination is a directory that already holds a `junit.xml`: `shutil.move` refuses.
        blocked = self.ws / "temp" / "junit" / "tests.xml"
        blocked.mkdir(parents=True)
        (blocked / "junit.xml").write_text("in the way")
        result = self.step("tests", sys.executable, "-c", WRITES)
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not move", result.stdout.decode())

    def test_a_command_that_cannot_run_gives_127(self):
        self.assertEqual(self.step("tests", "/nonexistent/command").returncode, 127)


class Stopping(Step):
    def blocker(self, extra="", after=""):
        """A stand-in that writes a half-finished JUnit file, says it is up, and waits for a release."""
        self.up_path, self.up = self.fifo("up")
        self.release_path, self.release = self.fifo("release")
        self.addCleanup(os.write, self.release, b"x")
        return (
            sys.executable,
            "-c",
            WRITES.replace("open(p + '/junit.xml', 'w').write(os.environ['NEXTEST_PROFILE'])", "open(p + '/junit.xml', 'w').write('<testsuites><testsuite')")
            + extra
            + f"os.write(os.open('{self.up_path}', os.O_RDWR), str(os.getpid()).encode() + b'\\n')\n"
            + f"os.read(os.open('{self.release_path}', os.O_RDWR), 1)\n"
            + after,
        )

    def test_a_run_told_to_stop_publishes_nothing_and_fails_and_its_command_hears_it(self):
        process = self.start_step("killed", *self.blocker("import signal\nsignal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"))
        self.assertEqual(self.read_until(process, self.up), "fd")
        os.read(self.up, 32)
        process.send_signal(signal.SIGTERM)
        self.wait_relayed(process)
        os.write(self.release, b"x")
        self.assertNotEqual(self.exits(process), 0)
        self.assertIsNone(self.published("killed"))

    def test_a_later_step_does_not_publish_what_the_orphan_of_an_earlier_one_wrote(self):
        # The command of step A ignores the signal, and the runner's last SIGKILL takes the script.
        wrote_path, wrote = self.fifo("wrote")
        finish = (
            "open(p + '/junit.xml', 'w').write('<testsuites/>')\n"
            f"os.write(os.open('{wrote_path}', os.O_RDWR), b'x')\n"
        )
        process = self.start_step(
            "orphan-a", *self.blocker("import signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n", finish)
        )
        self.assertEqual(self.read_until(process, self.up), "fd")
        orphan = int(os.read(self.up, 32))
        orphan_ended = self.exit_event(orphan)
        process.send_signal(signal.SIGTERM)
        self.wait_relayed(process)
        process.kill()
        process.wait()
        # Step A's command lives on. Released, it finishes its write while step B is about to run.
        os.write(self.release, b"x")
        ready, _, _ = select.select([wrote, orphan_ended], [], [], BOUND)
        self.assertIn(wrote, ready, "the orphan did not finish its write: it was killed")
        later = self.step("orphan-b", "true")
        self.assertEqual(later.returncode, 1, "step B wrote no file, so it fails")
        self.assertIsNone(self.published("orphan-b"))
        self.assertIsNone(self.published("orphan-a"))
        self.assertEqual((self.ws / "target/nextest/ci-orphan-a/junit.xml").read_text(), "<testsuites/>")


if __name__ == "__main__":
    unittest.main()
