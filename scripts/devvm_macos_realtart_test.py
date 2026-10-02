"""`up` with the real `Tart` wrapper against a stub tart executable, with real children and real signals.

The stub keeps VM state in files, runs `tart run` as a long-lived child and, on request, blocks in an
`exec` while telling the test (over a FIFO) that it is blocked. The test then sends the signal: no timers.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from scripts import devvm_macos as m
from scripts.devvm_macos_testlib import Env, kill_self

REPO_ROOT = Path(__file__).resolve().parent.parent

STUB = r"""#!/bin/sh
S="$STUB_DIR"; mkdir -p "$S/state"
cmd=$1; shift
case "$cmd" in
list)
  n=$(cat "$S/list.count" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$S/list.count"
  if [ "$n" = 2 ] && [ -e "$S/block.count" ]; then echo $$ > "$S/exec.pid"; echo count > "$S/fifo"; read x < "$S/release"; exit 0; fi
  printf '[{"Name":"%s","Source":"OCI","State":"stopped"}' "$BASE"
  for f in "$S"/state/*; do [ -e "$f" ] || continue
    printf ',{"Name":"%s","Source":"local","State":"%s"}' "$(basename "$f")" "$(cat "$f")"; done
  printf ']\n' ;;
clone)
  if [ -e "$S/block.clone" ]; then echo $$ > "$S/exec.pid"; echo clone > "$S/fifo"; read x < "$S/release"; exit 0; fi
  mkdir -p "$TART_HOME/vms/$2"; : > "$TART_HOME/vms/$2/disk.img"; echo stopped > "$S/state/$2" ;;
run) shift; echo running > "$S/state/$1"; echo $$ > "$S/run.pid"; read x < "$S/run.release"; exit 0 ;;
stop) kill "$(cat "$S/run.pid")" 2>/dev/null; echo stopped > "$S/state/$1" ;;
delete) rm -rf "$TART_HOME/vms/$1" "$S/state/$1" ;;
exec)
  [ "$1" = "-i" ] && shift
  shift
  case "$1" in
  true)
    if [ -e "$S/block.boot" ]; then echo $$ > "$S/exec.pid"; echo boot > "$S/fifo"; read x < "$S/release"; exit 0; fi
    exit 0 ;;
  bash)
    if [ -e "$S/block.provision" ]; then echo $$ > "$S/exec.pid"; echo provision > "$S/fifo"; read x < "$S/release"; exit 0; fi
    cat > /dev/null ;;
  sh)
    if [ -e "$S/block.archive" ]; then echo $$ > "$S/exec.pid"; echo archive > "$S/fifo"; read x < "$S/release"; exit 0; fi
    cat > /dev/null ;;
  *) cat > /dev/null ;;
  esac ;;
esac
"""


class StubEnv:
    def __init__(self, test: unittest.TestCase):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.stub_dir = self.root / "stub"
        self.stub_dir.mkdir()
        self.fifo = self.stub_dir / "fifo"
        os.mkfifo(self.fifo)
        release = self.stub_dir / "release"
        os.mkfifo(release)
        # Held open for reading and writing by the test: the stub's `read` finds the release whenever it comes.
        self.release_fd = os.open(release, os.O_RDWR)
        run_release = self.stub_dir / "run.release"
        os.mkfifo(run_release)
        self.run_release_fd = os.open(run_release, os.O_RDWR)
        test.addCleanup(os.close, self.release_fd)
        test.addCleanup(os.close, self.run_release_fd)
        # However the test ends, every child of the stub is released and exits: none outlives the test.
        test.addCleanup(self._free_every_child)
        stub = self.root / "tart"
        stub.write_text(STUB)
        stub.chmod(0o755)
        home = self.root / "home"
        home.mkdir()
        patch = mock.patch.dict(os.environ, {"STUB_DIR": str(self.stub_dir), "TART_HOME": str(home), "BASE": m.BASE_IMAGE})
        patch.start()
        test.addCleanup(patch.stop)
        # a repo with the provision script, as Env builds it
        self.repo = Env(test).repo
        self.state = self.root / "state"
        self.backend = m.MacosBackend(m.Tart(str(stub)), self.repo, self.state)
        self.stub = stub
        self.cleanup_started = False
        self._forbid_blocking_tart_run(test)

    def _forbid_blocking_tart_run(self, test) -> None:
        """Until cleanup starts, every tart call must go through the gate (a cancellable wait). A plain
        subprocess.run of tart would block on the stub's child, so fail at once instead of hanging."""
        real_run, real_teardown = subprocess.run, self.backend._teardown
        lists = []

        def run(argv, *a, **kw):
            if argv and str(argv[0]) == str(self.stub) and not self.cleanup_started and argv[1] not in ("stop", "delete"):
                lists.append(argv[1])
                if not (argv[1] == "list" and lists.count("list") == 1):  # the base-image pre-check runs before the gate
                    raise AssertionError(f"a blocking `tart {argv[1]}` that no signal can cut short")
            return real_run(argv, *a, **kw)

        def teardown(name):
            self.cleanup_started = True
            return real_teardown(name)

        self.backend._teardown = teardown
        patch = mock.patch.object(subprocess, "run", run)
        patch.start()
        test.addCleanup(patch.stop)

    def _free_every_child(self) -> None:
        for fd in (self.release_fd, self.run_release_fd):
            os.write(fd, b"x\n" * 16)

    def guard_unwakeable_selects(self, test) -> None:
        """For flows where every child finishes by itself: a select with no timeout that nothing can ever
        wake (the helper threads are finished and nothing is ready) is an assertion, not a hang."""
        real_select, real_start, real_join = m.select.select, threading.Thread.start, threading.Thread.join
        helpers: list[threading.Thread] = []

        def start(thread):
            real_start(thread)
            helpers.append(thread)

        def select(rlist, wlist, xlist, timeout=None):
            if timeout is not None:
                return real_select(rlist, wlist, xlist, timeout)
            for thread in list(helpers):
                real_join(thread)
            ready = real_select(rlist, wlist, xlist, 0)
            if not any(ready):
                raise AssertionError("a select that nothing can ever wake")
            return ready

        for patch in (mock.patch.object(threading.Thread, "start", start), mock.patch.object(m.select, "select", select)):
            patch.start()
            test.addCleanup(patch.stop)

    def block(self, what: str) -> None:
        (self.stub_dir / f"block.{what}").write_text("")

    def signal_when_stub_blocks(self, sig: int) -> threading.Thread:
        """The stub says over the FIFO that it is blocked in an exec; only then is the signal sent."""

        def wait_then_signal() -> None:
            with open(self.fifo) as f:
                f.readline()
            try:
                kill_self(sig)
            finally:
                # The blocked stub child is released too, so a wait that no signal can cut short returns instead
                # of blocking. A correct wait was cancelled by the signal, whatever the child then does.
                os.write(self.release_fd, b"x\n")

        thread = threading.Thread(target=wait_then_signal, daemon=True)
        thread.start()
        return thread

    def up(self):
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            try:
                self.backend.up(argparse.Namespace(rev=None, rosetta=False, allow_elevation=None, display=False))
            except SystemExit as e:
                return e.code, err.getvalue()
        return None, err.getvalue()

    def vm_states(self) -> list[str]:
        d = self.stub_dir / "state"
        return [p.name for p in d.iterdir()] if d.exists() else []

    def pid(self, name: str) -> int:
        return int((self.stub_dir / name).read_text())


class RealTartCancelTests(unittest.TestCase):
    def test_a_signal_while_the_archive_is_being_copied_in_reaps_git_and_the_exec(self) -> None:
        env = StubEnv(self)
        env.block("archive")
        # more than a pipe buffer of tar, so `git archive` is still blocked writing when the signal comes
        (env.repo / "big.bin").write_bytes(os.urandom(1 << 20))
        for args in (["add", "-A"], ["commit", "-q", "-m", "big"]):
            subprocess.run(["git", "-C", str(env.repo), *args], check=True, capture_output=True)
        env.signal_when_stub_blocks(signal.SIGTERM)
        gits = []
        real_popen = subprocess.Popen

        def popen(*a, **kw):
            p = real_popen(*a, **kw)
            if a and a[0][:1] == ["git"]:
                gits.append(p)
            return p

        with mock.patch.object(m.subprocess, "Popen", popen):
            code, err = env.up()
        self.assertEqual(code, 128 + signal.SIGTERM, err)
        self.assertTrue(gits)
        self.assertEqual([g.returncode is None for g in gits], [False] * len(gits), "git archive was not reaped")
        self.assert_gone_and_reaped(env.pid("exec.pid"))
        self.assertEqual(env.vm_states(), [])

    def setUp(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))

    def assert_gone_and_reaped(self, pid: int) -> None:
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)  # still answering means running, or a zombie nobody reaped

    def test_a_normal_up_and_destroy_work_through_the_real_wrapper(self) -> None:
        env = StubEnv(self)
        env.guard_unwakeable_selects(self)
        code, err = env.up()
        self.assertIsNone(code, err)
        self.assertEqual(len(env.vm_states()), 1)
        env.cleanup_started = True  # destroy is cleanup: its tart calls are not cancellable by design
        with contextlib.redirect_stderr(io.StringIO()):
            env.backend.destroy(argparse.Namespace())
        self.assertEqual(env.vm_states(), [])
        self.assertFalse((env.state / "macos-arm64" / "vm_name").exists())

    def test_a_signal_while_the_boot_exec_is_blocked_cancels_and_leaves_no_process_behind(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(sig=signal.Signals(sig).name):
                env = StubEnv(self)
                env.block("boot")
                env.signal_when_stub_blocks(sig)
                code, err = env.up()
                self.assertEqual(code, 128 + sig, err)
                self.assertIn("removed VM", err)
                self.assertEqual(env.vm_states(), [])
                self.assertFalse((env.state / "macos-arm64" / "vm_name").exists())
                self.assert_gone_and_reaped(env.pid("exec.pid"))
                self.assert_gone_and_reaped(env.pid("run.pid"))

    def test_a_signal_while_counting_or_cloning_is_blocked_cancels_and_leaves_no_process_behind(self) -> None:
        for step in ("count", "clone"):
            with self.subTest(step=step):
                env = StubEnv(self)
                env.block(step)
                env.signal_when_stub_blocks(signal.SIGTERM)
                code, err = env.up()
                self.assertEqual(code, 128 + signal.SIGTERM, err)
                self.assertEqual(env.vm_states(), [])
                self.assertFalse((env.state / "macos-arm64" / "vm_name").exists())
                self.assert_gone_and_reaped(env.pid("exec.pid"))

    def test_a_clone_whose_setup_fails_starts_no_clone_process_and_leaves_no_orphan_vm(self) -> None:
        env = StubEnv(self)
        env.block("clone")  # a clone that gets started would block, then create a VM nobody tracks
        real_clone = env.backend.tart.clone
        in_clone = []

        def clone(src, name, gate=None):
            in_clone.append(True)
            try:
                return real_clone(src, name, gate=gate)
            finally:
                in_clone.clear()

        def pipe():
            if in_clone:
                raise OSError(errno.EMFILE, "Too many open files")
            return real_pipe()

        real_pipe, real_popen, clones = os.pipe, subprocess.Popen, []

        def popen(argv, *a, **kw):
            if "clone" in argv:
                clones.append(argv)
            return real_popen(argv, *a, **kw)

        env.backend.tart.clone = clone
        with mock.patch.object(m.os, "pipe", pipe), mock.patch.object(m.subprocess, "Popen", popen):
            code, err = env.up()
        self.assertEqual(code, 1, err)
        self.assertIn("Too many open files", err)
        self.assertEqual(clones, [], "a `tart clone` process was started")
        env._free_every_child()
        self.assertEqual(env.vm_states(), [])
        self.assertFalse((env.state / "macos-arm64" / "vm_name").exists())

    def test_a_signal_while_provisioning_is_blocked_cancels_and_leaves_no_process_behind(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(sig=signal.Signals(sig).name):
                env = StubEnv(self)
                env.block("provision")
                env.signal_when_stub_blocks(sig)
                code, err = env.up()
                self.assertEqual(code, 128 + sig, err)
                self.assertEqual(env.vm_states(), [])
                self.assert_gone_and_reaped(env.pid("exec.pid"))
                self.assert_gone_and_reaped(env.pid("run.pid"))


CHILD = r"""
import json, os, signal, sys, unittest
from scripts import devvm_macos as m
from scripts.devvm_macos_testlib import Env, kill_self

sig = int(sys.argv[1])
env = Env(unittest.TestCase())
real = env.backend._checkpoint
env.backend._checkpoint = lambda label: (kill_self(sig) if label == "booted" else None, real(label))[1]
code = None
try:
    env.up()
except SystemExit as e:
    code = e.code
os.write(1, json.dumps({
    "code": code,
    "vms": env.tart.local_names(),
    "claim": (env.sdir / "vm_name").exists(),
    "procs_alive": [p.name for p in env.tart.procs.values() if p.poll() is None],
}).encode())
sys.exit(code)
"""


class ClosedStderrTests(unittest.TestCase):
    """Signals arrive when the terminal is gone (SIGHUP) or `| tee` died with Ctrl-C: stderr is a dead pipe."""

    def run_child(self, sig: int) -> tuple[int, dict]:
        r, w = os.pipe()
        os.close(r)  # no reader: every write to stderr fails with EPIPE
        proc = subprocess.run(
            [sys.executable, "-c", CHILD, str(int(sig))],
            stderr=w,
            stdout=subprocess.PIPE,
            cwd=REPO_ROOT,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        )
        os.close(w)
        return proc.returncode, json.loads(proc.stdout)

    def test_cleanup_and_the_exit_code_survive_a_dead_stderr(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(sig=signal.Signals(sig).name):
                returncode, state = self.run_child(sig)
                self.assertEqual(returncode, 128 + sig, state)
                self.assertEqual(state["vms"], [])
                self.assertFalse(state["claim"])
                self.assertEqual(state["procs_alive"], [])


class BrokenStreamTests(unittest.TestCase):
    def test_say_survives_a_failing_stream_and_mutes_it(self) -> None:
        class Broken(io.StringIO):
            def write(self, _s):
                raise BrokenPipeError

        saved, broken = sys.stderr, Broken()
        self.addCleanup(setattr, sys, "stderr", saved)
        sys.stderr = broken
        m._say("anything")  # must not raise
        self.assertIsNot(sys.stderr, broken, "the failing stream was not replaced")
        m._say("again")


if __name__ == "__main__":
    unittest.main()
