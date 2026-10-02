"""`up` with the real `Tart` wrapper against a stub tart executable, with real children and real signals.

The stub keeps VM state in files, runs `tart run` as a long-lived child and, on request, blocks in an
`exec` while telling the test (over a FIFO) that it is blocked. The test then sends the signal: no timers.
"""

from __future__ import annotations

import argparse
import contextlib
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
from scripts.devvm_macos_testlib import Env

REPO_ROOT = Path(__file__).resolve().parent.parent

STUB = r"""#!/bin/sh
S="$STUB_DIR"; mkdir -p "$S/state"
cmd=$1; shift
case "$cmd" in
list)
  printf '[{"Name":"%s","Source":"OCI","State":"stopped"}' "$BASE"
  for f in "$S"/state/*; do [ -e "$f" ] || continue
    printf ',{"Name":"%s","Source":"local","State":"%s"}' "$(basename "$f")" "$(cat "$f")"; done
  printf ']\n' ;;
clone) mkdir -p "$TART_HOME/vms/$2"; : > "$TART_HOME/vms/$2/disk.img"; echo stopped > "$S/state/$2" ;;
run) shift; echo running > "$S/state/$1"; echo $$ > "$S/run.pid"; exec sleep 1000000 ;;
stop) kill "$(cat "$S/run.pid")" 2>/dev/null; echo stopped > "$S/state/$1" ;;
delete) rm -rf "$TART_HOME/vms/$1" "$S/state/$1" ;;
exec)
  [ "$1" = "-i" ] && shift
  shift
  case "$1" in
  true)
    if [ -e "$S/block.boot" ]; then echo $$ > "$S/exec.pid"; echo boot > "$S/fifo"; exec sleep 1000000; fi
    exit 0 ;;
  bash)
    if [ -e "$S/block.provision" ]; then echo $$ > "$S/exec.pid"; echo provision > "$S/fifo"; exec sleep 1000000; fi
    cat > /dev/null ;;
  sh)
    if [ -e "$S/block.archive" ]; then echo $$ > "$S/exec.pid"; echo archive > "$S/fifo"; exec sleep 1000000; fi
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

    def block(self, what: str) -> None:
        (self.stub_dir / f"block.{what}").write_text("")

    def signal_when_stub_blocks(self, sig: int) -> threading.Thread:
        """The stub says over the FIFO that it is blocked in an exec; only then is the signal sent."""

        def wait_then_signal() -> None:
            with open(self.fifo) as f:
                f.readline()
            os.kill(os.getpid(), sig)

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
        code, err = env.up()
        self.assertIsNone(code, err)
        self.assertEqual(len(env.vm_states()), 1)
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
from scripts.devvm_macos_testlib import Env

sig = int(sys.argv[1])
env = Env(unittest.TestCase())
real = env.backend._checkpoint
env.backend._checkpoint = lambda label: (os.kill(os.getpid(), sig) if label == "booted" else None, real(label))[1]
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

        saved = sys.stderr
        self.addCleanup(setattr, sys, "stderr", saved)
        sys.stderr = Broken()
        m._say("anything")  # must not raise
        m._say("again")
        self.assertIsNot(sys.stderr, saved)


if __name__ == "__main__":
    unittest.main()
