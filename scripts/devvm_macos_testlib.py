"""Shared fakes for the devvm macOS tests: a FakeTart with the surface of devvm_macos.Tart, and an Env wiring it in."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import devvm_macos as m


def _vm(name: str, state: str = "stopped", source: str = "local") -> dict:
    return {"Name": name, "Source": source, "State": state}


# Fakes ================================================================================


class FakeProc:
    def __init__(self, tart: FakeTart, name: str):
        self.tart, self.name, self.returncode = tart, name, None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.tart.event("terminate")
        self.returncode = -15
        self.tart.set_state(self.name, "stopped")

    def wait(self):
        assert self.returncode is not None, "wait() on a live fake process would hang"
        return self.returncode


class FakeTart:
    """Same surface as devvm_macos.Tart, backed by a dict and a temp dir.

    `events` records each call with whether the host-wide cap lock was held during it; `hooks`
    run code at a named call (used to deliver signals). With `guest_home` set, `exec` and
    `exec_popen` run the guest-side shell for real on the host, with HOME there.
    """

    binary = "fake-tart"

    def __init__(self, home: Path):
        self.home = home
        self.vm_list: list[dict] = [_vm(m.BASE_IMAGE, source="OCI")]
        self.fail: dict[str, int] = {}  # step -> exit code: clone, stop, delete
        self.stop_keeps_running = False
        self.exec_rc = lambda args: 0
        self.run_exits_immediately = False
        self.calls: list[str] = []
        self.events: list[tuple[str, bool]] = []
        self.hooks: dict[str, object] = {}
        self.procs: dict[str, FakeProc] = {}
        self.guest_home: Path | None = None
        self.clone_raises = False
        self.stop_error: Exception | None = None
        self.vms_error: Exception | None = None

    def cap_lock_held(self) -> bool:
        with open(self.home / "devvm-cap.lock", "a") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            return False

    def event(self, name: str) -> None:
        self.events.append((name, self.cap_lock_held()))
        hook = self.hooks.get(name)
        if hook:
            hook()

    def vms(self, gate=None):
        self.event("vms")
        if self.vms_error is not None:
            raise self.vms_error
        return [dict(v) for v in self.vm_list]

    def set_state(self, name, state):
        for v in self.vm_list:
            if v["Name"] == name:
                v["State"] = state

    def add_running(self, name):
        self.vm_list.append(_vm(name, "running"))

    def clone(self, src, name, gate=None):
        self.calls.append("clone")
        self.event("clone")
        if "clone" in self.fail:
            return self.fail["clone"]
        self.vm_list.append(_vm(name))
        d = self.home / "vms" / name
        d.mkdir(parents=True)
        (d / "disk.img").write_text("x")
        if self.clone_raises:
            raise OSError("clone blew up after creating the VM")
        return 0

    def start(self, name, log):
        self.calls.append("start")
        self.event("start")
        log.write_text("")
        self.set_state(name, "running")
        proc = FakeProc(self, name)
        if self.run_exits_immediately:
            proc.returncode = 1
        self.procs[name] = proc
        return proc

    def stop(self, name):
        self.calls.append("stop")
        self.event("stop")
        if self.stop_error is not None:
            raise self.stop_error
        if "stop" in self.fail:
            return self.fail["stop"]
        if not self.stop_keeps_running:
            self.set_state(name, "stopped")  # the `tart run` child exits later, on its own schedule
        return 0

    def delete(self, name):
        self.calls.append("delete")
        self.event("delete")
        if "delete" in self.fail:
            return self.fail["delete"]
        self.vm_list = [v for v in self.vm_list if v["Name"] != name]
        return 0

    def _local_env(self):
        return {"HOME": str(self.guest_home), "PATH": "/usr/bin:/bin"}

    def exec(self, name, args, *, stdin=None, capture_output=False, gate=None):
        self.calls.append("exec:" + " ".join(args)[:40])
        self.event("exec:true" if args == ["true"] else "exec:stage")
        if self.guest_home is not None and args != ["true"] and args[0] == "sh":
            return subprocess.run(args, stdin=stdin, env=self._local_env(), capture_output=True)
        if stdin is not None:
            stdin.read()
        return subprocess.CompletedProcess(args, self.exec_rc(args))

    def exec_popen(self, name, args, *, stdout):
        self.event("exec_popen")
        assert self.guest_home is not None
        return subprocess.Popen(args, stdout=stdout, stderr=subprocess.DEVNULL, env=self._local_env())

    def identity(self, name):
        st = (self.home / "vms" / name / "disk.img").stat()
        return {"ino": st.st_ino, "dev": st.st_dev}

    def local_names(self):
        return [v["Name"] for v in self.vm_list if v["Source"] == "local"]


class Env:
    """A temp repo, state dir and fake tart wired into a MacosBackend."""

    def __init__(self, test: unittest.TestCase):
        tmp = self._tmp = tempfile.TemporaryDirectory()  # kept alive: its finalizer deletes the directory
        test.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.repo = root / "repo"
        script = self.repo / m.PROVISION_SCRIPT
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/sh\n")
        for args in (["init", "-q"], ["config", "user.email", "t@e.invalid"], ["config", "user.name", "t"], ["add", "-A"], ["commit", "-q", "-m", "c"]):
            subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)
        self.tart = FakeTart(root / "tart-home")
        self.tart.home.mkdir()
        self.state = root / "state"
        self.backend = m.MacosBackend(self.tart, self.repo, self.state)
        self.sdir = self.state / m.GUEST_NAME

    def up(self, **kw):
        kw = {"rev": None, "rosetta": False, "allow_elevation": None, "display": False, **kw}
        with contextlib.redirect_stdout(io.StringIO()):
            return self.backend.up(argparse.Namespace(**kw))

    def destroy(self):
        return self.backend.destroy(argparse.Namespace())

    def claim(self):
        f = self.sdir / "vm_name"
        return f.read_text().split()[0] if f.exists() else None

    def assert_cap_lock_free(self, test):
        with open(self.tart.home / "devvm-cap.lock", "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)  # raises BlockingIOError if still held

    def assert_nothing_leaked(self, test, procs=True):
        test.assertEqual(self.tart.local_names(), [])
        if procs:  # `destroy` runs in another process than `up`'s child, which exits on `tart stop`
            test.assertEqual([p.name for p in self.tart.procs.values() if p.poll() is None], [], "a tart run child is still alive")
        test.assertIsNone(self.claim())
        test.assertFalse((self.sdir / "identity.json").exists(), "the identity file was left behind")
        self.assert_cap_lock_free(test)


@contextlib.contextmanager
def captured():
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        yield err


def exits_with(test: unittest.TestCase, fn, code=1):
    with captured() as err, test.assertRaises(SystemExit) as ctx:
        fn()
    test.assertEqual(ctx.exception.code, code)
    return err.getvalue()


