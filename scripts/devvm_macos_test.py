"""Host-side tests for devvm_macos.py against a fake `tart` (no VM, no real tart).

Run with: python3 -m unittest scripts.devvm_macos_test
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import io
import json
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import devvm, devvm_macos as m


def _vm(name: str, state: str = "stopped", source: str = "local") -> dict:
    return {"Name": name, "Source": source, "State": state}


# Fakes ================================================================================


class FakeProc:
    def __init__(self, tart: FakeTart, name: str):
        self.tart, self.name, self.returncode = tart, name, None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15
        self.tart.set_state(self.name, "stopped")

    def wait(self):
        assert self.returncode is not None, "wait() on a live fake process would hang"
        return self.returncode


class FakeTart:
    """Same surface as devvm_macos.Tart, backed by a dict and a temp dir."""

    binary = "fake-tart"

    def __init__(self, home: Path):
        self.home = home
        self.vm_list: list[dict] = [_vm(m.BASE_IMAGE, source="OCI")]
        self.fail: dict[str, int] = {}  # step -> exit code: clone, stop, delete
        self.stop_keeps_running = False
        self.exec_rc = lambda args: 0
        self.run_exits_immediately = False
        self.calls: list[str] = []
        self.procs: dict[str, FakeProc] = {}

    def vms(self):
        return [dict(v) for v in self.vm_list]

    def set_state(self, name, state):
        for v in self.vm_list:
            if v["Name"] == name:
                v["State"] = state

    def add_running(self, name):
        self.vm_list.append(_vm(name, "running"))

    def clone(self, src, name):
        self.calls.append("clone")
        if "clone" in self.fail:
            return self.fail["clone"]
        self.vm_list.append(_vm(name))
        d = self.home / "vms" / name
        d.mkdir(parents=True)
        (d / "disk.img").write_text("x")
        return 0

    def start(self, name, log):
        self.calls.append("start")
        log.write_text("")
        self.set_state(name, "running")
        proc = FakeProc(self, name)
        if self.run_exits_immediately:
            proc.returncode = 1
        self.procs[name] = proc
        return proc

    def stop(self, name):
        self.calls.append("stop")
        if "stop" in self.fail:
            return self.fail["stop"]
        if not self.stop_keeps_running:
            self.set_state(name, "stopped")
            if name in self.procs:
                self.procs[name].returncode = 0
        return 0

    def delete(self, name):
        self.calls.append("delete")
        if "delete" in self.fail:
            return self.fail["delete"]
        self.vm_list = [v for v in self.vm_list if v["Name"] != name]
        return 0

    def exec(self, name, args, *, stdin=None, capture_output=False):
        self.calls.append("exec:" + " ".join(args)[:40])
        if stdin is not None:
            stdin.read()
        return subprocess.CompletedProcess(args, self.exec_rc(args))

    def identity(self, name):
        st = (self.home / "vms" / name / "disk.img").stat()
        return {"ino": st.st_ino, "dev": st.st_dev}

    def local_names(self):
        return [v["Name"] for v in self.vm_list if v["Source"] == "local"]


class Env:
    """A temp repo, state dir and fake tart wired into a MacosBackend."""

    def __init__(self, test: unittest.TestCase):
        tmp = tempfile.TemporaryDirectory()
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

    def assert_nothing_leaked(self, test):
        test.assertEqual(self.tart.local_names(), [])
        test.assertIsNone(self.claim())
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


# Pure helpers =========================================================================


class CountRunningTests(unittest.TestCase):
    def test_counts_only_running_local_vms(self) -> None:
        vms = [_vm("a", "running"), _vm("b"), _vm("img", "running", "OCI"), _vm("c", "running")]
        self.assertEqual(m.count_running(vms), 2)

    def test_running_flag_counts_even_without_a_state_string(self) -> None:
        self.assertEqual(m.count_running([{"Source": "local", "Name": "a", "Running": True}]), 1)

    def test_entries_without_a_source_are_not_counted(self) -> None:
        self.assertEqual(m.count_running([{"Name": "a", "State": "running"}]), 0)

    def test_suspended_is_not_running(self) -> None:
        self.assertEqual(m.count_running([_vm("a", "suspended")]), 0)


class CapTests(unittest.TestCase):
    def test_below_the_cap_passes(self) -> None:
        m.check_cap(0)
        m.check_cap(m.MAX_CONCURRENT_VMS - 1)

    def test_at_the_cap_refuses_with_the_licence_in_the_message(self) -> None:
        with self.assertRaises(m.CapExceeded) as ctx:
            m.check_cap(m.MAX_CONCURRENT_VMS)
        self.assertIn("licen", str(ctx.exception))


class IdentityTests(unittest.TestCase):
    def test_equal_identities_match(self) -> None:
        self.assertTrue(m.identity_matches({"ino": 5, "dev": 1}, {"ino": 5, "dev": 1}))

    def test_either_key_differing_does_not_match(self) -> None:
        self.assertFalse(m.identity_matches({"ino": 5, "dev": 1}, {"ino": 6, "dev": 1}))
        self.assertFalse(m.identity_matches({"ino": 5, "dev": 1}, {"ino": 5, "dev": 2}))

    def test_missing_keys_never_match(self) -> None:
        self.assertFalse(m.identity_matches({}, {}))
        self.assertFalse(m.identity_matches({"ino": 5}, {"ino": 5, "dev": 1}))


class NamingTests(unittest.TestCase):
    def test_names_are_unique_128_bit(self) -> None:
        a, b = m.new_vm_name(), m.new_vm_name()
        self.assertNotEqual(a, b)
        self.assertRegex(a, r"^devvm-macos-[0-9a-f]{32}$")

    def test_existing_name_is_refused(self) -> None:
        with self.assertRaises(m.NameTaken):
            m.require_name_free("x", [_vm("x", "running")])
        m.require_name_free("y", [_vm("x")])

    def test_foreign_names_are_refused(self) -> None:
        for name in ("macos-tahoe-base", m.BASE_IMAGE):
            with self.assertRaises(ValueError):
                m.require_own_name(name)


class ResolveRevTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Env(self).repo

    def test_head_resolves_to_a_full_sha(self) -> None:
        self.assertRegex(m.resolve_rev(self.repo, "HEAD"), r"^[0-9a-f]{40}$")

    def test_unknown_rev_is_an_error(self) -> None:
        with self.assertRaises(m.BadRev):
            m.resolve_rev(self.repo, "no-such-rev")

    def test_option_looking_rev_is_an_error_and_creates_nothing(self) -> None:
        target = self.repo / "pwned"
        with self.assertRaises(m.BadRev):
            m.resolve_rev(self.repo, f"--output={target}")
        self.assertFalse(target.exists())


class GuestCommandTests(unittest.TestCase):
    """Run the guest-side shell for real on the host, in a scratch HOME."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        (self.home / "cosca").mkdir()
        bin_dir = self.home / ".cargo" / "bin"
        bin_dir.mkdir(parents=True)
        cargo = bin_dir / "cargo"
        cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$CARGO_TARGET_DIR"; for a; do printf "[%s]\\n" "$a"; done\n')
        cargo.chmod(0o755)

    def sh(self, *argv: str, **kw) -> subprocess.CompletedProcess:
        env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin"}
        return subprocess.run(list(argv), env=env, capture_output=True, text=True, **kw)

    def test_hostile_arguments_reach_the_command_literally(self) -> None:
        hostile = ["a b", "$(touch pwned)", "x;y", "'q'", ""]
        r = self.sh("bash", "-c", m.build_remote_command(["cargo", *hostile]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.splitlines(), [f"{self.home}/cargo-target", *(f"[{a}]" for a in hostile)])
        self.assertFalse((self.home / "cosca" / "pwned").exists())

    def test_fetch_expands_tilde_in_the_guest_and_tars_the_base_name(self) -> None:
        (self.home / "out").mkdir()
        (self.home / "out" / "f.txt").write_text("hi")
        env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin"}
        for path in ("~/out", "~/out/", str(self.home / "out")):
            tar = subprocess.run(["sh", "-c", m.FETCH_SCRIPT, "_", path], env=env, capture_output=True)
            self.assertEqual(tar.returncode, 0, tar.stderr)
            listing = subprocess.run(["tar", "-t"], input=tar.stdout, capture_output=True)
            self.assertIn("out/f.txt", listing.stdout.decode().split(), path)

    def test_fetch_paths_are_validated(self) -> None:
        for good in ("/a/b", "~/a", "/a/b/"):
            m.parse_guest_path(good)
        for bad in ("a/b", "", "/", "~/", "/a/..", "/a/.", "~"):
            with self.assertRaises(ValueError, msg=bad):
                m.parse_guest_path(bad)


# Lifecycle against the fake tart ======================================================


class UpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(self)
        sleeper = mock.patch.object(m.time, "sleep", lambda _s: None)
        sleeper.start()
        self.addCleanup(sleeper.stop)

    def test_success_leaves_a_running_vm_with_claim_and_identity(self) -> None:
        with captured():
            self.env.up(rosetta=True)
        (name,) = self.env.tart.local_names()
        self.assertEqual(self.env.claim(), name)
        self.assertEqual(json.loads((self.env.sdir / "identity.json").read_text()), self.env.tart.identity(name))
        self.assertEqual(self.env.tart.vm_list[-1]["State"], "running")
        self.assertTrue(any("--rosetta" in c or c.startswith("exec:bash -c bash -s") for c in self.env.tart.calls))
        self.env.assert_cap_lock_free(self)

    def test_bad_rev_fails_before_anything_boots(self) -> None:
        args = argparse.Namespace(rev="nope", rosetta=False, allow_elevation=None, display=False)
        exits_with(self, lambda: self.env.backend.up(args))
        self.assertEqual(self.env.tart.calls, [])
        self.env.assert_nothing_leaked(self)

    def test_missing_base_image_fails_before_anything_boots(self) -> None:
        self.env.tart.vm_list = []
        exits_with(self, self.env.up)
        self.assertEqual(self.env.tart.calls, [])

    def test_clone_failure_leaves_nothing_and_prints_no_removed(self) -> None:
        self.env.tart.fail["clone"] = 1
        err = exits_with(self, self.env.up)
        self.assertNotIn("removed", err)
        self.env.assert_nothing_leaked(self)

    def test_cap_refusal_leaves_nothing_and_never_clones(self) -> None:
        self.env.tart.add_running("other-1")
        self.env.tart.add_running("other-2")
        err = exits_with(self, self.env.up)
        self.assertIn("licen", err)
        self.assertNotIn("clone", self.env.tart.calls)
        self.assertIsNone(self.env.claim())
        self.assertEqual(sorted(self.env.tart.local_names()), ["other-1", "other-2"])

    def test_an_agent_that_never_answers_is_bounded_and_cleaned_up(self) -> None:
        self.env.tart.exec_rc = lambda args: 1
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            err = exits_with(self, self.env.up)
        self.assertIn("did not answer", err)
        self.assertIn("removed VM", err)
        self.env.assert_nothing_leaked(self)

    def test_tart_run_exiting_early_is_reported_and_cleaned_up(self) -> None:
        self.env.tart.exec_rc = lambda args: 1
        self.env.tart.run_exits_immediately = True
        err = exits_with(self, self.env.up)
        self.assertIn("exited", err)
        self.env.assert_nothing_leaked(self)

    def test_stage_failure_after_boot_stops_the_child_and_deletes_the_vm(self) -> None:
        self.env.tart.exec_rc = lambda args: 1 if args[:2] == ["sh", "-c"] else 0
        exits_with(self, self.env.up)
        self.env.assert_nothing_leaked(self)
        self.assertIn("stop", self.env.tart.calls)
        self.assertLess(self.env.tart.calls.index("stop"), self.env.tart.calls.index("delete"))

    def test_provision_failure_is_cleaned_up(self) -> None:
        self.env.tart.exec_rc = lambda args: 1 if args[:2] == ["bash", "-c"] and "-s" in args[2] else 0
        exits_with(self, self.env.up)
        self.env.assert_nothing_leaked(self)

    def test_delete_failure_keeps_state_names_the_vm_and_keeps_the_original_error(self) -> None:
        self.env.tart.exec_rc = lambda args: 1
        self.env.tart.fail["delete"] = 1
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            err = exits_with(self, self.env.up)
        (name,) = self.env.tart.local_names()
        self.assertIn(name, err)
        self.assertIn("destroy", err)
        self.assertIn("did not answer", err)
        self.assertNotIn("removed VM", err)
        self.assertEqual(self.env.claim(), name)
        self.env.assert_cap_lock_free(self)

    def test_a_vm_that_will_not_stop_keeps_the_state(self) -> None:
        self.env.tart.exec_rc = lambda args: 1
        self.env.tart.stop_keeps_running = True
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            err = exits_with(self, self.env.up)
        self.assertIn("did not stop it", err)
        self.assertIsNotNone(self.env.claim())

    def test_ctrl_c_during_boot_cleans_up_and_propagates(self) -> None:
        def interrupt(args):
            raise KeyboardInterrupt

        self.env.tart.exec_rc = interrupt
        with captured(), self.assertRaises(KeyboardInterrupt):
            self.env.up()
        self.env.assert_nothing_leaked(self)

    def test_sigterm_and_sighup_run_the_cleanup(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGHUP):
            env = Env(self)

            def kill_self(args, sig=sig):
                os.kill(os.getpid(), sig)
                return 1

            env.tart.exec_rc = kill_self
            with captured():
                with self.assertRaises(SystemExit) as ctx:
                    env.up()
            self.assertEqual(ctx.exception.code, 128 + sig)
            env.assert_nothing_leaked(self)

    def test_second_up_in_one_worktree_is_refused_and_touches_nothing(self) -> None:
        with captured():
            self.env.up()
        (first,) = self.env.tart.local_names()
        exits_with(self, self.env.up)
        self.assertEqual(self.env.tart.local_names(), [first])
        self.assertEqual(self.env.claim(), first)

    def test_windows_only_flags_are_rejected(self) -> None:
        args = argparse.Namespace(rev=None, rosetta=False, allow_elevation=True, display=False)
        exits_with(self, lambda: self.env.backend.up(args))
        self.assertEqual(self.env.tart.calls, [])


class ClaimTests(unittest.TestCase):
    def test_claim_is_atomic_and_exclusive_and_leaves_no_temp_file(self) -> None:
        env = Env(self)
        env.backend._claim("devvm-macos-a")
        with self.assertRaises(m.AlreadyUp):
            env.backend._claim("devvm-macos-b")
        self.assertEqual(env.claim(), "devvm-macos-a")
        self.assertEqual([p.name for p in env.sdir.glob("*.tmp")], [])

    def test_reading_a_missing_claim_is_none_and_an_empty_one_is_empty(self) -> None:
        env = Env(self)
        self.assertIsNone(env.backend._read_claim())
        env.sdir.mkdir(parents=True)
        (env.sdir / "vm_name").write_text("")
        self.assertEqual(env.backend._read_claim(), "")


class DestroyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(self)
        with captured():
            self.env.up()
        (self.name,) = self.env.tart.local_names()

    def test_destroys_the_vm_it_created_and_clears_state(self) -> None:
        with captured():
            self.env.destroy()
        self.env.assert_nothing_leaked(self)

    def test_refuses_a_replaced_vm(self) -> None:
        (self.env.tart.home / "vms" / self.name / "disk.img").unlink()
        (self.env.tart.home / "vms" / self.name / "disk.img").write_text("replacement")
        (self.env.sdir / "identity.json").write_text(json.dumps({"ino": 1, "dev": 1}))
        exits_with(self, self.env.destroy)
        self.assertEqual(self.env.tart.local_names(), [self.name])
        self.assertNotIn("stop", self.env.tart.calls)

    def test_missing_identity_fails_closed(self) -> None:
        (self.env.sdir / "identity.json").unlink()
        err = exits_with(self, self.env.destroy)
        self.assertIn("cannot be verified", err)
        self.assertEqual(self.env.tart.local_names(), [self.name])

    def test_unparsable_identity_fails_closed(self) -> None:
        (self.env.sdir / "identity.json").write_text("{not json")
        exits_with(self, self.env.destroy)
        self.assertEqual(self.env.tart.local_names(), [self.name])

    def test_identity_missing_a_key_fails_closed(self) -> None:
        (self.env.sdir / "identity.json").write_text(json.dumps({"ino": 1}))
        exits_with(self, self.env.destroy)
        self.assertEqual(self.env.tart.local_names(), [self.name])

    def test_missing_disk_image_is_a_clear_error(self) -> None:
        (self.env.tart.home / "vms" / self.name / "disk.img").unlink()
        err = exits_with(self, self.env.destroy)
        self.assertIn("disk.img", err)

    def test_a_vm_already_gone_is_noted_and_state_cleared(self) -> None:
        self.env.tart.vm_list = [v for v in self.env.tart.vm_list if v["Name"] != self.name]
        with captured() as err:
            self.env.destroy()
        self.assertIn("already gone", err.getvalue())
        self.env.assert_nothing_leaked(self)

    def test_delete_failure_keeps_state(self) -> None:
        self.env.tart.fail["delete"] = 1
        exits_with(self, self.env.destroy)
        self.assertEqual(self.env.claim(), self.name)

    def test_an_empty_claim_is_cleaned_up_with_a_warning(self) -> None:
        (self.env.sdir / "vm_name").write_text("")
        with captured() as err:
            self.env.destroy()
        self.assertIn("empty claim", err.getvalue())
        self.assertFalse((self.env.sdir / "vm_name").exists())

    def test_a_foreign_name_in_the_claim_is_refused(self) -> None:
        (self.env.sdir / "vm_name").write_text("macos-tahoe-base\n")
        with self.assertRaises(ValueError):
            self.env.destroy()
        self.assertIn(m.BASE_IMAGE, self.env.tart.local_names() + [v["Name"] for v in self.env.tart.vm_list])

    def test_destroy_waits_for_the_worktree_lock(self) -> None:
        with open(self.env.sdir / "lock", "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            seen = []
            real = m.fcntl.flock

            def spy(f, op):
                seen.append(op)
                if op & fcntl.LOCK_NB:
                    raise BlockingIOError
                return None  # pretend the blocking acquire succeeded

            with mock.patch.object(m.fcntl, "flock", spy), captured() as err:
                self.env.destroy()
            self.assertIn("waiting for", err.getvalue())
            del real


class OtherVerbTests(unittest.TestCase):
    def test_halt_is_refused(self) -> None:
        env = Env(self)
        err = exits_with(self, lambda: env.backend.halt(argparse.Namespace()))
        self.assertIn("destroy", err)

    def test_run_requires_a_brought_up_guest(self) -> None:
        env = Env(self)
        err = exits_with(self, lambda: env.backend.run(argparse.Namespace(cmd=["--", "true"], unelevated=False, timeout=None)))
        self.assertIn("has not been brought up", err)

    def test_run_propagates_the_guest_exit_code(self) -> None:
        env = Env(self)
        with captured():
            env.up()
        env.tart.exec_rc = lambda args: 7
        exits_with(self, lambda: env.backend.run(argparse.Namespace(cmd=["--", "false"], unelevated=False, timeout=None)), code=7)

    def test_run_rejects_windows_only_flags(self) -> None:
        env = Env(self)
        exits_with(self, lambda: env.backend.run(argparse.Namespace(cmd=["--", "x"], unelevated=True, timeout=None)))

    def test_status_reports_each_state(self) -> None:
        env = Env(self)
        self.assertEqual(env.backend.status(), "not created")
        with captured():
            env.up()
        self.assertTrue(env.backend.status().startswith("running"))


class DispatchTests(unittest.TestCase):
    def test_each_guest_gets_its_backend_once(self) -> None:
        with mock.patch.object(devvm.devvm_macos, "Tart", lambda: object()):
            self.assertIsInstance(devvm.backend_for(devvm.GUESTS["macos-arm64"]), devvm.devvm_macos.MacosBackend)
        self.assertIsInstance(devvm.backend_for(devvm.GUESTS["linux-x64"]), devvm.VagrantBackend)
        self.assertIsInstance(devvm.backend_for(devvm.GUESTS["windows-x64"]), devvm.VagrantBackend)

    def test_vagrant_guests_reject_macos_flags(self) -> None:
        args = argparse.Namespace(guest="linux-x64", allow_elevation=None, display=False, rev="HEAD", rosetta=False)
        exits_with(self, lambda: devvm.cmd_up(args))
        args = argparse.Namespace(guest="linux-x64", allow_elevation=None, display=False, rev=None, rosetta=True)
        exits_with(self, lambda: devvm.cmd_up(args))


if __name__ == "__main__":
    unittest.main()
