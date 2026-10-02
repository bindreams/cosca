"""Host-side tests for devvm_macos.py against a fake `tart` (no VM, no real tart).

Run with: python3 -m unittest scripts.devvm_macos_test (CI runs all the devvm test modules)
"""

from __future__ import annotations

import argparse
import contextlib
import errno
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

from scripts import devvm, devvm_macos as m
from scripts.devvm_macos_testlib import Env, FakeTart, _vm, captured, exits_with

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

    def test_the_message_does_not_claim_every_counted_vm_is_macos(self) -> None:
        with self.assertRaises(m.CapExceeded) as ctx:
            m.check_cap(m.MAX_CONCURRENT_VMS)
        self.assertNotIn("macOS VMs are already", str(ctx.exception))
        self.assertIn("Tart VMs", str(ctx.exception))


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
            self.assertTrue(any(n.endswith("out/f.txt") for n in listing.stdout.decode().split()), path)

    def test_fetch_of_a_name_starting_with_at_gets_that_directory_not_an_archive(self) -> None:
        (self.home / "@out").mkdir()
        (self.home / "@out" / "f.txt").write_text("hi")
        evil = self.home / "evil-src"
        evil.mkdir()
        (evil / "evil.txt").write_text("x")
        subprocess.run(["tar", "-cf", str(self.home / "out"), "-C", str(evil), "evil.txt"], check=True)
        env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin"}
        tar = subprocess.run(["sh", "-c", m.FETCH_SCRIPT, "_", "~/@out"], env=env, capture_output=True)
        names = subprocess.run(["tar", "-t"], input=tar.stdout, capture_output=True).stdout.decode().split()
        self.assertTrue(any(n.endswith("@out/f.txt") for n in names), names)
        self.assertNotIn("evil.txt", names)

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

    def test_a_clone_that_raises_after_creating_the_vm_is_cleaned_up(self) -> None:
        self.env.tart.clone_raises = True
        err = exits_with(self, self.env.up)
        self.assertIn("clone blew up", err)
        self.env.assert_nothing_leaked(self)

    def test_a_teardown_step_that_raises_is_contained_and_reported(self) -> None:
        self.env.tart.fail_first_agent_probe()
        self.env.tart.stop_error = RuntimeError("stop blew up")
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            err = exits_with(self, self.env.up)
        self.assertIn("could not remove", err)
        self.assertIn("stop blew up", err)
        self.assertIn("did not answer", err, "the original error was lost")
        self.assertIsNotNone(self.env.claim())

    def test_a_cleanup_that_itself_fails_does_not_mask_the_original_error(self) -> None:
        self.env.tart.add_running("other-1")
        self.env.tart.add_running("other-2")
        with mock.patch.object(self.env.backend, "_clear_state", side_effect=OSError("disk gone")):
            err = exits_with(self, self.env.up)
        self.assertIn("licen", err)
        self.assertIn("cleanup of", err)
        self.assertIn("disk gone", err)

    def test_cap_refusal_leaves_nothing_and_never_clones(self) -> None:
        self.env.tart.add_running("other-1")
        self.env.tart.add_running("other-2")
        err = exits_with(self, self.env.up)
        self.assertIn("licen", err)
        self.assertNotIn("clone", self.env.tart.calls)
        self.assertIsNone(self.env.claim())
        self.assertEqual(sorted(self.env.tart.local_names()), ["other-1", "other-2"])

    def test_an_agent_that_never_answers_is_bounded_and_cleaned_up(self) -> None:
        self.env.tart.fail_first_agent_probe()
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            err = exits_with(self, self.env.up)
        self.assertIn("did not answer", err)
        self.assertIn("removed VM", err)
        self.env.assert_nothing_leaked(self)

    def test_tart_run_exiting_early_is_reported_and_cleaned_up(self) -> None:
        self.env.tart.fail_first_agent_probe()
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
        self.env.tart.fail_first_agent_probe()
        self.env.tart.fail["delete"] = 1
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            err = exits_with(self, self.env.up)
        (name,) = self.env.tart.local_names()
        self.assertIn(name, err)
        self.assertIn("destroy", err)
        self.assertIn("did not answer", err)
        self.assertNotIn("removed VM", err)
        self.assertEqual(self.env.claim(), name)
        self.assertEqual(self.env.tart.calls.count("delete"), 1, "cleanup ran twice")
        self.env.assert_cap_lock_free(self)

    def test_a_vm_that_will_not_stop_keeps_the_state(self) -> None:
        self.env.tart.fail_first_agent_probe()
        self.env.tart.stop_keeps_running = True
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            err = exits_with(self, self.env.up)
        self.assertIn("did not stop it", err)
        self.assertIsNotNone(self.env.claim())

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


class CapLockTests(unittest.TestCase):
    """The licence cap is only as strong as the lock around count, clone and boot."""

    def setUp(self) -> None:
        self.env = Env(self)
        sleeper = mock.patch.object(m.time, "sleep", lambda _s: None)
        sleeper.start()
        self.addCleanup(sleeper.stop)

    def held(self, name: str) -> list[bool]:
        return [h for n, h in self.env.tart.events if n == name]

    def test_count_clone_start_and_the_first_exec_all_run_under_the_cap_lock(self) -> None:
        with captured():
            self.env.up()
        events = self.env.tart.events
        self.assertEqual(self.held("clone"), [True])
        self.assertEqual(self.held("start"), [True])
        self.assertEqual(self.held("exec:true"), [True])
        self.assertEqual(events[[n for n, _ in events].index("clone") - 1], ("vms", True), "the count before the clone")

    def test_staging_runs_without_the_cap_lock(self) -> None:
        with captured():
            self.env.up()
        self.assertEqual(set(self.held("exec:stage")), {False})

    def test_teardown_after_a_boot_failure_holds_the_cap_lock(self) -> None:
        self.env.tart.fail_first_agent_probe()
        with mock.patch.object(m, "AGENT_BOOT_TIMEOUT_SECONDS", 0):
            exits_with(self, self.env.up)
        self.assertEqual(set(self.held("stop") + self.held("delete") + self.held("terminate")), {True})

    def test_teardown_after_a_stage_failure_holds_the_cap_lock(self) -> None:
        self.env.tart.exec_rc = lambda args: 1 if args[:2] == ["sh", "-c"] else 0
        exits_with(self, self.env.up)
        self.assertEqual(self.held("stop") + self.held("delete") + self.held("terminate"), [True, True, True])

    def test_a_name_collision_is_refused_before_cloning(self) -> None:
        self.env.tart.vm_list.append(_vm("devvm-macos-fixed"))
        with mock.patch.object(m, "new_vm_name", lambda: "devvm-macos-fixed"):
            err = exits_with(self, self.env.up)
        self.assertIn("already exists", err)
        self.assertNotIn("clone", self.env.tart.calls)
        self.assertEqual(self.env.tart.local_names(), ["devvm-macos-fixed"])


class ListWithoutTartTests(unittest.TestCase):
    def test_list_does_not_need_tart(self) -> None:
        env = {"PATH": "/usr/bin:/bin"}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            devvm, "STATE_DIR", Path(tmp)
        ), mock.patch.object(devvm, "_vagrant_status", lambda g: "not created"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                devvm.cmd_list(argparse.Namespace())
        self.assertRegex(out.getvalue(), r"macos-arm64\s+not created")


class FetchAndSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(self)
        with captured():
            self.env.up()
        guest = self.env.sdir.parent / "guest-home"
        guest.mkdir()
        self.guest = guest
        self.env.tart.guest_home = guest

    def fetch(self, guest_path: str) -> Path:
        dest = self.env.sdir.parent / f"out-{abs(hash(guest_path))}"
        args = argparse.Namespace(guest_path=guest_path, host_dest=str(dest))
        with captured():
            self.env.backend.fetch(args)
        return dest

    def test_fetch_copies_a_tilde_path(self) -> None:
        (self.guest / "res").mkdir()
        (self.guest / "res" / "f.txt").write_text("hi")
        self.assertEqual((self.fetch("~/res") / "res" / "f.txt").read_text(), "hi")

    def test_a_basename_that_looks_like_a_tar_option_is_fetched_not_parsed(self) -> None:
        for base in ("-out", "--newer=x"):
            with self.subTest(base=base):
                (self.guest / base).mkdir()
                (self.guest / base / "f.txt").write_text("hi")
                self.assertEqual((self.fetch(f"~/{base}") / base / "f.txt").read_text(), "hi")

    def test_fetch_of_a_missing_path_fails(self) -> None:
        args = argparse.Namespace(guest_path="~/nope", host_dest=str(self.guest / "o"))
        exits_with(self, lambda: self.env.backend.fetch(args))

    def test_sync_replaces_the_guests_tree_with_the_rev(self) -> None:
        with captured():
            self.env.backend.sync(argparse.Namespace(rev=None))
        self.assertTrue((self.guest / "cosca" / m.PROVISION_SCRIPT).is_file())

    def test_sync_needs_a_brought_up_guest(self) -> None:
        env = Env(self)
        err = exits_with(self, lambda: env.backend.sync(argparse.Namespace(rev=None)))
        self.assertIn("has not been brought up", err)


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


class UnexpectedFailureTests(unittest.TestCase):
    """Any failure ends in a message, cleanup and an exit status: 1, or 128+signal if one was recorded.
    Never a traceback."""

    def setUp(self) -> None:
        self.addCleanup(signal.signal, signal.SIGTERM, signal.getsignal(signal.SIGTERM))

    def run_up(self, env: Env, failure: str, with_signal: bool):
        def sigterm_once(counter=[]) -> None:
            counter.append(True)
            if len(counter) == 2:  # the count in `up`; the base-image pre-check is the first `vms` call
                os.kill(os.getpid(), signal.SIGTERM)

        if failure.startswith("tart list"):
            env.tart.vms_error = (
                subprocess.CalledProcessError(1, "tart list") if "non-zero" in failure else ValueError("bad json")
            )
            env.tart.vms_error_on_call = 2
            if with_signal:
                env.tart.hooks["vms"] = sigterm_once
        elif failure == "identity cannot be read":
            env.tart.identity_error = FileNotFoundError("disk.img")
            if with_signal:
                env.tart.hooks["clone"] = lambda: os.kill(os.getpid(), signal.SIGTERM)
        elif failure == "the claim cannot be written":

            def claim(name):
                if with_signal:
                    os.kill(os.getpid(), signal.SIGTERM)
                raise OSError(errno.ENOSPC, "No space left on device")

            env.backend._claim = claim
        with captured() as err:
            try:
                env.up()
            except SystemExit as e:
                return e.code, err.getvalue()
        return None, err.getvalue()

    def test_up_reports_every_failure_class_and_cleans_up(self) -> None:
        for failure in ("tart list exits non-zero", "tart list prints bad json", "identity cannot be read", "the claim cannot be written"):
            for with_signal in (False, True):
                with self.subTest(failure=failure, signal=with_signal):
                    env = Env(self)
                    code, err = self.run_up(env, failure, with_signal)
                    self.assertEqual(code, 128 + signal.SIGTERM if with_signal else 1, err)
                    self.assertIn("error:", err)
                    self.assertNotIn("Traceback", err)
                    env.assert_nothing_leaked(self)
                    self.assertIsNone(env.backend._gate, "the gate was left installed")

    def test_destroy_reports_a_failing_tart_list_as_a_message(self) -> None:
        for with_signal in (False, True):
            with self.subTest(signal=with_signal):
                env = Env(self)
                with captured():
                    env.up()
                env.tart.vms_error = subprocess.CalledProcessError(1, "tart list")
                if with_signal:
                    real = env.tart.vms
                    env.tart.vms = lambda gate=None: (os.kill(os.getpid(), signal.SIGTERM), real(gate))[1]
                with captured() as err, self.assertRaises(SystemExit) as ctx:
                    env.destroy()
                self.assertEqual(ctx.exception.code, 128 + signal.SIGTERM if with_signal else 1, err.getvalue())
                self.assertIn("error:", err.getvalue())
                self.assertIsNone(env.backend._gate)

    def test_the_identity_temp_file_does_not_outlive_a_failed_write(self) -> None:
        env = Env(self)
        with mock.patch.object(m.os, "replace", side_effect=OSError(errno.ENOSPC, "No space left on device")):
            with captured():
                with self.assertRaises(SystemExit):
                    env.up()
        self.assertEqual([p.name for p in env.sdir.glob("*.tmp")], [])


class RemoveVmTests(unittest.TestCase):
    def test_a_vm_that_is_not_listed_is_not_stopped_or_deleted(self) -> None:
        env = Env(self)
        self.assertIsNone(env.backend._remove_vm("devvm-macos-absent", None))
        self.assertNotIn("stop", env.tart.calls)
        self.assertNotIn("delete", env.tart.calls)


class DestroyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(self)
        with captured():
            self.env.up()
        (self.name,) = self.env.tart.local_names()

    def test_destroys_the_vm_it_created_and_clears_state(self) -> None:
        with captured():
            self.env.destroy()
        self.env.assert_nothing_leaked(self, procs=False)

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
        self.env.assert_nothing_leaked(self, procs=False)

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
        err = exits_with(self, self.env.destroy)
        self.assertIn("refusing to touch", err)
        self.assertIn(m.BASE_IMAGE, [v["Name"] for v in self.env.tart.vm_list])
        self.assertNotIn("stop", self.env.tart.calls)

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

    def test_status_survives_a_failing_tart_list_and_a_missing_tart(self) -> None:
        env = Env(self)
        with captured():
            env.up()
        for error in (subprocess.CalledProcessError(1, "tart"), ValueError("bad json"), OSError("gone"), RuntimeError("x")):
            with self.subTest(error=type(error).__name__):
                env.tart.vms_error = error
                self.assertTrue(env.backend.status().startswith("unknown"), env.backend.status())
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=True):
            no_tart = m.MacosBackend(None, env.repo, env.state)
            self.assertTrue(no_tart.status().startswith("unknown"), no_tart.status())

    def test_status_reports_each_state(self) -> None:
        env = Env(self)
        self.assertEqual(env.backend.status(), "not created")
        with captured():
            env.up()
        self.assertTrue(env.backend.status().startswith("running"))


class DispatchTests(unittest.TestCase):
    def test_each_guest_gets_its_backend_once(self) -> None:
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
