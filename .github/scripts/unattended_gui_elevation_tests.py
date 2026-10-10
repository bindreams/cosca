"""Tests of the disposable-machine guard and the polkit version check in unattended-gui-elevation.py."""

import importlib.util
import json
import os
import pathlib
import plistlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "unattended_gui_elevation", pathlib.Path(__file__).with_name("unattended-gui-elevation.py")
)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

CI = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}


def refused(system, environ, present=()):
    try:
        script.require_disposable(system, environ=environ, exists=lambda path: path in present)
    except SystemExit as exit_:
        return str(exit_.code)
    return None


class Disposable(unittest.TestCase):
    def test_a_hosted_runner_is_disposable(self):
        for system in ("Linux", "Darwin", "Windows"):
            self.assertIsNone(refused(system, CI))

    def test_a_self_hosted_runner_is_not(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}
        self.assertIn("GITHUB_ACTIONS=true", refused("Linux", env))

    def test_each_ci_variable_alone_is_not_enough(self):
        self.assertIsNotNone(refused("Linux", {"GITHUB_ACTIONS": "true"}))
        self.assertIsNotNone(refused("Linux", {"RUNNER_ENVIRONMENT": "github-hosted"}))
        self.assertIsNotNone(refused("Linux", {"GITHUB_ACTIONS": "false", "RUNNER_ENVIRONMENT": "github-hosted"}))

    def test_a_developer_machine_is_refused_naming_what_is_missing(self):
        message = refused("Darwin", {})
        self.assertIn("RUNNER_ENVIRONMENT=github-hosted", message)
        self.assertIn(script.DEVVM_MARKER, message)

    def test_a_container_is_not_disposable(self):
        # Mutant: a container marker is accepted again.
        for marker in ("/.dockerenv", "/run/.containerenv"):
            self.assertIsNotNone(refused("Linux", {}, present=(marker,)))

    def test_the_devvm_marker_counts_on_linux_and_macos_only(self):
        self.assertIsNone(refused("Linux", {}, present=(script.DEVVM_MARKER,)))
        self.assertIsNone(refused("Darwin", {}, present=(script.DEVVM_MARKER,)))
        self.assertIsNotNone(refused("Windows", {}, present=(script.DEVVM_MARKER,)))


def run_main(argv, system, environ, present=(), geteuid=lambda: 0, state_path=None, reverters=None):
    """Runs `main` with recording enablers and reverters; returns (exit message or None, systems enabled)."""
    enabled = []
    enablers = {name: (lambda user, save, name=name: enabled.append((name, user))) for name in ("Linux", "Darwin", "Windows")}
    reverted = reverters or {
        name: (lambda user, prior, name=name: enabled.append(("revert " + name, user))) for name in ("Linux", "Darwin", "Windows")
    }
    with tempfile.TemporaryDirectory() as scratch:
        try:
            script.main(
                argv,
                system=system,
                environ=environ,
                exists=lambda path: path in present,
                enablers=enablers,
                reverters=reverted,
                geteuid=geteuid,
                state_path=state_path or os.path.join(scratch, "state.json"),
            )
        except SystemExit as exit_:
            return str(exit_.code), enabled
    return None, enabled


class Main(unittest.TestCase):
    FLAG = "--this-machine-is-disposable"

    def test_it_refuses_without_the_flag_even_on_a_runner(self):
        # Mutant: the flag check is deleted.
        message, enabled = run_main([], "Linux", CI)
        self.assertIsNotNone(message, "it ran without the flag")
        self.assertIn(self.FLAG, message)
        self.assertEqual(enabled, [])

    def test_the_guard_runs_before_any_change(self):
        # Mutant: the guard runs after `enable_*`.
        message, enabled = run_main([self.FLAG, "--user", "u"], "Linux", {})
        self.assertIsNotNone(message, "it ran on a machine that is not disposable")
        self.assertIn("disposable machine", message)
        self.assertEqual(enabled, [])

    def test_a_disposable_machine_is_enabled(self):
        message, enabled = run_main([self.FLAG, "--user", "u"], "Linux", CI)
        self.assertIsNone(message)
        self.assertEqual(enabled, [("Linux", "u")])

    def test_user_is_rejected_off_linux_before_the_guard_or_a_change(self):
        for system in ("Darwin", "Windows"):
            # With no CI variables the guard would refuse too: the `--user` message must come first.
            message, enabled = run_main([self.FLAG, "--user", "u"], system, {})
            self.assertIsNotNone(message, f"--user was accepted on {system}")
            self.assertIn("--user applies to Linux only", message)
            self.assertEqual(enabled, [])

    def test_an_unsupported_platform_is_refused(self):
        message, enabled = run_main([self.FLAG], "Plan9", CI)
        self.assertIn("unsupported platform", message)
        self.assertEqual(enabled, [])

    def test_check_only_changes_nothing(self):
        message, enabled = run_main([self.FLAG, "--check-only"], "Darwin", CI)
        self.assertIsNone(message)
        self.assertEqual(enabled, [])
        message, _ = run_main([self.FLAG, "--check-only"], "Darwin", {})
        self.assertIn("disposable machine", message)


def ordinary(name):
    return SimpleNamespace(pw_uid=1000)


class EnableLinux(unittest.TestCase):
    @staticmethod
    def no_save(prior):
        raise AssertionError("saved a state")

    def refuse(self, user="runner", getpwnam=ordinary, **kwargs):
        """Runs `enable_linux` expecting a refusal that wrote nothing and ran nothing."""
        with (
            mock.patch.object(script.subprocess, "run", side_effect=AssertionError("ran a command")),
            mock.patch.object(script.os, "replace") as replace,
            mock.patch("builtins.open", side_effect=AssertionError("wrote a file")),
            self.assertRaises(SystemExit) as raised,
        ):
            script.enable_linux(user, self.no_save, getpwnam=getpwnam, **kwargs)
        replace.assert_not_called()
        return str(raised.exception)

    def test_without_systemd_it_refuses(self):
        # Mutant: the non-systemd case is let through.
        message = self.refuse(isdir=lambda path: False, init_comm=lambda pid: "bash")
        self.assertIn("systemd as PID 1", message)

    def test_a_systemd_runtime_without_systemd_as_init_is_refused(self):
        message = self.refuse(isdir=lambda path: True, init_comm=lambda pid: "bash")
        self.assertIn("systemd as PID 1", message)

    def test_a_missing_user_is_refused_before_anything_else(self):
        # Mutant: the user is not looked up.
        def missing(name):
            raise KeyError(name)

        message = self.refuse(user="nobody-here", getpwnam=missing, isdir=lambda p: True, init_comm=lambda p: "systemd")
        self.assertIn("is not an account", message)

    def test_root_is_refused_because_polkit_always_authorizes_it(self):
        # Mutant: uid 0 is accepted, which makes the post-check vacuous.
        message = self.refuse(
            user="root",
            getpwnam=lambda name: SimpleNamespace(pw_uid=0),
            isdir=lambda p: True,
            init_comm=lambda p: "systemd",
        )
        self.assertIn("is root", message)

    def test_every_tool_is_checked_before_the_rule_is_written(self):
        # Mutant: the tool check comes after `os.replace`.
        with (
            mock.patch.object(script.shutil, "which", lambda tool: None if tool == "systemctl" else "/usr/bin/" + tool),
            mock.patch.object(script.os, "replace") as replace,
            mock.patch("builtins.open", side_effect=AssertionError("wrote a file")),
            self.assertRaises(SystemExit) as raised,
        ):
            script.enable_linux("runner", self.no_save, isdir=lambda p: True, init_comm=lambda p: "systemd", getpwnam=ordinary)
        self.assertIn("systemctl", str(raised.exception))
        replace.assert_not_called()

    def test_an_unreadable_version_is_reported_as_such_before_anything_is_written(self):
        version = SimpleNamespace(stdout="who knows")
        with (
            mock.patch.object(script.shutil, "which", lambda tool: "/usr/bin/" + tool),
            mock.patch.object(script.subprocess, "run", return_value=version),
            mock.patch.object(script.os, "replace") as replace,
            self.assertRaises(SystemExit) as raised,
        ):
            script.enable_linux("runner", self.no_save, isdir=lambda p: True, init_comm=lambda p: "systemd", getpwnam=ordinary)
        self.assertIn("could not parse", str(raised.exception))
        replace.assert_not_called()

    def test_commands_run_without_the_callers_bus_or_systemctl_selection(self):
        # Mutant: the caller's environment is passed through.
        environment = {
            "PATH": "/usr/bin",
            "SYSTEMCTL_FORCE_BUS": "1",
            "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/x",
            "HOME": "/root",
        }
        clean = {"PATH": "/usr/bin", "HOME": "/root"}
        self.assertEqual(script.scrubbed_environment(environment), clean)
        seen = []

        def fake_run(command, **kwargs):
            seen.append(kwargs.get("env"))
            return SimpleNamespace(stdout="pkaction version 127", stderr="", returncode=0)

        with (
            mock.patch.object(script.shutil, "which", lambda tool: "/usr/bin/" + tool),
            mock.patch.object(script.subprocess, "run", fake_run),
            mock.patch.object(script.os, "replace"),
            mock.patch.object(script.os, "chmod"),
            mock.patch("builtins.open", mock.mock_open()),
            self.assertRaises(SystemExit),  # the last pkexec check sees stdout "pkaction ..." instead of "0"
        ):
            script.enable_linux(
                "runner",
                lambda prior: None,
                isdir=lambda p: True,
                init_comm=lambda p: "systemd",
                getpwnam=ordinary,
                environ=environment,
            )
        self.assertEqual(len(seen), 4)  # pkaction, the pkexec before, systemctl, the pkexec after
        for env in seen:
            self.assertEqual(env, clean)


class Root(unittest.TestCase):
    FLAG = "--this-machine-is-disposable"

    def test_a_posix_run_without_root_is_refused_before_any_change(self):
        # Mutant: the root check is dropped, so `security` may prompt and hang a headless guest.
        for system in ("Linux", "Darwin"):
            message, enabled = run_main([self.FLAG], system, CI, geteuid=lambda: 1000)
            self.assertIn("needs root", message)
            self.assertEqual(enabled, [])

    def test_windows_has_no_euid_to_check(self):
        message, enabled = run_main([self.FLAG], "Windows", CI, geteuid=None)
        self.assertIsNone(message)
        self.assertEqual(enabled, [("Windows", None)])

    def test_check_only_needs_no_root(self):
        message, _ = run_main([self.FLAG, "--check-only"], "Linux", CI, geteuid=lambda: 1000)
        self.assertIsNone(message)


class FakeWinreg:
    """A `winreg` over one value; `initial` is its (value, type) or None for absent."""

    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_SET_VALUE = 2
    KEY_QUERY_VALUE = 1
    KEY_WOW64_64KEY = 0x100
    REG_DWORD = 4
    REG_SZ = 1

    def __init__(self, initial, ignore_writes=False, ignore_deletes=False, store_type=None):
        self.stored = initial
        self.ignore_writes = ignore_writes
        self.ignore_deletes = ignore_deletes
        self.store_type = store_type
        self.opened = []
        self.writes = []

    def OpenKey(self, hive, key, reserved, access):
        self.opened.append((hive, key, access))
        return mock.MagicMock()

    def SetValueEx(self, handle, name, reserved, kind, value):
        self.writes.append((name, kind, value))
        if not self.ignore_writes:
            self.stored = (value, self.store_type or kind)

    def DeleteValue(self, handle, name):
        if self.stored is None:
            raise FileNotFoundError(name)
        if not self.ignore_deletes:
            self.stored = None

    def QueryValueEx(self, handle, name):
        if self.stored is None:
            raise FileNotFoundError(name)
        return self.stored


class EnableWindows(unittest.TestCase):
    def run_script(self, fake, function):
        with mock.patch.dict("sys.modules", {"winreg": fake}):
            function()

    def enable(self, initial, saved=None, **kwargs):
        fake = FakeWinreg(initial, **kwargs)
        self.run_script(fake, lambda: script.enable_windows(saved.append if saved is not None else lambda prior: None))
        return fake

    def revert(self, fake, prior):
        self.run_script(fake, lambda: script.revert_windows(prior))

    def test_the_value_is_written_and_read_back_from_the_64_bit_view(self):
        fake = self.enable((5, 4))
        self.assertEqual(fake.writes, [("ConsentPromptBehaviorAdmin", 4, 0)])
        _, key, access = fake.opened[0]
        self.assertTrue(key.endswith(r"Policies\System"))
        # Mutant: the 64-bit view or the query right is dropped, so a 32-bit process reads another key.
        self.assertEqual(access, 2 | 1 | 0x100)

    def test_a_value_that_did_not_stick_is_a_failure(self):
        # Mutant: the read-back is dropped, so a mistyped name or a lost write prints "enabled".
        with self.assertRaises(SystemExit) as raised:
            self.enable((5, 4), ignore_writes=True)
        self.assertIn("ConsentPromptBehaviorAdmin", str(raised.exception))

    def test_a_value_of_the_wrong_type_is_a_failure(self):
        # Mutant: the type is not compared.
        with self.assertRaises(SystemExit):
            self.enable((5, 4), store_type=1)

    def test_the_prior_value_and_type_are_saved_before_the_write(self):
        saved = []
        self.enable((5, 1), saved=saved)
        self.assertEqual(saved, [{"present": True, "value": 5, "type": 1}])

    def test_an_absent_value_is_saved_as_absent(self):
        saved = []
        self.enable(None, saved=saved)
        self.assertEqual(saved, [{"present": False}])

    def test_enable_then_revert_restores_the_saved_value_and_type(self):
        for initial in ((5, 4), ("2", 1)):
            saved = []
            fake = self.enable(initial, saved=saved)
            self.assertEqual(fake.stored, (0, 4))
            self.revert(fake, saved[0])
            # Mutant: the revert skips restoring, or restores a default instead of the saved value.
            self.assertEqual(fake.stored, initial)

    def test_enable_then_revert_deletes_a_value_that_was_absent(self):
        saved = []
        fake = self.enable(None, saved=saved)
        self.revert(fake, saved[0])
        self.assertIsNone(fake.stored)

    def test_a_revert_that_did_not_stick_is_a_failure(self):
        # Mutant: the read-back after restoring is dropped.
        with self.assertRaises(SystemExit):
            self.revert(FakeWinreg((0, 4), ignore_writes=True), {"present": True, "value": 5, "type": 4})

    def test_a_deletion_that_did_not_stick_is_a_failure(self):
        with self.assertRaises(SystemExit):
            self.revert(FakeWinreg((0, 4), ignore_deletes=True), {"present": False})

    def test_reverting_an_absent_value_twice_is_fine(self):
        fake = FakeWinreg(None)
        self.revert(fake, {"present": False})
        self.assertIsNone(fake.stored)


class FakeSecurity:
    """A `security authorizationdb` over one right."""

    def __init__(self, right, ignore_restore=False):
        self.right = right
        self.ignore_restore = ignore_restore
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        assert command[:2] == ["security", "authorizationdb"], command
        if command[2] == "read":
            return SimpleNamespace(stdout=plistlib.dumps(self.right), returncode=0)
        if len(command) == 5:  # write <right> allow
            self.right = {"class": "rule", "rule": [command[4]]}
        elif not self.ignore_restore:
            self.right = plistlib.loads(kwargs["input"])
        return SimpleNamespace(stdout=b"", returncode=0)


class MacOS(unittest.TestCase):
    PRIOR = {"class": "rule", "rule": ["authenticate-admin-nolimit"], "comment": "kept"}

    def enable(self, fake):
        saved = []
        with mock.patch.object(script.subprocess, "run", fake):
            script.enable_macos(saved.append)
        return saved[0]

    def revert(self, fake, prior):
        with mock.patch.object(script.subprocess, "run", fake):
            script.revert_macos(prior)

    def test_enable_then_revert_restores_the_saved_right(self):
        fake = FakeSecurity(self.PRIOR)
        prior = self.enable(fake)
        self.assertEqual(fake.right["rule"], ["allow"])
        self.revert(fake, prior)
        # Mutant: the revert skips restoring, or writes a default rule instead of the saved one.
        self.assertEqual(fake.right, self.PRIOR)

    def test_the_right_is_saved_before_the_write(self):
        fake = FakeSecurity(self.PRIOR)
        self.enable(fake)
        self.assertEqual(fake.calls[0][2], "read")
        self.assertEqual(fake.calls[1][2], "write")

    def test_the_databases_own_modified_timestamp_is_not_compared(self):
        # Measured on a hosted macOS runner: restoring the right sets `modified` to the time of the write.
        fake = FakeSecurity({**self.PRIOR, "modified": 1.0})
        prior = self.enable(fake)
        original_write = fake.__call__

        def restamping(command, **kwargs):
            result = original_write(command, **kwargs)
            if command[2] == "write" and "input" in kwargs:
                fake.right = {**fake.right, "modified": 2.0}
            return result

        self.revert(restamping, prior)
        self.assertEqual(fake.right["rule"], self.PRIOR["rule"])

    def test_a_restore_that_did_not_stick_is_a_failure(self):
        # Mutant: the read-back after restoring is dropped.
        fake = FakeSecurity(self.PRIOR)
        prior = self.enable(fake)
        fake.ignore_restore = True
        with self.assertRaises(SystemExit):
            self.revert(fake, prior)


class FakePolkit:
    """`subprocess.run` for the Linux commands; the user is granted `pkexec` while the rule file exists."""

    def __init__(self, rule_path, granted_without_rule=False):
        self.rule_path = rule_path
        self.granted_without_rule = granted_without_rule
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command[0])
        if command[0] == "pkaction":
            return SimpleNamespace(stdout="pkaction version 127", stderr="", returncode=0)
        if command[0] == "runuser":
            if os.path.exists(self.rule_path) or self.granted_without_rule:
                return SimpleNamespace(stdout="0\n", stderr="", returncode=0)
            return SimpleNamespace(stdout="", stderr="not authorized", returncode=126)
        return SimpleNamespace(stdout="", stderr="", returncode=0)


class Linux(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.rule = os.path.join(scratch.name, "49-cosca-unattended.rules")
        self.state = os.path.join(scratch.name, "state.json")

    def main(self, argv, polkit, geteuid=lambda: 0):
        enablers = {
            "Linux": lambda user, save: script.enable_linux(
                user,
                save,
                isdir=lambda p: True,
                init_comm=lambda p: "systemd",
                getpwnam=ordinary,
                rule_path=self.rule,
            )
        }
        reverters = {"Linux": lambda user, prior: script.revert_linux(user, prior, rule_path=self.rule)}
        with (
            mock.patch.object(script.shutil, "which", lambda tool: "/usr/bin/" + tool),
            mock.patch.object(script.subprocess, "run", polkit),
        ):
            script.main(
                ["--this-machine-is-disposable", *argv],
                system="Linux",
                environ=CI,
                enablers=enablers,
                reverters=reverters,
                geteuid=geteuid,
                state_path=self.state,
            )

    def test_enable_then_revert_leaves_no_rule_and_no_state(self):
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner"], polkit)
        self.assertTrue(os.path.exists(self.rule))
        self.assertTrue(os.path.exists(self.state))
        self.main(["--user", "runner", "--revert"], polkit)
        # Mutant: the revert skips removing the rule.
        self.assertFalse(os.path.exists(self.rule))
        self.assertFalse(os.path.exists(self.state))
        self.assertEqual(polkit.commands.count("systemctl"), 2)

    def test_a_rule_that_existed_is_restored_not_removed(self):
        # Mutant: the revert removes the rule file even when it was there before.
        with open(self.rule, "w", encoding="ascii") as handle:
            handle.write("// the machine's own rule\n")
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner"], polkit)
        self.main(["--user", "runner", "--revert"], polkit)
        with open(self.rule, encoding="ascii") as handle:
            self.assertEqual(handle.read(), "// the machine's own rule\n")

    def test_a_revert_where_polkit_still_grants_is_a_failure(self):
        # Mutant: the revert does not confirm that polkit no longer grants.
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner"], polkit)
        polkit.granted_without_rule = True
        with self.assertRaises(SystemExit) as raised:
            self.main(["--user", "runner", "--revert"], polkit)
        self.assertIn("still differs", str(raised.exception))
        self.assertTrue(os.path.exists(self.state), "the state file must survive a failed revert")

    def test_a_prior_rule_comes_back_byte_for_byte_with_its_mode(self):
        # Mutant: the rule is read as text, or restored with a fixed mode.
        original = b"// crlf\r\n\xff\xfe not text\r\n"
        with open(self.rule, "wb") as handle:
            handle.write(original)
        os.chmod(self.rule, 0o600)
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner"], polkit)
        self.assertEqual(os.stat(self.rule).st_mode & 0o777, 0o644)
        self.main(["--user", "runner", "--revert"], polkit)
        with open(self.rule, "rb") as handle:
            self.assertEqual(handle.read(), original)
        self.assertEqual(os.stat(self.rule).st_mode & 0o777, 0o600)

    def test_a_failed_enable_leaves_no_temporary_rule(self):
        # Mutant: the temporary file is not removed when the replace fails.
        polkit = FakePolkit(self.rule)
        with mock.patch.object(script.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                self.main(["--user", "runner"], polkit)
        self.assertFalse(os.path.exists(self.rule + ".new"))

    def test_a_failed_revert_leaves_no_temporary_rule(self):
        with open(self.rule, "wb") as handle:
            handle.write(b"prior")
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner"], polkit)
        with mock.patch.object(script.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                self.main(["--user", "runner", "--revert"], polkit)
        self.assertFalse(os.path.exists(self.rule + ".new"))

    def test_a_grant_that_existed_before_is_not_a_failure_to_revert(self):
        polkit = FakePolkit(self.rule, granted_without_rule=True)
        self.main(["--user", "runner"], polkit)
        self.main(["--user", "runner", "--revert"], polkit)
        self.assertFalse(os.path.exists(self.rule))

    def test_revert_with_no_state_does_nothing(self):
        # Mutant: a missing state file raises.
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner", "--revert"], polkit)
        self.assertEqual(polkit.commands, [])

    def test_revert_needs_the_user(self):
        with self.assertRaises(SystemExit) as raised:
            self.main(["--revert"], FakePolkit(self.rule))
        self.assertIn("--user is required", str(raised.exception))

    def test_a_state_file_for_another_user_is_refused(self):
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner"], polkit)
        with self.assertRaises(SystemExit) as raised:
            self.main(["--user", "other", "--revert"], polkit)
        self.assertIn("not for 'Linux' with --user 'other'", str(raised.exception))
        self.assertTrue(os.path.exists(self.rule))

    def test_a_second_enable_is_refused(self):
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner"], polkit)
        with self.assertRaises(SystemExit) as raised:
            self.main(["--user", "runner"], polkit)
        self.assertIn("run --revert first", str(raised.exception))

    def test_revert_needs_root_before_any_change(self):
        polkit = FakePolkit(self.rule)
        self.main(["--user", "runner"], polkit)
        with self.assertRaises(SystemExit) as raised:
            self.main(["--user", "runner", "--revert"], polkit, geteuid=lambda: 1000)
        self.assertIn("needs root", str(raised.exception))
        self.assertTrue(os.path.exists(self.rule))


class Revert(unittest.TestCase):
    FLAG = "--this-machine-is-disposable"

    def state(self, system, user=None, prior=None):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        path = os.path.join(scratch.name, "state.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"system": system, "user": user, "prior": prior or {}}, handle)
        return path

    def test_revert_runs_the_same_guard_as_enable(self):
        # Mutant: the guard is skipped for --revert.
        message, ran = run_main([self.FLAG, "--revert"], "Darwin", {})
        self.assertIn("disposable machine", message)
        self.assertEqual(ran, [])

    def test_revert_needs_the_flag(self):
        message, ran = run_main(["--revert"], "Darwin", CI)
        self.assertIn(self.FLAG, message)
        self.assertEqual(ran, [])

    def test_revert_needs_root_on_posix(self):
        for system, argv in (("Linux", ["--user", "u"]), ("Darwin", [])):
            message, ran = run_main([self.FLAG, "--revert", *argv], system, CI, geteuid=lambda: 1000)
            self.assertIn("needs root", message)
            self.assertEqual(ran, [])

    def test_revert_with_a_state_file_runs_the_reverter_and_removes_the_file(self):
        path = self.state("Darwin")
        message, ran = run_main([self.FLAG, "--revert"], "Darwin", CI, state_path=path)
        self.assertIsNone(message)
        self.assertEqual(ran, [("revert Darwin", None)])
        self.assertFalse(os.path.exists(path))

    def test_a_state_file_for_another_os_is_refused(self):
        path = self.state("Linux", "u")
        message, ran = run_main([self.FLAG, "--revert"], "Darwin", CI, state_path=path)
        self.assertIn("was written for 'Linux'", message)
        self.assertEqual(ran, [])
        self.assertTrue(os.path.exists(path))

    def test_revert_without_state_does_nothing_on_every_os(self):
        for system, argv in (("Darwin", []), ("Windows", []), ("Linux", ["--user", "u"])):
            message, ran = run_main([self.FLAG, "--revert", *argv], system, CI, geteuid=lambda: 0)
            self.assertIsNone(message)
            self.assertEqual(ran, [])

    def test_revert_and_check_only_are_exclusive(self):
        message, _ = run_main([self.FLAG, "--revert", "--check-only"], "Darwin", CI)
        self.assertIsNotNone(message)

    def test_a_failed_revert_keeps_the_state_file(self):
        path = self.state("Darwin")

        def failing(user, prior):
            sys.exit("restore failed")

        message, _ = run_main([self.FLAG, "--revert"], "Darwin", CI, state_path=path, reverters={"Darwin": failing})
        self.assertEqual(message, "restore failed")
        self.assertTrue(os.path.exists(path))


class PolkitRule(unittest.TestCase):
    def test_the_user_pattern_accepts_account_names_and_rejects_script_injection(self):
        for name in ("runner", "vagrant", "_apt", "a.b-c", "User1"):
            self.assertTrue(script.USER_PATTERN.fullmatch(name), name)
        for name in ("", "1abc", 'a"b', "a b", "a;b", "a\nb", "a'+'b"):
            self.assertFalse(script.USER_PATTERN.fullmatch(name), repr(name))

    def test_the_rule_allows_exactly_that_user_every_action(self):
        rule = script.POLKIT_RULE.format(user="runner")
        self.assertIn('subject.user == "runner"', rule)
        self.assertIn("polkit.Result.YES", rule)
        self.assertEqual(rule.count("addRule"), 1)


class PolkitVersion(unittest.TestCase):
    def test_javascript_rules_need_0_106(self):
        self.assertFalse(script.polkit_supports_javascript_rules("pkaction version 0.105"))
        self.assertTrue(script.polkit_supports_javascript_rules("pkaction version 0.106"))
        self.assertTrue(script.polkit_supports_javascript_rules("pkaction version 0.120"))
        self.assertTrue(script.polkit_supports_javascript_rules("pkaction version 127"))

    def test_an_unparsable_version_is_not_a_too_old_one(self):
        self.assertIsNone(script.polkit_supports_javascript_rules("pkaction version unknown"))


if __name__ == "__main__":
    unittest.main()
