"""Tests of the disposable-machine guard and the polkit version check in unattended-gui-elevation.py."""

import importlib.util
import os
import pathlib
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


def run_main(argv, system, environ, present=(), geteuid=lambda: 0):
    """Runs `main` with recording enablers; returns (exit message or None, systems enabled)."""
    enabled = []
    enablers = {name: (lambda user, name=name: enabled.append((name, user))) for name in ("Linux", "Darwin", "Windows")}
    try:
        script.main(
            argv, system=system, environ=environ, exists=lambda path: path in present, enablers=enablers, geteuid=geteuid
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
    def refuse(self, user="runner", getpwnam=ordinary, **kwargs):
        """Runs `enable_linux` expecting a refusal that wrote nothing and ran nothing."""
        with (
            mock.patch.object(script.subprocess, "run", side_effect=AssertionError("ran a command")),
            mock.patch.object(script.os, "replace") as replace,
            mock.patch("builtins.open", side_effect=AssertionError("wrote a file")),
            self.assertRaises(SystemExit) as raised,
        ):
            script.enable_linux(user, getpwnam=getpwnam, **kwargs)
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
            script.enable_linux("runner", isdir=lambda p: True, init_comm=lambda p: "systemd", getpwnam=ordinary)
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
            script.enable_linux("runner", isdir=lambda p: True, init_comm=lambda p: "systemd", getpwnam=ordinary)
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
                "runner", isdir=lambda p: True, init_comm=lambda p: "systemd", getpwnam=ordinary, environ=environment
            )
        self.assertEqual(len(seen), 3)
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
    """A `winreg` that records writes and answers reads from `stored`."""

    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_SET_VALUE = 2
    KEY_QUERY_VALUE = 1
    KEY_WOW64_64KEY = 0x100
    REG_DWORD = 4

    def __init__(self, stored):
        self.stored = stored
        self.opened = []
        self.writes = []

    def OpenKey(self, hive, key, reserved, access):
        self.opened.append((hive, key, access))
        return mock.MagicMock()

    def SetValueEx(self, handle, name, reserved, kind, value):
        self.writes.append((name, kind, value))

    def QueryValueEx(self, handle, name):
        return self.stored


class EnableWindows(unittest.TestCase):
    def enable(self, stored):
        fake = FakeWinreg(stored)
        with mock.patch.dict("sys.modules", {"winreg": fake}):
            script.enable_windows()
        return fake

    def test_the_value_is_written_and_read_back_from_the_64_bit_view(self):
        fake = self.enable((0, 4))
        self.assertEqual(fake.writes, [("ConsentPromptBehaviorAdmin", 4, 0)])
        _, key, access = fake.opened[0]
        self.assertTrue(key.endswith(r"Policies\System"))
        # Mutant: the 64-bit view or the query right is dropped, so a 32-bit process reads another key.
        self.assertEqual(access, 2 | 1 | 0x100)

    def test_a_value_that_did_not_stick_is_a_failure(self):
        # Mutant: the read-back is dropped, so a mistyped name or a lost write prints "enabled".
        with self.assertRaises(SystemExit) as raised:
            self.enable((5, 4))
        self.assertIn("ConsentPromptBehaviorAdmin", str(raised.exception))

    def test_a_value_of_the_wrong_type_is_a_failure(self):
        # Mutant: the type is not compared.
        with self.assertRaises(SystemExit):
            self.enable((0, 1))


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
