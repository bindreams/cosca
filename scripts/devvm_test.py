"""Host-side unit tests for devvm.py's and devvm_windows.py's pure/host-only logic.

Deliberately small, by design, not by omission — covers stage_tree's two fixed bugs (stale
files not removed on re-stage; a tracked-but-since-deleted file crashing the stage instead of
being skipped), the run-argv-splitting function, powershell_quote, the diagnostic-route split
(_diag_write/build_run_inner) that picks Write-Host vs [Console]::Error.WriteLine depending on
whether WinRM has a host attached, cmd_run's/cmd_up's own pure validation branches (flag
combinations that exit before any vagrant/WinRM call is made), and devvm_windows.py's two pulled-
out pure functions (should_wait_for_session, parse_reboot_required_marker). Everything else in
either module shells out to vagrant/WinRM and is only meaningfully testable inside a real guest
(see scripts/README.md).

Run with: uv run python -m unittest scripts.devvm_test -v

Host-safe: every test here only touches a throwaway temp directory and spawns ordinary
short-lived git/rsync subprocesses of this repo's own tooling — it never touches real system
state (no sudo, no cgroups, no elevation), so it runs directly on this machine, not in a VM.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import devvm, devvm_windows

TEST_GUEST = devvm.Guest(name="devvm-test-guest", communicator="ssh", box="unused/for-tests")
TEST_WINDOWS_GUEST = devvm.Guest(
    name="devvm-test-windows-guest", communicator="winrm", box="unused/for-tests", tree_path_posix="C:/cosca"
)


def _run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _init_repo_with_tracked_files(repo: Path, files: dict[str, str]) -> None:
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "devvm-test@example.invalid")
    _run_git(repo, "config", "user.name", "devvm test")
    for name, content in files.items():
        (repo / name).write_text(content)
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "initial")


class StageTreeTests(unittest.TestCase):
    def test_removed_file_disappears_from_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            dest = Path(tmp) / "dest"
            _init_repo_with_tracked_files(repo, {"a.txt": "a", "b.txt": "b"})

            devvm.stage_tree(TEST_GUEST, repo_root=repo, dest=dest)
            self.assertTrue((dest / "a.txt").exists())
            self.assertTrue((dest / "b.txt").exists())

            _run_git(repo, "rm", "-q", "b.txt")
            devvm.stage_tree(TEST_GUEST, repo_root=repo, dest=dest)

            self.assertTrue((dest / "a.txt").exists())
            self.assertFalse((dest / "b.txt").exists())

    def test_tracked_but_missing_file_is_skipped_not_crashed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            dest = Path(tmp) / "dest"
            _init_repo_with_tracked_files(repo, {"a.txt": "a", "b.txt": "b"})

            # Deleted from disk WITHOUT `git rm` — `git ls-files` still lists it.
            (repo / "b.txt").unlink()

            devvm.stage_tree(TEST_GUEST, repo_root=repo, dest=dest)

            self.assertTrue((dest / "a.txt").exists())
            self.assertFalse((dest / "b.txt").exists())


class ParseRunArgvTests(unittest.TestCase):
    def test_plain_guest_and_command(self) -> None:
        head, unelevated, timeout, cmd_tail = devvm.parse_run_argv(["windows-x64", "--", "cargo", "build"])
        self.assertEqual(head, ["windows-x64"])
        self.assertFalse(unelevated)
        self.assertIsNone(timeout)
        self.assertEqual(cmd_tail, ["cargo", "build"])

    def test_unelevated_flag_anywhere_is_extracted(self) -> None:
        head, unelevated, _timeout, cmd_tail = devvm.parse_run_argv(["windows-x64", "--unelevated", "--", "whoami"])
        self.assertTrue(unelevated)
        self.assertNotIn("--unelevated", head)
        self.assertEqual(cmd_tail, ["whoami"])

    def test_timeout_flag_anywhere_is_extracted(self) -> None:
        head, unelevated, timeout, cmd_tail = devvm.parse_run_argv(
            ["windows-x64", "--timeout", "60", "--unelevated", "--", "whoami"]
        )
        self.assertEqual(timeout, 60)
        self.assertNotIn("--timeout", head)
        self.assertNotIn("60", head)
        self.assertTrue(unelevated)
        self.assertEqual(cmd_tail, ["whoami"])

    def test_no_double_dash_means_empty_cmd_tail(self) -> None:
        _head, _unelevated, _timeout, cmd_tail = devvm.parse_run_argv(["windows-x64"])
        self.assertEqual(cmd_tail, [])

    def test_timeout_equals_form_is_extracted(self) -> None:
        head, _unelevated, timeout, cmd_tail = devvm.parse_run_argv(["windows-x64", "--timeout=60", "--", "whoami"])
        self.assertEqual(timeout, 60)
        self.assertNotIn("--timeout=60", head)
        self.assertEqual(cmd_tail, ["whoami"])

    def test_bad_timeout_value_exits_cleanly_not_a_traceback(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            devvm.parse_run_argv(["windows-x64", "--timeout", "abc", "--", "whoami"])
        self.assertEqual(ctx.exception.code, 2)

    def test_bad_timeout_equals_value_exits_cleanly_not_a_traceback(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            devvm.parse_run_argv(["windows-x64", "--timeout=abc", "--", "whoami"])
        self.assertEqual(ctx.exception.code, 2)


class PowershellQuoteTests(unittest.TestCase):
    def test_plain_token_is_wrapped_in_single_quotes(self) -> None:
        quoted = devvm.powershell_quote("cargo")
        self.assertTrue(quoted.startswith("'"))
        self.assertTrue(quoted.endswith("'"))
        self.assertIn("cargo", quoted)

    def test_embedded_single_quote_is_doubled(self) -> None:
        quoted = devvm.powershell_quote("it's")
        self.assertIn("it''s", quoted)


class DiagWriteTests(unittest.TestCase):
    def test_direct_route_uses_write_host(self) -> None:
        stmt = devvm._diag_write(True, '"devvm: $_"')
        self.assertEqual(stmt, 'Write-Host "devvm: $_"')

    def test_nested_route_uses_console_error_writeline(self) -> None:
        stmt = devvm._diag_write(False, '"devvm: $_"')
        self.assertEqual(stmt, '[Console]::Error.WriteLine("devvm: $_")')


class BuildRunInnerTests(unittest.TestCase):
    def test_direct_route_diagnostics_use_write_host_only(self) -> None:
        inner = devvm.build_run_inner(TEST_WINDOWS_GUEST, ["cargo", "test"], direct=True)
        self.assertIn("Write-Host", inner)
        self.assertNotIn("[Console]::Error.WriteLine", inner)

    def test_nested_route_diagnostics_use_console_error_only(self) -> None:
        inner = devvm.build_run_inner(TEST_WINDOWS_GUEST, ["cargo", "test"], direct=False)
        self.assertIn("[Console]::Error.WriteLine", inner)
        self.assertNotIn("Write-Host", inner)

    def test_command_tokens_are_individually_quoted(self) -> None:
        inner = devvm.build_run_inner(TEST_WINDOWS_GUEST, ["cargo", "test", "it's a test"], direct=True)
        self.assertIn("& 'cargo' 'test' 'it''s a test'", inner)

    def test_exit_code_prefers_lastexitcode_falls_back_to_dollar_question(self) -> None:
        # Checks the generated structure, not an exact verbatim string: this only confirms the
        # PowerShell text sets up the LASTEXITCODE-preferred/$?-fallback decision and exits on
        # $__devvmExit, not that PowerShell actually evaluates it as intended — no PowerShell
        # engine runs in this test. The $?-survives-the-if-condition assumption this logic
        # relies on is live-verified on the real guest instead (see build_run_inner's
        # docstring): `run windows-x64 -- Get-Item C:\nope` exercises exactly this
        # no-$LASTEXITCODE/$?-fallback branch and exits nonzero end to end.
        inner = devvm.build_run_inner(TEST_WINDOWS_GUEST, ["cargo", "test"], direct=True)
        self.assertIn("$null -ne $LASTEXITCODE", inner)
        self.assertIn("$__devvmExit = $LASTEXITCODE", inner)
        self.assertIn("$__devvmExit = [int](-not $?)", inner)
        self.assertIn("$global:LASTEXITCODE = $null", inner)
        self.assertTrue(inner.endswith("exit $__devvmExit"))


def _forbid_subprocess_and_vagrant(test: unittest.TestCase) -> None:
    """Make a validation test that falls through its guard fail loudly instead of silently
    making a real `vagrant`/rsync call against this host. Two layers, since devvm.py imports
    `run_vagrant` by name (`from devvm_common import (..., run_vagrant, ...)`), which binds it
    into devvm's own module globals — patching `devvm_common.run_vagrant` afterwards would not
    touch that already-bound name (the same dual-module-identity trap `dotfile_dir` had; see
    CmdUpValidationTests below). So: patch the name devvm.py actually calls (`devvm.run_vagrant`)
    AND patch `subprocess.run`/`subprocess.Popen` globally, so a real subprocess launch is
    impossible regardless of which module's copy of which wrapper ends up being reached.
    """

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("validation should have exited before any vagrant/subprocess call")

    test.enterContext(mock.patch.object(devvm, "run_vagrant", _raise))
    test.enterContext(mock.patch.object(subprocess, "run", _raise))
    test.enterContext(mock.patch.object(subprocess, "Popen", _raise))


class CmdRunValidationTests(unittest.TestCase):
    # cmd_run does GUESTS[args.guest] internally, so these use real guest keys (not
    # TEST_GUEST/TEST_WINDOWS_GUEST). run_vagrant and subprocess are stubbed to raise loudly
    # (see _forbid_subprocess_and_vagrant) so that if a validation check regresses and falls
    # through, the test fails on that instead of silently making a real vagrant/rsync call
    # against this host.

    def setUp(self) -> None:
        _forbid_subprocess_and_vagrant(self)

    def test_unelevated_on_non_winrm_guest_exits(self) -> None:
        args = argparse.Namespace(guest="linux-x64", unelevated=True, timeout=None, cmd=["whoami"])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
            devvm.cmd_run(args)
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("--unelevated only applies to Windows guests", stderr.getvalue())

    def test_timeout_without_unelevated_exits(self) -> None:
        args = argparse.Namespace(guest="windows-x64", unelevated=False, timeout=60, cmd=["whoami"])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
            devvm.cmd_run(args)
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("--timeout only applies to --unelevated", stderr.getvalue())

    def test_non_positive_timeout_exits(self) -> None:
        # Boundary case: the reviewer mutation this guards against changed `timeout <= 0` to
        # `timeout < 0`, which would let exactly 0 fall through — so this uses 0, not a
        # negative value, to pin that boundary.
        args = argparse.Namespace(guest="windows-x64", unelevated=True, timeout=0, cmd=["whoami"])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
            devvm.cmd_run(args)
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("--timeout must be positive, got 0", stderr.getvalue())

    def test_timeout_over_max_exits(self) -> None:
        over_max = devvm.WINDOWS_RUN_UNELEVATED_MAX_TIMEOUT_SECONDS + 1
        args = argparse.Namespace(guest="windows-x64", unelevated=True, timeout=over_max, cmd=["whoami"])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
            devvm.cmd_run(args)
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn(
            f"--timeout must be at most {devvm.WINDOWS_RUN_UNELEVATED_MAX_TIMEOUT_SECONDS}", stderr.getvalue()
        )


class CmdUpValidationTests(unittest.TestCase):
    # cmd_up's own guard order (see its comment in devvm.py) runs --allow-elevation/--display
    # validation before dotfile_dir(guest).mkdir(...), so a real STATE_DIR is never even
    # consulted by a passing test. dotfile_dir is patched anyway, directly on `devvm` (the
    # module object devvm.py's own `cmd_up` resolves that name against at call time) rather than
    # on `devvm_common.STATE_DIR`: devvm.py imports `devvm_common` by inserting its own directory
    # onto sys.path and doing `from devvm_common import (...)`, which registers a *different*
    # module object under sys.modules["devvm_common"] than the one this test file's `from
    # scripts import devvm_common` binds — confirmed empirically
    # (`devvm.dotfile_dir is devvm_common.dotfile_dir` is False) — so patching
    # `devvm_common.STATE_DIR` here would not affect what devvm.py's own `cmd_up` actually calls.
    # run_vagrant and subprocess are also stubbed (see _forbid_subprocess_and_vagrant), as a
    # second line of defense if a validation check regresses and falls through anyway.

    def setUp(self) -> None:
        _forbid_subprocess_and_vagrant(self)

    def test_allow_elevation_on_non_winrm_guest_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(devvm, "dotfile_dir", lambda _guest: Path(tmp)):
                args = argparse.Namespace(guest="linux-x64", allow_elevation=True, display=False)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
                    devvm.cmd_up(args)
                self.assertEqual(ctx.exception.code, 1)
                self.assertIn("--allow-elevation only applies to Windows guests", stderr.getvalue())

    def test_display_on_non_winrm_guest_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(devvm, "dotfile_dir", lambda _guest: Path(tmp)):
                args = argparse.Namespace(guest="linux-x64", allow_elevation=None, display=True)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
                    devvm.cmd_up(args)
                self.assertEqual(ctx.exception.code, 1)
                self.assertIn("--display only applies to Windows guests", stderr.getvalue())


class ShouldWaitForSessionTests(unittest.TestCase):
    def test_started_guest_waits(self) -> None:
        self.assertTrue(devvm_windows.should_wait_for_session(started_guest=True, rebooted=False))

    def test_rebooted_waits(self) -> None:
        self.assertTrue(devvm_windows.should_wait_for_session(started_guest=False, rebooted=True))

    def test_both_waits(self) -> None:
        self.assertTrue(devvm_windows.should_wait_for_session(started_guest=True, rebooted=True))

    def test_neither_does_not_wait(self) -> None:
        self.assertFalse(devvm_windows.should_wait_for_session(started_guest=False, rebooted=False))


class ParseRebootRequiredMarkerTests(unittest.TestCase):
    def test_true_marker_is_true(self) -> None:
        self.assertIs(devvm_windows.parse_reboot_required_marker("blah\nDEVVM_REBOOT_REQUIRED=1\nblah"), True)

    def test_false_marker_is_false(self) -> None:
        self.assertIs(devvm_windows.parse_reboot_required_marker("blah\nDEVVM_REBOOT_REQUIRED=0\nblah"), False)

    def test_no_marker_is_none(self) -> None:
        self.assertIsNone(devvm_windows.parse_reboot_required_marker("blah\nno marker here\nblah"))

    def test_both_markers_present_prefers_true(self) -> None:
        # Matches provision_windows_guest's own caller checking REBOOT_MARKER_TRUE first (see
        # parse_reboot_required_marker's docstring).
        output = "DEVVM_REBOOT_REQUIRED=1\nDEVVM_REBOOT_REQUIRED=0"
        self.assertIs(devvm_windows.parse_reboot_required_marker(output), True)


if __name__ == "__main__":
    unittest.main()
