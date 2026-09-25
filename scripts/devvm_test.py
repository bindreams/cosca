"""Host-side unit tests for devvm.py's pure/host-only logic.

Deliberately small, by design, not by omission — covers stage_tree's two fixed bugs (stale
files not removed on re-stage; a tracked-but-since-deleted file crashing the stage instead of
being skipped), the run-argv-splitting function, powershell_quote, the diagnostic-route split
(_diag_write/build_run_inner) that picks Write-Host vs [Console]::Error.WriteLine depending on
whether WinRM has a host attached, and cmd_run's/cmd_up's own pure validation branches (flag
combinations that exit before any vagrant/WinRM call is made). Everything else in devvm.py
shells out to vagrant/WinRM and is only meaningfully testable inside a real guest (see
scripts/README.md).

Run with: uv run python -m unittest scripts.devvm_test -v

Host-safe: every test here only touches a throwaway temp directory and spawns ordinary
short-lived git/rsync subprocesses of this repo's own tooling — it never touches real system
state (no sudo, no cgroups, no elevation), so it runs directly on this machine, not in a VM.
"""

from __future__ import annotations

import argparse
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import devvm, devvm_common

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


class CmdRunValidationTests(unittest.TestCase):
    # cmd_run does GUESTS[args.guest] internally, so these use real guest keys (not
    # TEST_GUEST/TEST_WINDOWS_GUEST) — and none of these reach a vagrant/WinRM call, since
    # every branch here exits before build_run_inner is ever built.

    def test_unelevated_on_non_winrm_guest_exits(self) -> None:
        args = argparse.Namespace(guest="linux-x64", unelevated=True, timeout=None, cmd=["whoami"])
        with self.assertRaises(SystemExit):
            devvm.cmd_run(args)

    def test_timeout_without_unelevated_exits(self) -> None:
        args = argparse.Namespace(guest="windows-x64", unelevated=False, timeout=60, cmd=["whoami"])
        with self.assertRaises(SystemExit):
            devvm.cmd_run(args)

    def test_non_positive_timeout_exits(self) -> None:
        args = argparse.Namespace(guest="windows-x64", unelevated=True, timeout=0, cmd=["whoami"])
        with self.assertRaises(SystemExit):
            devvm.cmd_run(args)

    def test_timeout_over_max_exits(self) -> None:
        args = argparse.Namespace(
            guest="windows-x64",
            unelevated=True,
            timeout=devvm.WINDOWS_RUN_UNELEVATED_MAX_TIMEOUT_SECONDS + 1,
            cmd=["whoami"],
        )
        with self.assertRaises(SystemExit):
            devvm.cmd_run(args)


class CmdUpValidationTests(unittest.TestCase):
    # cmd_up's second statement is dotfile_dir(guest).mkdir(...). dotfile_dir lives in
    # devvm_common.py and resolves STATE_DIR against that module's own globals, not devvm's —
    # so devvm_common.STATE_DIR (not devvm.STATE_DIR) is patched to a throwaway temp directory,
    # so that mkdir call never touches this repo's real .tmp/devvm, before either validation
    # check below runs.

    def test_allow_elevation_on_non_winrm_guest_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(devvm_common, "STATE_DIR", Path(tmp)):
                args = argparse.Namespace(guest="linux-x64", allow_elevation=True, display=False)
                with self.assertRaises(SystemExit):
                    devvm.cmd_up(args)

    def test_display_on_non_winrm_guest_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(devvm_common, "STATE_DIR", Path(tmp)):
                args = argparse.Namespace(guest="linux-x64", allow_elevation=None, display=True)
                with self.assertRaises(SystemExit):
                    devvm.cmd_up(args)


if __name__ == "__main__":
    unittest.main()
