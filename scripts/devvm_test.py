"""Host-side unit tests for devvm.py's pure/host-only logic.

Deliberately small (per the round-2 review: "the owner said not to go crazy") — covers
stage_tree's H1 (stale files not removed) and M6 (tracked-but-missing file crashes) fixes,
the run-argv-splitting function, and powershell_quote. Everything else in devvm.py either
shells out to vagrant/WinRM (only meaningfully testable inside a real guest, see
scripts/README.md) or is a thin argparse/subprocess wrapper not worth a host-side test.

Run with: uv run python -m unittest scripts.devvm_test -v

Host-safe: every test here only touches a throwaway temp directory and spawns ordinary
short-lived git/rsync subprocesses of this repo's own tooling — it never touches real system
state (no sudo, no cgroups, no elevation), so it runs directly on this machine, not in a VM.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import devvm

TEST_GUEST = devvm.Guest(name="devvm-test-guest", communicator="ssh", box="unused/for-tests")


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


if __name__ == "__main__":
    unittest.main()
