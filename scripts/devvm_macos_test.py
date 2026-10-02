"""Host-side unit tests for devvm_macos.py's pure logic (VM cap, naming, command building).

Run with: uv run python -m unittest scripts.devvm_macos_test -v

Host-safe: nothing here calls tart or touches a VM.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts import devvm_macos as m


def _tart_list(*entries: tuple[str, str, str]) -> str:
    return json.dumps([{"Source": src, "Name": name, "State": state} for src, name, state in entries])


class CountRunningTests(unittest.TestCase):
    def test_counts_only_running_local_vms(self) -> None:
        out = _tart_list(
            ("local", "a", "running"),
            ("local", "b", "stopped"),
            ("OCI", "ghcr.io/x/y:latest", "stopped"),
            ("local", "c", "running"),
        )
        self.assertEqual(m.count_running(out), 2)

    def test_empty(self) -> None:
        self.assertEqual(m.count_running("[]"), 0)

    def test_suspended_is_not_running(self) -> None:
        self.assertEqual(m.count_running(_tart_list(("local", "a", "suspended"))), 0)


class CapTests(unittest.TestCase):
    def test_two_running_is_allowed_to_start_a_new_one_only_below_two(self) -> None:
        m.check_cap(0)
        m.check_cap(1)

    def test_third_vm_refused_with_clear_error(self) -> None:
        with self.assertRaises(m.CapExceeded) as ctx:
            m.check_cap(2)
        self.assertIn("2", str(ctx.exception))
        self.assertIn("licen", str(ctx.exception))


class NamingTests(unittest.TestCase):
    def test_names_are_unique_and_prefixed(self) -> None:
        a = m.new_vm_name(Path("/r"))
        b = m.new_vm_name(Path("/r"))
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith(m.VM_PREFIX))

    def test_destroy_refuses_foreign_names(self) -> None:
        with self.assertRaises(ValueError):
            m.require_own_name("macos-tahoe-base")
        with self.assertRaises(ValueError):
            m.require_own_name(m.BASE_IMAGE)


class RemoteCommandTests(unittest.TestCase):
    def test_quotes_args_and_sets_path_and_target_dir(self) -> None:
        cmd = m.build_remote_command(["cargo", "nextest", "run", "-E", "test(/a b/)"])
        self.assertIn('export PATH="$HOME/.cargo/bin:$PATH"', cmd)
        self.assertIn("cd ~/cosca", cmd)
        self.assertIn("CARGO_TARGET_DIR=$HOME/cargo-target", cmd)
        self.assertIn("'test(/a b/)'", cmd)


if __name__ == "__main__":
    unittest.main()
