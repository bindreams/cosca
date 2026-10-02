"""The real `Tart` wrapper against a stub tart executable that logs its argv, stdin and process group."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import devvm_macos as m

STUB = r"""#!/bin/sh
{ printf '%s\0' "$@"; printf '\n'; } >> "$STUB_DIR/argv"
ps -o pgid= -p $$ | tr -d ' ' >> "$STUB_DIR/pgid"
case "$1" in
list) cat "$STUB_DIR/list.json" ;;
exec) [ "$2" = "-i" ] && cat > "$STUB_DIR/stdin"; echo from-guest ;;
run) echo running ;;
esac
exit "$(cat "$STUB_DIR/rc" 2>/dev/null || echo 0)"
"""


class TartWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        stub = self.dir / "tart"
        stub.write_text(STUB)
        stub.chmod(0o755)
        (self.dir / "list.json").write_text(json.dumps([{"Name": "a", "Source": "local", "State": "running"}]))
        env = mock.patch.dict(os.environ, {"STUB_DIR": str(self.dir), "TART_HOME": str(self.dir / "home")})
        env.start()
        self.addCleanup(env.stop)
        self.tart = m.Tart(str(stub))

    def calls(self) -> list[list[str]]:
        raw = (self.dir / "argv").read_text()
        return [line.split("\0")[:-1] for line in raw.split("\n") if line]

    def pgids(self) -> list[int]:
        return [int(x) for x in (self.dir / "pgid").read_text().split()]

    def set_rc(self, rc: int) -> None:
        (self.dir / "rc").write_text(str(rc))

    def assert_own_session(self) -> None:
        self.assertNotIn(os.getpgrp(), self.pgids(), "the child shares our process group: a terminal Ctrl-C would reach it")

    def test_vms_parses_the_json_and_runs_list(self) -> None:
        self.assertEqual(self.tart.vms()[0]["Name"], "a")
        self.assertEqual(self.calls(), [["list", "--format", "json"]])
        self.assert_own_session()

    def test_vms_raises_when_tart_list_fails(self) -> None:
        self.set_rc(1)
        with self.assertRaises(subprocess.CalledProcessError):
            self.tart.vms()

    def test_clone_passes_source_and_name_and_returns_the_exit_code(self) -> None:
        self.set_rc(3)
        self.assertEqual(self.tart.clone("src", "dst"), 3)
        self.assertEqual(self.calls(), [["clone", "src", "dst"]])

    def test_start_runs_headless_in_its_own_session_and_logs_output(self) -> None:
        log = self.dir / "run.log"
        proc = self.tart.start("vm", log)
        proc.wait()
        self.assertEqual(self.calls(), [["run", "--no-graphics", "vm"]])
        self.assertIn("running", log.read_text())
        self.assert_own_session()

    def test_stop_and_delete_run_in_their_own_session(self) -> None:
        for verb in ("stop", "delete"):
            with self.subTest(verb=verb):
                (self.dir / "pgid").write_text("")
                self.assertEqual(getattr(self.tart, verb)("vm"), 0)
                self.assertEqual(self.calls()[-1], [verb, "vm"])
                self.assert_own_session()

    def test_exec_without_stdin_has_no_dash_i(self) -> None:
        self.tart.exec("vm", ["true"], capture_output=True)
        self.assertEqual(self.calls(), [["exec", "vm", "true"]])

    def test_exec_with_stdin_passes_dash_i_and_the_data(self) -> None:
        src = self.dir / "in.txt"
        src.write_text("payload")
        with open(src, "rb") as f:
            self.tart.exec("vm", ["cat"], stdin=f)
        self.assertEqual(self.calls(), [["exec", "-i", "vm", "cat"]])
        self.assertEqual((self.dir / "stdin").read_text(), "payload")

    def test_exec_popen_streams_stdout(self) -> None:
        proc = self.tart.exec_popen("vm", ["tar"], stdout=subprocess.PIPE)
        self.assertEqual(proc.stdout.read(), b"from-guest\n")
        proc.wait()
        self.assertEqual(self.calls(), [["exec", "vm", "tar"]])

    def test_identity_reads_the_disk_image_under_tart_home(self) -> None:
        disk = self.dir / "home" / "vms" / "vm" / "disk.img"
        disk.parent.mkdir(parents=True)
        disk.write_text("x")
        st = disk.stat()
        self.assertEqual(self.tart.identity("vm"), {"ino": st.st_ino, "dev": st.st_dev})
        with self.assertRaises(FileNotFoundError):
            self.tart.identity("missing")


class TartBinTests(unittest.TestCase):
    def test_tart_env_var_wins_and_must_be_a_file(self) -> None:
        with tempfile.NamedTemporaryFile() as f, mock.patch.dict(os.environ, {"TART": f.name}):
            self.assertEqual(m.tart_bin(), f.name)
        with mock.patch.dict(os.environ, {"TART": "/no/such/tart"}), self.assertRaises(RuntimeError):
            m.tart_bin()

    def test_path_lookup_and_a_clear_error_without_tart(self) -> None:
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=True), self.assertRaises(RuntimeError) as ctx:
            m.tart_bin()
        self.assertIn("tart not found", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
