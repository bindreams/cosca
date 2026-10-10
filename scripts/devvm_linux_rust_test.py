"""scripts/devvm/provision/linux-rust.sh's apt block, run against stub commands.

Stub `sudo`, `systemctl`, `apt-get` and `cloud-init` sit alone on PATH (plus the few real tools the
script's tail needs) and log each call to a file, so a test asserts the call sequence and the exit
status. The cargo tail runs too: a stub cargo and cargo-nextest at the pinned version make it skip
every download. Host-safe: nothing here touches real system state.

Run with: python3 -m unittest scripts.devvm_linux_rust_test -v
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "devvm" / "provision" / "linux-rust.sh"
NEXTEST_VERSION = re.search(r'NEXTEST_TAG_X86_64="cargo-nextest-([\d.]+)"', SCRIPT.read_text(encoding="utf-8"))[1]
REAL_TOOLS = ("bash", "awk", "head", "uname", "rm", "mkdir", "tar", "curl", "sha256sum", "shasum", "cat", "env")
TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer")
SERVICES = ("apt-daily.service", "apt-daily-upgrade.service", "unattended-upgrades.service")
LOCK_FLAG = "DPkg::Lock::Timeout=-1"

# Each stub logs "<name> <args>" to $STUB_LOG. Behaviour comes from the environment.
STUBS = {
    "sudo": """\
while [ $# -gt 0 ]; do
    case "$1" in
    *=*) export "$1"; shift ;;
    *) break ;;
    esac
done
exec "$@"
""",
    "systemctl": """\
echo "systemctl $*" >>"$STUB_LOG"
unit="${*: -1}"
case "$1" in
is-active) case " $STUB_ACTIVE " in *" $unit "*) exit 0 ;; *) exit 3 ;; esac ;;
show)
    case " $STUB_NOT_LOADED " in *" $unit "*) echo not-found ;; *) echo loaded ;; esac
    exit 0 ;;
stop) case " $STUB_STOP_FAIL " in *" $unit "*) exit 1 ;; esac ;;
esac
exit 0
""",
    "apt-get": 'echo "apt-get $*" >>"$STUB_LOG"; exit "${STUB_APT_STATUS:-0}"\n',
    "cloud-init": 'echo "cloud-init $*" >>"$STUB_LOG"; exit "${STUB_CLOUD_INIT_STATUS:-0}"\n',
}
PROBES = ("cc", "pkexec", "doas", "pkaction")


class Result:
    def __init__(self, proc: subprocess.CompletedProcess[str], log: list[str]) -> None:
        self.status = proc.returncode
        self.stderr = proc.stderr
        self.log = log

    def calls(self, prefix: str) -> list[str]:
        return [line for line in self.log if line.startswith(prefix)]


def write_exe(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def run_script(
    test: unittest.TestCase,
    *,
    probes: tuple[str, ...] = (),
    cloud_init: bool = True,
    active: tuple[str, ...] = (),
    not_loaded: tuple[str, ...] = (),
    stop_fail: tuple[str, ...] = (),
    apt_status: int = 0,
    cloud_init_status: int = 0,
) -> Result:
    tmp = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
    bin_dir, home, log = tmp / "bin", tmp / "home", tmp / "log"
    bin_dir.mkdir()
    (home / ".cargo" / "bin").mkdir(parents=True)
    log.touch()
    for name, body in STUBS.items():
        if name != "cloud-init" or cloud_init:
            write_exe(bin_dir / name, body)
    for name in probes:
        write_exe(bin_dir / name, "exit 0\n")
    for name in REAL_TOOLS:
        real = shutil.which(name)
        if real:
            (bin_dir / name).symlink_to(real)
    write_exe(bin_dir / "cargo", 'echo "cargo 1.0.0"\n')
    write_exe(home / ".cargo" / "bin" / "cargo", f'echo "cargo-nextest {NEXTEST_VERSION} (stub)"\n')
    env = {
        "PATH": str(bin_dir),
        "HOME": str(home),
        "STUB_LOG": str(log),
        "STUB_ACTIVE": " ".join(active),
        "STUB_NOT_LOADED": " ".join(not_loaded),
        "STUB_STOP_FAIL": " ".join(stop_fail),
        "STUB_APT_STATUS": str(apt_status),
        "STUB_CLOUD_INIT_STATUS": str(cloud_init_status),
    }
    bash = shutil.which("bash")
    proc = subprocess.run([bash, str(SCRIPT)], env=env, capture_output=True, text=True, check=False)
    return Result(proc, log.read_text(encoding="utf-8").splitlines())


class AptBlockTests(unittest.TestCase):
    def test_all_tools_present_makes_no_apt_call(self) -> None:
        r = run_script(self, probes=PROBES)
        self.assertEqual(r.status, 0, r.stderr)
        self.assertEqual(r.log, [])

    def test_apt_is_told_to_wait_on_the_lock_without_a_bound(self) -> None:
        r = run_script(self)
        self.assertEqual(r.status, 0, r.stderr)
        [update] = [l for l in r.calls("apt-get") if " update" in l]
        [install] = [l for l in r.calls("apt-get") if " install" in l]
        for line in (update, install):
            self.assertIn(f"-o {LOCK_FLAG}", line)

    def test_timers_and_services_are_stopped_before_apt_runs(self) -> None:
        r = run_script(self)
        stops = [l for l in r.log if l.startswith("systemctl stop ")]
        self.assertEqual(
            stops, [f"systemctl stop {u}" for u in (*TIMERS, *SERVICES)]
        )
        first_apt = next(i for i, l in enumerate(r.log) if l.startswith("apt-get"))
        last_stop = max(i for i, l in enumerate(r.log) if l.startswith("systemctl stop"))
        self.assertLess(last_stop, first_apt)

    def test_apt_failure_restarts_the_active_units_and_fails(self) -> None:
        active = ("apt-daily.timer", "unattended-upgrades.service")
        r = run_script(self, active=active, apt_status=100)
        self.assertNotEqual(r.status, 0)
        self.assertEqual(r.calls("systemctl start"), [f"systemctl start {u}" for u in active])
        self.assertGreater(
            max(i for i, l in enumerate(r.log) if l.startswith("systemctl start")),
            max(i for i, l in enumerate(r.log) if l.startswith("apt-get")),
        )

    def test_only_the_units_active_before_are_restarted(self) -> None:
        r = run_script(self, active=("apt-daily-upgrade.timer",))
        self.assertEqual(r.status, 0, r.stderr)
        self.assertEqual(r.calls("systemctl start"), ["systemctl start apt-daily-upgrade.timer"])

    def test_nothing_is_restarted_when_nothing_was_active(self) -> None:
        r = run_script(self)
        self.assertEqual(r.calls("systemctl start"), [])

    def test_a_unit_that_is_not_loaded_is_skipped_without_failing(self) -> None:
        r = run_script(self, not_loaded=("unattended-upgrades.service",))
        self.assertEqual(r.status, 0, r.stderr)
        self.assertNotIn("systemctl stop unattended-upgrades.service", r.log)
        self.assertIn("systemctl stop apt-daily.service", r.log)

    def test_a_stop_failure_fails_before_apt_and_restarts_what_was_active(self) -> None:
        r = run_script(
            self, active=("apt-daily.timer",), stop_fail=("apt-daily-upgrade.timer",)
        )
        self.assertNotEqual(r.status, 0)
        self.assertIn("devvm: could not stop apt-daily-upgrade.timer", r.stderr)
        self.assertEqual(r.calls("apt-get"), [])
        self.assertEqual(r.calls("systemctl start"), ["systemctl start apt-daily.timer"])


class CloudInitTests(unittest.TestCase):
    def test_exit_0_continues(self) -> None:
        r = run_script(self, cloud_init_status=0)
        self.assertEqual(r.status, 0, r.stderr)
        self.assertEqual(r.calls("cloud-init"), ["cloud-init status --wait"])
        self.assertNotIn("exit status", r.stderr)

    def test_exit_2_logs_and_continues(self) -> None:
        r = run_script(self, cloud_init_status=2)
        self.assertEqual(r.status, 0, r.stderr)
        self.assertIn("cloud-init finished with exit status 2", r.stderr)
        self.assertTrue(r.calls("apt-get"))

    def test_any_other_status_fails_before_touching_apt_or_units(self) -> None:
        for status in (1, 3, 127):
            with self.subTest(status=status):
                r = run_script(self, cloud_init_status=status)
                self.assertNotEqual(r.status, 0)
                self.assertEqual(r.calls("apt-get"), [])
                self.assertEqual(r.calls("systemctl stop"), [])

    def test_no_cloud_init_is_not_an_error(self) -> None:
        r = run_script(self, cloud_init=False)
        self.assertEqual(r.status, 0, r.stderr)
        self.assertTrue(r.calls("apt-get"))


if __name__ == "__main__":
    unittest.main()
