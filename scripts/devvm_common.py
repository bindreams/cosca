"""Primitives shared between devvm.py (CLI/orchestration, Linux-guest logic) and
devvm_windows.py (Windows-guest lifecycle: provisioning, reboot, licensing, session-wait).

Exists to break what would otherwise be an import cycle: devvm.py's subcommands (cmd_up,
cmd_sync, cmd_run) call into devvm_windows.py, and devvm_windows.py needs the same
guest/vagrant primitives devvm.py itself uses (Guest, run_vagrant, ...). Both import from
here instead; devvm_windows.py never imports devvm.py.

Not meaningfully testable or interesting on its own — see devvm_test.py and
scripts/README.md for what's actually covered and why.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
GUESTS_DIR = SCRIPT_DIR / "devvm" / "guests"
WINDOWS_PROVISION_DIR = SCRIPT_DIR / "devvm" / "provision"

# All mutable Vagrant/QEMU state lives here, under the worktree and gitignored — never in
# the developer's home directory. The one exception is the downloaded box cache itself: see
# scripts/README.md#state-directories for why that one piece is unavoidably global.
STATE_DIR = REPO_ROOT / ".tmp" / "devvm"


@dataclass(frozen=True)
class Guest:
    name: str
    communicator: str  # "ssh" or "winrm"
    box: str
    available: bool = True
    unavailable_reason: str | None = None
    tree_path_posix: str | None = None  # where the read-only tree copy lands in-guest


def guest_dir(guest: Guest) -> Path:
    return GUESTS_DIR / guest.name


def dotfile_dir(guest: Guest) -> Path:
    return STATE_DIR / guest.name / ".vagrant"


def stage_dir(guest: Guest) -> Path:
    return STATE_DIR / guest.name / "tree"


def auto_consent_state_path(guest: Guest) -> Path:
    return STATE_DIR / guest.name / "auto_consent"


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        print(
            f"error: '{name}' not found on PATH. See scripts/README.md#prerequisites for what to install.",
            file=sys.stderr,
        )
        sys.exit(1)


def vagrant_env(guest: Guest, *, display: bool = False) -> dict[str, str]:
    env = dict(os.environ)
    env["VAGRANT_DOTFILE_PATH"] = str(dotfile_dir(guest))
    env["DEVVM_STAGE_DIR"] = str(stage_dir(guest))
    env["DEVVM_WINDOWS_DISPLAY"] = "1" if display else "0"
    return env


def run_vagrant(guest: Guest, args: list[str], *, display: bool = False, check: bool = True) -> int:
    # For `vagrant winrm -c ...` specifically: `vagrant winrm`'s own process exit code is 0
    # for a zero remote exit and exactly 1 for any nonzero one, never the remote value itself.
    # So the returncode this function hands back (and sys.exit()s with) only preserves
    # zero-vs-nonzero for WinRM guests, not the remote command's actual exit code.
    require_tool("vagrant")
    cwd = guest_dir(guest)
    cmd = ["vagrant", *args]
    print(f"+ (cd {cwd} && {shlex.join(cmd)})", file=sys.stderr)
    result = subprocess.run(cmd, cwd=cwd, env=vagrant_env(guest, display=display))
    if check and result.returncode != 0:
        sys.exit(result.returncode)
    return result.returncode


def run_vagrant_streaming(
    guest: Guest,
    args: list[str],
    *,
    display: bool = False,
    check: bool = True,
) -> tuple[int, str]:
    """Like run_vagrant, but also returns everything printed to stdout/stderr.

    Streams output live to this process's stdout as it arrives (important here: a Windows
    `up` under TCG emulation can take over ten minutes, so a developer needs to see progress,
    not silence followed by a wall of text at the end) while also accumulating it, so cmd_up
    can scan for the DEVVM_REBOOT_REQUIRED marker windows-account-and-uac.ps1 prints. Reading
    a subprocess's stdout line-by-line until the pipe closes is a blocking read on a real
    completion event, not a timed poll.
    """
    require_tool("vagrant")
    cwd = guest_dir(guest)
    cmd = ["vagrant", *args]
    print(f"+ (cd {cwd} && {shlex.join(cmd)})", file=sys.stderr)
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=vagrant_env(guest, display=display),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    lines = []
    for line in proc.stdout:
        sys.stdout.write(line)
        lines.append(line)
    returncode = proc.wait()
    if check and returncode != 0:
        sys.exit(returncode)
    return returncode, "".join(lines)


@dataclass(frozen=True)
class BoundedWinrmResult:
    """Result of a bounded `vagrant winrm -c` call (see run_vagrant_winrm_bounded).

    `timed_out` reports the specific subprocess.TimeoutExpired run_vagrant_winrm_bounded's own
    `deadline` raised — vagrant/WinRM never answered in time, so the process was killed —
    distinct from every other outcome, including an ordinary nonzero exit WinRM itself
    returned in time. A caller that retries in a loop until its own deadline (e.g.
    wait_for_windows_session) doesn't need the distinction — either way it just asks again. A
    caller that makes a single bounded call and has to report a reason to a human right now
    (get_windows_interactive_username's caller in devvm.py's cmd_run) does.
    """

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


def run_vagrant_winrm_bounded(guest: Guest, powershell_cmd: str, deadline: float) -> BoundedWinrmResult:
    """Like `subprocess.run(["vagrant", "winrm", "-c", powershell_cmd], ...)`, but bounded by
    `deadline` (a time.monotonic() value) instead of running unbounded.

    Why not a plain `timeout=`: `vagrant` execs a Ruby child to do the actual work, so killing
    only the Go launcher process on timeout would leave that Ruby child running, reparented to
    PID 1, orphaned on the HOST — the leaked-process hazard CLAUDE.local.md's sandbox rule
    exists to prevent. `start_new_session=True` makes the launcher (and everything it forks) its
    own process group, so a timeout kills the whole group via `os.killpg`, not just the
    launcher.

    On a real timeout, returns `timed_out=True` with a nonzero returncode and empty
    stdout/stderr — see BoundedWinrmResult's own docstring for why that's reported explicitly,
    rather than folded into the same "nonzero returncode" shape an ordinary WinRM failure
    produces.
    """
    remaining = max(deadline - time.monotonic(), 0.001)
    proc = subprocess.Popen(
        ["vagrant", "winrm", "-c", powershell_cmd],
        cwd=guest_dir(guest),
        env=vagrant_env(guest),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=remaining)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        stdout, stderr = proc.communicate()
        return BoundedWinrmResult(1, stdout, stderr, timed_out=True)
    return BoundedWinrmResult(proc.returncode, stdout, stderr, timed_out=False)


def powershell_quote(value: str) -> str:
    """Quote a single token as a PowerShell single-quoted string literal.

    Single-quoted strings in PowerShell are taken verbatim except for `'`, which is escaped
    by doubling. Used with the `&` call operator (`& 'cmd' 'arg one' 'arg two'`) so each
    argument is passed through as a literal, not re-parsed/re-split by PowerShell.
    """
    return "'" + value.replace("'", "''") + "'"


def get_vagrant_machine_state(guest: Guest) -> str:
    """The guest's current state per `vagrant status --machine-readable` (e.g. "running",
    "poweroff", "not_created", "stopped"). Used by devvm_windows._require_guest_running (and,
    through it, reboot_windows_guest_and_wait and wait_for_windows_session) to fail fast once
    the guest is no longer running, instead of retrying `vagrant winrm` in a tight loop against
    a guest that is never coming back on its own.

    `vagrant status` reads local state via the qemu provider's own read_state action: a
    liveness check (`Process.kill(0, pid)`, see vagrant-qemu's driver.rb) against the PID in
    the guest's own pidfile, not a QMP query — no WinRM round-trip, so this stays fast and
    answers even when WinRM itself is unresponsive.
    """
    require_tool("vagrant")
    result = subprocess.run(
        ["vagrant", "status", "--machine-readable"],
        cwd=guest_dir(guest),
        env=vagrant_env(guest),
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        fields = line.split(",", 3)
        if len(fields) >= 4 and fields[2] == "state":
            return fields[3]
    raise RuntimeError(
        f"devvm: could not find a 'state' line in `vagrant status --machine-readable` for "
        f"guest '{guest.name}' (exit {result.returncode}) — output:\n{result.stdout}"
    )
