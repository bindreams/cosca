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

import contextlib
import hashlib
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    arch: str = "amd64"
    # Display text of this guest's Hyper-V box, `name (hyperv/amd64)`. `box` stays the QEMU box.
    # None: no Hyper-V box, so the guest does not run on a Windows host.
    hyperv_box: str | None = None


def host_provider(platform: str = sys.platform) -> str:
    """The Vagrant provider devvm drives on this host: Hyper-V on Windows, QEMU elsewhere."""
    return "hyperv" if platform == "win32" else "qemu"


def host_unsupported_reason(guest: Guest, platform: str = sys.platform) -> str | None:
    """Why `guest` cannot run on this host's provider, or None if it can.

    Separate from Guest.available (the guest exists at all, checked first in every command): commands
    call this only after their flag validation, so devvm_test.py's validation tests pass on any host.
    """
    if host_provider(platform) == "hyperv" and guest.hyperv_box is None:
        return "it has no Hyper-V box (its box is QEMU-only), and a Windows host runs guests only on Hyper-V"
    return None


def require_host_support(guest: Guest) -> None:
    reason = host_unsupported_reason(guest)
    if reason is not None:
        print(f"error: guest '{guest.name}' is not available on this host: {reason}", file=sys.stderr)
        sys.exit(1)


def guest_dir(guest: Guest) -> Path:
    return GUESTS_DIR / guest.name


def dotfile_dir(guest: Guest) -> Path:
    return STATE_DIR / guest.name / ".vagrant"


def stage_dir(guest: Guest) -> Path:
    return STATE_DIR / guest.name / "tree"


def auto_consent_state_path(guest: Guest) -> Path:
    return STATE_DIR / guest.name / "auto_consent"


@contextlib.contextmanager
def stage_lock(stage: Path) -> Iterator[None]:
    """Hold an exclusive lock on the staged tree `stage` (the wipe, the copy and whatever reads it).

    An OS file lock, so it is released when the process dies. If another devvm command holds it,
    exits with a message rather than waiting: such a command can run for minutes (`vagrant up`),
    and the developer is better told than left hanging.
    """
    lock_path = stage.parent / f"{stage.name}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT)
    try:
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, PermissionError):  # a held lock: flock's EWOULDBLOCK, LockFile's EACCES
            print(
                f"error: another devvm command is using {stage}; wait for it to finish and run this again",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            yield
        finally:
            if sys.platform == "win32":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


def vm_name(guest: Guest) -> str:
    """The Hyper-V VM name of this worktree's `guest`, the only place it is computed.

    The hash of the staging path keeps two worktrees' VMs apart. Never select a VM by this name for
    anything that changes or opens it: use the id Vagrant stores (devvm_hyperv.vm_id).
    """
    digest = hashlib.sha256(str(stage_dir(guest)).encode()).hexdigest()
    return f"cosca-devvm-{guest.name}-{digest[:8]}"


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
    env["DEVVM_PROVIDER"] = host_provider()
    env["DEVVM_VMNAME"] = vm_name(guest)
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
    only the launcher process on timeout would leave that Ruby child running, orphaned on the
    HOST — the leaked-process hazard CLAUDE.local.md's sandbox rule exists to prevent. Off
    Windows, `start_new_session=True` makes the launcher (and everything it forks) its own
    process group, so a timeout kills the whole group via `os.killpg`, not just the launcher. On
    Windows, which has no process groups, the launcher runs in a Job Object
    (devvm_winjob.KillOnCloseJob) and a timeout terminates the whole job.

    On a real timeout, returns `timed_out=True` with a nonzero returncode and empty
    stdout/stderr — see BoundedWinrmResult's own docstring for why that's reported explicitly,
    rather than folded into the same "nonzero returncode" shape an ordinary WinRM failure
    produces.
    """
    remaining = max(deadline - time.monotonic(), 0.001)
    with _started_in_kill_tree_scope(
        ["vagrant", "winrm", "-c", powershell_cmd],
        cwd=guest_dir(guest),
        env=vagrant_env(guest),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as (proc, kill_tree):
        try:
            stdout, stderr = proc.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            kill_tree()
            stdout, stderr = proc.communicate()
            return BoundedWinrmResult(1, stdout, stderr, timed_out=True)
        return BoundedWinrmResult(proc.returncode, stdout, stderr, timed_out=False)


@contextlib.contextmanager
def _started_in_kill_tree_scope(argv: list[str], **popen_kwargs: Any) -> Iterator[tuple[Any, Callable[[], None]]]:
    """Start `argv` so that its whole process tree can be killed; yield the process and a callable that kills the tree.

    Windows has no process groups, so the process runs in a Job Object that outlives the `with`
    body, which kills whatever is left on exit (devvm_winjob.KillOnCloseJob). Elsewhere it leads
    its own session, and the tree is its process group.
    """
    if sys.platform == "win32":
        from devvm_winjob import KillOnCloseJob

        with KillOnCloseJob() as job, job.popen(argv, **popen_kwargs) as proc:
            yield proc, job.terminate
    else:
        proc = subprocess.Popen(argv, start_new_session=True, **popen_kwargs)
        yield proc, lambda: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


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

    `vagrant status` reads local state through the provider's own read_state action, with no
    WinRM round-trip, so this stays fast and answers even when WinRM itself is unresponsive. The
    qemu provider checks liveness (`Process.kill(0, pid)`, see vagrant-qemu's driver.rb) of the
    PID in the guest's pidfile; the Hyper-V provider asks Hyper-V for the state of the VM id
    Vagrant stored.
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
