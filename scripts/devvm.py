#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""devvm - provision throwaway VMs for cosca's system-affecting tests.

cosca's subject matter (elevation, cgroups, Windows Job Objects, process trees) means its
most interesting tests change real system state. Those tests must never run on a developer's
own machine (see CLAUDE.local.md's sandbox rule, which this tool exists to satisfy). This
script provisions, starts, connects to, and destroys throwaway VMs for that purpose, via
Vagrant + QEMU.

See scripts/README.md for prerequisites, guest details, and usage examples.
"""

from __future__ import annotations

import argparse
import base64
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Last output line windows-account-and-uac.ps1 prints, telling devvm.py whether an
# EnableLUA/autologon change it just made needs a reboot to take effect (see cmd_up).
REBOOT_MARKER_TRUE = "DEVVM_REBOOT_REQUIRED=1"
REBOOT_MARKER_FALSE = "DEVVM_REBOOT_REQUIRED=0"

# SoftwareLicensingProduct.LicenseStatus: 1 means Licensed. Anything else (5 = Notification is
# what a TIMEBASED_EVAL image reports once its evaluation period elapses - measured directly,
# 2026-09-24, on stromweld/windows-10 202503.09.0) means the guest is not currently licensed
# and needs a rearm before it's safe to leave unattended - see ensure_windows_license_current.
WINDOWS_LICENSE_STATUS_LICENSED = 1
# Rearm proactively within this many minutes of the eval period actually running out, not
# just once it's already hit zero - a guest that dies mid-provisioning run (see
# ensure_windows_license_current's docstring for the incident this is fixing) is worse than
# spending a rearm slightly early. One day's buffer is cheap next to the box's eval window
# (on the order of months) and the two rearms this image ships with.
WINDOWS_LICENSE_NEAR_EXPIRY_MINUTES = 24 * 60

# windows-run-unelevated.ps1 (the guest side of `devvm.py run --unelevated --timeout`) feeds
# -TimeoutSeconds, converted to milliseconds, into .NET WaitHandle.WaitOne(int), which takes a
# signed 32-bit millisecond count. A --timeout value whose *1000 doesn't fit in Int32 would
# only fail on the guest, after a slow round-trip there and back - reject it here instead,
# where the mistake is immediate and the error message is in front of the person who typed it.
WINDOWS_RUN_UNELEVATED_MAX_TIMEOUT_SECONDS = (2**31 - 1) // 1000

# The human-facing failure bound for reboot_windows_guest_and_wait's post-reboot wait: a
# guest reboot is a genuinely external event (it might never complete), and this is the same
# already-configured, already-real bound the Windows Vagrantfile itself uses
# (config.vm.boot_timeout / config.winrm.timeout, both 3600s in
# scripts/devvm/guests/windows-x64/Vagrantfile) — not a second, uncoordinated guess.
WINDOWS_REBOOT_DEADLINE_SECONDS = 3600

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


GUESTS: dict[str, Guest] = {
    "linux-x64": Guest(
        name="linux-x64",
        communicator="ssh",
        box="generic/ubuntu2204 (qemu/amd64)",
        tree_path_posix="/home/vagrant/cosca",
    ),
    "linux-arm64": Guest(
        name="linux-arm64",
        communicator="ssh",
        box="perk/ubuntu-2204-arm64 (qemu/arm64)",
        tree_path_posix="/home/vagrant/cosca",
    ),
    "windows-x64": Guest(
        name="windows-x64",
        communicator="winrm",
        box="stromweld/windows-10 (qemu/amd64)",
        tree_path_posix="C:/cosca",
    ),
    "windows-arm64": Guest(
        name="windows-arm64",
        communicator="winrm",
        box="(none)",
        available=False,
        unavailable_reason=(
            "no publicly available Vagrant box for Windows on arm64 targets the qemu or "
            "libvirt provider this tool uses (checked, 2026-09-23: stromweld, hbsmith, "
            "pipegz, nullx, aihua, apter-tech, chicken-wire, santiago-bassett, Sy3Omda on "
            "Vagrant Cloud — all arm64 Windows boxes there are parallels/vmware_desktop/utm "
            "only). Build your own box from a Windows-on-ARM evaluation VHDX and pass its "
            "path via `qe.image_path` in a custom Vagrantfile if you need this lane; see "
            "scripts/README.md#windows-arm64."
        ),
    ),
}


def guest_dir(guest: Guest) -> Path:
    return GUESTS_DIR / guest.name


def dotfile_dir(guest: Guest) -> Path:
    return STATE_DIR / guest.name / ".vagrant"


def stage_dir(guest: Guest) -> Path:
    return STATE_DIR / guest.name / "tree"


def auto_consent_state_path(guest: Guest) -> Path:
    return STATE_DIR / guest.name / "auto_consent"


def read_persisted_auto_consent(guest: Guest) -> bool:
    """The auto-consent choice `up --allow-elevation` last made for this guest.

    Persisted so that a later `sync` or plain `up` (with no --allow-elevation/--no-
    allow-elevation flag) reuses the developer's actual choice instead of silently
    defaulting to (and resetting the guest to) off.
    """
    path = auto_consent_state_path(guest)
    if not path.exists():
        return False
    return path.read_text().strip() == "1"


def write_persisted_auto_consent(guest: Guest, value: bool) -> None:
    path = auto_consent_state_path(guest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("1" if value else "0")


def require_available(guest: Guest) -> None:
    if not guest.available:
        print(f"error: guest '{guest.name}' is not available: {guest.unavailable_reason}", file=sys.stderr)
        sys.exit(1)


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
    # For `vagrant winrm -c ...` specifically: measured directly (2026-09-23) by running a
    # remote command that exited {0, 1, 2, 42, 255} in turn — `vagrant winrm`'s own process
    # exit code was 0 for the zero case and exactly 1 for every nonzero case, never the
    # remote value. So the returncode this function hands back (and sys.exit()s with) only
    # preserves zero-vs-nonzero for WinRM guests, not the remote command's actual exit code.
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


def powershell_quote(value: str) -> str:
    """Quote a single token as a PowerShell single-quoted string literal.

    Single-quoted strings in PowerShell are taken verbatim except for `'`, which is escaped
    by doubling. Used with the `&` call operator (`& 'cmd' 'arg one' 'arg two'`) so each
    argument is passed through as a literal, not re-parsed/re-split by PowerShell.
    """
    return "'" + value.replace("'", "''") + "'"


def stage_tree(guest: Guest, *, repo_root: Path = REPO_ROOT, dest: Path | None = None) -> None:
    """Rebuild a fresh copy of the working tree's git-TRACKED files under dest (default:
    .tmp/devvm/<guest>/tree).

    Every guest is served from this staged copy (not raw repo_root) so what lands in a guest
    is exactly `git ls-files` — never untracked files (e.g. CLAUDE.local.md, .claude/) and
    never a worktree's .git, which is a FILE (pointing at the parent repo's gitdir), not a
    directory, so a plain rsync `--exclude=.git/` pattern silently fails to match it and
    leaks it into the guest.

    dest is wiped and recreated on every call rather than rsync'd with `--delete`: measured
    directly (rsync 3.5.1) that `--delete` combined with `--files-from` is a silent no-op for
    removals — a file dropped from both the source tree and the files-list stays behind in an
    already-populated dest. Wiping dest first sidesteps the interaction entirely, since there
    is never anything stale left for a `--delete` flag to need to remove.

    Filtered to files that still exist on disk: `git ls-files` can list a tracked path that
    isn't actually present in the working tree (deleted-but-unstaged, or a sparse-checkout
    skip-worktree entry) — feeding a missing path to `rsync --files-from` makes rsync exit 23
    with a raw traceback instead of a clean sync. A tracked-but-absent path is a normal git
    state, not a caller bug, so it's silently excluded rather than treated as an error.

    `git ls-files -z` / `rsync --from0` avoid whitespace/newline-in-filename hazards that a
    plain newline-joined list would have.
    """
    require_tool("rsync")
    require_tool("git")
    if dest is None:
        dest = stage_dir(guest)

    ls_files = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    tracked = [p for p in ls_files.stdout.split(b"\0") if p]
    existing = [p for p in tracked if (repo_root / p.decode()).is_file()]

    dest.parent.mkdir(parents=True, exist_ok=True)
    files_list = dest.parent / "tracked-files.list"
    files_list.write_bytes(b"\0".join(existing) + (b"\0" if existing else b""))

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    cmd = [
        "rsync",
        "--archive",
        "--from0",
        f"--files-from={files_list}",
        f"{repo_root}/",
        f"{dest}/",
    ]
    print(f"+ {shlex.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, check=True)


def parse_run_argv(rest: list[str]) -> tuple[list[str], bool, int | None, list[str]]:
    """Split `run`'s own argv (everything after the literal "run" token) into
    (head, unelevated, timeout, cmd_tail).

    `head` is what's left for argparse to parse (in practice just the guest name, since both
    devvm-own flags below are stripped out of it before argparse ever sees it); `unelevated`
    is whether `--unelevated` appeared anywhere in `rest` before a `--` separator; `timeout` is
    the integer following a `--timeout` token, if one appeared before `--`, else None;
    `cmd_tail` is everything after the first literal `--`, verbatim (or `[]` if there is none).

    This exists because argparse's `nargs=REMAINDER` (needed on `cmd` so arbitrary flags in
    the user's own command, e.g. `cargo test -- --nocapture`, pass through untouched) greedily
    swallows EVERY remaining token once positional-matching reaches it — including a devvm-own
    flag like `--unelevated`/`--timeout` placed anywhere at or after `guest`, with or without a
    `--` separator; confirmed directly: `run windows-x64 --unelevated -- cargo test` left
    args.unelevated False, with `cmd`'s REMAINDER eating `--unelevated` itself. Extracting both
    flags by hand, before argparse ever runs, sidesteps the quirk entirely and lets either flag
    appear on either side of `guest`.

    The obvious alternative — drop REMAINDER, declare `cmd` as `nargs="*"`, and let argparse's
    own `--` handling do this — does NOT work on Python 3.11 (this repo's pinned minimum, see
    the `requires-python` header): confirmed directly with `uv run --python 3.11/3.12/3.13`,
    `run windows-x64 --unelevated -- cargo test` parses correctly from 3.12 onward but raises
    "unrecognized arguments: -- cargo test" on 3.11 — a stdlib argparse bug (`--` combined with
    a preceding optional and a `nargs="*"` positional) fixed only in 3.12. Hand-rolling stays
    necessary as long as 3.11 is supported.

    Handles both `--timeout N` and `--timeout=N` spellings (argparse itself accepts both for a
    single-value option, so this must too), and reports a bad integer the same way argparse
    would — a one-line message on stderr and exit(2), not a raw traceback.
    """
    if "--" in rest:
        idx = rest.index("--")
        before, cmd_tail = rest[:idx], rest[idx + 1 :]
    else:
        before, cmd_tail = rest, []

    def parse_timeout(raw: str) -> int:
        try:
            return int(raw)
        except ValueError:
            print(f"devvm.py run: argument --timeout: invalid int value: {raw!r}", file=sys.stderr)
            sys.exit(2)

    head: list[str] = []
    unelevated = False
    timeout: int | None = None
    i = 0
    while i < len(before):
        tok = before[i]
        if tok == "--unelevated":
            unelevated = True
            i += 1
        elif tok == "--timeout":
            if i + 1 >= len(before):
                print("devvm.py run: argument --timeout: expected one argument", file=sys.stderr)
                sys.exit(2)
            timeout = parse_timeout(before[i + 1])
            i += 2
        elif tok.startswith("--timeout="):
            timeout = parse_timeout(tok[len("--timeout=") :])
            i += 1
        else:
            head.append(tok)
            i += 1

    return head, unelevated, timeout, cmd_tail


# Subcommands ==========================================================================


def cmd_list(_args: argparse.Namespace) -> None:
    require_tool("vagrant")
    for guest in GUESTS.values():
        if not guest.available:
            print(f"{guest.name:14s} UNAVAILABLE  {guest.unavailable_reason}")
            continue
        dotfile = dotfile_dir(guest)
        if not dotfile.exists():
            state = "not created"
        else:
            proc = subprocess.run(
                ["vagrant", "status", "--machine-readable"],
                cwd=guest_dir(guest),
                env=vagrant_env(guest),
                capture_output=True,
                text=True,
            )
            state = "unknown"
            for line in proc.stdout.splitlines():
                fields = line.split(",")
                if len(fields) >= 4 and fields[2] == "state":
                    state = fields[3]
                    break
        print(f"{guest.name:14s} {state:14s} {guest.box}  (communicator: {guest.communicator})")


def run_windows_script(
    guest: Guest,
    script_path: Path,
    *,
    elevated: bool = True,
    env: dict[str, str] | None = None,
    display: bool = False,
) -> str:
    """Run a Windows provisioning .ps1 script directly over `vagrant winrm`, instead of
    through Vagrant's WinRM shell provisioner.

    Why: Vagrant's shell provisioner's WinRM path (`provision_winrm` in vagrant 2.4.9's own
    plugins/provisioners/shell/provisioner.rb) calls `@machine.guest.capability(:wait_for_reboot)`
    UNCONDITIONALLY at the very start of every invocation, before it even uploads the script.
    That capability (plugins/guests/windows/cap/reboot.rb, scripts/reboot_detect.ps1) doesn't
    just check for a pending reboot — it actively PROBES for one by running a real
    `shutdown -f -r -t 60` (a genuine 60-second-out forced restart) and then, if nothing was
    already scheduled, immediately `shutdown -a` to cancel it. That is a real, if usually
    aborted-in-time, standing restart fuse on every ordinary provisioning step — confirmed via
    guest System-log event 1074/1075 pairs lining up with `vagrant provision` runs (measured
    2026-09-24; see scripts/README.md's root-cause note). `vagrant winrm -c` never reaches
    that capability — confirmed by reading plugins/commands/winrm/command.rb,
    communicators/winrm/communicator.rb, and communicators/winrm/shell.rb end to end: none of
    them reference `wait_for_reboot` or `reboot_detect` — so driving each script through it
    removes the fuse entirely. `-e`/`--elevated` requests the `winrm-elevated` shell type,
    matching the shell provisioner's `privileged: true` without going anywhere near
    `wait_for_reboot`.

    Uploads the script itself via `vagrant upload` (plain WinRM file transfer, no guest
    process/command line involved) and runs it with `-File`, rather than inlining its content
    as a base64/UTF-16LE `-EncodedCommand`. `-EncodedCommand`'s encoded text becomes part of
    the guest-side `powershell.exe` command line, which Windows' CreateProcess caps at 32767
    chars total - measured directly (2026-09-25): windows-rust.ps1 alone already encodes to a
    ~25350-char command line, comfortably under that limit today but with no margin that's
    guaranteed to hold as the script grows, and no PowerShell-side error if it's ever crossed
    (CreateProcess just fails on the guest). `-File` sidesteps the limit entirely - the
    command line is always the same small, fixed size regardless of script content. The
    upload destination is fixed, dedicated scratch space (C:\\Windows\\Temp), deliberately NOT
    under C:\\cosca-stage/C:\\cosca: windows-clean-stage.ps1 wipes the former and
    windows-mirror-tree.ps1 mirrors-with-deletion into the latter, and either could race an
    upload landing there depending on which script is currently running. Env vars are still
    passed via a `$env:NAME = 'value'; ` prefix ahead of the `-File` invocation, same
    mechanism as before.

    Returns the combined stdout/stderr so callers (e.g. windows-account-and-uac.ps1's
    DEVVM_REBOOT_REQUIRED marker) can scan it. Raises via `run_vagrant_streaming`'s own
    check=True on a nonzero exit, same as a failing shell provisioner previously would (and via
    `run_vagrant`'s own check=True if the upload itself fails).
    """
    guest_script_path = f"C:\\Windows\\Temp\\devvm-{script_path.name}"
    run_vagrant(guest, ["upload", str(script_path), guest_script_path], display=display)
    env_prefix = "".join(f"$env:{name} = {powershell_quote(value)}; " for name, value in (env or {}).items())
    inner = (
        f"{env_prefix}powershell -NoProfile -ExecutionPolicy Bypass "
        f"-File {powershell_quote(guest_script_path)}; exit $LASTEXITCODE"
    )
    args = ["winrm"]
    if elevated:
        args.append("-e")
    args += ["-c", inner]
    _, output = run_vagrant_streaming(guest, args, display=display)
    return output


def get_vagrant_machine_state(guest: Guest) -> str:
    """The guest's current state per `vagrant status --machine-readable` (e.g. "running",
    "poweroff", "not_created", "stopped"). Used by reboot_windows_guest_and_wait to fail fast
    once the guest is no longer running, instead of retrying `vagrant winrm` in a tight loop
    against a guest that is never coming back on its own.

    `vagrant status` reads local state via the qemu provider's own read_state action (a QMP
    query against the guest's own QEMU process, confirmed directly 2026-09-25) — no WinRM
    round-trip, so this stays fast and answers even when WinRM itself is unresponsive.
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


def get_windows_boot_time(guest: Guest) -> str | None:
    """The guest's current LastBootUpTime (an ISO-8601-ish CIM datetime string), or None if
    WinRM isn't answering right now. Used by reboot_windows_guest_and_wait to detect a real
    boot-time change rather than just "WinRM answered" (which can spuriously be true in the
    few seconds between issuing `shutdown /r` and the guest actually going down).

    No `timeout=` of our own on this subprocess call. `vagrant` is a Go launcher binary that
    execs a Ruby child to do the actual work (confirmed directly, 2026-09-25: `file
    $(which vagrant)` is a native Mach-O executable, and `ps -o pid,ppid,command` during a live
    `vagrant winrm -c` call shows a `ruby .../vagrant winrm -c ...` child under it) - so a
    `subprocess.run(..., timeout=N)` here would SIGKILL only that immediate Go process on
    expiry, not its Ruby child, which keeps running, reparented to PID 1, orphaned on the HOST.
    Reproduced directly the same way: a 2s-timeout probe against this exact command left a
    `ruby .../vagrant winrm -c ...` process running under PPID 1 after Python's own timeout
    fired - precisely the leaked-process hazard CLAUDE.local.md's sandbox rule exists to
    prevent, and not something `start_new_session=True` + `os.killpg` fixes for free either
    (the Go launcher would still need to actually forward the kill to its Ruby child for that
    to help, which isn't guaranteed).
    `vagrant winrm -c` has NO readiness wait of its own — confirmed by reading vagrant's
    `plugins/commands/winrm/command.rb` end to end: its `execute` calls
    `machine.communicate.execute(cmd, opts)` directly, with no `wait_for_ready` call or any
    other connection-readiness wait anywhere in the path. So a WinRM connection attempt against
    a guest that isn't listening can fail (or hang) on its own schedule, not bounded by the
    Windows Vagrantfile's `winrm.timeout` — that config value only bounds Vagrant's
    `wait_for_communicator`/`wait_for_ready` capability, which this command never calls. The
    real failure bound for a caller that loops on this function (reboot_windows_guest_and_wait)
    is WINDOWS_REBOOT_DEADLINE_SECONDS, applied there — not anything inside this function.
    """
    result = subprocess.run(
        ["vagrant", "winrm", "-c", "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')"],
        cwd=guest_dir(guest),
        env=vagrant_env(guest),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    return output or None


def get_windows_interactive_username(guest: Guest) -> str | None:
    """The name logged into the guest's interactive (session 0 console / RDP session 1)
    desktop right now, via `Win32_ComputerSystem.UserName`, or None if nobody is logged in yet
    (blank result) or WinRM isn't answering. Used by reboot_windows_guest_and_wait to confirm
    autologon has actually produced a real interactive session — the thing
    windows-run-unelevated.ps1's scheduled task borrows a filtered token from — not just that
    the kernel has finished booting.
    """
    result = subprocess.run(
        ["vagrant", "winrm", "-c", "(Get-CimInstance Win32_ComputerSystem).UserName"],
        cwd=guest_dir(guest),
        env=vagrant_env(guest),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    return output or None


def _require_guest_running(guest: Guest, deadline: float, *, what: str) -> None:
    """Raise if the guest is no longer 'running' per vagrant, or if `deadline` (a
    time.monotonic() value) has passed. Shared by reboot_windows_guest_and_wait's two wait
    loops so a powered-off/crashed guest fails immediately instead of retrying WinRM forever,
    and so both loops share the same single wall-clock failure bound.
    """
    state = get_vagrant_machine_state(guest)
    if state != "running":
        raise RuntimeError(
            f"devvm: guest '{guest.name}' is no longer 'running' (vagrant status: {state!r}) "
            f"while waiting for {what} — it will not come back on its own; run `devvm.py up` "
            "to bring it back."
        )
    if time.monotonic() >= deadline:
        raise RuntimeError(
            f"devvm: guest '{guest.name}' did not finish {what} within "
            f"{WINDOWS_REBOOT_DEADLINE_SECONDS}s of being rebooted."
        )


def reboot_windows_guest_and_wait(guest: Guest) -> None:
    """Issue a real guest reboot ourselves and block until the guest reports a new boot time
    and a real interactive (autologon) session on top of it.

    Deliberately does NOT go through Vagrant's named `reboot-if-needed` shell provisioner /
    `Reboot.reboot` capability: that path is itself a shell provisioner, so it still runs
    through `provision_winrm`'s unconditional `wait_for_reboot` fuse first, and its own
    `wait_for_reboot` wait loop (plugins/guests/windows/cap/reboot.rb) is a `sleep 10` poll on
    top of that same reboot_detect.ps1 probe. Issuing `shutdown /r` directly (the same command
    `Reboot.reboot` itself runs, confirmed by reading cap/reboot.rb) and then waiting for a
    genuine boot-time change avoids both.

    `shutdown /r /t 0`'s own exit code is NOT trusted as a pass/fail signal: measured directly
    (2026-09-25), a `/t 0` shutdown tears down the guest (and its WinRM connection) essentially
    immediately, so `vagrant winrm` can report a nonzero exit purely because the connection
    dropped out from under it mid-response — not because the reboot failed to schedule. The
    wait loop below is the real check that the reboot actually happened; a nonzero exit here
    is logged but does not abort early on its own.

    No `time.sleep()` anywhere in either wait loop, and no chosen retry interval of devvm.py's
    own: each iteration IS the wait — a real WinRM round-trip or a real `vagrant status`
    query — and failure just means "ask again immediately," not "nap, then ask again." Each
    loop iteration is bounded by one shared wall-clock deadline
    (WINDOWS_REBOOT_DEADLINE_SECONDS, reusing the Windows Vagrantfile's own 3600s
    boot_timeout/winrm.timeout — a real, already-configured, human-facing failure bound for a
    guest reboot genuinely never completing) and by `_require_guest_running` failing fast the
    moment `vagrant status` reports the guest isn't running any more, instead of retrying
    `vagrant winrm` in a tight loop against a guest that is never answering again (a powered-off
    or crashed guest would otherwise burn a host core forever, since `vagrant winrm` itself has
    no readiness wait — see get_windows_boot_time's docstring).
    """
    before = get_windows_boot_time(guest)
    if before is None:
        raise RuntimeError(
            f"devvm: could not read guest '{guest.name}' current boot time before rebooting "
            "it — is WinRM answering at all?"
        )
    print(f"+ rebooting guest '{guest.name}' directly (shutdown /r) and waiting for a new boot time", file=sys.stderr)
    returncode = run_vagrant(guest, ["winrm", "-c", 'shutdown /r /t 0 /f /d p:4:1 /c "devvm reboot"'], check=False)
    if returncode != 0:
        print(
            f"devvm: `vagrant winrm` reported a nonzero exit ({returncode}) issuing the "
            f"reboot on guest '{guest.name}' — with `/t 0` that's expected even on a "
            "successfully-scheduled reboot, since the connection drops out from under it "
            "almost immediately. Proceeding to wait for a real boot-time change, which is the "
            "actual check.",
            file=sys.stderr,
        )

    deadline = time.monotonic() + WINDOWS_REBOOT_DEADLINE_SECONDS
    while True:
        _require_guest_running(guest, deadline, what="a new boot time")
        after = get_windows_boot_time(guest)
        if after is not None and after != before:
            break

    # LastBootUpTime changes as soon as the kernel finishes booting, which can still be ahead
    # of autologon actually producing a real interactive session — the thing
    # windows-run-unelevated.ps1's scheduled task needs to borrow a filtered token from. Wait
    # for that explicitly too, under the same deadline, instead of letting the next unelevated
    # probe race it.
    while True:
        _require_guest_running(guest, deadline, what="an interactive (autologon) session")
        username = get_windows_interactive_username(guest)
        if username is not None:
            return


def get_windows_license_state(guest: Guest) -> tuple[int, float, int]:
    """Read the guest's Windows license status via WMI/CIM: (LicenseStatus,
    GracePeriodRemaining in minutes, RemainingWindowsReArmCount).

    Reads the same underlying data `slmgr.vbs /dlv` prints, but structured: no parsing of
    slmgr's free-text human-readable output, just the WMI properties behind it
    (SoftwareLicensingProduct for the active product entry - the one with a non-null
    PartialProductKey - and SoftwareLicensingService for the rearm counter).
    """
    cmd = (
        "$p = Get-CimInstance SoftwareLicensingProduct | "
        "Where-Object { $_.PartialProductKey } | Select-Object -First 1; "
        "$s = Get-CimInstance SoftwareLicensingService; "
        'Write-Host ("DEVVM_LICENSE_STATUS=" + $p.LicenseStatus); '
        'Write-Host ("DEVVM_LICENSE_GRACE_MINUTES=" + $p.GracePeriodRemaining); '
        'Write-Host ("DEVVM_LICENSE_REARM_REMAINING=" + $s.RemainingWindowsReArmCount)'
    )
    _, output = run_vagrant_streaming(guest, ["winrm", "-c", cmd])
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line and line.split("=", 1)[0] in (
            "DEVVM_LICENSE_STATUS",
            "DEVVM_LICENSE_GRACE_MINUTES",
            "DEVVM_LICENSE_REARM_REMAINING",
        ):
            key, value = line.split("=", 1)
            values[key] = value.strip()
    try:
        return (
            int(values["DEVVM_LICENSE_STATUS"]),
            float(values["DEVVM_LICENSE_GRACE_MINUTES"]),
            int(values["DEVVM_LICENSE_REARM_REMAINING"]),
        )
    except (KeyError, ValueError) as e:
        raise RuntimeError(
            f"devvm: could not read guest '{guest.name}' Windows license state via WMI - "
            f"missing or unparsable marker(s) in output ({e}):\n{output}"
        ) from e


def ensure_windows_license_current(guest: Guest, *, display: bool = False) -> None:
    """Rearm the guest's time-based Windows evaluation license if it's expired or within
    WINDOWS_LICENSE_NEAR_EXPIRY_MINUTES of expiring, then reboot for the rearm to take effect.

    Why this exists: measured directly (2026-09-24) that the stromweld/windows-10 box's eval
    image self-terminates once its evaluation period elapses - guest System event log ID 1074,
    initiator C:\\Windows\\system32\\wlms\\wlms.exe (the Windows License Manager Service)
    running as NT AUTHORITY\\SYSTEM, "The license period for this installation of Windows has
    expired. The operating system is shutting down." That is a genuine guest-initiated ACPI
    power-off - not a devvm.py/cosca command, not a crash - so it ends the whole QEMU process.
    Confirmed via `slmgr /dlv` at the time: License Status: Notification, Notification Reason:
    0xC004FC07 (evaluation period exceeded). It took the guest down mid-provisioning, with no
    warning beyond the ID 1074 event a few seconds ahead of the actual shutdown.

    Runs on every `up` (create is always True in cmd_up's own call into
    provision_windows_guest - `vagrant up` is itself idempotent, so this runs whether the guest
    is being created for the first time or merely started again), not on every `sync` -
    because Windows evaluation rearms are a limited, consumable resource (this image ships
    with 2), not something to spend on every provisioning pass; `sync` (create=False) never
    reaches this function at all.

    Direct `vagrant winrm -c` (no `-e`/elevated shell) is enough for `slmgr /rearm`, the same
    as `reboot_windows_guest_and_wait`'s `shutdown /r`: this box already hands WinRM sessions a
    full, unfiltered High-integrity token (LocalAccountTokenFilterPolicy=1 - see cmd_run's
    comment on the same fact), so no separate elevation request is needed for a
    privileged operation issued over WinRM.
    """
    status, grace_minutes, rearm_remaining = get_windows_license_state(guest)
    needs_rearm = status != WINDOWS_LICENSE_STATUS_LICENSED or grace_minutes < WINDOWS_LICENSE_NEAR_EXPIRY_MINUTES
    if not needs_rearm:
        print(
            f"note: guest '{guest.name}' Windows evaluation license is current "
            f"(status={status}, grace={grace_minutes:.0f}min) - no rearm needed.",
            file=sys.stderr,
        )
        return
    if rearm_remaining <= 0:
        print(
            f"error: guest '{guest.name}' Windows evaluation license is expired or near "
            f"expiry (status={status}, grace={grace_minutes:.0f}min) and has 0 rearms "
            "remaining - the box's evaluation can no longer be extended; use a newer box.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"note: guest '{guest.name}' Windows evaluation license is expired or near expiry "
        f"(status={status}, grace={grace_minutes:.0f}min, {rearm_remaining} rearm(s) "
        "remaining) - running slmgr /rearm and rebooting for it to take effect.",
        file=sys.stderr,
    )
    run_vagrant(guest, ["winrm", "-c", "cscript.exe //nologo C:\\Windows\\System32\\slmgr.vbs /rearm"], display=display)
    reboot_windows_guest_and_wait(guest)
    new_status, new_grace_minutes, _ = get_windows_license_state(guest)
    if new_status != WINDOWS_LICENSE_STATUS_LICENSED:
        print(
            f"error: guest '{guest.name}' Windows evaluation license still not current after "
            f"rearm and reboot (status={new_status}, grace={new_grace_minutes:.0f}min) - the "
            "rearm did not take effect as expected. This is a bug (or the box's own rearm "
            "budget silently didn't reset), not something to proceed past.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"note: guest '{guest.name}' Windows evaluation license rearmed successfully "
        f"(status={new_status}, grace={new_grace_minutes:.0f}min).",
        file=sys.stderr,
    )


def provision_windows_guest(guest: Guest, *, auto_consent: bool, display: bool = False, create: bool) -> None:
    """Create (if `create`) and/or provision a Windows guest, driving each provisioning
    script directly over `vagrant winrm` (see run_windows_script) instead of Vagrant's WinRM
    shell provisioner — see that function's docstring for why.

    Order matches the original Vagrantfile-declared provisioner order exactly, since later
    steps depend on earlier ones: windows-clean-stage.ps1 must run before the "file"
    provisioner (still Vagrant-driven — plugins/provisioners/file/provisioner.rb is confirmed
    clean of any wait_for_reboot call, so there's no reason to reimplement WinRM file upload
    by hand) re-populates C:\\cosca-stage; windows-mirror-tree.ps1 and windows-lock-tree.ps1
    depend on that upload; windows-account-and-uac.ps1 and windows-rust.ps1 are independent of
    each other but both come last, matching the original order (rust installs before the
    reboot-required check, same as before this refactor).

    The license-rearm check (create only) runs before every other provisioning step,
    including windows-clean-stage.ps1: an expired-eval shutdown can land mid-step regardless
    of which step it is (measured 2026-09-24: it hit during windows-lock-tree.ps1), so there's
    no later step that's actually safer to run first - checking immediately, before spending
    any time on the rest, is strictly better than finding out partway through.
    """
    if create:
        # --no-provision: a fresh `up` would otherwise auto-run the one remaining
        # Vagrantfile-declared provisioner (the "file" upload) as part of creation, and then
        # the explicit `vagrant provision` call two lines down would run it a second,
        # redundant time. Skipping it here makes exactly one invocation happen either way
        # (create or not), driven explicitly below.
        run_vagrant(guest, ["up", "--provider", "qemu", "--no-provision"], display=display)
        ensure_windows_license_current(guest, display=display)
    run_windows_script(guest, WINDOWS_PROVISION_DIR / "windows-clean-stage.ps1", elevated=True, display=display)
    # The lone remaining Vagrantfile-declared provisioner: uploads the staged tree into
    # C:/cosca-stage. `run: "always"` on it means a plain `vagrant provision` re-runs it every
    # time, same as before this refactor.
    run_vagrant(guest, ["provision"], display=display)
    run_windows_script(guest, WINDOWS_PROVISION_DIR / "windows-mirror-tree.ps1", elevated=True, display=display)
    run_windows_script(guest, WINDOWS_PROVISION_DIR / "windows-lock-tree.ps1", elevated=True, display=display)
    account_output = run_windows_script(
        guest,
        WINDOWS_PROVISION_DIR / "windows-account-and-uac.ps1",
        elevated=True,
        display=display,
        env={"DEVVM_WINDOWS_AUTO_CONSENT": "1" if auto_consent else "0"},
    )
    run_windows_script(guest, WINDOWS_PROVISION_DIR / "windows-rust.ps1", elevated=False, display=display)

    if REBOOT_MARKER_TRUE in account_output:
        print(
            "note: an EnableLUA or autologon change needs a reboot to take effect — "
            "rebooting the guest now directly (devvm.py-driven; see reboot_windows_guest_and_wait, "
            "not Vagrant's wait_for_reboot fuse).",
            file=sys.stderr,
        )
        reboot_windows_guest_and_wait(guest)
    elif REBOOT_MARKER_FALSE not in account_output:
        print(
            "error: windows-account-and-uac.ps1 did not print a DEVVM_REBOOT_REQUIRED "
            "marker — can't tell whether a reboot is needed, so refusing to guess. This is a "
            "bug in the provisioner script, not something to silently proceed past.",
            file=sys.stderr,
        )
        sys.exit(1)


def cmd_up(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    dotfile_dir(guest).mkdir(parents=True, exist_ok=True)
    display = bool(getattr(args, "display", False))
    if args.allow_elevation and guest.communicator != "winrm":
        print("error: --allow-elevation only applies to Windows guests", file=sys.stderr)
        sys.exit(1)
    if display and guest.communicator != "winrm":
        print("error: --display only applies to Windows guests", file=sys.stderr)
        sys.exit(1)
    if guest.communicator == "winrm":
        # `--allow-elevation`/`--no-allow-elevation` explicitly sets and persists the choice;
        # omitting the flag reuses whatever was last persisted (default off) instead of
        # silently resetting it to off on every `up`.
        if args.allow_elevation is None:
            auto_consent = read_persisted_auto_consent(guest)
        else:
            auto_consent = args.allow_elevation
            write_persisted_auto_consent(guest, auto_consent)
    else:
        auto_consent = False
    if auto_consent:
        print(
            "note: auto-approve-consent is ON for this guest — ShellExecuteExW(\"runas\") will "
            "elevate without a UAC prompt. This is an opt-in probe-only mode; see "
            "scripts/README.md#windows-guests.",
            file=sys.stderr,
        )
    if display:
        print(
            "note: --display is ON for this guest — QEMU will open a local window on this Mac "
            "(-display cocoa -vga std) instead of running headless. This is a local window "
            "only, not VNC or any other network-exposed display; the loopback-only port "
            "forwarding guarantee is unaffected.",
            file=sys.stderr,
        )
    # Every guest's synced folder (Linux: rsync synced_folder; Windows: "file" provisioner)
    # sources from this staged, git-tracked-only copy — it must exist before `vagrant up`.
    stage_tree(guest)
    if guest.communicator == "winrm":
        provision_windows_guest(guest, auto_consent=auto_consent, display=display, create=True)
    else:
        run_vagrant(guest, ["up", "--provider", "qemu", "--provision"])
    if guest.communicator == "ssh":
        print(f"note: the read-only working tree is synced to {guest.tree_path_posix} — run `devvm.py sync {guest.name}` after local changes.")
    else:
        print(f"note: the read-only working tree is copied to {guest.tree_path_posix} — run `devvm.py sync {guest.name}` after local changes.")


def cmd_sync(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    if not dotfile_dir(guest).exists():
        print(f"error: guest '{guest.name}' has not been brought up yet; run `devvm.py up {guest.name}` first", file=sys.stderr)
        sys.exit(1)
    stage_tree(guest)
    if guest.communicator == "ssh":
        run_vagrant(guest, ["rsync"])
    else:
        # Reuse the persisted auto-consent choice (set by `up --allow-elevation`) rather than
        # implicitly defaulting to off and silently resetting a guest that had it on.
        auto_consent = read_persisted_auto_consent(guest)
        provision_windows_guest(guest, auto_consent=auto_consent, create=False)


def cmd_ssh(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    if guest.communicator == "ssh":
        run_vagrant(guest, ["ssh"])
        return
    # `vagrant powershell` shells out to a local powershell.exe/pwsh on the HOST, not the
    # guest — Vagrant 2.4.9's plugins/commands/powershell/command.rb:74 raises HostUnsupported
    # immediately on any host it doesn't detect as Windows. Refuse with the same message a
    # developer would otherwise get from a raw Vagrant traceback, pointing at the two working
    # alternatives instead: `run` for a one-off command, or RDP for an interactive session (the
    # loopback-only forwarded port every Windows guest already exposes — see that guest's
    # Vagrantfile). Don't bake in a host assumption beyond this check itself: on an actual
    # Windows host, `vagrant powershell` works fine and is used as before.
    if not sys.platform.startswith("win"):
        print(
            f"error: `devvm.py ssh {guest.name}` runs `vagrant powershell`, which only works "
            "on a Windows host — Vagrant 2.4.9 raises HostUnsupported immediately on any other "
            "host (plugins/commands/powershell/command.rb:74), before ever touching the guest. "
            f"Use `devvm.py run {guest.name} -- <cmd>` for a one-off command, or RDP into the "
            "guest for an interactive session (127.0.0.1:3389 by default — see the 'rdp' "
            f"forwarded_port in scripts/devvm/guests/{guest.name}/Vagrantfile).",
            file=sys.stderr,
        )
        sys.exit(1)
    run_vagrant(guest, ["powershell"])


def cmd_run(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    cmd_args = list(args.cmd)
    if cmd_args and cmd_args[0] == "--":
        cmd_args = cmd_args[1:]
    if not cmd_args:
        print("error: no command given; usage: devvm.py run <guest> -- <cmd...>", file=sys.stderr)
        sys.exit(1)
    if args.unelevated and guest.communicator != "winrm":
        print("error: --unelevated only applies to Windows guests", file=sys.stderr)
        sys.exit(1)
    if args.timeout is not None and not args.unelevated:
        print("error: --timeout only applies to --unelevated", file=sys.stderr)
        sys.exit(1)
    timeout = args.timeout if args.timeout is not None else 3600
    if timeout <= 0:
        print(f"error: --timeout must be positive, got {timeout}", file=sys.stderr)
        sys.exit(1)
    if timeout > WINDOWS_RUN_UNELEVATED_MAX_TIMEOUT_SECONDS:
        print(
            f"error: --timeout must be at most {WINDOWS_RUN_UNELEVATED_MAX_TIMEOUT_SECONDS} "
            f"(seconds*1000 must fit in a 32-bit millisecond count on the guest side), got "
            f"{timeout}",
            file=sys.stderr,
        )
        sys.exit(1)

    if guest.communicator == "ssh":
        # `vagrant ssh -c` runs a non-interactive, non-login shell, which doesn't source
        # ~/.bashrc — put rustup's install location on PATH explicitly rather than relying
        # on shell startup files the provisioner appended it to.
        inner = (
            f'export PATH="$HOME/.cargo/bin:$PATH"; '
            f"cd {guest.tree_path_posix} && CARGO_TARGET_DIR=$HOME/cargo-target {shlex.join(cmd_args)}"
        )
        run_vagrant(guest, ["ssh", "-c", inner])
        return

    # PowerShell over WinRM: cd into the read-only copy, point Cargo's build output at a
    # writable directory outside it, then run the requested command.
    #
    # No script-wide $ErrorActionPreference = "Stop" here (deliberately): Windows PowerShell
    # 5.1 sets $? to $false for a native command whenever ANYTHING reaches that command's real
    # stderr stream, regardless of exit code — e.g. cargo's own normal build-progress lines.
    # Under a script-wide Stop, that turns a successful `cargo build` into a terminating
    # NativeCommandError. Instead, `-ErrorAction Stop` is scoped to just the `Set-Location`
    # call, so a guest tree that's gone missing (e.g. `windows-mirror-tree.ps1` never ran)
    # still fails loudly without that scope swallowing the requested command's own stderr
    # noise.
    #
    # Getting the real exit code out reliably needs more than `exit $LASTEXITCODE`:
    # $LASTEXITCODE is only ever set by a *native* command. A typo'd command name
    # (CommandNotFoundException), the `Set-Location -ErrorAction Stop` failing, or `& $cmd`
    # itself being a cmdlet rather than an external program (no native process ever ran) all
    # leave $LASTEXITCODE at whatever it was before this one-liner started — often $null —
    # which `exit $LASTEXITCODE` then turns into exit code 0, i.e. success. Confirmed directly
    # (2026-09-25): `run windows-x64 -- carg test` (typo) and a missing tree directory both
    # previously exited 0. Fixed by: a script-scope `trap` that turns any *terminating* error
    # (the typo, the failed Set-Location, an uncaught throw) into an explicit `exit 1`
    # regardless of $ErrorActionPreference; resetting $LASTEXITCODE to $null immediately before
    # the real command runs, so a stale value from something earlier in the same PowerShell
    # session can't leak through as a false success; and, after the command, preferring
    # $LASTEXITCODE when it was actually set (the native-command case) and otherwise falling
    # back to `$?` (the cmdlet-only case, mapped to a 0/1 process exit code) rather than
    # assuming a native command ran at all.
    #
    # Every token — command name included — is quoted as a PowerShell string literal and
    # passed through the `&` call operator, so args with spaces/quotes/special characters
    # aren't re-parsed or re-split by PowerShell the way a naive `" ".join(...)` would allow.
    quoted_path = powershell_quote(guest.tree_path_posix)
    quoted_cmd = " ".join(powershell_quote(part) for part in cmd_args)
    inner = (
        'trap { Write-Host "devvm: $_"; exit 1 }; '
        f"Set-Location -Path {quoted_path} -ErrorAction Stop; "
        f'$env:CARGO_TARGET_DIR = "$HOME\\cargo-target"; '
        "$global:LASTEXITCODE = $null; "
        f"& {quoted_cmd}; "
        "if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }; "
        "exit [int](-not $?)"
    )

    if not args.unelevated:
        # Direct WinRM: a network logon with a full, unfiltered High-integrity token on this
        # box (LocalAccountTokenFilterPolicy=1) — fine for ordinary build/test commands, but
        # NOT a stand-in for the real interactive unelevated-user UAC path; see --unelevated.
        run_vagrant(guest, ["winrm", "-c", inner])
        return

    # --unelevated: route the same command through windows-run-unelevated.ps1 (already
    # present on the guest — it's part of the git-tracked tree staged/mirrored there), which
    # runs it via a scheduled task borrowing the current interactive logon's real filtered
    # token at LIMITED run level. Base64/UTF-16LE is exactly what PowerShell's own
    # -EncodedCommand expects, and sidesteps re-quoting `inner` (which already contains
    # nested quotes) through another two layers of shell (vagrant winrm -c, then schtasks).
    encoded = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    runner_path = f"{guest.tree_path_posix}/scripts/devvm/provision/windows-run-unelevated.ps1"
    # windows-run-unelevated.ps1 itself ends with `exit $exitCode` (the probe's real exit
    # code, propagated through its named-pipe wait — see that script), and has its own
    # script-scope `trap` that turns every terminating error inside ITS OWN scope into an
    # explicit `exit 1` before that. But this outer one-liner needs the same trap+reset+
    # fallback pattern as `inner` above, for failures that never reach that inner scope at
    # all: `& runner_path ...` itself throwing before the script body even starts (a bad
    # `-EncodedCommand` value failing PowerShell's own parameter binding, the file having gone
    # missing from the staged tree, ...) is a terminating error in THIS scope, not
    # windows-run-unelevated.ps1's — its own trap never gets a chance to run, and without a
    # trap here too, the error propagates straight out of this whole one-liner, silently
    # exiting 0. Confirmed directly (2026-09-25): `vagrant winrm -c 'throw "x"; exit
    # $LASTEXITCODE'` exits 0, not 1 — the same silent-success shape.
    #
    # When windows-run-unelevated.ps1's own `exit $exitCode` DOES run, that's a native-process-
    # equivalent script exit and reliably sets $LASTEXITCODE (confirmed by that script's own
    # `-TimeoutSeconds`/exit-code round-trip testing), so the `if ($null -ne $LASTEXITCODE)`
    # branch below is what actually carries the probe's real exit code out. The exact value
    # doesn't survive past this point either way: `run_vagrant`'s own `vagrant winrm -c` call
    # below collapses every nonzero exit code to 1 (see its comment) — only success vs. failure
    # reaches the caller, not which command in the chain failed or with what code.
    outer = (
        'trap { Write-Host "devvm: $_"; exit 1 }; '
        "$global:LASTEXITCODE = $null; "
        f"& {powershell_quote(runner_path)} -EncodedCommand {powershell_quote(encoded)} "
        f"-TimeoutSeconds {timeout}; "
        "if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }; "
        "exit [int](-not $?)"
    )
    run_vagrant(guest, ["winrm", "-c", outer])


def cmd_halt(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    run_vagrant(guest, ["halt"])


def cmd_destroy(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    returncode = run_vagrant(guest, ["destroy", "-f"], check=False)
    if returncode != 0:
        print(
            f"error: `vagrant destroy` failed (exit {returncode}) for guest '{guest.name}' — "
            "leaving .tmp/devvm state in place rather than deleting it out from under a VM "
            "that may still be running. Investigate (e.g. `vagrant status`, a stuck lock) "
            "and re-run `destroy` once it's actually gone.",
            file=sys.stderr,
        )
        sys.exit(returncode)
    guest_state = STATE_DIR / guest.name
    if guest_state.exists():
        shutil.rmtree(guest_state)


# CLI ==================================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devvm.py",
        description="Provision throwaway VMs for cosca's system-affecting tests. Dev tooling only — never a CI replacement.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list known guests and their state").set_defaults(func=cmd_list)

    p = sub.add_parser("up", help="create/start a guest and provision it")
    p.add_argument("guest", choices=GUESTS.keys())
    p.add_argument(
        "--allow-elevation",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="(Windows only) auto-approve UAC consent prompts, for unattended probe runs. Off "
        "by default. Persisted per guest — omit the flag on a later `up`/`sync` to keep "
        "reusing whatever was last set; pass --no-allow-elevation to explicitly turn it "
        "back off.",
    )
    p.add_argument(
        "--display",
        action="store_true",
        help="(Windows only) open a local QEMU window on this Mac (-display cocoa -vga std) "
        "instead of running headless, e.g. so a human can watch the guest's console live. "
        "Headless remains the default; this is a local window only, never VNC or any other "
        "network-exposed display. Not persisted — pass it again on every `up` that needs it.",
    )
    p.set_defaults(func=cmd_up)

    p = sub.add_parser("sync", help="push the current working tree into a running guest")
    p.add_argument("guest", choices=GUESTS.keys())
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("ssh", help="open an interactive shell in a guest")
    p.add_argument("guest", choices=GUESTS.keys())
    p.set_defaults(func=cmd_ssh)

    p = sub.add_parser("run", help="run one command in a guest, e.g.: devvm.py run linux-x64 -- cargo test")
    p.add_argument("guest", choices=GUESTS.keys())
    p.add_argument(
        "--unelevated",
        action="store_true",
        help="(Windows only) run via a scheduled task borrowing the current interactive "
        "logon's real filtered (non-elevated) token, instead of WinRM's own full-rights "
        "network-logon token — needed to measure the actual UAC/runas consent path.",
    )
    p.add_argument(
        "--timeout",
        type=int,
        help="Seconds to wait for an --unelevated command to finish (default 3600).",
    )
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="command to run, prefixed with --")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("halt", help="shut down a guest, keeping its disk")
    p.add_argument("guest", choices=GUESTS.keys())
    p.set_defaults(func=cmd_halt)

    p = sub.add_parser("destroy", help="delete a guest and its state entirely")
    p.add_argument("guest", choices=GUESTS.keys())
    p.set_defaults(func=cmd_destroy)

    return parser


def main(argv: list[str] | None = None) -> None:
    argv = list(argv if argv is not None else sys.argv[1:])

    # Special-case `run`: pull `--unelevated`, `--timeout`, and the trailing `-- <cmd...>` out
    # ourselves before argparse ever sees them — see parse_run_argv's docstring for why.
    unelevated = False
    timeout: int | None = None
    if argv[:1] == ["run"]:
        head, unelevated, timeout, cmd_tail = parse_run_argv(argv[1:])
        argv = ["run", *head]
    else:
        cmd_tail = None

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        args.unelevated = unelevated
        args.timeout = timeout
        args.cmd = cmd_tail if cmd_tail is not None else []
    args.func(args)


if __name__ == "__main__":
    main()
