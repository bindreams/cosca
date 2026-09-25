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
# what a TIMEBASED_EVAL image reports once its evaluation period elapses, on
# stromweld/windows-10 202503.09.0) means the guest is not currently licensed and needs a
# rearm before it's safe to leave unattended - see ensure_windows_license_current.
WINDOWS_LICENSE_STATUS_LICENSED = 1
# Rearm proactively within this many minutes of the eval period actually running out, not
# just once it's already hit zero - a guest that dies mid-provisioning run (see
# ensure_windows_license_current's docstring for the incident this is fixing) is worse than
# spending a rearm slightly early. One day's buffer is cheap next to the box's eval window
# (on the order of months) and the two rearms this image ships with.
WINDOWS_LICENSE_NEAR_EXPIRY_MINUTES = 24 * 60

# windows-run-unelevated.ps1 (the guest side of `devvm.py run --unelevated --timeout`) feeds
# -TimeoutSeconds, converted to milliseconds via its own Get-RemainingMs, into .NET
# NamedPipeClientStream.Connect(int) and Process.WaitForExit(int), both of which take a signed
# 32-bit millisecond count. A --timeout value whose *1000 doesn't fit in Int32 would only fail
# on the guest, after a slow round-trip there and back - reject it here instead, where the
# mistake is immediate and the error message is in front of the person who typed it.
WINDOWS_RUN_UNELEVATED_MAX_TIMEOUT_SECONDS = (2**31 - 1) // 1000

# The human-facing failure bound for reboot_windows_guest_and_wait's post-reboot wait and
# wait_for_windows_session's session wait (reused verbatim by provision_windows_guest even on
# an `up` that never reboots): a guest coming back up, or a session appearing, is a genuinely
# external event that might never complete, and this is the same already-configured,
# already-real bound the Windows Vagrantfile itself uses (config.vm.boot_timeout /
# config.winrm.timeout, both 3600s in scripts/devvm/guests/windows-x64/Vagrantfile) — not a
# second, uncoordinated guess.
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


def powershell_quote(value: str) -> str:
    """Quote a single token as a PowerShell single-quoted string literal.

    Single-quoted strings in PowerShell are taken verbatim except for `'`, which is escaped
    by doubling. Used with the `&` call operator (`& 'cmd' 'arg one' 'arg two'`) so each
    argument is passed through as a literal, not re-parsed/re-split by PowerShell.
    """
    return "'" + value.replace("'", "''") + "'"


def _diag_write(direct: bool, message_expr: str) -> str:
    """PowerShell statement text writing `message_expr` (an already-formed PS string
    expression) to the route's real diagnostic channel.

    `direct=True` (run over WinRM directly, a real WinRM/PSRP host attached) uses `Write-Host`.
    `direct=False` (nested inside windows-run-unelevated.ps1's headless
    `cmd.exe /d /c powershell -NonInteractive ...` child, no host attached) uses
    `[Console]::Error.WriteLine`, which bypasses $Host and writes straight to the process's own
    stderr handle.

    The two are not interchangeable: `[Console]::Error.WriteLine` writes nowhere on the direct
    route — `wsmprovhost` (the WinRM-side host process) has no stderr handle to reach. `Write-
    Host` on the nested route is what gets CLIXML-serialized onto that child's stderr in the
    first place (PS 5.1's "Default Host" behavior with no console attached).
    """
    if direct:
        return f"Write-Host {message_expr}"
    return f"[Console]::Error.WriteLine({message_expr})"


def build_run_inner(guest: Guest, cmd_args: list[str], *, direct: bool) -> str:
    """Build the PowerShell one-liner `cmd_run` runs on the guest: cd into the read-only tree
    copy, point Cargo's build output at a writable directory outside it, run the requested
    command, and propagate its real exit code.

    `direct` selects the diagnostic-writing mechanism (see `_diag_write`) for the two contexts
    this same script runs in: directly over WinRM (`direct=True`) or nested inside
    windows-run-unelevated.ps1's headless child (`direct=False`, --unelevated).

    No script-wide $ErrorActionPreference = "Stop" (deliberately): Windows PowerShell 5.1 sets
    $? to $false for a native command whenever ANYTHING reaches its real stderr stream,
    regardless of exit code — e.g. cargo's own normal build-progress lines — which under a
    script-wide Stop would turn a successful `cargo build` into a terminating
    NativeCommandError. `-ErrorAction Stop` is scoped to just `Set-Location`, so a guest tree
    that's gone missing still fails loudly without swallowing the requested command's own
    stderr noise.

    Getting the real exit code out reliably needs more than `exit $LASTEXITCODE`:
    $LASTEXITCODE is only ever set by a *native* command — a typo'd command name, a cmdlet-only
    invocation, or `Set-Location -ErrorAction Stop` failing all leave it at whatever it was
    before this one-liner started (often $null), which `exit $LASTEXITCODE` would then turn
    into exit code 0. Fixed by: a script-scope `trap` turning any *terminating* error into an
    explicit exit 1; resetting $LASTEXITCODE to $null right before the real command runs; and
    afterward preferring $LASTEXITCODE when it was actually set (the native-command case),
    otherwise falling back to `$?` (the cmdlet-only case, e.g. a non-terminating error from
    `Get-Item` on a missing path — mapped to a 0/1 process exit code).

    The `if ($null -ne $LASTEXITCODE)` condition is itself a bare comparison, not a cmdlet or
    pipeline invocation, so evaluating it does not itself update `$?` — PowerShell only updates
    `$?` for command/pipeline invocations, not for assignment or plain expression statements.
    Live-verified on the real guest (not just reasoned about): `run windows-x64 --
    Get-Item C:\\nope` exercises exactly this `direct=True`/no-`$LASTEXITCODE`/`else`-branch
    path (`Get-Item` on a missing path is a cmdlet-only failure, so $LASTEXITCODE stays $null)
    and exits nonzero end to end, as it would only do if `-not $?` still saw the real failure
    at that point.

    Every token — command name included — is quoted as a PowerShell string literal and passed
    through the `&` call operator, so args with spaces/quotes/special characters aren't
    re-parsed or re-split by PowerShell the way a naive `" ".join(...)` would.

    The real exit code is printed as text, via the same per-route diagnostic channel, whenever
    it's nonzero — the only place it's visible to a developer at all: `vagrant winrm -c`
    collapses every nonzero process exit code to 1 before it reaches devvm.py (see
    run_vagrant's comment), so devvm.py's own exit status can only ever say success-or-failure.

    `$ProgressPreference = 'SilentlyContinue'` (first statement) silences PowerShell's own
    module-loading progress record, another CLIXML source on the nested route unrelated to
    anything this one-liner itself prints.
    """
    quoted_path = powershell_quote(guest.tree_path_posix)
    quoted_cmd = " ".join(powershell_quote(part) for part in cmd_args)
    trap_write = _diag_write(direct, '"devvm: $_"')
    exit_write = _diag_write(direct, '"devvm: command exited $__devvmExit"')
    return (
        "$ProgressPreference = 'SilentlyContinue'; "
        f"trap {{ {trap_write}; exit 1 }}; "
        f"Set-Location -Path {quoted_path} -ErrorAction Stop; "
        f'$env:CARGO_TARGET_DIR = "$HOME\\cargo-target"; '
        "$global:LASTEXITCODE = $null; "
        f"& {quoted_cmd}; "
        "if ($null -ne $LASTEXITCODE) { $__devvmExit = $LASTEXITCODE } else { $__devvmExit = [int](-not $?) }; "
        f"if ($__devvmExit -ne 0) {{ {exit_write} }}; "
        "exit $__devvmExit"
    )


def stage_tree(guest: Guest, *, repo_root: Path = REPO_ROOT, dest: Path | None = None) -> None:
    """Rebuild a fresh copy of the working tree's git-TRACKED files under dest (default:
    .tmp/devvm/<guest>/tree).

    Every guest is served from this staged copy (not raw repo_root) so what lands in a guest
    is exactly `git ls-files` — never untracked files (e.g. CLAUDE.local.md, .claude/) and
    never a worktree's .git, which is a FILE (pointing at the parent repo's gitdir), not a
    directory, so a plain rsync `--exclude=.git/` pattern silently fails to match it and
    leaks it into the guest.

    dest is wiped and recreated on every call rather than rsync'd with `--delete`: on rsync
    3.5.1, `--delete` combined with `--files-from` is a silent no-op for removals — a file
    dropped from both the source tree and the files-list stays behind in an already-populated
    dest. Wiping dest first sidesteps the interaction entirely, since there is never anything
    stale left for a `--delete` flag to need to remove.

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
    `--` separator: `run windows-x64 --unelevated -- cargo test` leaves args.unelevated False,
    with `cmd`'s REMAINDER eating `--unelevated` itself. Extracting both
    flags by hand, before argparse ever runs, sidesteps the quirk entirely and lets either flag
    appear on either side of `guest`.

    The obvious alternative — drop REMAINDER, declare `cmd` as `nargs="*"`, and let argparse's
    own `--` handling do this — does NOT work on Python 3.11 (this repo's pinned minimum, see
    the `requires-python` header): under `uv run --python 3.11/3.12/3.13`,
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
            # get_vagrant_machine_state raises on unparsable output; `list` degrades to
            # "unknown" for that one guest instead of aborting the whole listing.
            try:
                state = get_vagrant_machine_state(guest)
            except RuntimeError:
                state = "unknown"
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
    guest System-log event 1074/1075 pairs lining up with `vagrant provision` runs (see
    scripts/README.md's root-cause note). `vagrant winrm -c` never reaches
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
    chars total - windows-rust.ps1 alone already encodes to a ~25350-char command line,
    comfortably under that limit today but with no margin that's guaranteed to hold as the
    script grows, and no PowerShell-side error if it's ever crossed (CreateProcess just fails
    on the guest). `-File` sidesteps the limit entirely - the
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
    "poweroff", "not_created", "stopped"). Used by _require_guest_running (and, through it,
    reboot_windows_guest_and_wait and wait_for_windows_session) to fail fast once the guest is
    no longer running, instead of retrying `vagrant winrm` in a tight loop against a guest that
    is never coming back on its own.

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


def set_windows_reboot_marker(guest: Guest) -> None:
    """Create a volatile registry key on the guest — one Windows guarantees does NOT survive a
    reboot (RegistryOptions.Volatile) — as a reboot-detection marker. Call before issuing the
    reboot; reboot_windows_guest_and_wait then polls get_windows_reboot_marker_present for its
    absence.

    Not a LastBootUpTime comparison: this guest's own clock has been observed to jump by hours
    across an ordinary reboot (NTP resync), which would make a wall-clock timestamp comparison
    unreliable in either direction.
    """
    cmd = (
        "$k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("
        "'SOFTWARE\\DevvmRebootMarker', $true, [Microsoft.Win32.RegistryOptions]::Volatile); "
        "$k.Close()"
    )
    run_vagrant(guest, ["winrm", "-c", cmd])


def get_windows_reboot_marker_present(guest: Guest) -> tuple[bool | None, str]:
    """Whether set_windows_reboot_marker's key still exists, or None if WinRM isn't answering
    right now (the wait loop treats that as "still waiting", not as an answer either way) —
    paired with the raw WinRM stdout+stderr, so a caller whose deadline expires while still
    getting None can report what the guest was actually saying, not just silence.

    No `timeout=` of our own on this subprocess call: `vagrant` execs a Ruby child to do the
    actual work, and a Python-side timeout would SIGKILL only the Go launcher, leaving that
    Ruby child running, reparented to PID 1, orphaned on the HOST — the leaked-process hazard
    CLAUDE.local.md's sandbox rule exists to prevent. The real failure bound for a caller that
    loops on this function (reboot_windows_guest_and_wait) is WINDOWS_REBOOT_DEADLINE_SECONDS,
    applied there.
    """
    result = subprocess.run(
        [
            "vagrant",
            "winrm",
            "-c",
            "if (Test-Path 'HKLM:\\SOFTWARE\\DevvmRebootMarker') { 'PRESENT' } else { 'ABSENT' }",
        ],
        cwd=guest_dir(guest),
        env=vagrant_env(guest),
        capture_output=True,
        text=True,
    )
    combined_output = result.stdout + result.stderr
    if result.returncode != 0:
        return None, combined_output
    output = result.stdout.strip()
    if output == "ABSENT":
        return False, combined_output
    if output == "PRESENT":
        return True, combined_output
    return None, combined_output


def get_windows_autologon_configured(guest: Guest) -> tuple[bool | None, str]:
    """Whether `HKLM:\\...\\Winlogon`'s `AutoAdminLogon` is already `1` on the guest right now,
    or None if WinRM isn't answering or gave an answer that isn't the explicit SET/UNSET this
    prints (the same "don't guess, retry" contract as get_windows_reboot_marker_present) —
    paired with the raw WinRM stdout+stderr, for the same reason.
    windows-account-and-uac.ps1 is the only thing that sets it, and the value persists across
    reboots once set — so this is `True` on any guest that has completed account/UAC
    provisioning at least once, even on an `up` that doesn't run that script again.
    provision_windows_guest uses this to know whether to wait for an interactive session
    before returning, on a guest where autologon was already configured by an earlier `up`.
    """
    result = subprocess.run(
        [
            "vagrant",
            "winrm",
            "-c",
            "if ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
            "-Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon -eq '1') { 'SET' } else { 'UNSET' }",
        ],
        cwd=guest_dir(guest),
        env=vagrant_env(guest),
        capture_output=True,
        text=True,
    )
    combined_output = result.stdout + result.stderr
    if result.returncode != 0:
        return None, combined_output
    output = result.stdout.strip()
    if output == "UNSET":
        return False, combined_output
    if output == "SET":
        return True, combined_output
    return None, combined_output


def get_windows_interactive_username(guest: Guest) -> tuple[str | None, str]:
    """The domain-qualified name of the guest's autologon account ("vagrant") if it currently
    has a live interactive logon anywhere, or None if it doesn't yet or WinRM isn't answering —
    paired with the raw WinRM stdout+stderr, for the same reason as
    get_windows_reboot_marker_present. Used by wait_for_windows_session to confirm autologon
    has actually produced a real interactive session — the thing
    windows-run-unelevated.ps1's scheduled task borrows a filtered token from — not just that
    the kernel has finished booting.

    Not `Win32_ComputerSystem.UserName` (an earlier version of this check): that property
    reports only the CONSOLE (session 1) session's owner, and goes blank the moment an RDP
    logon takes over that session — which this tool's own README recommends for interactive
    debugging. RDP taking over a client-SKU console session doesn't log the account out, it
    keeps driving the same interactive session remotely — so `vagrant` was genuinely still
    logged in, but reported as absent.

    Not `Win32_LoggedOnUser`/`Win32_LogonSession` either (a later version of this check,
    replacing the one above): live-verified 2026-09-25 that after fully signing 'vagrant' out
    (`logoff <session id>`, confirmed via `query session` no longer listing any session for the
    account), `Win32_LoggedOnUser` piped through `Win32_LogonSession` kept reporting the SAME
    LogonId, LogonType 2 (Interactive), for 'vagrant' as before the sign-out — a stale WMI/LSA
    association, not a live session. Waiting on that after a sign-out would return immediately
    with a false positive instead of actually waiting for the next real logon.

    The owner of a running `explorer.exe` (the desktop shell itself) does not have that
    staleness problem: in the same measurement it correctly went from 'vagrant' to nothing the
    moment the sign-out completed, and it needs no logon-type enumeration to be
    session-type-agnostic across console, RDP, and cached logons — a live desktop shell is
    proof enough on its own. This is therefore the sole check now, filtered to the owning
    account so an explorer.exe belonging to a different user already logged onto the same box
    can't be mistaken for 'vagrant's own session.

    windows-run-unelevated.ps1 runs the identical check, for the same reason, to find the
    `-UserId` its own scheduled task borrows a token from — see its header comment.
    """
    cmd = (
        "$o = Get-CimInstance -ClassName Win32_Process -Filter \"Name='explorer.exe'\" | "
        "ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName GetOwner } | "
        "Where-Object { $_.ReturnValue -eq 0 -and $_.User -eq 'vagrant' } | Select-Object -First 1; "
        'if ($o) { "$($o.Domain)\\$($o.User)" }'
    )
    result = subprocess.run(
        ["vagrant", "winrm", "-c", cmd],
        cwd=guest_dir(guest),
        env=vagrant_env(guest),
        capture_output=True,
        text=True,
    )
    combined_output = result.stdout + result.stderr
    if result.returncode != 0:
        return None, combined_output
    output = result.stdout.strip()
    return (output or None), combined_output


def _require_guest_running(guest: Guest, deadline: float, *, what: str, last_output: str = "") -> None:
    """Raise if the guest is no longer 'running' per vagrant, or if `deadline` (a
    time.monotonic() value) has passed. Shared by reboot_windows_guest_and_wait's wait loop and
    wait_for_windows_session's wait loop so a powered-off/crashed guest fails immediately
    instead of retrying WinRM forever, and so both loops fail on the same kind of monotonic
    bound (each call site passes its own `deadline`, not necessarily tied to a reboot).

    `last_output`, if given, is the raw stdout+stderr from the loop's most recent WinRM check —
    included in the deadline error so a human debugging a timeout sees what the guest was
    actually saying right before giving up, not just the bare "didn't finish within Ns."
    """
    state = get_vagrant_machine_state(guest)
    if state != "running":
        raise RuntimeError(
            f"devvm: guest '{guest.name}' is no longer 'running' (vagrant status: {state!r}) "
            f"while waiting for {what} — it will not come back on its own; run `devvm.py up` "
            "to bring it back."
        )
    if time.monotonic() >= deadline:
        message = (
            f"devvm: guest '{guest.name}' did not finish {what} within "
            f"{WINDOWS_REBOOT_DEADLINE_SECONDS}s."
        )
        if last_output.strip():
            message += f"\nLast WinRM output:\n{last_output}"
        raise RuntimeError(message)


def wait_for_windows_session(guest: Guest, deadline: float) -> None:
    """Block until the guest reports a real interactive (autologon) session on the console
    (session 1) — the thing windows-run-unelevated.ps1's scheduled task needs to borrow a
    filtered token from — or `deadline` (a time.monotonic() value) passes.

    A reboot's own marker clearing as soon as the kernel finishes booting can still be ahead
    of autologon actually producing that session. Callers that know a session is coming (a
    reboot that just configured autologon, or a guest that already has autologon configured)
    call this explicitly instead of letting the next unelevated probe race it.

    No `time.sleep()`: each iteration is a real WinRM round-trip, and failure just means "ask
    again immediately," not "nap, then ask again." Bounded by `deadline` and by
    `_require_guest_running` failing fast the moment `vagrant status` reports the guest isn't
    running any more.
    """
    last_output = ""
    while True:
        _require_guest_running(
            guest, deadline, what="an interactive (autologon) session", last_output=last_output
        )
        username, last_output = get_windows_interactive_username(guest)
        if username is not None:
            return


def reboot_windows_guest_and_wait(guest: Guest) -> None:
    """Issue a real guest reboot ourselves and block until the guest reports the reboot
    actually happened: set_windows_reboot_marker's marker, set before the reboot, has gone
    missing after it.

    Says nothing about sessions. A reboot completing is not the same as autologon having
    produced a real interactive session on top of it — callers that need one call
    wait_for_windows_session themselves afterward, under their own deadline.
    provision_windows_guest calls wait_for_windows_session conditionally — only when
    get_windows_autologon_configured says autologon is set — once, at the end of its own
    provisioning flow, regardless of whether THIS run's `up` actually rebooted the guest to get
    there: an already-provisioned guest where autologon was configured by an earlier `up` and
    this `up` only reboots for a license rearm (or doesn't reboot at all) still needs that wait,
    since nothing else is waiting for its session to come up.

    Deliberately does NOT go through Vagrant's named `reboot-if-needed` shell provisioner /
    `Reboot.reboot` capability: that path is itself a shell provisioner, so it still runs
    through `provision_winrm`'s unconditional `wait_for_reboot` fuse first, and its own
    `wait_for_reboot` wait loop (plugins/guests/windows/cap/reboot.rb) is a `sleep 10` poll on
    top of that same reboot_detect.ps1 probe. Issuing `shutdown /r` directly (the same command
    `Reboot.reboot` itself runs, confirmed by reading cap/reboot.rb) and then waiting for the
    reboot marker to clear avoids both.

    `shutdown /r /t 0`'s own exit code is NOT trusted as a pass/fail signal: a `/t 0` shutdown
    tears down the guest (and its WinRM connection) essentially immediately, so `vagrant winrm`
    can report a nonzero exit purely because the connection dropped out from under it
    mid-response — not because the reboot failed to schedule. The
    wait loop below is the real check that the reboot actually happened; a nonzero exit here
    is logged but does not abort early on its own.

    No `time.sleep()`, and no chosen retry interval of devvm.py's own: each iteration IS the
    wait — a real WinRM round-trip or a real `vagrant status` query — and failure just means
    "ask again immediately," not "nap, then ask again." The loop is bounded by one monotonic
    deadline (WINDOWS_REBOOT_DEADLINE_SECONDS, reusing the Windows Vagrantfile's own 3600s
    boot_timeout/winrm.timeout — a real, already-configured, human-facing failure bound for a
    guest reboot genuinely never completing) and by `_require_guest_running` failing fast the
    moment `vagrant status` reports the guest isn't running any more, instead of retrying
    `vagrant winrm` in a tight loop against a guest that is never answering again (a powered-off
    or crashed guest would otherwise burn a host core forever, since `vagrant winrm` itself has
    no readiness wait — see get_windows_reboot_marker_present's docstring).
    """
    set_windows_reboot_marker(guest)
    print(f"+ rebooting guest '{guest.name}' directly (shutdown /r) and waiting for the reboot marker to clear", file=sys.stderr)
    returncode = run_vagrant(guest, ["winrm", "-c", 'shutdown /r /t 0 /f /d p:4:1 /c "devvm reboot"'], check=False)
    if returncode != 0:
        print(
            f"devvm: `vagrant winrm` reported a nonzero exit ({returncode}) issuing the "
            f"reboot on guest '{guest.name}' — with `/t 0` that's expected even on a "
            "successfully-scheduled reboot, since the connection drops out from under it "
            "almost immediately. Proceeding to wait for the reboot marker to clear, which is "
            "the actual check.",
            file=sys.stderr,
        )

    deadline = time.monotonic() + WINDOWS_REBOOT_DEADLINE_SECONDS
    last_output = ""
    while True:
        _require_guest_running(
            guest, deadline, what="the reboot marker to clear", last_output=last_output
        )
        present, last_output = get_windows_reboot_marker_present(guest)
        if present is False:
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

    Why this exists: the stromweld/windows-10 box's eval image self-terminates once its
    evaluation period elapses - the Windows License Manager Service (wlms.exe) issues a
    genuine guest-initiated ACPI power-off (System event log ID 1074), not a devvm.py/cosca
    command or a crash, ending the whole QEMU process with only a few seconds' warning. It has
    taken the guest down mid-provisioning.

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
    # Session-waiting, if needed, happens once at the end of provision_windows_guest — this
    # reboot can run before windows-account-and-uac.ps1 has ever configured autologon, on a
    # genuinely fresh box, so waiting for a session here unconditionally could hang the full
    # WINDOWS_REBOOT_DEADLINE_SECONDS for no reason.
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
    of which step it is (it has hit during windows-lock-tree.ps1), so there's
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

    # Whether or not the block above rebooted: a real interactive (autologon) session may not
    # exist yet the moment this returns, and windows-run-unelevated.ps1's scheduled task needs
    # one to borrow a filtered token from. Checked here, conditionally — only when autologon is
    # actually configured — rather than folded into the reboot decision above, because a
    # session can be missing without a reboot having just run — e.g. this `up`'s license rearm
    # found nothing needing a reboot, or rebooted on a guest an earlier `up` already configured
    # autologon on. Skipped entirely when autologon genuinely isn't configured at all (a guest
    # windows-account-and-uac.ps1 has never provisioned successfully), where there's no session
    # to wait for.
    #
    # A None (WinRM not answering this particular check yet, even though every script above
    # just succeeded over it) is retried, not guessed at or treated as fatal on the first
    # occurrence — the same "ask again immediately, fail only once the guest is gone or the
    # deadline passes" contract wait_for_windows_session and reboot_windows_guest_and_wait's
    # own loops use, via the same _require_guest_running and one shared deadline (also reused
    # below for wait_for_windows_session itself, if it turns out to be needed).
    deadline = time.monotonic() + WINDOWS_REBOOT_DEADLINE_SECONDS
    last_output = ""
    while True:
        _require_guest_running(
            guest, deadline, what="a readable autologon-configured state", last_output=last_output
        )
        autologon_configured, last_output = get_windows_autologon_configured(guest)
        if autologon_configured is not None:
            break
    if autologon_configured:
        wait_for_windows_session(guest, deadline)


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

    if not args.unelevated:
        # Direct WinRM: a network logon with a full, unfiltered High-integrity token on this
        # box (LocalAccountTokenFilterPolicy=1) — fine for ordinary build/test commands, but
        # NOT a stand-in for the real interactive unelevated-user UAC path; see --unelevated.
        inner = build_run_inner(guest, cmd_args, direct=True)
        run_vagrant(guest, ["winrm", "-c", inner])
        return

    # --unelevated: route the same command through windows-run-unelevated.ps1 (already
    # present on the guest — it's part of the git-tracked tree staged/mirrored there), which
    # runs it via a scheduled task borrowing the current interactive logon's real filtered
    # token at LIMITED run level. Base64/UTF-16LE is exactly what PowerShell's own
    # -EncodedCommand expects, and sidesteps re-quoting `inner` (which already contains
    # nested quotes) through the further layers of shell it passes through on the guest
    # (windows-run-unelevated.ps1 itself, then its own wrapper script, then cmd.exe).
    inner = build_run_inner(guest, cmd_args, direct=False)
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
    # exiting 0: `vagrant winrm -c 'throw "x"; exit $LASTEXITCODE'` exits 0, not 1 — the same
    # silent-success shape.
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
