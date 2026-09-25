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

CLI/orchestration and Linux-guest logic live here. Windows-guest lifecycle (provisioning,
reboot, licensing, session-wait) lives in devvm_windows.py; primitives shared by both (Guest,
run_vagrant, ...) live in devvm_common.py — see that module's own docstring for why the split
needs a third module rather than just these two.

See scripts/README.md for prerequisites, guest details, and usage examples.
"""

from __future__ import annotations

import argparse
import base64
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Sibling-module import, working whether this script runs directly as `__main__`
# (`uv run scripts/devvm.py ...` / `./scripts/devvm.py ...` puts scripts/ itself on sys.path
# automatically) or is loaded as `scripts.devvm` (devvm_test.py's `python -m unittest
# scripts.devvm_test` puts REPO_ROOT on sys.path instead, not scripts/ — scripts/ has no
# __init__.py and is a namespace package). Without this, the second mode's bare `import
# devvm_common` would fail with ModuleNotFoundError.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from devvm_common import (  # noqa: E402
    REPO_ROOT,
    STATE_DIR,
    Guest,
    auto_consent_state_path,
    dotfile_dir,
    get_vagrant_machine_state,
    powershell_quote,
    require_tool,
    run_vagrant,
    stage_dir,
)
from devvm_windows import get_windows_interactive_username, provision_windows_guest  # noqa: E402

# windows-run-unelevated.ps1 (the guest side of `devvm.py run --unelevated --timeout`) feeds
# -TimeoutSeconds, converted to milliseconds via its own Get-RemainingMs, into .NET
# NamedPipeClientStream.Connect(int) and Process.WaitForExit(int), both of which take a signed
# 32-bit millisecond count. A --timeout value whose *1000 doesn't fit in Int32 would only fail
# on the guest, after a slow round-trip there and back - reject it here instead, where the
# mistake is immediate and the error message is in front of the person who typed it.
WINDOWS_RUN_UNELEVATED_MAX_TIMEOUT_SECONDS = (2**31 - 1) // 1000


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
            "libvirt provider this tool uses. Build your own box from a Windows-on-ARM "
            "evaluation VHDX and pass its path via `qe.image_path` in a custom Vagrantfile "
            "if you need this lane; see scripts/README.md#windows-arm64 for details."
        ),
    ),
}


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


def cmd_up(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    display = bool(getattr(args, "display", False))
    # Both flag-validity checks run before dotfile_dir's mkdir or any other side effect below:
    # a validation check that's supposed to reject a flag combination should never let a real
    # filesystem/subprocess side effect happen first, on this or a later line, if it fails to
    # fire (e.g. a boundary-condition typo) — fail loudly with nothing to have already done.
    if args.allow_elevation and guest.communicator != "winrm":
        print("error: --allow-elevation only applies to Windows guests", file=sys.stderr)
        sys.exit(1)
    if display and guest.communicator != "winrm":
        print("error: --display only applies to Windows guests", file=sys.stderr)
        sys.exit(1)
    dotfile_dir(guest).mkdir(parents=True, exist_ok=True)
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
    # windows-run-unelevated.ps1's scheduled task needs an explicit interactive logon to borrow
    # a token from (see that script's own $currentUser comment) — resolved here, once, instead
    # of the guest-side script re-running the identical WMI query a second time.
    #
    # Bounded by `timeout` itself, not a short hardcoded window: this is a real `vagrant winrm`
    # round-trip against a guest that can be under TCG emulation, where even a trivial command
    # commonly takes on the order of 30s — a fixed 30s budget here previously made this lookup
    # itself the thing that timed out, which then misreported as "no interactive logon" instead
    # of a timeout.
    interactive_deadline = time.monotonic() + timeout
    interactive_user, interactive_output = get_windows_interactive_username(guest, interactive_deadline)
    if interactive_user is None:
        if time.monotonic() >= interactive_deadline:
            print(
                f"error: timed out after {timeout}s waiting for WinRM to report whether "
                "'vagrant' has an interactive (session 1, console or RDP-redirected) logon. "
                "Try a longer --timeout.",
                file=sys.stderr,
            )
        else:
            print(
                "error: no interactive (session 1, console or RDP-redirected) logon for 'vagrant' "
                "was found, so there is no logon for --unelevated's scheduled task to borrow. See "
                "windows-account-and-uac.ps1's autologon setup.",
                file=sys.stderr,
            )
        if interactive_output.strip():
            print(f"Last WinRM output:\n{interactive_output}", file=sys.stderr)
        sys.exit(1)

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
        f"-InteractiveUser {powershell_quote(interactive_user)} "
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
