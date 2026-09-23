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
from dataclasses import dataclass
from pathlib import Path

# Last output line windows-account-and-uac.ps1 prints, telling devvm.py whether an
# EnableLUA/autologon change it just made needs a reboot to take effect (see cmd_up).
REBOOT_MARKER_TRUE = "DEVVM_REBOOT_REQUIRED=1"
REBOOT_MARKER_FALSE = "DEVVM_REBOOT_REQUIRED=0"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
GUESTS_DIR = SCRIPT_DIR / "devvm" / "guests"

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


def vagrant_env(guest: Guest, *, auto_consent: bool = False) -> dict[str, str]:
    env = dict(os.environ)
    env["VAGRANT_DOTFILE_PATH"] = str(dotfile_dir(guest))
    env["DEVVM_REPO_ROOT"] = str(REPO_ROOT)
    env["DEVVM_STAGE_DIR"] = str(stage_dir(guest))
    env["DEVVM_WINDOWS_AUTO_CONSENT"] = "1" if auto_consent else "0"
    return env


def run_vagrant(guest: Guest, args: list[str], *, auto_consent: bool = False, check: bool = True) -> int:
    # For `vagrant winrm -c ...` specifically: measured directly (2026-09-23) by running a
    # remote command that exited {0, 1, 2, 42, 255} in turn — `vagrant winrm`'s own process
    # exit code was 0 for the zero case and exactly 1 for every nonzero case, never the
    # remote value. So the returncode this function hands back (and sys.exit()s with) only
    # preserves zero-vs-nonzero for WinRM guests, not the remote command's actual exit code.
    require_tool("vagrant")
    cwd = guest_dir(guest)
    cmd = ["vagrant", *args]
    print(f"+ (cd {cwd} && {shlex.join(cmd)})", file=sys.stderr)
    result = subprocess.run(cmd, cwd=cwd, env=vagrant_env(guest, auto_consent=auto_consent))
    if check and result.returncode != 0:
        sys.exit(result.returncode)
    return result.returncode


def run_vagrant_streaming(
    guest: Guest, args: list[str], *, auto_consent: bool = False, check: bool = True
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
        env=vagrant_env(guest, auto_consent=auto_consent),
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
    """
    if "--" in rest:
        idx = rest.index("--")
        before, cmd_tail = rest[:idx], rest[idx + 1 :]
    else:
        before, cmd_tail = rest, []

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
            timeout = int(before[i + 1])
            i += 2
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


def run_windows_provision(guest: Guest, vagrant_args: list[str], *, auto_consent: bool) -> None:
    """Run a `vagrant up`/`vagrant provision` on a winrm guest, and act on the
    DEVVM_REBOOT_REQUIRED marker windows-account-and-uac.ps1 prints as its last output line:
    trigger the named reboot-if-needed provisioner and re-verify, or fail loudly if the
    marker is simply missing (a provisioner bug, not something to silently proceed past).
    """
    _, output = run_vagrant_streaming(guest, vagrant_args, auto_consent=auto_consent)
    if REBOOT_MARKER_TRUE in output:
        print(
            "note: an EnableLUA or autologon change needs a reboot to take effect — "
            "rebooting the guest now via Vagrant's own reboot-and-wait capability.",
            file=sys.stderr,
        )
        run_vagrant(guest, ["provision", "--provision-with", "reboot-if-needed"])
        verify_windows_account_settings(guest)
    elif REBOOT_MARKER_FALSE not in output:
        print(
            "error: windows-account-and-uac.ps1 did not print a DEVVM_REBOOT_REQUIRED "
            "marker — can't tell whether a reboot is needed, so refusing to guess. This is a "
            "bug in the provisioner script, not something to silently proceed past.",
            file=sys.stderr,
        )
        sys.exit(1)


def verify_windows_account_settings(guest: Guest) -> None:
    """Post-reboot sanity check that EnableLUA and autologon actually took effect."""
    check_cmd = (
        '$lua = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion'
        '\\Policies\\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA; '
        '$auto = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT'
        '\\CurrentVersion\\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)'
        ".AutoAdminLogon; "
        'Write-Host "DEVVM_VERIFY_LUA=$lua"; '
        'Write-Host "DEVVM_VERIFY_AUTOLOGON=$auto"'
    )
    _, output = run_vagrant_streaming(guest, ["winrm", "-c", check_cmd])
    lua_ok = "DEVVM_VERIFY_LUA=1" in output
    autologon_ok = "DEVVM_VERIFY_AUTOLOGON=1" in output
    if not lua_ok or not autologon_ok:
        print(
            "error: post-reboot verification failed — EnableLUA/autologon did not take "
            f"effect as expected (lua_ok={lua_ok}, autologon_ok={autologon_ok}). Output:\n{output}",
            file=sys.stderr,
        )
        sys.exit(1)


def cmd_up(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    dotfile_dir(guest).mkdir(parents=True, exist_ok=True)
    if args.allow_elevation and guest.communicator != "winrm":
        print("error: --allow-elevation only applies to Windows guests", file=sys.stderr)
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
    # Every guest's synced folder (Linux: rsync synced_folder; Windows: "file" provisioner)
    # sources from this staged, git-tracked-only copy — it must exist before `vagrant up`.
    stage_tree(guest)
    if guest.communicator == "winrm":
        run_windows_provision(
            guest, ["up", "--provider", "qemu", "--provision"], auto_consent=auto_consent
        )
    else:
        run_vagrant(guest, ["up", "--provider", "qemu", "--provision"], auto_consent=auto_consent)
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
        run_windows_provision(guest, ["provision"], auto_consent=auto_consent)


def cmd_ssh(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    if guest.communicator == "ssh":
        run_vagrant(guest, ["ssh"])
    else:
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
    # No script-wide $ErrorActionPreference = "Stop" here (deliberately, and unlike the
    # previous version of this function): Windows PowerShell 5.1 sets $? to $false for a
    # native command whenever ANYTHING reaches that command's real stderr stream, regardless
    # of exit code — e.g. cargo's own normal build-progress lines. Under a script-wide Stop,
    # that turns a successful `cargo build` into a terminating NativeCommandError. Instead,
    # `-ErrorAction Stop` is scoped to just the `Set-Location` call, so a genuinely bad --dir
    # path still fails loudly without that scope swallowing the native command's own stderr
    # noise. The trailing `exit $LASTEXITCODE` makes this script's own process exit code
    # reflect the native command's real exit code, independent of $?. Every token — command
    # name included — is quoted as a PowerShell string literal and passed through the `&`
    # call operator, so args with spaces/quotes/special characters aren't re-parsed or
    # re-split by PowerShell the way a naive `" ".join(...)` would allow.
    quoted_path = powershell_quote(guest.tree_path_posix)
    quoted_cmd = " ".join(powershell_quote(part) for part in cmd_args)
    inner = (
        f"Set-Location -Path {quoted_path} -ErrorAction Stop; "
        f'$env:CARGO_TARGET_DIR = "$HOME\\cargo-target"; '
        f"& {quoted_cmd}; "
        "exit $LASTEXITCODE"
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
    # code, propagated through its named-pipe wait — see that script). The trailing
    # `exit $LASTEXITCODE` here is belt-and-suspenders, not dead code: a .ps1 invoked via `&`
    # does not by itself terminate the *calling* script's execution on a nonzero exit without
    # this, it only sets $LASTEXITCODE for the calling script to act on. That said, the exact
    # value doesn't survive past this point either way: `run_vagrant`'s own `vagrant winrm -c`
    # call below collapses every nonzero exit code to 1 (see its comment) — only success vs.
    # failure reaches the caller, not which command in the chain failed or with what code.
    outer = (
        f"& {powershell_quote(runner_path)} -EncodedCommand {powershell_quote(encoded)} "
        f"-TimeoutSeconds {timeout}; "
        "exit $LASTEXITCODE"
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
