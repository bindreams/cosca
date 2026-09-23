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
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

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
    require_tool("vagrant")
    cwd = guest_dir(guest)
    cmd = ["vagrant", *args]
    print(f"+ (cd {cwd} && {shlex.join(cmd)})", file=sys.stderr)
    result = subprocess.run(cmd, cwd=cwd, env=vagrant_env(guest, auto_consent=auto_consent))
    if check and result.returncode != 0:
        sys.exit(result.returncode)
    return result.returncode


def stage_tree(guest: Guest) -> None:
    """rsync a filtered copy of the working tree into .tmp/devvm/<guest>/tree.

    Used as the upload source for guests whose communicator can't rsync directly into the
    guest (Windows/winrm). Linux/ssh guests rsync straight from REPO_ROOT and skip this.
    """
    require_tool("rsync")
    dest = stage_dir(guest)
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [
        "rsync",
        "--archive",
        "--delete",
        "--exclude=.git/",
        "--exclude=target/",
        "--exclude=.tmp/",
        f"{REPO_ROOT}/",
        f"{dest}/",
    ]
    print(f"+ {shlex.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, check=True)


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


def cmd_up(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    dotfile_dir(guest).mkdir(parents=True, exist_ok=True)
    if args.allow_elevation and guest.communicator != "winrm":
        print("error: --allow-elevation only applies to Windows guests", file=sys.stderr)
        sys.exit(1)
    if args.allow_elevation:
        print(
            "note: auto-approve-consent is ON for this guest — ShellExecuteExW(\"runas\") will "
            "elevate without a UAC prompt. This is an opt-in probe-only mode; see "
            "scripts/README.md#windows-guests.",
            file=sys.stderr,
        )
    if guest.communicator == "winrm":
        # The Windows guest's "file" provisioner uploads this staged copy (see its
        # Vagrantfile) — it must exist before the first `vagrant up --provision` runs it.
        stage_tree(guest)
    run_vagrant(guest, ["up", "--provider", "qemu", "--provision"], auto_consent=args.allow_elevation)
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
    if guest.communicator == "ssh":
        run_vagrant(guest, ["rsync"])
    else:
        stage_tree(guest)
        run_vagrant(guest, ["provision"])


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

    if guest.communicator == "ssh":
        # `vagrant ssh -c` runs a non-interactive, non-login shell, which doesn't source
        # ~/.bashrc — put rustup's install location on PATH explicitly rather than relying
        # on shell startup files the provisioner appended it to.
        inner = (
            f'export PATH="$HOME/.cargo/bin:$PATH"; '
            f"cd {guest.tree_path_posix} && CARGO_TARGET_DIR=$HOME/cargo-target {shlex.join(cmd_args)}"
        )
        run_vagrant(guest, ["ssh", "-c", inner])
    else:
        # PowerShell over WinRM: cd into the read-only copy, point Cargo's build output at a
        # writable directory outside it, then run the requested command.
        user_cmd = " ".join(cmd_args)
        inner = (
            f"cd {guest.tree_path_posix}; "
            f'$env:CARGO_TARGET_DIR = "$HOME\\cargo-target"; '
            f"{user_cmd}"
        )
        run_vagrant(guest, ["winrm", "-c", inner])


def cmd_halt(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    run_vagrant(guest, ["halt"])


def cmd_destroy(args: argparse.Namespace) -> None:
    guest = GUESTS[args.guest]
    require_available(guest)
    run_vagrant(guest, ["destroy", "-f"], check=False)
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
        action="store_true",
        help="(Windows only) auto-approve UAC consent prompts, for unattended probe runs. Off by default.",
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
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
