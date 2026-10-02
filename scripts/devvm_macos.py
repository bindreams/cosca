"""macOS guest lifecycle for devvm.py, via Tart (https://tart.run).

Each `up` makes a fresh copy-on-write `tart clone` of the pulled base image under a unique
name, runs it headless, and `destroy` always deletes it. The base image is never started or
modified. Apple's licence allows at most 2 concurrent macOS VMs per Mac, so `up` refuses a
third; the count is host-wide (every running local Tart VM, not just this tool's).

The base image is Cirrus Labs' `macos-tahoe-base`, NOT GitHub's runner image: CI stays the
merge gate, this is for fast local RED/GREEN and pre-checks. See scripts/README.md#macos-arm64.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

GUEST_NAME = "macos-arm64"
BASE_IMAGE = "ghcr.io/cirruslabs/macos-tahoe-base:latest"
VM_PREFIX = "devvm-macos-"
MAX_CONCURRENT_VMS = 2
GUEST_TREE = "~/cosca"
GUEST_USER = "admin"
PROVISION_SCRIPT = "scripts/devvm/provision/macos-rust.sh"


class CapExceeded(RuntimeError):
    pass


def tart_bin() -> str:
    """The tart executable: $TART if set, else `tart` on PATH."""
    explicit = os.environ.get("TART")
    if explicit:
        if not Path(explicit).is_file():
            raise RuntimeError(f"$TART is set to '{explicit}', which is not a file")
        return explicit
    found = shutil.which("tart")
    if found is None:
        raise RuntimeError(
            "tart not found: put it on PATH or set $TART to its path. See scripts/README.md#macos-arm64."
        )
    return found


def count_running(tart_list_json: str) -> int:
    n = 0
    for entry in json.loads(tart_list_json):
        if entry.get("Source") == "local" and (entry.get("State") == "running" or entry.get("Running") is True):
            n += 1
    return n


def check_cap(running: int) -> None:
    if running >= MAX_CONCURRENT_VMS:
        raise CapExceeded(
            f"{running} macOS VMs are already running on this Mac; Apple's licence allows at most "
            f"{MAX_CONCURRENT_VMS} concurrently. Destroy one first (`devvm.py destroy macos-arm64` "
            "in the worktree that owns it, or `tart list`)."
        )


def new_vm_name(repo_root: Path) -> str:
    import hashlib

    tag = hashlib.sha256(str(repo_root).encode()).hexdigest()[:6]
    return f"{VM_PREFIX}{tag}-{secrets.token_hex(3)}"


def require_own_name(name: str) -> None:
    """Never delete or stop anything this tool did not create (the base image included)."""
    if not name.startswith(VM_PREFIX):
        raise ValueError(f"refusing to touch '{name}': not a devvm-created VM (must start with '{VM_PREFIX}')")


def build_remote_command(cmd_args: list[str]) -> str:
    return (
        'export PATH="$HOME/.cargo/bin:$PATH"; '
        f"cd {GUEST_TREE} && CARGO_TARGET_DIR=$HOME/cargo-target {shlex.join(cmd_args)}"
    )


# Host-side tart calls =================================================================


def _tart(args: list[str], **kw) -> subprocess.CompletedProcess:
    cmd = [tart_bin(), *args]
    print(f"+ {shlex.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, **kw)


def _list_json() -> str:
    return _tart(["list", "--format", "json"], check=True, capture_output=True, text=True).stdout


def _state_dir(state_root: Path) -> Path:
    return state_root / GUEST_NAME


def read_vm_name(state_root: Path) -> str | None:
    f = _state_dir(state_root) / "vm_name"
    return f.read_text().strip() if f.exists() else None


def require_vm(state_root: Path) -> str:
    name = read_vm_name(state_root)
    if name is None:
        print("error: guest 'macos-arm64' has not been brought up; run `devvm.py up macos-arm64` first", file=sys.stderr)
        sys.exit(1)
    require_own_name(name)
    return name


def _exec(name: str, args: list[str], *, stdin=None, check: bool = False, **kw) -> subprocess.CompletedProcess:
    flags = ["-i"] if stdin is not None else []
    return _tart(["exec", *flags, name, *args], stdin=stdin, check=check, **kw)


def _archive_into_guest(repo_root: Path, name: str, rev: str) -> None:
    git = subprocess.Popen(["git", "-C", str(repo_root), "archive", "--format=tar", rev], stdout=subprocess.PIPE)
    assert git.stdout is not None
    untar = _exec(
        name,
        ["sh", "-c", f"rm -rf {GUEST_TREE} && mkdir -p {GUEST_TREE} && tar -x -C {GUEST_TREE}"],
        stdin=git.stdout,
    )
    git.stdout.close()
    if git.wait() != 0 or untar.returncode != 0:
        print(f"error: copying `git archive {rev}` into the guest failed", file=sys.stderr)
        sys.exit(1)


def _wait_for_agent(name: str, run: subprocess.Popen, log: Path) -> None:
    """Block until `tart exec` answers. `tart ip --wait` can return before `tart run` has
    registered the VM as running, so readiness is the first successful exec. The only failure
    is `tart run` itself exiting; retrying is a re-check of a deterministic condition."""
    while True:
        if _exec(name, ["true"], capture_output=True).returncode == 0:
            return
        if run.poll() is not None:
            print(f"error: `tart run` for {name} exited ({run.returncode}); see {log}", file=sys.stderr)
            sys.exit(1)
        time.sleep(1)


def up(repo_root: Path, state_root: Path, *, rev: str, rosetta: bool) -> None:
    if read_vm_name(state_root) is not None:
        print("error: guest 'macos-arm64' already exists for this worktree; `destroy` it first", file=sys.stderr)
        sys.exit(1)
    local = _tart(["list", "--format", "json"], check=True, capture_output=True, text=True).stdout
    if BASE_IMAGE not in {e.get("Name") for e in json.loads(local)}:
        print(
            f"error: base image {BASE_IMAGE} is not pulled. Check free disk (about 30 GB needed), then run: "
            f"{tart_bin()} pull {BASE_IMAGE}",
            file=sys.stderr,
        )
        sys.exit(1)

    sdir = _state_dir(state_root)
    sdir.mkdir(parents=True, exist_ok=True)
    name = new_vm_name(repo_root)
    # The cap check and the clone+run must be atomic across agents: two concurrent `up`s
    # would otherwise both see one running VM and both start another. The lock is held
    # until the new VM reports `running`.
    lock_path = Path.home() / ".tart" / "devvm-cap.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            check_cap(count_running(_list_json()))
        except CapExceeded as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
        _tart(["clone", BASE_IMAGE, name], check=True)
        (sdir / "vm_name").write_text(name + "\n")
        log = open(sdir / "tart-run.log", "wb")
        run = subprocess.Popen(
            [tart_bin(), "run", "--no-graphics", name],
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        _wait_for_agent(name, run, sdir / "tart-run.log")
    _archive_into_guest(repo_root, name, rev)
    # The provision script comes from THIS checkout (streamed on stdin), not from the rev
    # being tested: an older --rev may predate it. Only .github/ci-toolchain is read from the rev.
    with open(repo_root / PROVISION_SCRIPT, "rb") as script:
        r = _exec(
            name,
            ["bash", "-c", 'bash -s -- "$HOME/cosca" "$@"', "_", *(["--rosetta"] if rosetta else [])],
            stdin=script,
        )
    if r.returncode != 0:
        print("error: provisioning failed; `devvm.py destroy macos-arm64` to clean up", file=sys.stderr)
        sys.exit(r.returncode)
    print(f"note: {name} is up; source from `git archive {rev}` is at {GUEST_TREE} (committed state only).")


def sync(repo_root: Path, state_root: Path, *, rev: str) -> None:
    _archive_into_guest(repo_root, require_vm(state_root), rev)


def run(state_root: Path, cmd_args: list[str]) -> None:
    name = require_vm(state_root)
    r = _exec(name, ["bash", "-c", build_remote_command(cmd_args)])
    sys.exit(r.returncode)


def fetch(state_root: Path, guest_path: str, host_dest: Path) -> None:
    """Copy a file or directory out of the guest into host_dest (a directory, created)."""
    name = require_vm(state_root)
    host_dest.mkdir(parents=True, exist_ok=True)
    parent, base = os.path.split(guest_path.rstrip("/"))
    tar = _exec(name, ["tar", "-c", "-C", parent or ".", base], stdout=subprocess.PIPE)
    untar = subprocess.run(["tar", "-x", "-C", str(host_dest)], input=tar.stdout)
    if tar.returncode != 0 or untar.returncode != 0:
        print(f"error: fetching {guest_path} failed", file=sys.stderr)
        sys.exit(1)


def ssh(state_root: Path) -> None:
    name = require_vm(state_root)
    os.execvp(tart_bin(), [tart_bin(), "exec", "-i", "-t", name, "bash", "-l"])


def status(state_root: Path) -> str:
    name = read_vm_name(state_root)
    if name is None:
        return "not created"
    for e in json.loads(_list_json()):
        if e.get("Name") == name:
            return f"{e.get('State', '?')} ({name})"
    return f"missing ({name})"


def halt(state_root: Path) -> None:
    _tart(["stop", require_vm(state_root)], check=True)


def destroy(state_root: Path) -> None:
    """Stop and delete this worktree's VM. Only ever acts on a name this tool created."""
    name = read_vm_name(state_root)
    if name is None:
        return
    require_own_name(name)
    present = {e.get("Name") for e in json.loads(_list_json())}
    if name in present:
        _tart(["stop", name], check=False)
        r = _tart(["delete", name])
        if r.returncode != 0:
            print(f"error: `tart delete {name}` failed; leaving state in place", file=sys.stderr)
            sys.exit(r.returncode)
    shutil.rmtree(_state_dir(state_root))
