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
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

GUEST_NAME = "macos-arm64"
BASE_IMAGE_REPO = "ghcr.io/cirruslabs/macos-tahoe-base"
BASE_IMAGE_TAG = "latest"
BASE_IMAGE_DIGEST = "sha256:1b093499716409d29e8b5336844528e1cae375db97d2ad8e5aeff78cf0da201e"
BASE_IMAGE = f"{BASE_IMAGE_REPO}@{BASE_IMAGE_DIGEST}"
# Failure bound on an external event (the guest booting and its agent answering), surfaced to a
# human; not a sync primitive between processes this tool controls.
AGENT_BOOT_TIMEOUT_SECONDS = 600
VM_PREFIX = "devvm-macos-"
MAX_CONCURRENT_VMS = 2
GUEST_TREE = "~/cosca"
GUEST_USER = "admin"
PROVISION_SCRIPT = "scripts/devvm/provision/macos-rust.sh"


class CapExceeded(RuntimeError):
    pass


class NameTaken(RuntimeError):
    pass


class BadRev(ValueError):
    pass


class AlreadyUp(RuntimeError):
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
    """A fresh 128-bit name. repo_root is unused: the name must not depend on the worktree."""
    return f"{VM_PREFIX}{uuid.uuid4().hex}"


def require_name_free(name: str, tart_list_json: str) -> None:
    if name in {e.get("Name") for e in json.loads(tart_list_json)}:
        raise NameTaken(f"a Tart VM named '{name}' already exists; refusing to clone over it")


def resolve_rev(repo_root: Path, rev: str) -> str:
    """The full commit sha for rev. `--end-of-options` keeps an option-looking rev from being
    read as a git flag; everything later uses the sha, which cannot look like one."""
    r = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise BadRev(f"'{rev}' is not a commit in {repo_root}")
    return r.stdout.strip()


def identity_matches(recorded: dict, current: dict) -> bool:
    return recorded.get("ino") == current.get("ino") and recorded.get("dev") == current.get("dev")


def tart_home() -> Path:
    return Path(os.environ.get("TART_HOME") or Path.home() / ".tart")


def vm_identity(name: str) -> dict:
    st = (tart_home() / "vms" / name / "disk.img").stat()
    return {"ino": st.st_ino, "dev": st.st_dev}


def claim_state(state_root: Path, name: str) -> None:
    """Atomically claim this worktree's single macOS guest (O_EXCL), before anything is cloned."""
    d = _state_dir(state_root)
    d.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(d / "vm_name", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        raise AlreadyUp("guest 'macos-arm64' already exists for this worktree; `destroy` it first") from None
    with os.fdopen(fd, "w") as f:
        f.write(name + "\n")


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
    return f.read_text().split()[0] if f.exists() and f.read_text().strip() else None


def _identity_file(state_root: Path) -> Path:
    return _state_dir(state_root) / "identity.json"


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
    git = subprocess.Popen(["git", "-C", str(repo_root), "archive", "--format=tar", "--end-of-options", rev], stdout=subprocess.PIPE)
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
    registered the VM as running, so readiness is the first successful exec. Guest boot is an
    external event that may never complete, so the wait has a failure bound reported to the
    human; `tart run` exiting also fails it."""
    deadline = time.monotonic() + AGENT_BOOT_TIMEOUT_SECONDS
    while True:
        if _exec(name, ["true"], capture_output=True).returncode == 0:
            return
        if run.poll() is not None:
            raise RuntimeError(f"`tart run` for {name} exited ({run.returncode}); see {log}")
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"the guest {name} did not answer within {AGENT_BOOT_TIMEOUT_SECONDS}s of starting "
                f"(boot hang, or an image without the Tart guest agent); see {log}"
            )
        time.sleep(1)


def _lock_cap(lock) -> None:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("devvm: another `up` holds the host-wide macOS VM lock; waiting for it...", file=sys.stderr)
        fcntl.flock(lock, fcntl.LOCK_EX)


def _teardown(state_root: Path, name: str) -> None:
    """Best-effort removal of a VM this tool created, used when `up` fails or is interrupted."""
    require_own_name(name)
    try:
        if name in {e.get("Name") for e in json.loads(_list_json())}:
            _tart(["stop", name], check=False)
            _tart(["delete", name], check=False)
    finally:
        for f in ("vm_name", "identity.json"):
            (_state_dir(state_root) / f).unlink(missing_ok=True)


def up(repo_root: Path, state_root: Path, *, rev: str, rosetta: bool) -> None:
    try:
        sha = resolve_rev(repo_root, rev)  # before anything boots
    except BadRev as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    local = _list_json()
    if BASE_IMAGE not in {e.get("Name") for e in json.loads(local)}:
        print(
            f"error: base image {BASE_IMAGE} is not pulled. Check free disk (about 30 GB needed), then run: "
            f"{tart_bin()} pull {BASE_IMAGE}",
            file=sys.stderr,
        )
        sys.exit(1)

    sdir = _state_dir(state_root)
    name = new_vm_name(repo_root)
    # The cap check, the claim and the clone+run must be atomic across agents: two concurrent
    # `up`s would otherwise both see one running VM and both start another. The lock is
    # released as soon as the new VM answers, or when it fails.
    lock_path = tart_home() / "devvm-cap.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    run = None
    created = False
    try:
        with open(lock_path, "w") as lock:
            _lock_cap(lock)
            try:
                claim_state(state_root, name)  # refuses a second `up` in this worktree
            except AlreadyUp as e:
                print(f"error: {e}", file=sys.stderr)
                sys.exit(1)
            created = True
            current = _list_json()
            try:
                check_cap(count_running(current))
                require_name_free(name, current)
            except (CapExceeded, NameTaken) as e:
                print(f"error: {e}", file=sys.stderr)
                sys.exit(1)
            _tart(["clone", BASE_IMAGE, name], check=True)
            _identity_file(state_root).write_text(json.dumps(vm_identity(name)))
            log = sdir / "tart-run.log"
            with open(log, "wb") as logf:
                run = subprocess.Popen(
                    [tart_bin(), "run", "--no-graphics", name],
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            _wait_for_agent(name, run, log)
        _archive_into_guest(repo_root, name, sha)
        # The provision script comes from THIS checkout (streamed on stdin), not from the rev
        # being tested: an older --rev may predate it. Only .github/ci-toolchain is read from the rev.
        with open(repo_root / PROVISION_SCRIPT, "rb") as script:
            r = _exec(
                name,
                ["bash", "-c", 'bash -s -- "$HOME/cosca" "$@"', "_", *(["--rosetta"] if rosetta else [])],
                stdin=script,
            )
        if r.returncode != 0:
            raise RuntimeError("provisioning failed")
    except BaseException as e:
        if created:
            if not isinstance(e, SystemExit):
                print(f"error: {e!r}" if not isinstance(e, RuntimeError) else f"error: {e}", file=sys.stderr)
            _teardown(state_root, name)
            print(f"devvm: removed the partly-created VM {name}", file=sys.stderr)
        if isinstance(e, RuntimeError):
            sys.exit(1)
        raise
    print(f"note: {name} is up; source from `git archive {sha}` is at {GUEST_TREE} (committed state only).")


def sync(repo_root: Path, state_root: Path, *, rev: str) -> None:
    name = require_vm(state_root)
    try:
        sha = resolve_rev(repo_root, rev)
    except BadRev as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    _archive_into_guest(repo_root, name, sha)


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
    """Stop and delete this worktree's VM. Only acts on a name this tool created, and only if
    the VM on disk is still the one it created (a same-named replacement is refused)."""
    name = read_vm_name(state_root)
    if name is None:
        return
    require_own_name(name)
    present = {e.get("Name") for e in json.loads(_list_json())}
    if name in present:
        idf = _identity_file(state_root)
        if idf.exists() and not identity_matches(json.loads(idf.read_text()), vm_identity(name)):
            print(
                f"error: VM {name} is not the one this worktree created (its disk changed); refusing "
                "to stop or delete it. Inspect `tart list` by hand.",
                file=sys.stderr,
            )
            sys.exit(1)
        r = _tart(["stop", name])
        if r.returncode != 0:
            print(f"error: `tart stop {name}` failed; leaving state in place", file=sys.stderr)
            sys.exit(r.returncode)
        r = _tart(["delete", name])
        if r.returncode != 0:
            print(f"error: `tart delete {name}` failed; leaving state in place", file=sys.stderr)
            sys.exit(r.returncode)
    shutil.rmtree(_state_dir(state_root))
