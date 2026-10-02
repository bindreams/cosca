"""macOS guest backend for devvm.py via Tart (https://tart.run); see scripts/README.md#macos-arm64.

The base image is Cirrus Labs' `macos-tahoe-base`, not GitHub's runner image: CI stays the merge gate.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import shlex
import shutil
import signal
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
# Failure bound on guest boot (an external event), reported to the human.
AGENT_BOOT_TIMEOUT_SECONDS = 600
VM_PREFIX = "devvm-macos-"
MAX_CONCURRENT_VMS = 2
GUEST_TREE = "~/cosca"
PROVISION_SCRIPT = "scripts/devvm/provision/macos-rust.sh"
# Guest side of `fetch`: expands a leading `~/` in the guest, then tars the path.
FETCH_SCRIPT = (
    'p=$1; case "$p" in "~/"*) p="$HOME/${p#"~/"}";; esac; '
    'p=${p%/}; exec tar -c -C "$(dirname "$p")" "$(basename "$p")"'
)


class CapExceeded(RuntimeError):
    pass


class NameTaken(RuntimeError):
    pass


class BadRev(ValueError):
    pass


class AlreadyUp(RuntimeError):
    pass


class UpError(RuntimeError):
    """A failure `up` reports to the human after cleaning up."""


# Pure helpers =========================================================================


def tart_bin() -> str:
    """The tart executable: $TART if set, else `tart` on PATH."""
    explicit = os.environ.get("TART")
    if explicit:
        if not Path(explicit).is_file():
            raise RuntimeError(f"$TART is set to '{explicit}', which is not a file")
        return explicit
    found = shutil.which("tart")
    if found is None:
        raise RuntimeError("tart not found: put it on PATH or set $TART to its path. See scripts/README.md#macos-arm64.")
    return found


def tart_home() -> Path:
    return Path(os.environ.get("TART_HOME") or Path.home() / ".tart")


def count_running(vms: list[dict]) -> int:
    return sum(
        1
        for e in vms
        if e.get("Source") == "local" and (e.get("State") == "running" or e.get("Running") is True)
    )


def check_cap(running: int) -> None:
    if running >= MAX_CONCURRENT_VMS:
        raise CapExceeded(
            f"{running} macOS VMs are already running on this Mac; Apple's licence allows at most "
            f"{MAX_CONCURRENT_VMS} concurrently. Destroy one first (`devvm.py destroy macos-arm64` "
            "in the worktree that owns it, or `tart list`)."
        )


def new_vm_name() -> str:
    return f"{VM_PREFIX}{uuid.uuid4().hex}"


def require_name_free(name: str, vms: list[dict]) -> None:
    if name in {e.get("Name") for e in vms}:
        raise NameTaken(f"a Tart VM named '{name}' already exists; refusing to clone over it")


def require_own_name(name: str) -> None:
    """Never delete or stop anything this tool did not create (the base image included)."""
    if not name.startswith(VM_PREFIX):
        raise ValueError(f"refusing to touch '{name}': not a devvm-created VM (must start with '{VM_PREFIX}')")


def resolve_rev(repo_root: Path, rev: str) -> str:
    """The full commit sha for rev; `--end-of-options` keeps an option-looking rev from being a git flag."""
    r = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise BadRev(f"'{rev}' is not a commit in {repo_root}")
    return r.stdout.strip()


def identity_matches(recorded: dict, current: dict) -> bool:
    keys = ("ino", "dev")
    return all(k in recorded and k in current and recorded[k] == current[k] for k in keys)


def build_remote_command(cmd_args: list[str]) -> str:
    return (
        'export PATH="$HOME/.cargo/bin:$PATH"; '
        f"cd {GUEST_TREE} && CARGO_TARGET_DIR=$HOME/cargo-target {shlex.join(cmd_args)}"
    )


def parse_guest_path(path: str) -> str:
    """Validate a fetch source: absolute, or `~/`-relative (expanded in the guest)."""
    if not (path.startswith("/") or path.startswith("~/")):
        raise ValueError(f"fetch needs an absolute path (or ~/...), got '{path}'; quote ~ so the host shell leaves it")
    target = path[2:] if path.startswith("~/") else path
    if os.path.basename(target.rstrip("/")) in ("", ".", ".."):
        raise ValueError(f"'{path}' names no file or directory")
    return path


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


@contextlib.contextmanager
def _flock(path: Path, waiting_for: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"devvm: waiting for {waiting_for}...", file=sys.stderr)
            fcntl.flock(f, fcntl.LOCK_EX)
        yield


@contextlib.contextmanager
def _signals_raise():
    """SIGTERM and SIGHUP raise SystemExit, so `up`'s cleanup runs like it does for Ctrl-C."""

    def handler(signum, _frame):
        raise SystemExit(128 + signum)

    old = {s: signal.signal(s, handler) for s in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for s, h in old.items():
            signal.signal(s, h)


# Tart runner (the test seam) ==========================================================


class Tart:
    """Thin wrapper over the tart CLI; tests substitute a fake with the same methods."""

    def __init__(self, binary: str | None = None):
        self.binary = binary or tart_bin()
        self.home = tart_home()

    def _cmd(self, args: list[str]) -> list[str]:
        cmd = [self.binary, *args]
        print(f"+ {shlex.join(cmd)}", file=sys.stderr)
        return cmd

    def vms(self) -> list[dict]:
        out = subprocess.run(self._cmd(["list", "--format", "json"]), check=True, capture_output=True, text=True)
        return json.loads(out.stdout)

    def clone(self, src: str, name: str) -> int:
        return subprocess.run(self._cmd(["clone", src, name])).returncode

    def start(self, name: str, log: Path) -> subprocess.Popen:
        with open(log, "wb") as logf:
            return subprocess.Popen(
                self._cmd(["run", "--no-graphics", name]),
                stdout=logf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

    def stop(self, name: str) -> int:
        return subprocess.run(self._cmd(["stop", name])).returncode

    def delete(self, name: str) -> int:
        return subprocess.run(self._cmd(["delete", name])).returncode

    def _exec_cmd(self, name: str, args: list[str], stdin) -> list[str]:
        return self._cmd(["exec", *(["-i"] if stdin is not None else []), name, *args])

    def exec(self, name, args, *, stdin=None, capture_output=False) -> subprocess.CompletedProcess:
        return subprocess.run(self._exec_cmd(name, args, stdin), stdin=stdin, capture_output=capture_output)

    def exec_popen(self, name, args, *, stdout) -> subprocess.Popen:
        return subprocess.Popen(self._exec_cmd(name, args, None), stdout=stdout)

    def exec_interactive(self, name: str) -> None:
        cmd = self._cmd(["exec", "-i", "-t", name, "bash", "-l"])
        os.execvp(cmd[0], cmd)

    def identity(self, name: str) -> dict:
        """The VM's disk identity; raises FileNotFoundError if its disk.img is missing."""
        st = (self.home / "vms" / name / "disk.img").stat()
        return {"ino": st.st_ino, "dev": st.st_dev}


# Backend ==============================================================================


class MacosBackend:
    def __init__(self, tart: Tart, repo_root: Path, state_root: Path):
        self.tart = tart
        self.repo_root = repo_root
        self.sdir = state_root / GUEST_NAME
        self._proc: subprocess.Popen | None = None  # the `tart run` child `up` owns
        self._clone_attempted = False

    # state -----------------------------------------------------------------------

    @property
    def _claim_file(self) -> Path:
        return self.sdir / "vm_name"

    @property
    def _identity_file(self) -> Path:
        return self.sdir / "identity.json"

    def _read_claim(self) -> str | None:
        """The recorded VM name; None if there is no claim, "" if the claim is empty."""
        try:
            text = self._claim_file.read_text()
        except FileNotFoundError:
            return None
        parts = text.split()
        return parts[0] if parts else ""

    def _claim(self, name: str) -> None:
        self.sdir.mkdir(parents=True, exist_ok=True)
        tmp = self.sdir / f"vm_name.{uuid.uuid4().hex}.tmp"
        with open(tmp, "w") as f:
            f.write(name + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, self._claim_file)
        except FileExistsError:
            raise AlreadyUp("guest 'macos-arm64' already exists for this worktree; `destroy` it first") from None
        finally:
            tmp.unlink(missing_ok=True)

    def _clear_state(self) -> None:
        for f in (self._claim_file, self._identity_file):
            f.unlink(missing_ok=True)

    def _worktree_lock(self):
        return _flock(self.sdir / "lock", "another devvm command in this worktree")

    def _cap_lock(self):
        return _flock(self.tart.home / "devvm-cap.lock", "the host-wide macOS VM lock (another `up` is running)")

    def _require_vm(self) -> str:
        name = self._read_claim()
        if not name:
            print("error: guest 'macos-arm64' has not been brought up; run `devvm.py up macos-arm64` first", file=sys.stderr)
            sys.exit(1)
        require_own_name(name)
        return name

    # removal ---------------------------------------------------------------------

    def _names(self) -> set[str]:
        return {e.get("Name") for e in self.tart.vms()}

    def _remove_vm(self, name: str, proc: subprocess.Popen | None) -> str | None:
        """Stop and delete the VM, then confirm it is gone. Returns a problem description, or None."""
        require_own_name(name)
        if name in self._names():
            self.tart.stop(name)
            running = {e.get("Name") for e in self.tart.vms() if e.get("State") == "running" or e.get("Running") is True}
            if name in running:
                return f"`tart stop {name}` did not stop it"
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
            proc.wait()
        if name in self._names():
            rc = self.tart.delete(name)
            if rc != 0 or name in self._names():
                return f"`tart delete {name}` failed (exit {rc})"
        return None

    def _teardown(self, name: str) -> None:
        """Remove a VM `up` created. Never raises, so the original error survives; keeps the state on failure."""
        try:
            existed = name in self._names()
            problem = self._remove_vm(name, self._proc)
        except Exception as e:  # noqa: BLE001
            existed, problem = True, repr(e)
        if problem is None:
            self._clear_state()
            if existed:
                print(f"devvm: removed VM {name}", file=sys.stderr)
        else:
            print(
                f"devvm: could not remove VM {name}: {problem}. State kept; run `devvm.py destroy macos-arm64`.",
                file=sys.stderr,
            )

    # up --------------------------------------------------------------------------

    def _reject_windows_flags(self, args: argparse.Namespace) -> None:
        for flag, attr in (("--allow-elevation", "allow_elevation"), ("--display", "display")):
            if getattr(args, attr, None):
                print(f"error: {flag} only applies to Windows guests", file=sys.stderr)
                sys.exit(1)

    def up(self, args: argparse.Namespace) -> None:
        self._reject_windows_flags(args)
        try:
            sha = resolve_rev(self.repo_root, args.rev or "HEAD")
        except BadRev as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
        if BASE_IMAGE not in self._names():
            print(
                f"error: base image {BASE_IMAGE} is not pulled. Check free disk (about 30 GB needed), then run: "
                f"{self.tart.binary} pull {BASE_IMAGE}",
                file=sys.stderr,
            )
            sys.exit(1)
        name = new_vm_name()
        try:
            with _signals_raise(), self._worktree_lock():
                self._claim(name)
                self._up_claimed(name, sha, bool(getattr(args, "rosetta", False)))
        except (AlreadyUp, UpError) as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"note: {name} is up; source from `git archive {sha}` is at {GUEST_TREE} (committed state only).")

    def _up_claimed(self, name: str, sha: str, rosetta: bool) -> None:
        self._proc = None
        self._clone_attempted = False
        try:
            self._up_locked(name, sha, rosetta)
        except BaseException:
            if not self._clone_attempted:  # interrupted before any VM existed: the claim must not wedge the worktree
                self._clear_state()
            raise

    def _up_locked(self, name: str, sha: str, rosetta: bool) -> None:
        with self._cap_lock():
            try:
                self._acquire_cap_slot(name)
                self._create_vm(name)
                self._boot(name)
            except BaseException:
                self._teardown(name)
                raise
        try:
            self._stage(name, sha, rosetta)
        except BaseException:
            with self._cap_lock():
                self._teardown(name)
            raise

    def _acquire_cap_slot(self, name: str) -> None:
        vms = self.tart.vms()
        try:
            check_cap(count_running(vms))
            require_name_free(name, vms)
        except (CapExceeded, NameTaken) as e:
            raise UpError(str(e)) from None

    def _create_vm(self, name: str) -> None:
        self._clone_attempted = True
        rc = self.tart.clone(BASE_IMAGE, name)
        if rc != 0:
            raise UpError(f"`tart clone` failed (exit {rc})")
        _write_atomic(self._identity_file, json.dumps(self.tart.identity(name)))

    def _boot(self, name: str) -> None:
        log = self.sdir / "tart-run.log"
        self._proc = self.tart.start(name, log)
        self._wait_for_agent(name, self._proc, log)

    def _wait_for_agent(self, name: str, proc: subprocess.Popen, log: Path) -> None:
        # `tart ip --wait` can return before `tart run` registers the VM, so readiness is the first exec that answers.
        deadline = time.monotonic() + AGENT_BOOT_TIMEOUT_SECONDS
        while True:
            if self.tart.exec(name, ["true"], capture_output=True).returncode == 0:
                return
            if proc.poll() is not None:
                raise UpError(f"`tart run` for {name} exited ({proc.returncode}); see {log}")
            if time.monotonic() >= deadline:
                raise UpError(
                    f"the guest {name} did not answer within {AGENT_BOOT_TIMEOUT_SECONDS}s of starting "
                    f"(boot hang, or an image without the Tart guest agent); see {log}"
                )
            time.sleep(1)

    def _stage(self, name: str, sha: str, rosetta: bool) -> None:
        self._archive_into_guest(name, sha)
        # Streamed from THIS checkout: an older --rev may predate the script.
        with open(self.repo_root / PROVISION_SCRIPT, "rb") as script:
            r = self.tart.exec(
                name,
                ["bash", "-c", 'bash -s -- "$HOME/cosca" "$@"', "_", *(["--rosetta"] if rosetta else [])],
                stdin=script,
            )
        if r.returncode != 0:
            raise UpError("provisioning failed")

    def _archive_into_guest(self, name: str, sha: str) -> None:
        git = subprocess.Popen(
            ["git", "-C", str(self.repo_root), "archive", "--format=tar", "--end-of-options", sha],
            stdout=subprocess.PIPE,
        )
        assert git.stdout is not None
        untar = self.tart.exec(
            name,
            ["sh", "-c", f"rm -rf {GUEST_TREE} && mkdir -p {GUEST_TREE} && tar -x -C {GUEST_TREE}"],
            stdin=git.stdout,
        )
        git.stdout.close()
        if git.wait() != 0 or untar.returncode != 0:
            raise UpError(f"copying `git archive {sha}` into the guest failed")

    # other verbs -----------------------------------------------------------------

    def sync(self, args: argparse.Namespace) -> None:
        name = self._require_vm()
        try:
            sha = resolve_rev(self.repo_root, args.rev or "HEAD")
            self._archive_into_guest(name, sha)
        except (BadRev, UpError) as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)

    def run(self, args: argparse.Namespace) -> None:
        for flag, attr in (("--unelevated", "unelevated"), ("--timeout", "timeout")):
            if getattr(args, attr, None):
                print(f"error: {flag} only applies to Windows guests", file=sys.stderr)
                sys.exit(1)
        cmd_args = list(args.cmd)
        if cmd_args and cmd_args[0] == "--":
            cmd_args = cmd_args[1:]
        if not cmd_args:
            print("error: no command given; usage: devvm.py run <guest> -- <cmd...>", file=sys.stderr)
            sys.exit(1)
        name = self._require_vm()
        sys.exit(self.tart.exec(name, ["bash", "-c", build_remote_command(cmd_args)]).returncode)

    def ssh(self, _args: argparse.Namespace) -> None:
        self.tart.exec_interactive(self._require_vm())

    def fetch(self, args: argparse.Namespace) -> None:
        name = self._require_vm()
        try:
            guest_path = parse_guest_path(args.guest_path)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
        dest = Path(args.host_dest)
        dest.mkdir(parents=True, exist_ok=True)
        src = self.tart.exec_popen(name, ["sh", "-c", FETCH_SCRIPT, "_", guest_path], stdout=subprocess.PIPE)
        assert src.stdout is not None
        untar = subprocess.run(["tar", "-x", "-C", str(dest)], stdin=src.stdout)
        src.stdout.close()
        if src.wait() != 0 or untar.returncode != 0:
            print(f"error: fetching {guest_path} failed", file=sys.stderr)
            sys.exit(1)

    def halt(self, _args: argparse.Namespace) -> None:
        print("error: halt is not supported for macos-arm64 (a halted VM cannot be resumed); use `destroy`", file=sys.stderr)
        sys.exit(1)

    def status(self) -> str:
        name = self._read_claim()
        if name is None:
            return "not created"
        if not name:
            return "corrupt claim"
        for e in self.tart.vms():
            if e.get("Name") == name:
                return f"{e.get('State', '?')} ({name})"
        return f"missing ({name})"

    def destroy(self, _args: argparse.Namespace) -> None:
        """Stop and delete this worktree's VM, but only the one this worktree created."""
        with self._worktree_lock():
            name = self._read_claim()
            if name is None:
                return
            if not name:
                print("warning: empty claim file; removing it (no VM is recorded)", file=sys.stderr)
                self._clear_state()
                return
            require_own_name(name)
            if name not in self._names():
                print(f"note: VM {name} was already gone", file=sys.stderr)
                self._clear_state()
                return
            self._check_identity(name)
            problem = self._remove_vm(name, None)
            if problem is not None:
                print(f"error: {problem}; leaving state in place", file=sys.stderr)
                sys.exit(1)
            self._clear_state()

    def _check_identity(self, name: str) -> None:
        """Fail closed: a present VM is touched only if its recorded disk identity matches."""
        hint = "Inspect `tart list` and delete it by hand if it is yours."
        try:
            recorded = json.loads(self._identity_file.read_text())
        except (FileNotFoundError, ValueError):
            print(f"error: no usable identity recorded for VM {name}, so it cannot be verified as this worktree's. {hint}", file=sys.stderr)
            sys.exit(1)
        try:
            current = self.tart.identity(name)
        except FileNotFoundError:
            print(f"error: VM {name} has no disk.img under {self.tart.home}/vms; cannot verify it. {hint}", file=sys.stderr)
            sys.exit(1)
        if not identity_matches(recorded, current):
            print(f"error: VM {name} is not the one this worktree created (its disk changed); refusing. {hint}", file=sys.stderr)
            sys.exit(1)
