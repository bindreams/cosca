"""macOS guest backend for devvm.py via Tart (https://tart.run); see scripts/README.md#macos-arm64.

The base image is Cirrus Labs' `macos-tahoe-base`, not GitHub's runner image: CI stays the merge gate.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import select
import shlex
import shutil
import signal
import subprocess
import sys
import threading
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
CHECKPOINTS = ("start", "claimed", "locked", "counted", "cloned", "booted", "unlocked", "archived", "provisioned")
PROVISION_SCRIPT = "scripts/devvm/provision/macos-rust.sh"
# Guest side of `fetch`: expands a leading `~/` in the guest, then tars the path. The `./` keeps the
# name from being read as an option (`-x`) or, by bsdtar, as "copy entries from this archive" (`@x`).
FETCH_SCRIPT = (
    'p=$1; case "$p" in "~/"*) p="$HOME/${p#"~/"}";; esac; '
    'p=${p%/}; exec tar -c -C "$(dirname "$p")" "./$(basename "$p")"'
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
            f"{running} Tart VMs are already running on this Mac (every local VM is counted, Linux ones "
            f"included); Apple's licence allows at most {MAX_CONCURRENT_VMS} macOS VMs concurrently. "
            "Destroy one first (`devvm.py destroy macos-arm64` in the worktree that owns it, or `tart list`)."
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


def _say(message: str, *, file=None) -> None:
    """print() that cannot fail: a closed pipe or a hung-up terminal must not break cleanup or the exit code."""
    file = file if file is not None else sys.stderr
    try:
        print(message, file=file)
        file.flush()
    except (OSError, ValueError):
        # Point the stream at /dev/null, so neither later prints nor the flush at interpreter exit fail.
        null = open(os.devnull, "w")  # noqa: SIM115  lives as long as the process
        if file is sys.stderr:
            sys.stderr = null
        elif file is sys.stdout:
            sys.stdout = null


class Cancelled(BaseException):
    """A signal asked `up` or `destroy` to stop. Raised by SignalGate's own code, never from a signal handler."""

    def __init__(self, signo: int):
        super().__init__(signal.Signals(signo).name)
        self.signo = signo


class SignalGate:
    """Turns SIGINT, SIGTERM and SIGHUP into data.

    The Python handlers do nothing; the signal number is written to a non-blocking self-pipe
    (`signal.set_wakeup_fd`). Nothing is ever raised from a handler, so a signal cannot unwind
    through library code (subprocess, locks) halfway. Every wait multiplexes on the pipe via
    `wait_for`, and `check` is polled between steps; both raise `Cancelled` from ordinary code.
    Signals the process inherited as ignored (`nohup`, a backgrounded non-interactive shell)
    stay ignored.
    """

    SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    on_blocked = None  # test seam: a staticmethod called just before every blocking select

    def __init__(self) -> None:
        self.pending: list[int] = []
        self.abandoned: list[threading.Thread] = []  # lock waiters left behind by a cancelled wait
        self._old: dict[int, object] = {}
        self._old_wakeup = -1
        self._r, self._w = os.pipe()
        os.set_blocking(self._r, False)
        os.set_blocking(self._w, False)

    def __enter__(self) -> SignalGate:
        self._old_wakeup = signal.set_wakeup_fd(self._w, warn_on_full_buffer=False)
        for sig in self.SIGNALS:
            if signal.getsignal(sig) is not signal.SIG_IGN:
                self._old[sig] = signal.signal(sig, lambda _signo, _frame: None)
        return self

    def __exit__(self, *_exc) -> None:
        # Handlers first: a later signal then takes its default action instead of being recorded
        # and dropped. Then one last drain, so `pending` holds every signal that was recorded.
        for sig, handler in self._old.items():
            signal.signal(sig, handler)
        self._drain()
        signal.set_wakeup_fd(self._old_wakeup)
        os.close(self._r)
        os.close(self._w)

    def _drain(self) -> None:
        while True:
            try:
                data = os.read(self._r, 64)
            except BlockingIOError:
                return
            if not data:
                return
            self.pending.extend(data)

    def check(self) -> None:
        self._drain()
        if self.pending:
            raise Cancelled(self.pending[0])

    def wait_for(self, fds: list[int], timeout: float | None = None) -> list[int]:
        """Block until one of `fds` is readable or `timeout` passes; raise `Cancelled` on a signal."""
        if self.on_blocked:
            self.on_blocked()
        self.check()
        ready, _, _ = select.select([self._r, *fds], [], [], timeout)
        self.check()
        return [fd for fd in ready if fd != self._r]

    def sleep(self, seconds: float) -> None:
        self.wait_for([], seconds)

    def run(self, argv: list[str], *, stdin=None, capture_output=False, text=False, **kw) -> subprocess.CompletedProcess:
        """subprocess.run that a signal can cut short: the child is killed and reaped, then `Cancelled` is raised."""
        pipe = subprocess.PIPE if capture_output else None
        proc = subprocess.Popen(argv, stdin=stdin, stdout=pipe, stderr=pipe, text=text, **kw)
        done_r, done_w = os.pipe()
        result: list = []

        def communicate() -> None:
            try:
                result.append(proc.communicate())
            finally:
                os.write(done_w, b"x")

        waiter = threading.Thread(target=communicate, daemon=True)
        waiter.start()
        try:
            self.wait_for([done_r])
        except BaseException:
            proc.kill()
            raise
        finally:
            waiter.join()
            os.close(done_r)
            os.close(done_w)
        out, err = result[0]
        return subprocess.CompletedProcess(argv, proc.returncode, out, err)

    def flock(self, f) -> None:
        """Take an exclusive flock on `f`, waiting in a helper thread so that a signal can end the wait.

        On `Cancelled` this has taken over `f`: a waiter that is still blocked closes it, releasing
        the lock, the moment it would have acquired it. A lock acquired just before the cancel is
        released here. Either way no lock outlives the cancelled wait.
        """
        mutex, state = threading.Lock(), {"s": "waiting", "error": None}
        done_r, done_w = os.pipe()

        def acquire() -> None:
            error = None
            try:
                fcntl.flock(f, fcntl.LOCK_EX)
            except BaseException as e:  # noqa: BLE001
                error = e
            with mutex:
                if state["s"] == "abandoned":
                    f.close()
                else:
                    state["s"], state["error"] = "done", error
                    os.write(done_w, b"x")
            os.close(done_w)

        waiter = threading.Thread(target=acquire, daemon=True)
        waiter.start()
        try:
            self.wait_for([done_r])
        except BaseException:
            with mutex:
                if state["s"] == "done":
                    f.close()
                else:
                    state["s"] = "abandoned"
                    self.abandoned.append(waiter)
            os.close(done_r)
            raise
        os.close(done_r)
        waiter.join()
        if state["error"] is not None:
            f.close()
            raise state["error"]


@contextlib.contextmanager
def _flock(path: Path, waiting_for: str, gate: SignalGate | None = None):
    """Hold an exclusive flock; the wait can be ended by a signal only if a gate is given."""
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, "w")  # noqa: SIM115
    handed_off = False
    try:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _say(f"devvm: waiting for {waiting_for}...")
            if gate is None:
                fcntl.flock(f, fcntl.LOCK_EX)
            else:
                handed_off = True  # on Cancelled the gate has taken over `f`
                gate.flock(f)
                handed_off = False
        yield
    finally:
        if not handed_off:
            f.close()


# Tart runner (the test seam) ==========================================================


class Tart:
    """Thin wrapper over the tart CLI; tests substitute a fake with the same methods.

    Methods that take `gate` wait through it, so a signal ends them (child killed, `Cancelled` raised).
    """

    def __init__(self, binary: str | None = None):
        self.binary = binary or tart_bin()
        self.home = tart_home()

    def _cmd(self, args: list[str]) -> list[str]:
        cmd = [self.binary, *args]
        _say(f"+ {shlex.join(cmd)}")
        return cmd

    @staticmethod
    def _run(argv: list[str], gate: SignalGate | None, **kw) -> subprocess.CompletedProcess:
        return gate.run(argv, **kw) if gate else subprocess.run(argv, **kw)

    def vms(self, gate: SignalGate | None = None) -> list[dict]:
        out = self._run(
            self._cmd(["list", "--format", "json"]),
            gate,
            capture_output=True,
            text=True,
            start_new_session=True,  # cleanup's children must not see a terminal Ctrl-C
        )
        out.check_returncode()
        return json.loads(out.stdout)

    def clone(self, src: str, name: str, gate: SignalGate | None = None) -> int:
        return self._run(self._cmd(["clone", src, name]), gate).returncode

    def start(self, name: str, log: Path) -> subprocess.Popen:
        with open(log, "wb") as logf:
            return subprocess.Popen(
                self._cmd(["run", "--no-graphics", name]),
                stdout=logf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

    def stop(self, name: str) -> int:
        return subprocess.run(self._cmd(["stop", name]), start_new_session=True).returncode

    def delete(self, name: str) -> int:
        return subprocess.run(self._cmd(["delete", name]), start_new_session=True).returncode

    def _exec_cmd(self, name: str, args: list[str], stdin) -> list[str]:
        return self._cmd(["exec", *(["-i"] if stdin is not None else []), name, *args])

    def exec(self, name, args, *, stdin=None, capture_output=False, gate=None) -> subprocess.CompletedProcess:
        return self._run(self._exec_cmd(name, args, stdin), gate, stdin=stdin, capture_output=capture_output)

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
    def __init__(self, tart: Tart | None, repo_root: Path, state_root: Path):
        self._tart = tart  # built on first use: `list` and `status` must work without tart installed
        self.repo_root = repo_root
        self.sdir = state_root / GUEST_NAME
        self._proc: subprocess.Popen | None = None  # the `tart run` child `up` owns
        self._gate: SignalGate | None = None
        self.last_gate: SignalGate | None = None  # for tests: the abandoned lock waiters
        self._claimed = self._clone_attempted = self._cleaned = self._done = False

    @property
    def tart(self) -> Tart:
        if self._tart is None:
            self._tart = Tart()
        return self._tart

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

    def _worktree_lock(self, *, interruptible: bool):
        return _flock(self.sdir / "lock", "another devvm command in this worktree", self._gate if interruptible else None)

    def _cap_lock(self, *, interruptible: bool):
        return _flock(
            self.tart.home / "devvm-cap.lock",
            "the host-wide macOS VM lock (another `up` is running)",
            self._gate if interruptible else None,
        )

    def _pause(self, seconds: float) -> None:
        self._gate.sleep(seconds) if self._gate else time.sleep(seconds)

    def _checkpoint(self, label: str) -> None:
        assert label in CHECKPOINTS, label
        if self._gate:
            self._gate.check()

    def _require_vm(self) -> str:
        name = self._read_claim()
        if not name:
            _say("error: guest 'macos-arm64' has not been brought up; run `devvm.py up macos-arm64` first")
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
                _say(f"devvm: removed VM {name}")
        else:
            _say(
                f"devvm: could not remove VM {name}: {problem}. State kept; run `devvm.py destroy macos-arm64`.")

    def _cleanup(self, name: str, *, lock_held: bool) -> None:
        """Undo whatever `up` created, once. Signals are only recorded here, so it cannot be cut short."""
        if self._done or self._cleaned or not self._claimed:
            return
        self._cleaned = True
        try:
            if not self._clone_attempted:  # no VM exists: the claim must not wedge the worktree
                self._clear_state()
            elif lock_held:
                self._teardown(name)
            else:
                with self._cap_lock(interruptible=False):
                    self._teardown(name)
        except Exception as e:  # noqa: BLE001
            _say(f"devvm: cleanup of {name} failed: {e!r}. Run `devvm.py destroy macos-arm64`.")

    # up --------------------------------------------------------------------------

    def _reject_windows_flags(self, args: argparse.Namespace) -> None:
        for flag, attr in (("--allow-elevation", "allow_elevation"), ("--display", "display")):
            if getattr(args, attr, None):
                _say(f"error: {flag} only applies to Windows guests")
                sys.exit(1)

    def up(self, args: argparse.Namespace) -> None:
        self._reject_windows_flags(args)
        try:
            sha = resolve_rev(self.repo_root, args.rev or "HEAD")
        except BadRev as e:
            _say(f"error: {e}")
            sys.exit(1)
        if BASE_IMAGE not in self._names():
            _say(
                f"error: base image {BASE_IMAGE} is not pulled. Check free disk (about 30 GB needed), then run: "
                f"{self.tart.binary} pull {BASE_IMAGE}")
            sys.exit(1)
        name = new_vm_name()
        self._proc = None
        self._claimed = self._clone_attempted = self._cleaned = self._done = False
        error = cancelled = None
        with SignalGate() as gate:
            self._gate = self.last_gate = gate
            try:
                with self._worktree_lock(interruptible=True):
                    try:
                        self._up_steps(name, sha, bool(getattr(args, "rosetta", False)))
                    finally:
                        self._cleanup(name, lock_held=False)
            except Cancelled as c:
                cancelled = c.signo
            except (AlreadyUp, UpError) as e:
                error = str(e)
        self._gate = None
        # Read after the gate has restored the handlers and drained its pipe: every signal recorded at
        # any point is in `pending`, and one arriving later takes its default action.
        pending = gate.pending
        if error is not None:
            _say(f"error: {error}")
            sys.exit(128 + pending[0] if pending else 1)
        if cancelled is not None:
            _say(f"devvm: interrupted by {signal.Signals(cancelled).name}")
            sys.exit(128 + cancelled)
        _say(f"note: {name} is up; source from `git archive {sha}` is at {GUEST_TREE} (committed state only).", file=sys.stdout)
        if pending:
            _say(f"devvm: interrupted by {signal.Signals(pending[0]).name} after `up` had finished; {name} is up (`destroy` removes it)")
            sys.exit(128 + pending[0])

    def _up_steps(self, name: str, sha: str, rosetta: bool) -> None:
        cp = self._checkpoint
        cp("start")
        self._claim(name)
        self._claimed = True
        cp("claimed")
        with self._cap_lock(interruptible=True):
            try:
                cp("locked")
                self._acquire_cap_slot(name)
                cp("counted")
                self._create_vm(name)
                cp("cloned")
                self._boot(name)
                cp("booted")
            except BaseException:
                self._cleanup(name, lock_held=True)
                raise
        cp("unlocked")
        self._archive_into_guest(name, sha)
        cp("archived")
        self._provision(name, rosetta)
        cp("provisioned")
        self._done = True

    def _acquire_cap_slot(self, name: str) -> None:
        vms = self.tart.vms(gate=self._gate)
        try:
            check_cap(count_running(vms))
            require_name_free(name, vms)
        except (CapExceeded, NameTaken) as e:
            raise UpError(str(e)) from None

    def _create_vm(self, name: str) -> None:
        self._clone_attempted = True
        rc = self.tart.clone(BASE_IMAGE, name, gate=self._gate)
        if rc != 0:
            raise UpError(f"`tart clone` failed (exit {rc})")
        _write_atomic(self._identity_file, json.dumps(self.tart.identity(name)))

    def _boot(self, name: str) -> None:
        log = self.sdir / "tart-run.log"
        self._proc = self.tart.start(name, log)
        self._wait_for_agent(name, self._proc, log)

    def _wait_for_agent(self, name: str, proc: subprocess.Popen, log: Path) -> None:
        # `tart ip --wait` can return before `tart run` registers the VM, so readiness is the first exec that answers.
        # Guest boot is an external event: the wait is bounded and the failure reported; the pause between tries
        # ends at once on a signal.
        deadline = time.monotonic() + AGENT_BOOT_TIMEOUT_SECONDS
        while True:
            if self.tart.exec(name, ["true"], capture_output=True, gate=self._gate).returncode == 0:
                return
            if proc.poll() is not None:
                raise UpError(f"`tart run` for {name} exited ({proc.returncode}); see {log}")
            if time.monotonic() >= deadline:
                raise UpError(
                    f"the guest {name} did not answer within {AGENT_BOOT_TIMEOUT_SECONDS}s of starting "
                    f"(boot hang, or an image without the Tart guest agent); see {log}"
                )
            self._pause(1)

    def _provision(self, name: str, rosetta: bool) -> None:
        # Streamed from THIS checkout: an older --rev may predate the script.
        with open(self.repo_root / PROVISION_SCRIPT, "rb") as script:
            r = self.tart.exec(
                name,
                ["bash", "-c", 'bash -s -- "$HOME/cosca" "$@"', "_", *(["--rosetta"] if rosetta else [])],
                stdin=script,
                gate=self._gate,
            )
        if r.returncode != 0:
            raise UpError("provisioning failed")

    def _archive_into_guest(self, name: str, sha: str) -> None:
        git = subprocess.Popen(
            ["git", "-C", str(self.repo_root), "archive", "--format=tar", "--end-of-options", sha],
            stdout=subprocess.PIPE,
        )
        assert git.stdout is not None
        try:
            untar = self.tart.exec(
                name,
                ["sh", "-c", f"rm -rf {GUEST_TREE} && mkdir -p {GUEST_TREE} && tar -x -C {GUEST_TREE}"],
                stdin=git.stdout,
                gate=self._gate,
            )
        except BaseException:
            git.kill()
            git.wait()
            raise
        finally:
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
            _say(f"error: {e}")
            sys.exit(1)

    def run(self, args: argparse.Namespace) -> None:
        for flag, attr in (("--unelevated", "unelevated"), ("--timeout", "timeout")):
            if getattr(args, attr, None):
                _say(f"error: {flag} only applies to Windows guests")
                sys.exit(1)
        cmd_args = list(args.cmd)
        if cmd_args and cmd_args[0] == "--":
            cmd_args = cmd_args[1:]
        if not cmd_args:
            _say("error: no command given; usage: devvm.py run <guest> -- <cmd...>")
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
            _say(f"error: {e}")
            sys.exit(1)
        dest = Path(args.host_dest)
        dest.mkdir(parents=True, exist_ok=True)
        src = self.tart.exec_popen(name, ["sh", "-c", FETCH_SCRIPT, "_", guest_path], stdout=subprocess.PIPE)
        assert src.stdout is not None
        untar = subprocess.run(["tar", "-x", "-C", str(dest)], stdin=src.stdout)
        src.stdout.close()
        if src.wait() != 0 or untar.returncode != 0:
            _say(f"error: fetching {guest_path} failed")
            sys.exit(1)

    def halt(self, _args: argparse.Namespace) -> None:
        _say("error: halt is not supported for macos-arm64 (a halted VM cannot be resumed); use `destroy`")
        sys.exit(1)

    def status(self) -> str:
        name = self._read_claim()
        if name is None:
            return "not created"
        if not name:
            return "corrupt claim"
        try:
            vms = self.tart.vms()
        except Exception as e:  # noqa: BLE001  any failure of `tart list` must not break `list`
            return f"unknown ({name}; {e})"
        for e in vms:
            if e.get("Name") == name:
                return f"{e.get('State', '?')} ({name})"
        return f"missing ({name})"

    def destroy(self, _args: argparse.Namespace) -> None:
        """Stop and delete this worktree's VM, but only the one this worktree created.

        A signal cancels the wait for the worktree lock; once past it, destroy finishes what it started.
        """
        cancelled = None
        status = 0
        with SignalGate() as gate:
            self._gate = self.last_gate = gate
            try:
                with self._worktree_lock(interruptible=True):
                    status = self._destroy_locked()
            except Cancelled as c:
                cancelled = c.signo
        self._gate = None
        pending = gate.pending  # after the handlers are restored: nothing recorded is lost
        if cancelled is not None:
            _say(f"devvm: interrupted by {signal.Signals(cancelled).name} before destroy started")
            sys.exit(128 + cancelled)
        if pending:
            _say(f"devvm: interrupted by {signal.Signals(pending[0]).name}; destroy finished with status {status}")
            sys.exit(128 + pending[0])
        if status:
            sys.exit(status)

    def _destroy_locked(self) -> int:
        """Returns the exit status: 0, or 1 if destroy refused or failed."""
        name = self._read_claim()
        if name is None:
            return 0
        if not name:
            _say("warning: empty claim file; removing it (no VM is recorded)")
            self._clear_state()
            return 0
        require_own_name(name)
        if name not in self._names():
            _say(f"note: VM {name} was already gone")
            self._clear_state()
            return 0
        if not self._identity_verified(name):
            return 1
        problem = self._remove_vm(name, None)
        if problem is not None:
            _say(f"error: {problem}; leaving state in place")
            return 1
        self._clear_state()
        return 0

    def _identity_verified(self, name: str) -> bool:
        """Fail closed: a present VM is touched only if its recorded disk identity matches."""
        hint = "Inspect `tart list` and delete it by hand if it is yours."
        try:
            recorded = json.loads(self._identity_file.read_text())
        except (FileNotFoundError, ValueError):
            _say(f"error: no usable identity recorded for VM {name}, so it cannot be verified as this worktree's. {hint}")
            return False
        try:
            current = self.tart.identity(name)
        except FileNotFoundError:
            _say(f"error: VM {name} has no disk.img under {self.tart.home}/vms; cannot verify it. {hint}")
            return False
        if not identity_matches(recorded, current):
            _say(f"error: VM {name} is not the one this worktree created (its disk changed); refusing. {hint}")
            return False
        return True
