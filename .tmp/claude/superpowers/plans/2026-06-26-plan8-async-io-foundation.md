# Async I/O foundation (Plan 8, tokio mirror part 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mirror the sync owned-`Child` I/O surface in async (`subprocess::tokio::{Command, Child}`) on `tokio::process`, reusing the runtime-agnostic core verbatim.

**Architecture:** A new `subprocess::tokio` module behind an additive `tokio` feature. Async spawn builds a `::tokio::process::Command`, reaches its inner std command via `as_std_mut()`, and applies the same containment/stdio/identity machinery as the sync spawn (extracted to `pub(crate)`). The async `Child` wraps `::tokio::process::Child` (its async stdio + reaper) plus the stable `ProcessId` + `Attached`. `Drop` does a **guaranteed synchronous reap** (kill + blocking wait), matching the sync `Drop`.

**Tech Stack:** Rust 2021 (MSRV 1.87); `tokio` (features `process`, `rt`, `io-util`, `macros`) behind the `tokio` cargo feature; reuses `nix`/`windows`/`command-fds` (also from the async layer's `Drop`/reap).

## Global Constraints

- MSRV **1.87**, edition **2021**. `rustfmt` **max_width 120**. CI = `cargo fmt` + `cargo clippy --all-targets -- -D warnings` + `cargo test`, **and** the same three with `--features tokio` (any warning, incl. a per-feature unused import, fails).
- **Feature is additive:** enabling `tokio` must not change the sync API; sync builds compile no runtime. All async code is `#[cfg(feature = "tokio")]`.
- **No time-based synchronization; no data races; no arbitrary loop limits.** Death/EOF proven only by control-socket EOF/`ConnectionReset` or an inspected `ExitStatus`; `tokio::time::timeout` only as a failure bound. `WaitForSingleObject(_, INFINITE)`/blocking `waitpid` after a `SIGKILL`/`TerminateProcess` is an exit-event wait (the process WILL exit), not a timer — the sanctioned primitive the sync `wait` module already uses.
- **Confirmed design decisions (user, after plan-review):** (1) async `Drop` does a **guaranteed blocking reap** (not best-effort); (2) the async builder exposes only `contain()` (Strongest) in Plan 8 — `contain_with`/`nesting` defer to Plan 9; (3) the async API is a **strict subset** of sync this milestone: fd ≥ 3 and merge-into-a-piped-target return typed `Unsupported` (both need `AsyncFd`, deferred to Plan 9).
- **API shape:** async `wait`/`try_wait` take `&mut self` (tokio's model; compose `tokio::time::timeout` for bounded waits — no `wait_timeout`). `id()` returns the stable stored `ProcessId` (never tokio's nullable `id()`).
- `Error::Unsupported { op: String, platform: &'static str, detail: String }`.
- File org: `foo.rs` + `foo/` submodule style. Inside `src/tokio/*`, the tokio crate is `::tokio`.

---

### Task 1: `tokio` feature + module skeleton + spawn-core extraction

Plumbing + a refactor that keeps the sync path behaviorally identical (proven by the existing sync tests) while exposing the reusable spawn core. No async behavior yet. **Risk note for the implementer:** Step 4–5 generalize `attach`/`attach_job` to take a raw process handle; the Windows `attach_job` reads the handle in **two** helpers (`assign_to_kill_on_close_job` *and* `resume_initial_threads`) — both must be re-plumbed. Read `src/containment/windows.rs` in full before editing.

**Files:**
- Modify: `Cargo.toml` (optional `tokio` dep + feature)
- Modify: `src/lib.rs` (gated `pub mod tokio;`)
- Create: `src/tokio.rs` + stub `src/tokio/{command,child,spawn,pump}.rs`
- Modify: `src/child/spawn.rs` (helpers → `pub(crate)`; update the `attach` call site)
- Modify: `src/containment/dispatch.rs` (`attach` by `(pid, #[cfg(windows)] RawHandle)`)
- Modify: `src/containment/windows.rs` (`attach_job` + its two handle-reading helpers by `RawHandle`)
- Modify: `src/containment/dispatch_tests.rs` if it calls `attach` directly

**Interfaces:**
- Produces (made `pub(crate)`, bodies unchanged): `crate::child::spawn::{build_std_command, resolve_non_merge, dup, ChildEnd}`.
- Changes: `crate::containment::attach(pid: u32, #[cfg(windows)] proc_handle: std::os::windows::io::RawHandle, prepared: Prepared) -> Result<(Containment, Attached), Error>`.

- [ ] **Step 1: Add the feature**

`Cargo.toml`, under `[dependencies]`:

```toml
tokio = { version = "1", optional = true, features = ["process", "rt", "io-util", "macros"] }
```

and replace the `[features]` block (currently `pty = []`):

```toml
[features]
pty = []
tokio = ["dep:tokio"]
```

- [ ] **Step 2: Gated module + compiling stubs**

`src/lib.rs`, after `pub mod process;`:

```rust
#[cfg(feature = "tokio")]
pub mod tokio;
```

`src/tokio.rs`:

```rust
//! Async (tokio) mirror of the owned-`Child` I/O surface. Reuses the runtime-agnostic core.

#[path = "tokio/command.rs"]
mod command;
#[path = "tokio/child.rs"]
mod child;
#[path = "tokio/spawn.rs"]
mod spawn;
#[path = "tokio/pump.rs"]
mod pump;

pub use child::Child;
pub use command::Command;
```

Stubs (replaced in later tasks): `src/tokio/command.rs` → `//! Async Command builder.\npub struct Command;`; `src/tokio/child.rs` → `//! Async Child handle.\npub struct Child;`; `src/tokio/spawn.rs` → `//! Async spawn.`; `src/tokio/pump.rs` → `//! Async communicate.`.

- [ ] **Step 3: Helpers → `pub(crate)`**

In `src/child/spawn.rs`, change to `pub(crate)` (bodies unchanged): `type ChildEnd`, `fn build_std_command`, `fn resolve_non_merge`, `fn dup`. (The async spawn needs exactly these four; leave the rest private.)

- [ ] **Step 4: `attach` by pid + (Windows) raw handle**

In `src/containment/dispatch.rs`, replace the `attach` signature:

```rust
pub(crate) fn attach(
    pid: u32,
    #[cfg(windows)] proc_handle: std::os::windows::io::RawHandle,
    prepared: Prepared,
) -> Result<(Containment, Attached), Error> {
```

Inside `attach`: replace every `child.id()` with `pid`; replace `resolve_root_id(child)?` with `resolve_root_id(pid)?`; replace `crate::containment::windows::attach_job(child)` with `crate::containment::windows::attach_job(proc_handle)`; replace `let _ = (child, prepared);` with `let _ = prepared;`. Replace `resolve_root_id`:

```rust
/// Resolve the spawned root's identity by pid. **Precondition:** the caller holds the owning
/// `Child` (sync `std::process::Child` / async `::tokio::process::Child`) across this call — it
/// pins the pid against reuse, so the by-pid resolve is race-free (the freshly spawned root is
/// un-reaped, and on Windows still suspended, hence resolvable).
#[cfg(any(unix, windows))]
fn resolve_root_id(pid: u32) -> Result<crate::identity::ProcessId, Error> {
    crate::identity::ProcessId::of(pid).ok_or_else(|| Error::Containment {
        detail: "tree-walk root vanished before its identity could be read".into(),
    })
}
```

- [ ] **Step 5: `attach_job` (+ both handle-reading helpers) by `RawHandle`**

In `src/containment/windows.rs`: read the file. `attach_job(child: &std::process::Child)` calls `assign_to_kill_on_close_job(child)` AND `resume_initial_threads(child)`, each of which reads `child.as_raw_handle()`. Re-plumb **all three** to take `proc_handle: std::os::windows::io::RawHandle` and use it instead of `child.as_raw_handle()`. Add a doc line on the new `attach_job` signature:

```rust
/// `proc_handle` must remain open for the whole call (it pins the pid against reuse during the
/// Toolhelp thread walk in `resume_initial_threads`). Both callers hold the owning `Child` —
/// sync `std::process::Child`, async `::tokio::process::Child` — across the call, so it does.
```

- [ ] **Step 6: Update the sync spawn call site**

In `src/child/spawn.rs`, replace `crate::containment::attach(&child, prepared)?`:

```rust
#[cfg(windows)]
let proc_handle = {
    use std::os::windows::io::AsRawHandle;
    child.as_raw_handle()
};
let (containment, attached) = crate::containment::attach(
    child.id(),
    #[cfg(windows)]
    proc_handle,
    prepared,
)?;
```

- [ ] **Step 7: Verify**

Run (host): `cargo test` → all sync tests PASS (regression gate). `cargo build --features tokio` + `cargo clippy --all-targets --features tokio -- -D warnings` → clean.
Run (WSL): `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Users/bindreams/src/subprocess && CARGO_TARGET_DIR=/tmp/sp-target cargo test && CARGO_TARGET_DIR=/tmp/sp-target cargo clippy --all-targets --features tokio -- -D warnings'` → sync green, tokio clippy clean.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: tokio feature + module skeleton + spawn-core extraction (attach by pid/handle)"
```

---

### Task 2: async `Command` + async spawn + the async `Child` handle

Keystone: spawn over `::tokio::process::Command`, stdio resolution (tokio owns the standard pipes), identity-before-reap, attach (with error-path teardown), and the handle. Includes the `reap_now` teardown primitive (shared with `Drop` in Task 4).

**Files:**
- Modify: `src/tokio/command.rs`, `src/tokio/child.rs`, `src/tokio/spawn.rs`
- Modify: `tests/common/mod.rs` (async helpers)
- Create: `tests/tokio_io.rs`

**Interfaces:**
- Consumes: `crate::child::spawn::{build_std_command, resolve_non_merge, dup, ChildEnd}`; `crate::containment::{prepare, attach, Attached, Containment}`; `crate::command::Command as SyncCommand`; `crate::identity::ProcessId`; `crate::stdio::{Fd, ResolvedStdio, Stdio}`; `::tokio::process::{Command as TokioCommand, Child as TokioChild, ChildStdin, ChildStdout, ChildStderr}`.
- Produces: `subprocess::tokio::Command` with `spawn(&mut self) -> Result<Child, Error>` + `status` (async); `subprocess::tokio::Child` with `id`/`is_alive`/`containment` (`&self`), `wait`/`try_wait` (`&mut self`), `stdin`/`stdout`/`stderr` (`&mut self`); `pub(crate) fn child::reap_now(&mut TokioChild, pid: u32)`.

- [ ] **Step 1: Write the failing tests** — `tests/tokio_io.rs`:

```rust
//! Async (tokio) I/O integration tests. Requires `--features tokio`.
#![cfg(feature = "tokio")]

#[path = "common/mod.rs"]
mod common;

#[tokio::test]
async fn async_spawn_status_reports_exit_code() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "exit", "7"]);
    assert_eq!(cmd.status().await.expect("status").code(), Some(7));
}

#[tokio::test]
async fn async_id_is_a_real_stable_identity() {
    // id() returns the stored ProcessId — a real, resolvable identity that survives wait (tokio's
    // own Child::id() would be None after reap). Round-trip through Process::from_id to prove it
    // resolves while live, then confirm it is unchanged after wait.
    use std::io::Write as _;
    let (mut child, mut sock) = common::spawn_blocker_async();
    let id = child.id();
    assert_eq!(subprocess::Process::from_id(id).map(|p| p.id()), Some(id), "id() is a resolvable identity");
    sock.write_all(b"x").expect("release");
    child.wait().await.expect("wait");
    assert_eq!(child.id(), id, "id() stays the stable ProcessId after wait");
}

#[tokio::test]
async fn async_try_wait_is_none_before_exit_then_some_after() {
    // A blocker child is structurally wedged on its never-written socket → still running.
    let (mut child, mut sock) = common::spawn_blocker_async();
    assert!(child.try_wait().expect("try_wait").is_none(), "wedged child must be running");
    use std::io::Write as _;
    sock.write_all(b"x").expect("release the child");
    child.wait().await.expect("wait"); // sync point: the exit, not a timer
    assert!(child.try_wait().expect("try_wait").is_some(), "reaped child reports Some");
}

#[tokio::test]
async fn async_env_reaches_child() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "env", "SP_PLAN8"])
        .env("SP_PLAN8", "async");
    let out = cmd.output().await.expect("output");
    assert_eq!(out.stdout, b"SP_PLAN8=async\n");
}
```

`tests/common/mod.rs`, append:

```rust
/// Async `control-block` blocker (uncontained): a child that connects, tags "R", and blocks on
/// its socket. The accept/tag-read is sync std (the test side); the CHILD is async.
#[cfg(feature = "tokio")]
pub fn spawn_blocker_async() -> (subprocess::tokio::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "control-block", addr.as_str(), "R"]);
    let child = cmd.spawn().expect("spawn async blocker");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// Async analogue of `spawn_grandchild`, returning the root ("R") and grandchild ("G") control
/// sockets identified by tag (accept order is not guaranteed).
#[cfg(feature = "tokio")]
pub fn spawn_grandchild_async(contain: bool) -> (subprocess::tokio::Child, TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "spawn-grandchild", addr.as_str()]);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn async grandchild tree");
    let (mut root, mut grandchild) = (None, None);
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match &tag {
            b"R" => root = Some(s),
            b"G" => grandchild = Some(s),
            other => panic!("unexpected grandchild-tree tag {other:?}"),
        }
    }
    (child, root.expect("root R connected"), grandchild.expect("grandchild G connected"))
}
```

- [ ] **Step 2: Run to verify it fails**

Run (host): `cargo test --features tokio --test tokio_io` → FAIL (placeholder `Command`/`Child` have no methods).

- [ ] **Step 3: The async `Command`** — `src/tokio/command.rs`. Composition over the sync builder; only `contain()` (Strongest) is exposed (`contain_with`/`nesting` defer to Plan 9). **Why a parallel builder, not `Deref<Target = SyncCommand>`:** `Deref` would make the config methods return `&mut SyncCommand`, breaking the `cmd.arg(..).spawn()` chain into the async-only run methods. The ~15 one-line delegations over a *stable* sync builder are the deliberate cost of preserving that chaining symmetry:

```rust
//! Async `Command` builder — wraps the sync `crate::command::Command`, adding async run methods.
//! The config methods hand-mirror the sync builder (no compiler-enforced parity): mirror any new
//! sync builder method here too.

use crate::command::Command as SyncCommand;
use crate::error::Error;
use crate::stdio::Stdio;

use super::child::Child;

/// An async (tokio) process to configure and spawn — mirrors [`subprocess::Command`](crate::Command).
///
/// # Limitations (vs the sync API)
///
/// Arbitrary descriptors (fd ≥ 3) and merging stderr/stdout into a *piped* target are not yet
/// supported on the async API (they need an async parent pipe end) and return
/// [`Error::Unsupported`](crate::error::Error::Unsupported) at spawn.
#[derive(Debug, Default)]
pub struct Command {
    inner: SyncCommand,
}

impl Command {
    pub fn new() -> Command {
        Command { inner: SyncCommand::new() }
    }
    pub fn arg<S: Into<std::ffi::OsString>>(&mut self, a: S) -> &mut Command {
        self.inner.arg(a);
        self
    }
    pub fn args<I, S>(&mut self, args: I) -> &mut Command
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        self.inner.args(args);
        self
    }
    pub fn commandline<S: Into<std::ffi::OsString>>(&mut self, line: S) -> &mut Command {
        self.inner.commandline(line);
        self
    }
    pub fn executable<P: Into<std::path::PathBuf>>(&mut self, p: P) -> &mut Command {
        self.inner.executable(p);
        self
    }
    pub fn stdin(&mut self, t: Stdio) -> Result<&mut Command, Error> {
        self.inner.stdin(t)?;
        Ok(self)
    }
    pub fn stdout(&mut self, t: Stdio) -> Result<&mut Command, Error> {
        self.inner.stdout(t)?;
        Ok(self)
    }
    pub fn stderr(&mut self, t: Stdio) -> Result<&mut Command, Error> {
        self.inner.stderr(t)?;
        Ok(self)
    }
    pub fn fd(&mut self, slot: impl Into<crate::stdio::Fd>, t: Stdio) -> Result<&mut Command, Error> {
        self.inner.fd(slot, t)?;
        Ok(self)
    }
    pub fn env(&mut self, k: impl Into<std::ffi::OsString>, v: impl Into<std::ffi::OsString>) -> &mut Command {
        self.inner.env(k, v);
        self
    }
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Command
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<std::ffi::OsString>,
        V: Into<std::ffi::OsString>,
    {
        self.inner.envs(vars);
        self
    }
    pub fn env_remove(&mut self, k: impl Into<std::ffi::OsString>) -> &mut Command {
        self.inner.env_remove(k);
        self
    }
    pub fn env_clear(&mut self) -> &mut Command {
        self.inner.env_clear();
        self
    }
    pub fn current_dir(&mut self, dir: impl Into<std::path::PathBuf>) -> &mut Command {
        self.inner.current_dir(dir);
        self
    }
    pub fn kill_on_drop(&mut self, yes: bool) -> &mut Command {
        self.inner.kill_on_drop(yes);
        self
    }
    /// Contain the child's tree with the strongest available mechanism.
    pub fn contain(&mut self) -> &mut Command {
        self.inner.contain();
        self
    }

    /// Spawn the child. Spawn is synchronous; the returned `Child`'s waits are async.
    pub fn spawn(&mut self) -> Result<Child, Error> {
        super::spawn::spawn(&mut self.inner)
    }

    /// Run to completion with inherited stdio, returning the exit status.
    pub async fn status(&mut self) -> Result<std::process::ExitStatus, Error> {
        self.inner.stdin(Stdio::inherit())?;
        self.inner.stdout(Stdio::inherit())?;
        self.inner.stderr(Stdio::inherit())?;
        let mut child = self.spawn()?;
        child.wait().await
    }
}
```

- [ ] **Step 4: The async spawn** — `src/tokio/spawn.rs`:

```rust
//! Async spawn: a `::tokio::process::Command` over the sync spawn core via `as_std_mut`;
//! tokio owns piped std fds, we own file/null/inherit/merge ends; identity is read before any
//! await, then attach (with error-path teardown).

use std::collections::BTreeMap;
use std::process::Stdio as StdStdio;

use crate::child::spawn::{build_std_command, dup, resolve_non_merge, ChildEnd};
use crate::command::Command;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::stdio::{Fd, ResolvedStdio};

use super::child::{reap_now, Child};

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let fds = std::mem::take(cmd.fds_mut());
    let kill_on_drop = cmd.kill_on_drop_flag();

    // fd >= 3 and merge-into-a-piped-target need an async parent end (AsyncFd), not yet built;
    // reject them loudly rather than silently mis-wiring stdio.
    for slot in fds.keys() {
        if slot.raw() >= 3 {
            return Err(Error::Unsupported {
                op: format!("async {slot}"),
                platform: std::env::consts::OS,
                detail: "arbitrary descriptors (>= 3) are not yet supported on the async API".into(),
            });
        }
    }
    for slot in fds.keys() {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(slot) {
            if matches!(fds.get(target), Some(ResolvedStdio::Merge(_))) {
                return Err(Error::Unsupported {
                    op: format!("merge {slot} -> {target} -> <another merge>"),
                    platform: std::env::consts::OS,
                    detail: "chained merges are not supported".into(),
                });
            }
        }
    }

    let std_cmd = build_std_command(cmd)?;
    let mut tcmd = ::tokio::process::Command::new(std::ffi::OsStr::new(""));
    *tcmd.as_std_mut() = std_cmd;
    // tokio's own `kill_on_drop` is intentionally left at its `false` default: subprocess's
    // `Child::drop` (attached.hard_kill + reap_now) is the SOLE teardown owner. Forwarding the
    // builder's `kill_on_drop` to `tcmd` would make tokio fire its own kill and race reap_now.

    // Resolve our-owned child ends for non-pipe slots (PIPE slots are tokio-owned). Two passes
    // so a merge can dup a non-merge target's already-resolved end.
    let std_slots = [Fd::STDIN, Fd::STDOUT, Fd::STDERR];
    let mut child_ends: BTreeMap<Fd, ChildEnd> = BTreeMap::new();
    for slot in std_slots {
        match fds.get(&slot) {
            Some(ResolvedStdio::Pipe(_)) | Some(ResolvedStdio::Merge(_)) => {}
            other => {
                let (end, _parent) = resolve_non_merge(slot, other)?;
                child_ends.insert(slot, end);
            }
        }
    }
    for slot in std_slots {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(&slot) {
            if matches!(fds.get(target), Some(ResolvedStdio::Pipe(_))) {
                return Err(Error::Unsupported {
                    op: format!("async merge {slot} -> {target} (piped)"),
                    platform: std::env::consts::OS,
                    detail: "merging into a piped target needs an async parent end (not yet built); \
                             merge into file/null/inherit, or capture separately".into(),
                });
            }
            let src = child_ends.get(target).ok_or_else(|| Error::Unsupported {
                op: format!("merge {slot} -> {target}"),
                platform: std::env::consts::OS,
                detail: "merge target descriptor is not configured".into(),
            })?;
            child_ends.insert(slot, dup(src)?);
        }
    }

    for slot in std_slots {
        let stdio: StdStdio = match fds.get(&slot) {
            Some(ResolvedStdio::Pipe(_)) => StdStdio::piped(),
            _ => StdStdio::from(
                child_ends
                    .remove(&slot)
                    .unwrap_or_else(|| unreachable!("a configured non-pipe slot must have a resolved child end")),
            ),
        };
        match slot {
            Fd::STDIN => tcmd.stdin(stdio),
            Fd::STDOUT => tcmd.stdout(stdio),
            _ => tcmd.stderr(stdio),
        };
    }

    let prepared = crate::containment::prepare(tcmd.as_std_mut(), &cmd.contain_request());
    let mut child = tcmd.spawn().map_err(Error::Io)?;

    // Identity must be read before any await: spawn + attach are synchronous, so the runtime
    // cannot park and reap the child in between. On Windows the child is still CREATE_SUSPENDED
    // here (set in `prepare`), so it cannot have exited; `ProcessId::of` resolves by pid and
    // tokio's held handle pins the pid against reuse.
    let pid = child.id().expect("a freshly spawned, un-awaited tokio child has a pid");
    let id = ProcessId::of(pid)
        .ok_or_else(|| Error::Io(std::io::Error::other("spawned async child vanished before identity read")))?;

    #[cfg(windows)]
    let proc_handle = child.raw_handle().expect("a freshly spawned tokio child has a raw handle");
    let attach = crate::containment::attach(
        pid,
        #[cfg(windows)]
        proc_handle,
        prepared,
    );
    let (containment, attached) = match attach {
        Ok(v) => v,
        // The child is spawned (on Windows possibly CREATE_SUSPENDED) — tear it down so a failed
        // attach never leaks a live/suspended process.
        Err(e) => {
            reap_now(&mut child, pid, false); // never awaited — an already-Done child is impossible
            return Err(e);
        }
    };

    Ok(Child::from_parts(child, id, attached, kill_on_drop, containment))
}
```

- [ ] **Step 5: The async `Child` + `reap_now`** — `src/tokio/child.rs`:

```rust
//! Async `Child` handle, wrapping `::tokio::process::Child` plus the stable `ProcessId` and the
//! contained-tree `Attached`. Waits are `&mut self`; `id()` is the stable identity, never None.

use std::process::ExitStatus;

use crate::containment::{Attached, Containment};
use crate::error::Error;
use crate::identity::ProcessId;

#[derive(Debug)]
pub struct Child {
    child: ::tokio::process::Child,
    id: ProcessId,
    attached: Attached,
    kill_on_drop: bool,
    containment: Containment,
}

impl Child {
    pub(crate) fn from_parts(
        child: ::tokio::process::Child,
        id: ProcessId,
        attached: Attached,
        kill_on_drop: bool,
        containment: Containment,
    ) -> Child {
        Child { child, id, attached, kill_on_drop, containment }
    }

    /// The child's stable identity — valid after `wait`.
    pub fn id(&self) -> ProcessId {
        self.id
    }
    pub fn is_alive(&self) -> bool {
        self.id.is_alive()
    }
    pub fn containment(&self) -> Containment {
        self.containment
    }

    pub fn stdin(&mut self) -> Option<::tokio::process::ChildStdin> {
        self.child.stdin.take()
    }
    pub fn stdout(&mut self) -> Option<::tokio::process::ChildStdout> {
        self.child.stdout.take()
    }
    pub fn stderr(&mut self) -> Option<::tokio::process::ChildStderr> {
        self.child.stderr.take()
    }

    /// Block until the child exits, returning its status. For a bounded wait use
    /// `tokio::time::timeout(d, child.wait())`.
    pub async fn wait(&mut self) -> Result<ExitStatus, Error> {
        self.child.wait().await.map_err(Error::Io)
    }
    /// Exit status if the child has already exited (non-blocking).
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        self.child.try_wait().map_err(Error::Io)
    }
}

/// Guaranteed synchronous teardown, shared by `Drop` and the spawn error path: kill the child,
/// then block until it has exited. On Unix we wait with `WNOWAIT` (NOT reaping), so tokio's own
/// `Child` field-drop reaps the zombie synchronously in its drop (its `try_wait` returns
/// `Ok(Some)`, not a park-dependent orphan enqueue) — a guaranteed reap before `Drop` returns.
/// We only wait while tokio still owns the child (`id().is_some()`), which pins the pid; once
/// tokio is `Done` (a prior `wait()` reaped it), the pid may be recycled and we must not wait on
/// it. `done_ok` says whether an already-`Done` child is legal here: `true` for `Drop` (the user
/// may have `wait()`ed), `false` for the spawn-error path (the child was never awaited).
/// **Invariant:** no `wait()` future for this child is in flight when this runs.
pub(crate) fn reap_now(child: &mut ::tokio::process::Child, pid: u32, done_ok: bool) {
    // `start_kill` bounds the wait below — it MUST run in release (NOT inside `debug_assert!`,
    // whose argument is stripped in release). A no-op on an already-exited child.
    let killed = child.start_kill();
    debug_assert!(killed.is_ok(), "start_kill of an owned child should not fail");
    // A failed start_kill means this is not a live process to wait on (ESRCH = already exited;
    // EPERM is impossible for our own child) — skip, so a kill failure can never turn the bounded
    // exit-wait into an unbounded block. tokio's field-drop reaps any leftover zombie.
    if killed.is_err() {
        return;
    }
    // tokio `Done` ⇒ already reaped, pid possibly recycled ⇒ nothing to do (the recycled-pid wait
    // hazard the sync side avoids by holding a handle).
    if child.id().is_none() {
        debug_assert!(done_ok, "reap_now found an already-reaped child where one was impossible");
        return;
    }
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        use nix::sys::wait::{waitid, Id, WaitPidFlag};
        use nix::unistd::Pid;
        debug_assert!(pid <= i32::MAX as u32, "pid {pid} exceeds i32::MAX");
        let id = Id::Pid(Pid::from_raw(pid as i32));
        loop {
            match waitid(id, WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT) {
                Ok(_) => break, // exited; zombie left for tokio's in-drop reap
                Err(Errno::EINTR) => continue,
                // id() was Some above (tokio un-reaped ⇒ pid pinned), so no ECHILD / other errno
                // should occur — a debug tripwire, with a safe release `break`.
                Err(e) => {
                    debug_assert!(false, "waitid in reap_now failed unexpectedly: {e}");
                    break;
                }
            }
        }
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
        let _ = pid;
        let h = child.raw_handle().expect("tokio owns the handle while id() is Some");
        // SAFETY: tokio owns and (on its field-drop) closes the handle; we only wait on it.
        // INFINITE is bounded by `start_kill` above. Inspect the result like wait/windows.rs.
        let waited = unsafe { WaitForSingleObject(HANDLE(h), INFINITE) };
        debug_assert!(waited == WAIT_OBJECT_0, "reap_now did not observe the child's exit: {waited:?}");
    }
}
```

**Implementer note (not a docstring):** confirm `nix::sys::wait::WaitPidFlag::WNOWAIT` is exposed on Linux and macOS (it is — `waitid(2)` is POSIX). The crate's Linux floor is pidfd-capable (≥ 5.3), so tokio uses its pidfd reaper there; the no-zombie test (Task 4) exercises Linux and macOS in CI, and is also run under `--release` (Step 6) so the `start_kill`-must-run-in-release contract is gated.

- [ ] **Step 6: Run to verify it passes**

Run (host): `cargo test --features tokio --test tokio_io` → PASS (run the whole file — do not filter by test name, so a rename can't silently match zero).
Run (WSL): the same `--features tokio --test tokio_io` WSL command → PASS. `cargo clippy --all-targets --features tokio -- -D warnings` clean (host + WSL).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: async Command + spawn + Child handle (wait/try_wait/status/stdio) + reap_now"
```

---

### Task 3: async `communicate`/`output`/`read` + `run`/`run_line`

**Files:**
- Modify: `src/tokio/pump.rs`, `src/tokio/command.rs`, `src/tokio.rs`, `tests/tokio_io.rs`

**Interfaces:**
- Consumes: `::tokio::io::{AsyncReadExt, AsyncWriteExt}`; `Child::{stdin, stdout, stderr, wait}`.
- Produces: `Child::communicate(&mut self, input: Option<Vec<u8>>) -> Result<crate::Output, Error>`; `Command::{output, read}`; `subprocess::tokio::{run, run_line}`.

- [ ] **Step 1: Write the failing tests** — append to `tests/tokio_io.rs`:

```rust
#[tokio::test]
async fn async_output_captures_streams() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "emit", "5", "3"]);
    let out = cmd.output().await.expect("output");
    assert_eq!(out.stdout, vec![b'o'; 5]);
    assert_eq!(out.stderr, vec![b'e'; 3]);
    assert!(out.status.success());
}

#[tokio::test]
async fn async_communicate_is_deadlock_free() {
    // tee-both copies stdin to BOTH stdout and stderr; a non-concurrent reader would deadlock
    // once a pipe buffer fills. Concurrent try_join! must complete with all bytes on both.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "tee-both"]);
    cmd.stdin(subprocess::Stdio::pipe()).unwrap();
    cmd.stdout(subprocess::Stdio::pipe()).unwrap();
    cmd.stderr(subprocess::Stdio::pipe()).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    let payload = vec![b'z'; 4 * 1024 * 1024]; // > any plausible OS pipe buffer → a sequential reader wedges
    let out = child.communicate(Some(payload.clone())).await.expect("communicate");
    assert_eq!(out.stdout, payload);
    assert_eq!(out.stderr, payload);
}

#[tokio::test]
async fn async_communicate_tolerates_early_stdin_close() {
    // A child that exits without reading all of stdin closes the pipe early; write_all then
    // yields BrokenPipe. communicate must treat that as EOF and still return captured output.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "emit", "2", "0"]); // never reads stdin
    cmd.stdin(subprocess::Stdio::pipe()).unwrap();
    cmd.stdout(subprocess::Stdio::pipe()).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    // 4 MiB > any pipe buffer, so write_all is still in flight when `emit` exits and closes its
    // stdin read end — deterministically forcing the BrokenPipe the tolerance branch handles.
    let out = child.communicate(Some(vec![b'x'; 4 * 1024 * 1024])).await.expect("communicate tolerates BrokenPipe");
    assert_eq!(out.stdout, vec![b'o'; 2]);
    assert!(out.status.success());
}

#[tokio::test]
async fn async_read_errors_on_invalid_utf8() {
    // 0xFF mid-stream (between valid bytes) proves read drains to EOF, THEN validates UTF-8.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "emit-raw", "61", "ff", "62"]);
    let err = cmd.read().await.expect_err("invalid utf-8 must error");
    assert!(matches!(err, subprocess::error::Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData));
}

#[tokio::test]
async fn async_merge_into_pipe_is_unsupported() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.stdout(subprocess::Stdio::pipe()).unwrap();
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT)).unwrap();
    let err = cmd.spawn().expect_err("merge into a piped target is unsupported");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "got {err:?}");
}

#[tokio::test]
async fn async_fd3_is_unsupported() {
    // The async strict-subset rejection of arbitrary fd >= 3 (a non-pipe slot, so `fd()` itself
    // accepts it; the rejection is at spawn). Construct the fd-3 slot exactly as the sync
    // `arbitrary_fd_is_unsupported_on_windows` test does (confirm the public `Fd` constructor in
    // src/stdio.rs — `Fd::from(3u32)` here, adjust to match).
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.fd(subprocess::Fd::from(3u32), subprocess::Stdio::null()).unwrap();
    let err = cmd.spawn().expect_err("fd >= 3 is unsupported on the async API");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "got {err:?}");
}

#[tokio::test]
async fn async_chained_merge_is_unsupported() {
    // A merge whose target is itself a merge → Unsupported (mirrors the sync chained-merge test):
    // stderr -> stdout, and stdout -> stdin, so stdout's resolved kind is Merge.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.stdout(subprocess::Stdio::merge(subprocess::Fd::STDIN)).unwrap();
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT)).unwrap();
    let err = cmd.spawn().expect_err("chained merges are unsupported");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "got {err:?}");
}
```

(`Stdio::merge`/`Fd::STDOUT` are the existing sync constructors — confirm their exact names against `src/stdio.rs` when implementing; adjust the test to match.)

- [ ] **Step 2: Run to verify it fails**

Run (host): `cargo test --features tokio --test tokio_io async_output_captures_streams` → FAIL (no `output`/`communicate`).

- [ ] **Step 3: async `communicate`** — `src/tokio/pump.rs`:

```rust
//! Async `communicate`: write input to stdin (drop it for EOF) and read stdout + stderr to EOF
//! concurrently with `wait`, via `tokio::try_join!` — close-stdin-then-read-both with zero
//! threads. A child closing stdin early (BrokenPipe) is a normal EOF, not an error.

use ::tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::Output;

use super::child::Child;

impl Child {
    pub async fn communicate(&mut self, input: Option<Vec<u8>>) -> Result<Output, Error> {
        // Take the three streams into owned locals BEFORE the join: only `wait` then borrows
        // `self.child` (so the four-future join compiles), and tokio's `Child::wait` internally
        // drops `self.child.stdin`, already None here, so it cannot race the write future.
        let mut stdin = self.stdin();
        let mut stdout = self.stdout();
        let mut stderr = self.stderr();

        let write = async {
            // A child that exits without consuming all input closes the pipe early; a BrokenPipe
            // (on write OR flush) is a benign EOF — but surface any real I/O error.
            fn swallow_broken_pipe(e: std::io::Error) -> Result<(), std::io::Error> {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    Ok(())
                } else {
                    Err(e)
                }
            }
            if let Some(mut w) = stdin.take() {
                if let Some(bytes) = input.as_ref() {
                    w.write_all(bytes).await.or_else(swallow_broken_pipe)?;
                    w.flush().await.or_else(swallow_broken_pipe)?;
                }
                drop(w); // EOF
            }
            Ok::<(), std::io::Error>(())
        };
        let read_out = async {
            let mut buf = Vec::new();
            if let Some(mut r) = stdout.take() {
                r.read_to_end(&mut buf).await?;
            }
            Ok::<Vec<u8>, std::io::Error>(buf)
        };
        let read_err = async {
            let mut buf = Vec::new();
            if let Some(mut r) = stderr.take() {
                r.read_to_end(&mut buf).await?;
            }
            Ok::<Vec<u8>, std::io::Error>(buf)
        };
        let wait = async { self.child.wait().await };

        let ((), out, err, status) = ::tokio::try_join!(write, read_out, read_err, wait).map_err(Error::Io)?;
        Ok(Output { status, stdout: out, stderr: err })
    }
}
```

- [ ] **Step 4: `output`/`read`** — `src/tokio/command.rs` `impl Command`:

```rust
    pub async fn output(&mut self) -> Result<crate::Output, Error> {
        self.inner.stdin(Stdio::null())?;
        self.inner.stdout(Stdio::pipe())?;
        self.inner.stderr(Stdio::pipe())?;
        let mut child = self.spawn()?;
        child.communicate(None).await
    }

    pub async fn read(&mut self) -> Result<String, Error> {
        self.inner.stdin(Stdio::null())?;
        self.inner.stdout(Stdio::pipe())?;
        let mut child = self.spawn()?;
        let out = child.communicate(None).await?;
        String::from_utf8(out.stdout)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }
```

- [ ] **Step 5: `run`/`run_line`** — `src/tokio.rs`:

```rust
/// Start building an async command from an argument vector.
pub fn run<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut c = Command::new();
    c.args(args);
    c
}

/// Start building an async command from a single command-line string.
pub fn run_line(line: impl Into<std::ffi::OsString>) -> Command {
    let mut c = Command::new();
    c.commandline(line);
    c
}
```

- [ ] **Step 6: Run to verify it passes**

Run (host + WSL): the `--features tokio --test tokio_io` commands → all PASS. `cargo clippy --all-targets --features tokio -- -D warnings` clean.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: async communicate/output/read + run/run_line (try_join, BrokenPipe-tolerant)"
```

---

### Task 4: async `Drop` + `detach` + CI `--features tokio`

**Files:**
- Modify: `src/tokio/child.rs` (`Drop`, `detach`)
- Modify: `tests/tokio_io.rs` (drop + detach + Windows-contained tests)
- Modify: `.github/workflows/ci.yaml`

**Interfaces:**
- Consumes: `Attached::{hard_kill, disarm}`; `super::child::reap_now`.
- Produces: `impl Drop for Child`; `Child::detach(&mut self)`.

- [ ] **Step 1: Write the failing tests** — append to `tests/tokio_io.rs`:

```rust
#[tokio::test]
async fn async_drop_tears_down_a_contained_tree() {
    use std::io::Read as _;
    let (child, mut root, mut grand) = common::spawn_grandchild_async(true);
    // The new attach-by-pid/handle path must actually establish containment, else the EOFs below
    // could pass for unrelated reasons.
    assert_ne!(child.containment(), subprocess::Containment::None, "contained spawn must engage a mechanism");
    let root_id = child.id();
    drop(child); // tree teardown (attached.hard_kill) + reap_now(root)
    // The root is deterministically dead — reap_now blocked until its exit before Drop returned.
    assert!(!root_id.is_alive(), "the contained root must be torn down by Drop");
    // The grandchild's death is proven by its control-socket EOF — the crate's established
    // teardown-proof primitive (a real exit event; a survivor blocks the read → a CI failure,
    // never a false pass).
    for (who, s) in [("root", &mut root), ("grandchild", &mut grand)] {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("{who} not torn down on drop: {other:?}"),
        }
    }
}

#[tokio::test]
async fn async_drop_after_wait_still_tears_down_the_tree() {
    // After awaiting the root's exit it is already reaped (reap_now is then a no-op), so the tree
    // teardown must come from attached.hard_kill() on Drop — proven by the grandchild's EOF.
    use std::io::{Read as _, Write as _};
    let (mut child, mut root, mut grand) = common::spawn_grandchild_async(true);
    let root_id = child.id();
    root.write_all(b"x").expect("release the root so it exits");
    child.wait().await.expect("wait reaps the root");
    assert!(!root_id.is_alive(), "root exited");
    drop(child); // root already reaped → reap_now no-op; attached.hard_kill must still kill the grandchild
    let mut buf = [0u8; 1];
    match grand.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("grandchild not torn down by hard_kill after the root was waited: {other:?}"),
    }
}

#[tokio::test]
async fn async_detach_leaves_the_tree_running() {
    use std::io::{Read as _, Write as _};
    let (mut child, mut root, _grand) = common::spawn_grandchild_async(true);
    let root_id = child.id();
    child.detach();
    drop(child); // detached → Drop must NOT kill
    // Positive liveness (no race — we never signaled it): a buggy detach that let Drop kill the
    // root would make this false.
    assert!(root_id.is_alive(), "detach must leave the root running after the handle drops");
    // Release it and observe a CLEAN voluntary exit (Ok(0) EOF), distinct from a kill's reset.
    root.write_all(b"x").expect("release the live root");
    let mut buf = [0u8; 1];
    assert!(matches!(root.read(&mut buf), Ok(0)), "released root exits cleanly (EOF)");
    // _grand drops here → its socket closes → the reparented grandchild exits.
}

#[cfg(unix)]
#[tokio::test]
async fn async_drop_leaves_no_zombie() {
    // The guaranteed-reap contract: after Drop the child is FULLY reaped with no await in between
    // to trigger a runtime park. is_alive() is false (reap_now waited for exit) and waitpid(WNOHANG)
    // returns ECHILD (reaped) — not Ok(_)=zombie.
    use nix::sys::wait::{waitpid, WaitPidFlag};
    use nix::unistd::Pid;
    let (child, _sock) = common::spawn_blocker_async();
    let id = child.id();
    let pid = id.pid() as i32;
    drop(child);
    assert!(!id.is_alive(), "child must be exited after Drop");
    match waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)) {
        Err(nix::errno::Errno::ECHILD) => {} // fully reaped — no zombie
        other => panic!("expected ECHILD (child reaped, no zombie), got {other:?}"),
    }
}

#[cfg(windows)]
#[tokio::test]
async fn async_windows_contained_spawn_runs_then_job_tears_down() {
    // Verifies the CREATE_SUSPENDED + job-assign + out-of-band resume dance works under tokio: the
    // tree actually RAN (both tags accepted), containment is JobObject, and Drop tears it down.
    use std::io::Read as _;
    let (child, mut root, mut grand) = common::spawn_grandchild_async(true);
    assert_eq!(child.containment(), subprocess::Containment::JobObject, "Windows Strongest => JobObject");
    let root_id = child.id();
    drop(child);
    assert!(!root_id.is_alive(), "the contained root must be torn down by Drop");
    for (who, s) in [("root", &mut root), ("grandchild", &mut grand)] {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("{who} not torn down: {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run (host): `cargo test --features tokio --test tokio_io async_drop_tears_down_a_contained_tree` → FAIL (no `Drop`; the tree survives → read returns bytes/blocks → panic, or `detach` is undefined).

- [ ] **Step 3: `Drop` + `detach`** — `src/tokio/child.rs`, add:

```rust
impl Child {
    /// Leave the child (and its contained tree) running after this handle drops.
    pub fn detach(&mut self) {
        self.kill_on_drop = false;
        self.attached.disarm();
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return; // detached / opted out
        }
        // Tree teardown — the SOLE coverage for descendants (reap_now only guarantees the root),
        // so surface a real mechanism failure in debug. A no-op for an uncontained child.
        let tree = self.attached.hard_kill();
        debug_assert!(tree.is_ok(), "contained-tree teardown failed on async Drop: {:?}", tree.err());
        let _ = tree;
        // Guaranteed reap of the root on the real exit event (no park dependence). Briefly blocks
        // the dropping thread; the child is SIGKILL'd so it exits at once. `true`: a prior wait()
        // (a Done child) is legal on Drop.
        let pid = self.id.pid();
        reap_now(&mut self.child, pid, true);
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run (host, Windows): `cargo test --features tokio --test tokio_io` → PASS. (If `async_windows_contained_spawn_runs_then_job_tears_down` fails, tokio's wrapper is interfering with the CREATE_SUSPENDED/resume dance — STOP and report; that is the architecture risk flagged in Task 1.)
Run (WSL): the `--features tokio --test tokio_io` command → PASS.
Run (WSL, **release** — gates the "`start_kill` must run in release" contract): `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Users/bindreams/src/subprocess && CARGO_TARGET_DIR=/tmp/sp-target cargo test --release --features tokio --test tokio_io async_drop_leaves_no_zombie'` → PASS (a kill wrongly wrapped in `debug_assert!` would deadlock here, not in debug).

- [ ] **Step 5: CI `--features tokio`** — `.github/workflows/ci.yaml`. Read the existing `--features pty` test step in the `Test` matrix job and add, right after it, a mirroring step:

```yaml
      - name: Test (tokio)
        run: cargo test --locked --features tokio --target ${{ matrix.target }}
```

(Match the surrounding step's exact `run`/indentation/`--target` expression.)

- [ ] **Step 6: Full verify + commit**

```bash
cargo fmt
cargo clippy --all-targets --features tokio -- -D warnings
cargo test --features tokio        # host
git add -A
git commit -m "feat: async Child Drop (guaranteed reap) + detach + CI tokio step"
```

Then the full Linux suite (sync + tokio) via WSL:
`MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Users/bindreams/src/subprocess && CARGO_TARGET_DIR=/tmp/sp-target cargo test --locked && CARGO_TARGET_DIR=/tmp/sp-target cargo test --locked --features tokio'`

- [ ] **Step 7: Update `TODO.md`** — add a "Lifecycle / async (from Plan 8)" note for the confirmed Plan-9 deferrals (async `contain_with`/`nesting`; async fd ≥ 3 parent end via `AsyncFd`; async merge-into-a-piped-target; async explicit `kill`/`kill_tree`/`terminate_tree` + graceful trio; async foreign `Process`) **and** the recorded maintenance decision: *the async `tokio::Command` builder hand-mirrors the sync `Command` builder with no compiler-enforced parity, so a new sync builder method must be mirrored on the async builder by hand — a deliberate choice over a delegation macro / parity test, judged disproportionate for the ~15-method, stable surface.* Commit:

```bash
git add TODO.md
git commit -m "docs: note async Plan-9 deferrals (contain modes, fd>=3, merge-to-pipe, control, foreign)"
```

---

## Self-Review

**1. Spec coverage:** `tokio` feature + module + `subprocess::tokio::{Command,Child}` (Task 1–2); spawn-core extraction + `as_std_mut` reuse + `attach` by pid/handle, both Windows helpers re-plumbed (Task 1); async spawn with stdio resolution (`unreachable!` on the invariant break), identity-before-reap (contract `expect`), attach with error-path `reap_now` (Task 2); `&mut self` waits + stable `id()` + `try_wait`/`status` + stdio accessors (Task 2); async `communicate` (BrokenPipe-tolerant `try_join!`) + `output`/`read` + `run`/`run_line` (Task 3); guaranteed-reap `Drop` + `detach` (Task 4). Confirmed decisions honored: guaranteed reap (Task 4 `reap_now`), `contain()`-only async builder (Task 2 — no `contain_with`/`nesting`), strict-subset rejections (Task 2 spawn).

**2. Placeholder scan:** Task 1 stubs are scaffolding replaced in later tasks; no "TBD"/vague steps. Plan-task references kept in plan prose, not in shipped docstrings.

**3. Type consistency:** `attach(pid: u32, #[cfg(windows)] RawHandle, Prepared)` (Task 1) ↔ both call sites (Task 1 sync, Task 2 async). `reap_now(&mut ::tokio::process::Child, u32)` defined Task 2 (child.rs), used by spawn error-path (Task 2) + `Drop` (Task 4). `Child::from_parts(TokioChild, ProcessId, Attached, bool, Containment)` (Task 2) ↔ spawn (Task 2). `communicate(&mut self, Option<Vec<u8>>) -> Result<Output>` (Task 3) ↔ `output`/`read` (Task 3). Stream accessors return `::tokio::process::Child{Stdin,Stdout,Stderr}`. All test helpers (`spawn_control_async`/`spawn_blocker_async`/`spawn_grandchild_async`) are defined (Task 2) and used (Tasks 2–4) — no uncalled helper.
