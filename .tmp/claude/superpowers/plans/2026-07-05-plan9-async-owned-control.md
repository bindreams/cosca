# Plan 9 — Async Owned Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The async control surface for `subprocess::tokio::Child` — `kill`/`kill_tree`/`terminate`/`terminate_tree` plus the graceful-escalation trio — mirroring the sync contracts exactly, on a **reactor-native** async death-watch.

**Architecture:** The control ops compose existing primitives (`wait::terminate`, `Attached::{hard_kill, terminate}`, tokio `start_kill`). The one new primitive is `tokio::wait::grace_wait` — a non-reaping async grace-wait: Linux registers the identity-verified pidfd with the reactor via `AsyncFd`; macOS arms a kqueue `EVFILT_PROC|NOTE_EXIT` filter and registers the kqueue fd via `AsyncFd`; Windows has no pollable process handle, so a `spawn_blocking` watcher waits on `WaitForMultipleObjects([process_handle, cancel_event])` — a drop-guard signals the manual-reset cancel event when the grace-wait future goes away, so a cancelled watch releases its blocking-pool thread promptly (no detached thread, no `Runtime::drop` stall). The grace bound is `tokio::time::timeout` on Unix and the kernel wait's own timeout on Windows — a bound on a genuine external event (child exit), the sanctioned exception. The graceful trio lives in `src/tokio/child/graceful.rs`, a submodule of `tokio::child` (mirroring sync `src/child/graceful.rs`) so it reaches the private `require_contained` and fields.

**Tech Stack:** Rust (MSRV 1.87), tokio `["process", "rt", "io-util", "macros", "net", "time"]` — `net` added solely for `AsyncFd`, `time` solely for the grace bound.

## Global Constraints

- Spec: `.tmp/claude/superpowers/specs/2026-07-05-plan9-async-owned-control-design.md`. Sync sources of truth to mirror: `src/child.rs:113-141` (kill/kill_tree/terminate_tree), `src/child.rs:71-91` (require_contained), `src/child/graceful.rs` (the trio), `src/wait/{linux,macos,windows}.rs` (watch backends), `tests/graceful.rs` (test discipline).
- **No new crate dependencies.** The tokio dep line becomes exactly `tokio = { version = "1", optional = true, features = ["process", "rt", "io-util", "macros", "net", "time"] }` and the `[dev-dependencies]` line is unchanged.
- **No-time-sync test discipline:** death is proven only by control-socket EOF/ConnectionReset or an inspected `ExitStatus` signal — never sleep/poll/wall-clock. Escalation tests use SIGTERM-ignoring testbin modes + `Duration::ZERO` grace (child provably alive at the single poll → deterministic escalation). A generous grace (e.g. 30 s) on a promptly-exiting child is a failure bound, not synchronization.
- Error contracts mirror sync verbatim: uncontained `_tree` ops → `Error::Unsupported` (via `require_contained`); lone `terminate`/`graceful_shutdown` on Windows → `Error::Unsupported` (via `wait::terminate`).
- Cancellation contract (document + test): dropping a graceful future mid-grace cancels the watch on **every platform** — on Unix the `AsyncFd` deregisters and the fd closes; on Windows the drop-guard signals the cancel event (user decision 2026-07-12; mechanism in Architecture). The watch is non-reaping and signal-free: the child stays owned, and `Drop`'s teardown still applies.
- Before every commit: `cargo +stable fmt --check` and `cargo clippy --locked --features tokio --all-targets` must be clean (CI Lint runs stable with `-D warnings`).
- After each task, run the suite on WSL too: `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Users/bindreams/src/subprocess && export CARGO_TARGET_DIR=/tmp/sp-target && cargo test --locked --features tokio'` (the Unix signal paths and the pidfd watcher never run on the Windows host). macOS is CI-only: flag the kqueue backend for extra scrutiny at the branch-CI gate.
- Doc comments mirror the sync methods' docs, adjusted for async. Follow `writing-concisely`.
- **Recorded decision (user 2026-07-05; re-affirmed 2026-07-13 against a per-color-helper
  intermediate, covering the lone/tree axis):** the async control surface is a hand-mirror of
  sync. This explicitly
  covers the escalation policy skeleton (soft signal → non-reaping grace-wait → hard sweep →
  reap-last): its ~4-line sequence stays per-surface with the ordering invariant documented at
  each site — a closure-parameterized driver spanning sync and async execution is the rejected
  function-coloring shape. The parity harness is the scenario-mirrored test suites:
  `tests/tokio_control.rs` runs the SAME scenarios with the SAME assertions as
  `tests/graceful.rs` — a behavioral drift on either side breaks its suite. Keep the suites
  scenario-aligned when either side changes.

---

### Task 1: Builder mirror + explicit control ops (`kill`, `kill_tree`, `terminate_tree`)

**Files:**
- Modify: `src/tokio/command.rs` (add `contain_with`, `nesting` after `contain()` at :95-98)
- Modify: `src/tokio/child.rs` (add `kill`, `require_contained`, `kill_tree`, `terminate_tree` in the main `impl Child`, after `try_wait`)
- Modify: `src/containment.rs` (add the shared `require_contained(Containment, &Attached)` guard — the WHOLE guard, debug-assert + check + error, single-sourced)
- Modify: `src/child.rs:71-91` (sync `require_contained` delegates to the shared guard)
- Modify: `src/containment/treewalk.rs` (test-only fault seam: force the root identity-kill to no-op, so the `kill_tree` handle backstop is provably load-bearing)
- Modify: `src/containment/dispatch_tests.rs` (the sync + async backstop tests, driven by that seam)
- Modify: `tests/common/mod.rs` (add `spawn_control_async` + `spawn_tree_async`; make `spawn_blocker_async` a one-line alias)
- Create: `tests/tokio_control.rs`
- Create: `src/tokio/command_tests.rs` (declared inside `src/tokio/command.rs`)

**Interfaces:**
- Consumes: `Attached::{hard_kill(&self), terminate(&self, u32), is_actionable(&self)}`, `Containment::can_teardown(&self)`, tokio `Child::{start_kill, id}` — all existing.
- Produces (Tasks 2–3 rely on): `Child::kill(&mut self) -> Result<(), Error>`, `Child::kill_tree(&mut self) -> Result<(), Error>`, `Child::terminate_tree(&self) -> Result<(), Error>`, private `Child::require_contained(&self) -> Result<(), Error>`, test helpers `spawn_control_async(mode: &str, extra: &[&str], contain: bool) -> (subprocess::tokio::Child, TcpStream)` and `spawn_tree_async(mode: &str, configure: impl FnOnce(&mut subprocess::tokio::Command)) -> (subprocess::tokio::Child, TcpStream, TcpStream)`.

- [ ] **Step 1: Add the test helpers** — in `tests/common/mod.rs`, replace the body of `spawn_blocker_async` (at :70) with an alias and add `spawn_control_async` and `spawn_tree_async` above it:

```rust
/// Async analogue of `spawn_control`: spawn a testbin control child (it connects back and
/// sends its tag before the helper returns), optionally contained.
#[cfg(feature = "tokio")]
pub fn spawn_control_async(mode: &str, extra: &[&str], contain: bool) -> (subprocess::tokio::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut argv: Vec<String> = vec!["subprocess_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(testbin()).args(&argv);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn async control child");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R", grandchild
/// tag "G"), with builder configuration supplied by `configure` (containment mode, nesting).
/// Returns the root and grandchild control sockets identified by tag (accept order is not
/// guaranteed).
#[cfg(feature = "tokio")]
pub fn spawn_tree_async(
    mode: &str,
    configure: impl FnOnce(&mut subprocess::tokio::Command),
) -> (subprocess::tokio::Child, TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", mode, addr.as_str()]);
    configure(&mut cmd);
    let child = cmd.spawn().expect("spawn async tree");
    let (mut root, mut grandchild) = (None, None);
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match &tag {
            b"R" => root = Some(s),
            b"G" => grandchild = Some(s),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (child, root.expect("root R connected"), grandchild.expect("grandchild G connected"))
}
```

and `spawn_blocker_async` becomes (keep its existing doc comment):

```rust
#[cfg(feature = "tokio")]
pub fn spawn_blocker_async() -> (subprocess::tokio::Child, TcpStream) {
    spawn_control_async("control-block", &["R"], false)
}
```

Also re-express `spawn_grandchild_async_with` as a thin delegation over `spawn_tree_async`
(keeping its doc comment; `spawn_grandchild_async` already delegates to it), so exactly ONE
accept/tag-demux loop exists:

```rust
#[cfg(feature = "tokio")]
pub fn spawn_grandchild_async_with(
    contain: bool,
    kill_on_drop: bool,
) -> (subprocess::tokio::Child, TcpStream, TcpStream) {
    spawn_tree_async("spawn-grandchild", |cmd| {
        if contain {
            cmd.contain();
        }
        cmd.kill_on_drop(kill_on_drop);
    })
}
```

- [ ] **Step 2: Write the failing tests** — create `tests/tokio_control.rs`:

```rust
//! Async control-op integration tests (kill / kill_tree / terminate_tree + builder mirror).
//! Same death-proof discipline as tests/graceful.rs: control-socket EOF or an inspected
//! ExitStatus signal — never sleep/poll/wall-clock.
#![cfg(feature = "tokio")]

#[path = "common/mod.rs"]
mod common;

use std::io::Read;

fn expect_eof(who: &str, s: &mut std::net::TcpStream) {
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("{who} not torn down: {other:?}"),
    }
}

#[tokio::test]
async fn async_kill_terminates_the_child() {
    let (mut child, mut sock) = common::spawn_blocker_async();
    child.kill().expect("kill");
    expect_eof("blocker", &mut sock);
    let status = child.wait().await.expect("reap");
    assert!(!status.success(), "killed child cannot report success, got {status:?}");
}

#[tokio::test]
async fn async_kill_after_wait_is_ok() {
    use std::io::Write;
    let (mut child, mut sock) = common::spawn_blocker_async();
    sock.write_all(b"x").expect("release the blocker");
    child.wait().await.expect("reap");
    child.kill().expect("kill after wait is Ok");
}

#[tokio::test]
async fn async_kill_on_exited_unreaped_child_is_ok() {
    use std::io::Write;
    let (mut child, mut sock) = common::spawn_blocker_async();
    sock.write_all(b"x").expect("release the blocker");
    expect_eof("blocker", &mut sock); // real exit event; the child is NOT yet reaped
    child.kill().expect("kill on an exited-unreaped child is Ok");
    child.wait().await.expect("reap");
}

#[tokio::test]
async fn async_tree_ops_unsupported_when_uncontained() {
    let (mut child, mut sock) = common::spawn_blocker_async();
    let err = child.kill_tree().expect_err("uncontained kill_tree");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "got {err:?}");
    let err = child.terminate_tree().expect_err("uncontained terminate_tree");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await;
}

#[tokio::test]
async fn async_kill_tree_tears_down_tree() {
    let (mut child, mut root, mut grand) = common::spawn_grandchild_async(true);
    child.kill_tree().expect("kill_tree");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
    let status = child.wait().await.expect("reap root");
    assert!(!status.success(), "hard-killed root cannot report success, got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_terminate_tree_soft_kills_the_group() {
    use std::os::unix::process::ExitStatusExt;
    // control-block honors SIGTERM: the group signal alone (signal-only op) tears it down.
    let (mut child, mut sock) = common::spawn_control_async("control-block", &["R"], true);
    child.terminate_tree().expect("terminate_tree");
    expect_eof("root", &mut sock);
    let status = child.wait().await.expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "soft group signal must be SIGTERM, got {status:?}");
}

#[tokio::test]
async fn async_contain_with_treewalk_tears_down_tree() {
    // kill_tree on a TreeWalk-contained tree tears down BOTH members via the identity walk
    // (no kernel group needed). The builder mirror's value-sensitivity is the unit test's job
    // (src/tokio/command_tests.rs).
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild", |cmd| {
        cmd.contain_with(subprocess::ContainMode::TreeWalk)
            .nesting(subprocess::containment::Nesting::Opaque);
    });
    assert_eq!(child.containment(), subprocess::Containment::TreeWalk);
    child.kill_tree().expect("treewalk kill_tree");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
    let _ = child.wait().await.expect("reap");
}
```

- [ ] **Step 2b: The builder-mirror unit test** — value-sensitive at the request level,
mirroring sync `command_tests.rs`'s `contain_with_and_nesting_recorded`. Create
`src/tokio/command_tests.rs`:

```rust
//! Unit tests for the async builder mirror — assert the wrapped sync request records the
//! configured values (the integration suite only proves the spawn path).

use crate::containment::Nesting;
use crate::ContainMode;

#[test]
fn contain_with_and_nesting_recorded() {
    let mut cmd = super::Command::new();
    cmd.contain_with(ContainMode::TreeWalk).nesting(Nesting::Opaque);
    let req = cmd.inner.contain_request();
    assert_eq!(req.mode, Some(ContainMode::TreeWalk));
    assert_eq!(req.nesting, Nesting::Opaque);
}
```

and declare it at the bottom of `src/tokio/command.rs`:

```rust
#[cfg(test)]
#[path = "command_tests.rs"]
mod command_tests;
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test --locked --features tokio --test tokio_control`
Expected: COMPILE FAIL — `no method named kill/kill_tree/terminate_tree/contain_with/nesting` and missing helpers.

- [ ] **Step 4: Implement the builder mirror** — in `src/tokio/command.rs`, directly after `contain()` (:95-98):

```rust
    /// Contain with a specific [`ContainMode`](crate::ContainMode).
    pub fn contain_with(&mut self, mode: crate::ContainMode) -> &mut Command {
        self.inner.contain_with(mode);
        self
    }

    /// Set how this contained spawn marks its descendants (default
    /// [`Nesting::Mark`](crate::containment::Nesting::Mark)).
    pub fn nesting(&mut self, nesting: crate::containment::Nesting) -> &mut Command {
        self.inner.nesting(nesting);
        self
    }
```

- [ ] **Step 5: Implement the control ops** — in `src/tokio/child.rs`, in the main `impl Child` block after `try_wait`:

```rust
    /// Hard-kill the (lone) child. Handle-bound, so it cannot race a recycled pid.
    /// `Ok(())` if the child already exited or was reaped by a prior `wait` (tokio's
    /// `start_kill` maps the reaped state to `Ok`). Signal-only: does not reap —
    /// `wait().await` (or `Drop`) collects the exit status.
    pub fn kill(&mut self) -> Result<(), Error> {
        self.child.start_kill().map_err(Error::Io)
    }

    /// Hard-kill the contained tree. Requires an actionable containment mechanism
    /// (errors `Unsupported` otherwise — use [`kill`](Child::kill) for a lone process).
    /// If both the group teardown and the handle backstop fail, the group error is returned.
    pub fn kill_tree(&mut self) -> Result<(), Error> {
        self.require_contained()?;
        let group_result = self.attached.hard_kill();
        // Backstop for the TreeWalk mechanism: its hard_kill kills the root by identity, which
        // no-ops if `ProcessId::of` transiently fails to resolve — this handle-based kill
        // covers that, so its failure is contract-relevant.
        let backstop = self.kill();
        // Both-fail: the group error is surfaced; subsuming the backstop's is deliberate.
        group_result.and(backstop)
    }

    /// Send the graceful termination signal to the contained group — `SIGTERM` via
    /// `killpg`/cgroup, or `CTRL_BREAK` to the job/console group. **Signal-only:** does
    /// not wait or reap. Requires an actionable containment mechanism (errors
    /// `Unsupported` otherwise). Cooperative best-effort: on the `TreeWalk` mechanism a
    /// descendant whose identity transiently fails to resolve is intentionally left
    /// unsignaled; [`kill_tree`](Child::kill_tree) is the guaranteed hard teardown.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
        self.attached.terminate(self.id.pid())
    }

    /// Guard for the `_tree` operations (single-sourced with the sync `Child`).
    fn require_contained(&self) -> Result<(), Error> {
        crate::containment::require_contained(self.containment, &self.attached)
    }
```

Add the shared guard to `src/containment.rs` (top level, near the `Containment` impl) — the
WHOLE guard, not just the error string — and make the sync `Child::require_contained`
(`src/child.rs:71-91`) an identical one-line delegation (its doc comment moves here):

```rust
/// Guard for the `_tree` operations, shared by the sync and async `Child`: they act on the
/// containment group's teardown mechanism, so a child whose mechanism is a no-op has no tree
/// to act on.
pub(crate) fn require_contained(containment: Containment, attached: &Attached) -> Result<(), crate::error::Error> {
    debug_assert_eq!(
        containment.can_teardown(),
        attached.is_actionable(),
        "Containment/Attached actionability diverged"
    );
    if !attached.is_actionable() {
        return Err(crate::error::Error::Unsupported {
            op: "tree teardown (kill_tree / terminate_tree)".into(),
            platform: std::env::consts::OS,
            detail: "this child holds no actionable tree-teardown mechanism (uncontained, \
                     or a nested member of an ancestor's containment group). Use kill() for a \
                     lone process, or tear down the tree via the outermost .contain()ed handle."
                .into(),
        });
    }
    Ok(())
}
```

(The sync suite's existing uncontained-`Unsupported` tests keep passing untouched — the message
is byte-identical, just single-sourced.)

Also append the same both-fail sentence to the SYNC `kill_tree` rustdoc (`src/child.rs:120-121`,
doc parity): "If both the group teardown and the handle backstop fail, the group error is
returned."

- [ ] **Step 5b: Containment fault seam + backstop tests** — the
`kill_tree` handle backstop is load-bearing only when the mechanism's identity kill no-ops,
which is a transient race not otherwise forcible. Add a seam in `src/containment/treewalk.rs`
(the established `#[cfg(test)]` fault-module pattern from `src/child/spawn.rs`): guard the ROOT
identity-kill in `hard_kill` (`treewalk.rs:222-241`):

```rust
pub(crate) fn hard_kill(root: ProcessId) {
    let parents = crate::containment::enumerate::process_parents();
    let descendants = descendants(root, &parents);
    // Test-only fault seam: skip the root's identity kill (take semantics — see `fault`).
    #[cfg(test)]
    let skip_root = fault::take_force_root_kill_noop();
    #[cfg(not(test))]
    let skip_root = false;
    #[cfg(unix)]
    {
        if !skip_root {
            kill_by_identity(root, Signal::SIGKILL);
        }
        for id in descendants {
            kill_by_identity(id, Signal::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        if !skip_root {
            kill_by_identity(root);
        }
        for id in descendants {
            kill_by_identity(id);
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (root, descendants, skip_root);
}

/// Test-only: force the NEXT `hard_kill` on THIS thread to skip the root's identity kill
/// (makes the `kill_tree` handle backstop forcible). Take semantics: `hard_kill` consumes the
/// flag — arm and call on one thread; assert consumption via [`armed`].
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    thread_local! {
        static FORCE_ROOT_KILL_NOOP: Cell<bool> = const { Cell::new(false) };
    }
    pub(crate) fn set_force_root_kill_noop(on: bool) {
        FORCE_ROOT_KILL_NOOP.with(|f| f.set(on));
    }
    pub(crate) fn take_force_root_kill_noop() -> bool {
        FORCE_ROOT_KILL_NOOP.with(|f| f.replace(false))
    }
    pub(crate) fn armed() -> bool {
        FORCE_ROOT_KILL_NOOP.with(|f| f.get())
    }
}
```

and append the sync + async backstop tests to `src/containment/dispatch_tests.rs` (lib unit
tests — the seam is `pub(crate)`). If the backstop were dropped, the child would outlive
`kill_tree` and `wait` would return the blocker's own eventual `success` — a bounded, loud
failure:

```rust
// A long-lived TreeWalk-contained child; no descendants, so with the root identity-kill
// seam-disabled the ONLY killer is kill_tree's handle backstop. Armed AFTER the fallible
// spawn so a spawn panic cannot leak the flag.
#[test]
fn sync_kill_tree_backstop_is_load_bearing() {
    use super::super::treewalk::fault;
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn");
    fault::set_force_root_kill_noop(true);
    let result = child.kill_tree();
    assert!(!fault::armed(), "seam not consumed — hard_kill did not run on the arming thread");
    result.expect("kill_tree via backstop");
    let status = child.wait().expect("reap");
    assert!(!status.success(), "the handle backstop must be what killed the root, got {status:?}");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_kill_tree_backstop_is_load_bearing() {
    use super::super::treewalk::fault;
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    fault::set_force_root_kill_noop(true);
    let result = child.kill_tree();
    assert!(!fault::armed(), "seam not consumed — hard_kill did not run on the arming thread");
    result.expect("kill_tree via backstop");
    let status = child.wait().await.expect("reap");
    assert!(!status.success(), "the handle backstop must be what killed the root, got {status:?}");
}
```

Run: `cargo test --locked --lib backstop_is_load_bearing && cargo test --locked --features tokio --lib backstop_is_load_bearing`
Expected: PASS (1 sync test base; sync + async with the feature).

- [ ] **Step 6: Run to verify pass**

Run: `cargo test --locked --features tokio --test tokio_control`
Expected: PASS (7 tests on Unix, 6 on the Windows host — `async_terminate_tree_soft_kills_the_group` is Unix-gated).

- [ ] **Step 7: Full regression + lint**

Run: `cargo test --locked --features tokio && cargo test --locked && cargo +stable fmt --check && cargo clippy --locked --features tokio --all-targets && cargo clippy --locked --all-targets`
Expected: all green, zero warnings. Then the WSL run from Global Constraints.

- [ ] **Step 8: Commit**

```bash
git add src/tokio/command.rs src/tokio/command_tests.rs src/tokio/child.rs src/containment.rs src/child.rs src/containment/treewalk.rs src/containment/dispatch_tests.rs tests/common/mod.rs tests/tokio_control.rs
git commit -m "feat: async explicit control (kill/kill_tree/terminate_tree) + contain_with/nesting builder mirror + backstop fault seam"
```

---

### Task 2: The reactor-native async grace-wait (`tokio::wait::grace_wait`)

**Files:**
- Modify: `Cargo.toml` (tokio features += `net`, `time`. `Cargo.lock` may change: commit whatever `cargo build` regenerates)
- Modify: `src/wait/linux.rs:14` (make `open_verified` `pub(crate)`)
- Modify: `src/wait/macos.rs` (extract the existing nix arm sequence into `pub(crate) fn arm_proc_exit -> Option<Kqueue>` + a `drain_proc_exit` helper; `block_until_exit` consumes the arm — ONE definition of the subtle arm dance with two consumers, exactly the shape Linux has via `open_verified`; no new `unsafe`)
- Create: `src/wait/macos_tests.rs` (macOS CI-only: pins `drain_proc_exit`'s `Ok(None)` branch, the spurious-readiness loop's input)
- Modify: `src/wait/windows.rs` (add `new_cancel_event` + `signal_cancel` + `block_until_exit_or_cancel` — the event-cancellable variant of the blocking wait; `block_until_exit`/`kill`/`terminate` unchanged)
- Modify: `src/tokio.rs` (declare `pub(crate) mod wait;` — module file `src/tokio/wait.rs`)
- Create: `src/tokio/wait.rs`
- Create: `src/tokio/wait_tests.rs` (unit tests — `grace_wait` is `pub(crate)`, unreachable from `tests/`)

**Interfaces:**
- Consumes: `wait::backend::open_verified(ProcessId) -> Result<Option<OwnedFd>, Error>` (Linux), `wait::backend::arm_proc_exit(ProcessId) -> Result<Option<Kqueue>, Error>` + `wait::backend::drain_proc_exit(&Kqueue) -> Result<Option<()>, Error>` (macOS, extracted here), `wait::backend::{new_cancel_event() -> Result<OwnedHandle, Error>, signal_cancel(&OwnedHandle), block_until_exit_or_cancel(ProcessId, Duration, &OwnedHandle) -> Result<bool, Error>}` (Windows, added here), `ProcessId::{pid, exists}`, `tokio::io::unix::AsyncFd`, `tokio::time::timeout`, `tokio::task::spawn_blocking`.
- Produces (Task 3 relies on): `pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error>` in `src/tokio/wait.rs` — `Ok(true)` = exited within `grace`; `Ok(false)` = still alive at the deadline. Non-reaping, identity-verified, signal-free.

- [ ] **Step 1: Update `Cargo.toml`** — the tokio dependency line becomes:

```toml
# `macros` is required by the library, not only tests: `communicate` uses `tokio::try_join!`,
# which is gated behind tokio's `macros` feature. `net` is solely for `AsyncFd` (the
# reactor-native death-watch); `time` solely for the grace bound on it.
tokio = { version = "1", optional = true, features = ["process", "rt", "io-util", "macros", "net", "time"] }
```

(The nix line is unchanged — the macOS arm extraction stays on nix's safe `Kqueue`.)

Run `cargo build --locked --features tokio` — if it fails on the lockfile, run `cargo build --features tokio` once and commit the regenerated `Cargo.lock`.

- [ ] **Step 2: Make the Linux pidfd opener reusable** — in `src/wait/linux.rs:14`, change `fn open_verified` to `pub(crate) fn open_verified` (doc comment unchanged).

- [ ] **Step 2b: Extract the shared macOS arm (nix stays)** — in `src/wait/macos.rs`, split the
existing `block_until_exit` (lines 16-66) into an arm primitive + a drain helper + the blocking
wait, all still on nix (nix's `Kqueue` exposes its fd: `impl AsFd` and
`impl From<Kqueue> for OwnedFd` in nix 0.31 — verified against the pinned source, so the async
reactor registration needs NO raw-libc rewrite). `kill`/`terminate` and the module doc stay
unchanged; `placeholder()` stays. The arm/receipt/re-verify code moves verbatim:

```rust
/// Arm an `EVFILT_PROC | NOTE_EXIT` filter for `pid` on an EXISTING kqueue (`EV_RECEIPT`:
/// synchronous, receipt-checked). `Ok(None)` => the pid is already gone. The single
/// definition of the receipt dance — `arm_proc_exit` consumes it, and the decoy composition
/// test arms its second filter through it (no hand-rolled twin to drift).
pub(crate) fn arm_note_exit_on(kq: &Kqueue, pid: u32) -> Result<Option<()>, Error> {
    let change = KEvent::new(
        pid as usize,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    );
    // EV_RECEIPT makes EV_ADD synchronous: kevent returns exactly one receipt event
    // whose `data` is the add result (0 = armed, ESRCH = pid gone, other = errno).
    let mut receipt = [placeholder()];
    let n = kq
        .kevent(&[change], &mut receipt, None)
        .map_err(|e| Error::Io(e.into()))?;
    if n != 1 {
        return Err(Error::Io(std::io::Error::other(
            "kqueue EV_RECEIPT returned no receipt event",
        )));
    }
    let add_result = receipt[0].data() as i64;
    if add_result == libc::ESRCH as i64 {
        return Ok(None); // pid already gone
    }
    if add_result != 0 {
        return Err(Error::Io(std::io::Error::from_raw_os_error(add_result as i32)));
    }
    Ok(Some(()))
}

/// Create a kqueue and arm an `EVFILT_PROC | NOTE_EXIT` filter for `id`, re-verifying
/// identity. `Ok(None)` => already gone (treat as exited). The kqueue's fd polls readable
/// once the exit event is pending — consumed by the sync blocking wait below and by the
/// async reactor watch (`tokio::wait`).
pub(crate) fn arm_proc_exit(id: ProcessId) -> Result<Option<Kqueue>, Error> {
    let kq = Kqueue::new().map_err(|e| Error::Io(e.into()))?;
    if arm_note_exit_on(&kq, id.pid())?.is_none() {
        return Ok(None); // pid already gone
    }
    if !id.exists() {
        return Ok(None); // recycled before the filter armed
    }
    Ok(Some(kq))
}

/// Drain one pending event from an armed kqueue without blocking. `Ok(Some(()))` = the exit
/// event was observed; `Ok(None)` = nothing pending (spurious readiness — re-wait); `Err` =
/// EV_ERROR (any, mirroring the blocking wait) or a kevent failure.
pub(crate) fn drain_proc_exit(kq: &Kqueue) -> Result<Option<()>, Error> {
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut events = [placeholder()];
    loop {
        match kq.kevent(&[], &mut events, Some(zero)) {
            Ok(0) => return Ok(None), // nothing pending
            Ok(_) => {
                if events[0].flags().contains(EvFlags::EV_ERROR) {
                    return Err(Error::Io(std::io::Error::from_raw_os_error(events[0].data() as i32)));
                }
                return Ok(Some(())); // NOTE_EXIT
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
}

pub(crate) fn block_until_exit(id: ProcessId, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
    let Some(kq) = arm_proc_exit(id)? else {
        return Ok(true);
    };
    let mut events = [placeholder()];
    loop {
        // nix Kqueue::kevent takes Option<libc::timespec> (None = block forever).
        let timeout = crate::wait::remaining(deadline).map(|d| libc::timespec {
            tv_sec: d.as_secs().min(i64::MAX as u64) as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });
        match kq.kevent(&[], &mut events, timeout) {
            Ok(0) => return Ok(false), // timed out, still alive
            Ok(_) => {
                if events[0].flags().contains(EvFlags::EV_ERROR) {
                    return Err(Error::Io(std::io::Error::from_raw_os_error(events[0].data() as i32)));
                }
                return Ok(true); // NOTE_EXIT
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
}
```

Also declare a macOS-only unit-test module at the bottom of `src/wait/macos.rs`:

```rust
#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
```

and create `src/wait/macos_tests.rs`, covering `drain_proc_exit`'s `Ok(None)` branch. (The
loop's clear_ready + re-await COMPOSITION is covered end-to-end by
`watch_loop_survives_a_non_exit_drain_cycle` in `wait_tests` — a decoy second `NOTE_EXIT`
filter supplies a real first wake whose drain is scripted to report "no exit".)

```rust
//! Unit tests for the shared kqueue arm/drain primitives (macOS CI-only).

use crate::identity::ProcessId;

#[test]
fn drain_reports_none_when_no_event_pending() {
    let mut child = std::process::Command::new("sleep").arg("30").spawn().expect("spawn blocker");
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let kq = super::arm_proc_exit(id).expect("arm").expect("a live child arms");
    assert!(
        super::drain_proc_exit(&kq).expect("drain").is_none(),
        "no exit event yet must drain to None (spurious-readiness input)"
    );
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}
```

- [ ] **Step 2c: The event-cancellable Windows wait** — in `src/wait/windows.rs`, add the
cancel-event primitives and a two-handle variant of the blocking wait (`block_until_exit`,
`kill`, `terminate` unchanged). The async watch (Step 4) waits on BOTH the process handle and a
manual-reset event; signaling the event releases the wait promptly — a kernel primitive, not a
poll loop. Manual-reset means a signal is never consumed: set-once, released forever, so signal
and wait cannot race.

```rust
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;

use windows::Win32::Foundation::WAIT_FAILED; // merge into the existing Foundation import
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};

/// An unnamed manual-reset event, initially unsignaled, for releasing
/// `block_until_exit_or_cancel` early. Signal with [`signal_cancel`]; `OwnedHandle` closes it.
pub(crate) fn new_cancel_event() -> Result<OwnedHandle, Error> {
    // SAFETY: creating an unnamed event has no preconditions; the handle is immediately
    // wrapped in an OwnedHandle, which closes it.
    let h = unsafe { CreateEventW(None, true, false, None) }.map_err(|e| Error::Io(e.into()))?;
    // SAFETY: `h` is a freshly created, owned event handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0 as _) })
}

pub(crate) fn signal_cancel(event: &OwnedHandle) {
    // SAFETY: `event` is a live event handle (the OwnedHandle keeps it open).
    let set = unsafe { SetEvent(HANDLE(event.as_raw_handle())) };
    // SetEvent on a live owned event has no documented failure mode; if it ever failed, the
    // cancellation contract would silently degrade to an unbounded park (a hung
    // `Runtime::drop` under an unbounded grace) — so this fails LOUD in every build: a
    // diagnosable panic beats an unexplained hang. Called from Drop, so never double-panic:
    // during an unwind the process is already failing loudly and the in-flight panic wins.
    // Accepted residual: `panicking()` is thread-wide, so a SetEvent failure coinciding with
    // an UNRELATED unwind through the guard's frame goes unasserted — the alternative is an
    // abort, for a branch with no documented failure mode on a live owned event.
    if !std::thread::panicking() {
        assert!(set.is_ok(), "SetEvent on an owned event handle failed: {set:?}");
    }
}

/// `block_until_exit`, releasable early: returns `Ok(false)` as soon as `cancel` is signaled
/// (the process wins a tie — it is the lower wait index). `Ok(true)` = exited within `grace`.
pub(crate) fn block_until_exit_or_cancel(id: ProcessId, grace: Duration, cancel: &OwnedHandle) -> Result<bool, Error> {
    // SAFETY: OpenProcess tolerates a dead/invalid pid (returns Err); the handle is
    // closed on every return path below.
    let handle = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, id.pid()) }
    {
        Ok(h) => h,
        // gone / unopenable => exited (mirroring block_until_exit).
        Err(_) => return Ok(true),
    };
    if !id.exists() {
        close(handle);
        return Ok(true); // recycled before open
    }
    // Deliberately capped at INFINITE-1, never true INFINITE: the cancel event — signaled on
    // every drop path — is the release mechanism for large graces, and the cap is the
    // last-resort bound. (block_until_exit's None => INFINITE is for deliberately unbounded waits.)
    let ms = grace.as_millis().min((INFINITE - 1) as u128) as u32;
    let handles = [handle, HANDLE(cancel.as_raw_handle())];
    // SAFETY: both handles are live for the wait's duration.
    let waited = unsafe { WaitForMultipleObjects(&handles, false, ms) };
    // Capture BEFORE close(): CloseHandle would overwrite GetLastError.
    let wait_failed = (waited == WAIT_FAILED).then(std::io::Error::last_os_error);
    close(handle);
    if waited == WAIT_OBJECT_0 {
        Ok(true) // process exited
    } else if waited.0 == WAIT_OBJECT_0.0 + 1 || waited == WAIT_TIMEOUT {
        Ok(false) // released by cancel, or grace elapsed — still alive either way
    } else if let Some(e) = wait_failed {
        Err(Error::Io(e))
    } else {
        // Events cannot be abandoned (a mutex verdict); anything else is undocumented.
        // Report the raw verdict — GetLastError is only meaningful for WAIT_FAILED.
        debug_assert!(false, "unexpected WaitForMultipleObjects verdict: {waited:?}");
        Err(Error::Io(std::io::Error::other(format!(
            "unexpected WaitForMultipleObjects result: {waited:?}"
        ))))
    }
}
```

(If a `windows` 0.62 signature differs — e.g. `CreateEventW`'s optional-attributes/bool
parameters — adapt the call; the contract is only "an unnamed manual-reset event, initially
unsignaled".)

Also fix the same latent capture-after-close in the EXISTING `block_until_exit`
(`WaitForSingleObject` → `close(handle)` → `last_os_error()`): capture
`std::io::Error::last_os_error()` into a local when `waited` is neither `WAIT_OBJECT_0` nor
`WAIT_TIMEOUT`, BEFORE `close(handle)` runs — `CloseHandle` can overwrite `GetLastError`, so
the shipped ordering can report an unrelated error.

- [ ] **Step 3: Write the failing unit tests** — create `src/tokio/wait_tests.rs`:

```rust
//! Unit tests for the reactor-native grace-wait. In the library because `grace_wait` is
//! `pub(crate)`. Death-proof discipline: a generous grace on an already-dead child is a
//! failure bound (the exit event precedes the call); `Duration::ZERO` on a live child makes
//! the timeout branch deterministic.

use std::time::Duration;

// This module is declared INSIDE src/tokio/wait.rs, so `super` is `tokio::wait` itself.
use super::grace_wait;
use crate::identity::ProcessId;

// A long-lived std child (leak-proof: killed + reaped by each test).
fn std_blocker() -> std::process::Child {
    let mut cmd = std::process::Command::new(if cfg!(windows) { "ping" } else { "sleep" });
    #[cfg(windows)]
    cmd.args(["-n", "30", "127.0.0.1"]).stdout(std::process::Stdio::null());
    #[cfg(unix)]
    cmd.arg("30");
    cmd.spawn().expect("spawn std blocker")
}

#[tokio::test]
async fn grace_wait_true_for_exited_unreaped_child() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    child.kill().expect("kill");
    // NOT reaped yet (no wait): on Unix the child is a zombie — the watch must still see the
    // exit.
    let exited = grace_wait(id, Duration::from_secs(30)).await.expect("grace_wait");
    assert!(exited, "an exited (unreaped) child must report exited");
    child.wait().expect("reap");
}

#[tokio::test]
async fn grace_wait_false_for_live_child_at_zero_grace() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let exited = grace_wait(id, Duration::ZERO).await.expect("grace_wait");
    assert!(!exited, "a live child at ZERO grace must report still-alive");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

#[tokio::test]
async fn grace_wait_true_for_stale_identity() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    child.kill().expect("kill");
    child.wait().expect("reap"); // fully gone; the pid may even be recycled
    let exited = grace_wait(id, Duration::from_secs(30)).await.expect("grace_wait");
    assert!(exited, "a stale identity (reaped child) must report exited, never hang");
}

#[tokio::test]
async fn grace_wait_true_when_child_dies_mid_wait() {
    // The live-then-exits path: the watch arms on a LIVE child and must resolve on the real
    // exit event (our own kill). Whether the kill lands before or after arming, the result
    // must be `true`.
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let watch = ::tokio::spawn(grace_wait(id, Duration::from_secs(30)));
    child.kill().expect("kill mid-wait");
    let exited = watch.await.expect("join").expect("grace_wait");
    assert!(exited, "the watch must resolve on the child's exit");
    child.wait().expect("reap");
}

// The Windows release mechanism itself, deterministically: a PRE-signaled cancel event must
// release the wait on a LIVE child — no race, nothing to time. If the cancel plumbing were
// broken, the wait would sit at the (effectively infinite) Duration::MAX cap and the test
// harness's own bound would surface the hang loudly.
#[cfg(windows)]
#[test]
fn cancel_event_releases_the_blocking_wait() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let cancel = crate::wait::backend::new_cancel_event().expect("event");
    crate::wait::backend::signal_cancel(&cancel);
    let exited = crate::wait::backend::block_until_exit_or_cancel(id, Duration::MAX, &cancel)
        .expect("cancellable wait");
    assert!(!exited, "a live child with a signaled cancel must report still-alive");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

// The concurrent case: signal the cancel while the wait is (or is about to be) in flight.
// The manual-reset event is set-once/released-forever, so EVERY interleaving must release
// the watcher — this is race-INSENSITIVITY being proven, not an outcome bet on a race. If
// the release were broken, the join would hang at the harness's own failure bound.
#[cfg(windows)]
#[test]
fn cancel_event_signaled_mid_wait_releases_the_blocking_wait() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event().expect("event"));
    let watcher = std::thread::spawn({
        let cancel = cancel.clone();
        move || crate::wait::backend::block_until_exit_or_cancel(id, Duration::MAX, &cancel)
    });
    crate::wait::backend::signal_cancel(&cancel);
    let exited = watcher.join().expect("watcher thread").expect("cancellable wait");
    assert!(!exited, "a live child with a signaled cancel must report still-alive");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

// Drive the REAL macOS watch loop through its clear_ready + re-await cycle with genuine
// kernel events: a DECOY second NOTE_EXIT filter on the same kqueue supplies the first wake;
// the scripted drain consumes it (keeping the kqueue level low, so clear_ready cannot miss a
// wake) but reports "no exit" — the loop must re-await, and the target's real exit must still
// resolve it. Every wake is a real kernel event; the 30 s timeout is the failure bound.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn watch_loop_survives_a_non_exit_drain_cycle() {
    let mut decoy = std_blocker();
    let mut target = std_blocker();
    let target_id = ProcessId::of(target.id()).expect("identity of live target");
    let kq = crate::wait::backend::arm_proc_exit(target_id)
        .expect("arm target")
        .expect("a live target arms");
    // Arm the decoy on the SAME kqueue, through the production receipt dance.
    assert!(
        crate::wait::backend::arm_note_exit_on(&kq, decoy.id())
            .expect("arm decoy")
            .is_some(),
        "a live decoy arms"
    );
    decoy.kill().expect("kill decoy"); // the first, non-target wake

    let afd = ::tokio::io::unix::AsyncFd::with_interest(super::KqueueFd(kq), ::tokio::io::Interest::READABLE)
        .expect("register");
    let target_cell = std::cell::RefCell::new(None);
    let mut pending = Some(target);
    let watch = super::watch_readable(&afd, |kq| {
        let drained = crate::wait::backend::drain_proc_exit(kq)?;
        if let Some(mut t) = pending.take() {
            // First cycle (the decoy's event, consumed above): report "no exit" so the loop
            // clear_readys and re-awaits; only NOW create the target's exit event.
            t.kill().expect("kill target mid-cycle");
            *target_cell.borrow_mut() = Some(t);
            return Ok(None);
        }
        Ok(drained)
    });
    ::tokio::time::timeout(Duration::from_secs(30), watch)
        .await
        .expect("the re-awaited loop must resolve on the target's exit")
        .expect("watch");
    let mut target = target_cell.borrow_mut().take().expect("target stored by the first cycle");
    target.wait().expect("reap target");
    decoy.wait().expect("reap decoy");
}

// The POLLERR branch and the readiness contract, via synthetic Ready values — these pin the
// BRANCH LOGIC only. The real OS→Ready mapping (pidfd → epoll → mio → AsyncFd) is validated
// by the live-path tests above: grace_wait_true_for_exited_unreaped_child and
// grace_wait_true_when_child_dies_mid_wait run the whole stack on a real pidfd.
#[cfg(target_os = "linux")]
mod classify {
    use ::tokio::io::Ready;

    use super::super::classify_pidfd_ready;

    #[test]
    fn readable_and_read_closed_mean_exited() {
        assert!(matches!(classify_pidfd_ready(Ready::READABLE), Some(Ok(()))));
        assert!(matches!(classify_pidfd_ready(Ready::READ_CLOSED), Some(Ok(()))));
    }

    #[test]
    fn error_readiness_is_surfaced_not_swallowed() {
        assert!(matches!(classify_pidfd_ready(Ready::ERROR | Ready::READABLE), Some(Err(_))));
        assert!(matches!(classify_pidfd_ready(Ready::ERROR), Some(Err(_))));
    }

    #[test]
    fn unclassified_readiness_retries_never_a_false_verdict() {
        // tokio's documented false-positive wake: not an exit (would skip escalation on a
        // live child), not an error (would force-kill a graceful exit) — re-await.
        assert!(classify_pidfd_ready(Ready::EMPTY).is_none());
    }
}
```

Declare it inside `src/tokio/wait.rs` (Step 4 includes the declaration).

- [ ] **Step 4: Implement** — declare in `src/tokio.rs` (next to the other module declarations): `pub(crate) mod wait;` — then create `src/tokio/wait.rs`:

```rust
//! Reactor-native, non-reaping async grace-wait. Linux: the identity-verified pidfd is
//! registered with the reactor (`AsyncFd`); macOS: a kqueue `EVFILT_PROC|NOTE_EXIT` filter is
//! armed and its kqueue fd registered; Windows has no pollable process handle, so a
//! `spawn_blocking` watcher waits on the process handle AND a cancel event that a drop-guard
//! signals — a dropped grace-wait releases its watcher promptly on every platform. The grace
//! bound (`tokio::time::timeout` on Unix, the kernel wait's timeout on Windows) is a failure
//! bound on a genuine external event: the child's exit. Unix needs the runtime's IO + time
//! drivers (tokio panics otherwise) — documented on the public graceful methods.

use std::time::Duration;

use crate::error::Error;
use crate::identity::ProcessId;

/// `Ok(true)` = the process exited within `grace`; `Ok(false)` = still alive at the deadline.
/// Non-reaping and signal-free; identity-verified (a stale/recycled id reports exited).
#[cfg(unix)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    match ::tokio::time::timeout(grace, exit_watch(id)).await {
        Ok(watch) => watch.map(|()| true),
        Err(_elapsed) => Ok(false),
    }
}

#[cfg(windows)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    /// Signals the cancel event on drop (harmless after completion) so the blocking watcher
    /// returns promptly instead of parking out the grace, and `Runtime::drop` — which joins
    /// blocking tasks — does not stall.
    struct SignalOnDrop(std::sync::Arc<std::os::windows::io::OwnedHandle>);
    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            crate::wait::backend::signal_cancel(&self.0);
        }
    }
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event()?);
    let _guard = SignalOnDrop(cancel.clone());
    let joined = ::tokio::task::spawn_blocking(move || {
        crate::wait::backend::block_until_exit_or_cancel(id, grace, &cancel)
    })
    .await;
    match joined {
        Ok(result) => result,
        // block_until_exit_or_cancel does not panic — a panic here is a bug, not an I/O
        // condition; propagate it instead of masking it as an error.
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Keep the shutdown-cancelled discriminator visible instead of folding it into an
        // opaque error indistinguishable from a real wait failure. The final arm is
        // presently unreachable (panic and cancelled are tokio's only variants today) and
        // exists for type-system conservatism: a future variant surfaces as an Err, never a
        // false success — with a debug tripwire, mirroring the unexpected-wait-verdict arm.
        Err(e) if e.is_cancelled() => Err(Error::Io(std::io::Error::other(
            "grace-wait watcher cancelled (runtime shutting down)",
        ))),
        Err(e) => {
            debug_assert!(false, "unknown JoinError variant: {e:?}");
            Err(Error::Io(std::io::Error::other(e)))
        }
    }
}

/// Resolve when the process exits (no internal timeout — the caller bounds it).
#[cfg(target_os = "linux")]
async fn exit_watch(id: ProcessId) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    let Some(pidfd) = crate::wait::backend::open_verified(id)? else {
        return Ok(());
    };
    // The pidfd becomes readable (POLLIN) when the task becomes a zombie; POLLHUP once
    // reaped. Either readiness is terminal. A registration failure here (reactor at
    // capacity, etc.) is a genuine I/O error; a MISSING IO driver panics inside tokio
    // instead (documented on the graceful methods).
    let afd = AsyncFd::with_interest(pidfd, Interest::READABLE | Interest::ERROR).map_err(Error::Io)?;
    // ready() may complete with an empty/unclassified set (tokio's documented false
    // positive) — the same re-await discipline as the macOS watch_readable loop.
    loop {
        let mut guard = afd.ready(Interest::READABLE | Interest::ERROR).await.map_err(Error::Io)?;
        match classify_pidfd_ready(guard.ready()) {
            Some(verdict) => return verdict,
            None => guard.clear_ready(), // false-positive wake — re-await
        }
    }
}

/// Map a pidfd readiness to the watch verdict; `None` = unclassified readiness (tokio's
/// documented `ready()` false positive) — re-await: never a false "exited" (which would skip
/// escalation on a live child) and never a false watch failure (which would force-kill a
/// gracefully-exiting child). Factored out so the POLLERR branch and the readiness contract
/// are unit-testable with synthetic `Ready` values — a real pidfd cannot be made to surface
/// POLLERR on demand.
#[cfg(target_os = "linux")]
fn classify_pidfd_ready(ready: ::tokio::io::Ready) -> Option<Result<(), Error>> {
    // Mirror the sync backend: POLLERR is an error; POLLIN (zombie) / POLLHUP (reaped) = exited.
    if ready.is_error() {
        return Some(Err(Error::Io(std::io::Error::other("pidfd poll returned POLLERR"))));
    }
    if ready.is_readable() || ready.is_read_closed() {
        return Some(Ok(()));
    }
    None
}

/// Resolve when the process exits (no internal timeout — the caller bounds it).
#[cfg(target_os = "macos")]
async fn exit_watch(id: ProcessId) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    let Some(kq) = crate::wait::backend::arm_proc_exit(id)? else {
        return Ok(());
    };
    let afd = AsyncFd::with_interest(KqueueFd(kq), Interest::READABLE).map_err(Error::Io)?;
    watch_readable(&afd, crate::wait::backend::drain_proc_exit).await
}

/// `AsyncFd` requires `AsRawFd`; nix's `Kqueue` exposes only `AsFd` — delegate.
#[cfg(target_os = "macos")]
struct KqueueFd(nix::sys::event::Kqueue);
#[cfg(target_os = "macos")]
impl std::os::fd::AsRawFd for KqueueFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsFd;
        self.0.as_fd().as_raw_fd()
    }
}

/// The readiness/drain loop, parameterized over the drain so the re-await cycle is testable
/// against the REAL `AsyncFd` (see `wait_tests`). Exit is concluded only on a drained event;
/// `clear_ready` only after an EMPTY drain — mio's edge-triggered (`EV_CLEAR`) would-block
/// contract.
#[cfg(target_os = "macos")]
async fn watch_readable<F>(afd: &::tokio::io::unix::AsyncFd<KqueueFd>, mut drain: F) -> Result<(), Error>
where
    F: FnMut(&nix::sys::event::Kqueue) -> Result<Option<()>, Error>,
{
    loop {
        let mut guard = afd.readable().await.map_err(Error::Io)?;
        match drain(&afd.get_ref().0)? {
            Some(()) => return Ok(()),
            None => guard.clear_ready(), // no exit drained — re-await
        }
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
```

NOTE for the implementer: WSL compile+test covers Linux; macOS is CI-only — its safety rests on
the arm/drain primitives being SHARED with the sync backend (Step 2b), so the async arm adds
only the AsyncFd registration + the spurious-readiness loop.

- [ ] **Step 5: Run to verify pass (host = Windows arm)**

Run: `cargo test --locked --features tokio --lib wait_tests`
Expected: PASS (6 tests: the 4 grace_wait paths through the event-cancellable blocking arm + the pre-signaled and mid-wait cancel release tests).

- [ ] **Step 6: WSL run (Linux AsyncFd arm — the real gate)**

Run the WSL command from Global Constraints, plus `cargo test --locked --features tokio --lib wait_tests` inside it.
Expected: PASS (7 tests: the 4 grace_wait paths through pidfd/AsyncFd + the 3 Linux-gated `classify` tests; the `watch_loop` composition test is macOS CI-only).

- [ ] **Step 7: Full regression + lint**

Run: `cargo test --locked --features tokio && cargo test --locked && cargo +stable fmt --check && cargo clippy --locked --features tokio --all-targets && cargo clippy --locked --all-targets`
Expected: all green, zero warnings.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src/wait/linux.rs src/wait/macos.rs src/wait/macos_tests.rs src/wait/windows.rs src/tokio.rs src/tokio/wait.rs src/tokio/wait_tests.rs
git commit -m "feat: reactor-native async grace-wait (AsyncFd pidfd / kqueue; Windows spawn_blocking fallback)"
```

---

### Task 3: The async graceful trio (`terminate`, `graceful_shutdown`, `graceful_shutdown_tree`)

**Files:**
- Create: `src/tokio/child/graceful.rs`
- Create: `src/tokio/child/graceful_tests.rs` + `src/child/graceful_tests.rs` (watch-failure ordering twins)
- Modify: `src/tokio/child.rs` (declare the submodule)
- Modify: `src/child/graceful.rs` (sync twins, lone + tree: escalate-then-surface on a watch error)
- Modify: `src/wait.rs` (shared watch fault seam + `block_until_exit` seam head)
- Modify: `src/child/lifecycle.rs` (`wait_timeout` seam head — the sync lone path's watch)
- Modify: `src/tokio/wait.rs` (seam heads in both `grace_wait` arms)
- Modify: `testbin/main.rs` (add the `spawn-grandchild-ignore-term` + `spawn-grandchild-stubborn-child` modes)
- Modify: `tests/tokio_control.rs` (append the graceful tests)
- Modify: `tests/common/mod.rs` (generalize the sync tree spawner to `spawn_tree(mode, contain)`)
- Modify: `tests/graceful.rs` (sync twin of the survivor-sweep scenario — suite parity)
- Modify: `TODO.md`

**Interfaces:**
- Consumes (from Tasks 1–2): `Child::{kill(&mut self), kill_tree(&mut self), terminate_tree(&self)}`, private `Child::require_contained(&self)`, `crate::tokio::wait::grace_wait(ProcessId, Duration) -> Result<bool, Error>`, `spawn_control_async`, `spawn_tree_async`. Existing: `wait::terminate(ProcessId)`, `Child::{id(), wait().await}`.
- Produces: `Child::terminate(&self) -> Result<(), Error>`, `async Child::graceful_shutdown(&mut self, Duration) -> Result<ExitStatus, Error>`, `async Child::graceful_shutdown_tree(&mut self, Duration) -> Result<ExitStatus, Error>`; testbin modes `spawn-grandchild-ignore-term` + `spawn-grandchild-stubborn-child` + `control-block-ack-term`; sync test helper `spawn_tree(mode: &str, contain: bool) -> (subprocess::Child, Vec<TcpStream>)`.

- [ ] **Step 1: Add the testbin mode** — in `testbin/main.rs`, after the `spawn-grandchild-escapee` arm:

```rust
        #[cfg(unix)]
        "spawn-grandchild-ignore-term" => {
            // spawn-grandchild where BOTH members ignore SIGTERM: the group's soft signal
            // provably kills neither, so only a tree escalation's hard sweep tears them down.
            // SAFETY: installing SIG_IGN for SIGTERM has no preconditions and is always safe.
            unsafe {
                let _ = libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: see spawn-grandchild
            let _gc = std::process::Command::new(exe)
                .args(["control-block-ignore-term", &addr, "G"])
                .spawn()
                .unwrap();
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(unix)]
        "control-block-ack-term" => {
            // Like control-block-ignore-term, but the SIGTERM handler ACKS by writing "T" to
            // the control socket and returns — the process stays alive, so SIGKILL remains
            // its only terminating signal AND signal delivery is observable as a real event.
            use std::os::fd::AsRawFd;
            static SOCK_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
            extern "C" fn ack(_sig: libc::c_int) {
                let fd = SOCK_FD.load(std::sync::atomic::Ordering::Relaxed);
                if fd >= 0 {
                    // SAFETY: write(2) is async-signal-safe; the fd outlives the handler.
                    unsafe { libc::write(fd, b"T".as_ptr().cast(), 1) };
                }
            }
            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            SOCK_FD.store(sock.as_raw_fd(), std::sync::atomic::Ordering::Relaxed);
            // SAFETY: the handler only calls async-signal-safe write(2).
            unsafe {
                let _ = libc::signal(libc::SIGTERM, ack as libc::sighandler_t);
            }
            sock.write_all(tag.as_bytes()).unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            // Retry EINTR: the SIGTERM interrupts this read on platforms without SA_RESTART.
            loop {
                match sock.read(&mut buf) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    _ => break,
                }
            }
        }
        #[cfg(unix)]
        "spawn-grandchild-stubborn-child" => {
            // spawn-grandchild where only the GRANDCHILD ignores SIGTERM: the group's soft
            // signal kills the root (default disposition) but leaves the grandchild — a
            // survivor only the post-grace hard sweep can reach.
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: see spawn-grandchild
            let _gc = std::process::Command::new(exe)
                .args(["control-block-ignore-term", &addr, "G"])
                .spawn()
                .unwrap();
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
```

and the Windows analogues (a CTRL_BREAK-ignoring pair, so the Windows hard sweep can be proven
load-bearing). Helper above `main`:

```rust
#[cfg(windows)]
fn install_ignore_break() {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn ignore(_event: u32) -> BOOL {
        BOOL(1) // handled — do not die
    }
    // SAFETY: installing a console ctrl handler has no preconditions.
    unsafe { SetConsoleCtrlHandler(Some(ignore), true) }.expect("install ctrl handler");
}
```

and the two arms (same shape as the unix ignore-term pair):

```rust
        #[cfg(windows)]
        "control-block-ignore-break" => {
            // Ignore CTRL_BREAK, then behave exactly like control-block — only a hard kill ends us.
            install_ignore_break();
            let addr = &args[2];
            let tag = args.get(3).map(String::as_str).unwrap_or("?");
            let mut sock = std::net::TcpStream::connect(addr).unwrap();
            sock.write_all(tag.as_bytes()).unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
        #[cfg(windows)]
        "spawn-grandchild-ignore-break" => {
            // spawn-grandchild where BOTH members ignore CTRL_BREAK: whether or not the soft
            // group signal reaches this console group, only the hard sweep tears them down.
            install_ignore_break();
            let addr = args[2].clone();
            let exe = std::env::current_exe().unwrap();
            #[allow(clippy::zombie_processes)] // intentional: see spawn-grandchild
            let _gc = std::process::Command::new(exe)
                .args(["control-block-ignore-break", &addr, "G"])
                .spawn()
                .unwrap();
            let mut sock = std::net::TcpStream::connect(&addr).unwrap();
            sock.write_all(b"R").unwrap();
            sock.flush().unwrap();
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf);
        }
```

(`windows` crate + the `Win32_System_Console` feature are already dependencies. If the
`SetConsoleCtrlHandler` signature differs in windows 0.62, adjust the call — the contract is
only "install a handler that returns TRUE".)

- [ ] **Step 2: Write the failing tests** — append to `tests/tokio_control.rs`:

```rust
// Graceful-escalation trio (mirrors tests/graceful.rs child_* cases, async) =====

#[cfg(unix)]
#[tokio::test]
async fn async_terminate_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    let (mut child, mut sock) = common::spawn_blocker_async();
    child.terminate().expect("terminate sends SIGTERM");
    expect_eof("blocker", &mut sock);
    let status = child.wait().await.expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "control-block must die by SIGTERM, got {status:?}");
}

#[cfg(windows)]
#[tokio::test]
async fn async_terminate_unsupported_on_windows() {
    let (mut child, mut sock) = common::spawn_blocker_async();
    let err = child.terminate().expect_err("lone graceful terminate has no Windows primitive");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await;
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_graceful_path() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // control-block dies on default-disposition SIGTERM. The long grace is the safety bound on
    // a child that exits promptly — never the synchronization; correctness is the exit signal.
    let (mut child, mut sock) = common::spawn_blocker_async();
    let status = child.graceful_shutdown(Duration::from_secs(30)).await.expect("graceful_shutdown");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "graceful path must exit via SIGTERM, got {status:?}");
    expect_eof("blocker", &mut sock);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_escalates() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // SIG_IGN child + Duration::ZERO: provably alive at the single poll → deterministic
    // escalation; SIGKILL is the only terminating signal it can receive.
    let (mut child, mut sock) = common::spawn_control_async("control-block-ignore-term", &["R"], false);
    let status = child.graceful_shutdown(Duration::ZERO).await.expect("graceful_shutdown escalates");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "SIGTERM-ignoring child must be force-killed, got {status:?}");
    expect_eof("blocker", &mut sock);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_cancel_mid_grace_leaves_child_owned() {
    use std::future::Future;
    use std::time::Duration;
    // The documented cancellation contract: dropping the graceful future mid-grace cancels
    // the watch and performs no further signalling. Deterministic, no timers: poll the future
    // exactly ONCE (that sends SIGTERM and arms the watch), then drop it. The acking child's
    // handler returns without exiting, so nothing escalated => it must still be alive.
    let (mut child, mut sock) = common::spawn_control_async("control-block-ack-term", &["R"], false);
    {
        // Duration::MAX: the watch cannot time out, the SIGTERM-acking (never-exiting) child
        // cannot exit on the soft signal, and nothing escalates before the drop — so the
        // single poll (which sends SIGTERM and parks in the grace-wait) can resolve Ready
        // only through a genuine watch failure. Not asserted away as a race: a Ready is
        // surfaced loudly with its value.
        let mut fut = std::pin::pin!(child.graceful_shutdown(Duration::MAX));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("graceful future resolved at first poll instead of parking: {r:?}");
        }
        // The ack byte proves the single poll actually DELIVERED the SIGTERM (a real event,
        // not an assumption about await points) while the future is still parked.
        let mut ack = [0u8; 1];
        sock.read_exact(&mut ack).expect("SIGTERM ack");
        assert_eq!(&ack, b"T", "child must ack the SIGTERM sent by the first poll");
    } // <- future dropped mid-grace here
    // is_alive is THE non-escalation discriminator: this child can only die by SIGKILL (its
    // SIGTERM handler acks and returns), so its terminating signal cannot distinguish our
    // kill from an escalation — being alive here proves the cancelled graceful sent nothing
    // further.
    assert!(child.is_alive(), "cancelled graceful must not have escalated");
    child.kill().expect("explicit teardown after cancel");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await.expect("reap");
}

#[cfg(windows)]
#[tokio::test]
async fn async_graceful_tree_cancel_does_not_escalate_on_windows() {
    use std::future::Future;
    use std::time::Duration;
    // The Windows non-escalation discriminator (this is the only Windows grace_wait entry):
    // BOTH members ignore CTRL_BREAK, so after poll-once + drop the root can only be dead if
    // something escalated — being alive proves the cancelled graceful sent nothing further.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-break", |cmd| {
        cmd.contain();
    });
    {
        // Duration::MAX: the blocking watch cannot time out, the ignore-break members cannot
        // exit on the soft signal, and the cancel event is unsignaled until the drop — so a
        // first-poll Ready can only be a genuine watch failure, surfaced loudly with its
        // value. The drop's guarantee is observable, not timing-based: SignalOnDrop fires,
        // and the runtime-shutdown join (see the note at the end) would hang loudly if the
        // release failed.
        let mut fut = std::pin::pin!(child.graceful_shutdown_tree(Duration::MAX));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("graceful future resolved at first poll instead of parking: {r:?}");
        }
    } // <- future dropped mid-grace here
    assert!(child.is_alive(), "cancelled tree graceful must not have escalated");
    child.kill_tree().expect("explicit sweep after cancel");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
    let _ = child.wait().await.expect("reap after cancelled graceful");
    // End-to-end release proof rides on test teardown: the #[tokio::test] runtime's drop
    // JOINS blocking tasks, so if the dropped guard's cancel event failed to release the
    // Duration::MAX watcher, this test would hang at shutdown — loudly, at the harness bound.
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_tree_cancel_does_not_escalate() {
    use std::future::Future;
    use std::time::Duration;
    // The tree-path non-escalation discriminator: BOTH members ignore SIGTERM, so after
    // poll-once + drop the root can only be dead if something escalated — being alive proves
    // the cancelled graceful sent nothing further.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-term", |cmd| {
        cmd.contain();
    });
    {
        // Duration::MAX + SIGTERM-ignoring members: the single poll (group signal + park in
        // the grace-wait) can resolve Ready only through a genuine watch failure — surfaced
        // loudly with its value.
        let mut fut = std::pin::pin!(child.graceful_shutdown_tree(Duration::MAX));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("graceful future resolved at first poll instead of parking: {r:?}");
        }
    }
    assert!(child.is_alive(), "cancelled tree graceful must not have escalated");
    child.kill_tree().expect("explicit sweep after cancel");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
    let _ = child.wait().await.expect("reap");
}

#[cfg(windows)]
#[tokio::test]
async fn async_graceful_shutdown_tree_sweep_is_load_bearing_on_windows() {
    use std::time::Duration;
    // BOTH members ignore CTRL_BREAK, so whether or not the soft signal reaches this console
    // group, only the ZERO-grace hard sweep can tear the tree down.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-break", |cmd| {
        cmd.contain();
    });
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("tree escalates");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
}

#[cfg(windows)]
#[tokio::test]
async fn async_graceful_shutdown_unsupported_on_windows() {
    use std::time::Duration;
    let (mut child, mut sock) = common::spawn_blocker_async();
    let err = child
        .graceful_shutdown(Duration::from_secs(1))
        .await
        .expect_err("no Windows lone graceful");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await;
}

#[tokio::test]
async fn async_graceful_shutdown_tree_tears_down_tree() {
    use std::time::Duration;
    // A contained 2-level tree: the group's graceful signal (SIGTERM / CTRL_BREAK) plus the
    // hard sweep tear down BOTH members; both sockets EOF. All OSes.
    let (mut child, mut root, mut grand) = common::spawn_grandchild_async(true);
    child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("tree graceful");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_tree_graceful_root_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // A contained root that honors SIGTERM: the group signal makes it exit; the reaped status
    // is SIGTERM (15), not escalated.
    let (mut child, mut sock) = common::spawn_control_async("control-block", &["R"], true);
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("tree graceful");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "root must exit via SIGTERM, got {status:?}");
    expect_eof("root", &mut sock);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_tree_escalates_with_surviving_grandchild() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // BOTH tree members ignore SIGTERM (spawn-grandchild-ignore-term), so with ZERO grace both
    // are provably alive when the grace elapses — the hard sweep, not the soft signal, must
    // tear down the root AND the surviving grandchild.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-term", |cmd| {
        cmd.contain();
    });
    let status = child.graceful_shutdown_tree(Duration::ZERO).await.expect("tree escalates");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "ignored SIGTERM must escalate to SIGKILL, got {status:?}");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_tree_sweeps_survivor_after_graceful_root_exit() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // The exact case the sweep-before-reap invariant protects: the root honors the group
    // SIGTERM and exits within the grace, but the grandchild ignores it and survives — only
    // the post-grace hard sweep (running while the unreaped root still pins the group id)
    // can tear it down. The root's status stays SIGTERM: the sweep no-ops on the dead root.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-stubborn-child", |cmd| {
        cmd.contain();
    });
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("tree graceful with survivor");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "root must exit via SIGTERM (graceful), got {status:?}");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
}

#[tokio::test]
async fn async_graceful_tree_unsupported_when_uncontained() {
    use std::time::Duration;
    let (mut child, mut sock) = common::spawn_blocker_async();
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(1))
        .await
        .expect_err("uncontained tree graceful");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await;
}
```

- [ ] **Step 2b: The sync twin (suite parity)** — the sync suite shares the survivor-scenario
gap, and the recorded parity harness requires scenario alignment. In `tests/common/mod.rs`,
generalize the sync tree spawner over the testbin mode (its doc comment's death-proof contract
moves along; `spawn_grandchild` becomes a delegation, mirroring the async single-primitive
shape):

```rust
/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R" + one grandchild
/// tag "G"), optionally contained, and return the owned `Child` plus BOTH accepted sockets (the
/// two tag reads prove the 2-level tree is alive). The tree dies — and both sockets EOF — only
/// when the whole tree is torn down, so callers prove teardown by reading EOF on both, never by
/// a timer.
pub fn spawn_tree(mode: &str, contain: bool) -> (subprocess::Child, Vec<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = subprocess::Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", mode, addr.as_str()]);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn tree");
    // Demux by tag exactly like spawn_tree_async (accept order is not guaranteed, and a
    // duplicate or foreign tag is a harness bug worth failing loudly on).
    let (mut root, mut grand) = (None, None);
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match &tag {
            b"R" => root = Some(s),
            b"G" => grand = Some(s),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (child, vec![root.expect("root R connected"), grand.expect("grandchild G connected")])
}

/// Spawn the `spawn-grandchild` helper tree.
pub fn spawn_grandchild(contain: bool) -> (subprocess::Child, Vec<TcpStream>) {
    spawn_tree("spawn-grandchild", contain)
}
```

and append the twin to `tests/graceful.rs` (after `child_graceful_shutdown_tree_escalates`):

```rust
#[cfg(unix)]
#[test]
fn child_graceful_shutdown_tree_sweeps_survivor_after_graceful_root_exit() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // The exact case the sweep-before-reap invariant protects: the root honors the group
    // SIGTERM and exits within the grace, but the grandchild ignores it and survives — only
    // the post-grace hard sweep (running while the unreaped root still pins the group id)
    // can tear it down. The root's status stays SIGTERM: the sweep no-ops on the dead root.
    let (child, mut socks) = common::spawn_tree("spawn-grandchild-stubborn-child", true);
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect("tree graceful with survivor");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "root must exit via SIGTERM (graceful), got {status:?}"
    );
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test --locked --features tokio --test tokio_control`
Expected: COMPILE FAIL — `no method named terminate/graceful_shutdown/graceful_shutdown_tree`.

- [ ] **Step 4: Implement** — declare the submodule in `src/tokio/child.rs` next to the existing test-module declaration at the bottom:

```rust
#[path = "child/graceful.rs"]
mod graceful;
```

and create `src/tokio/child/graceful.rs`:

```rust
//! Async `Child` graceful shutdown — the soft-then-hard escalation trio. A submodule of
//! `child` (mirroring the sync `src/child/graceful.rs`) so it can reach `Child`'s private
//! `require_contained` and fields.

use std::process::ExitStatus;
use std::time::Duration;

use super::Child;
use crate::error::Error;

impl Child {
    /// Send `SIGTERM` to the (lone) child — a cooperative request to exit. Signal-only: does
    /// not wait or reap. Identity-bound, so it cannot race a concurrent reap onto a recycled
    /// pid. Unix only — Windows has no per-process graceful signal and returns `Unsupported`
    /// (use [`graceful_shutdown_tree`](Child::graceful_shutdown_tree) for a contained child).
    pub fn terminate(&self) -> Result<(), Error> {
        crate::wait::terminate(self.id())
    }

    /// Cooperative-then-forced lone shutdown: `SIGTERM`, wait up to `grace` for the child to
    /// exit, then `SIGKILL` if it has not — reaping either way and returning its `ExitStatus`.
    /// The status's terminating signal distinguishes a graceful exit from a forced one —
    /// best-effort at the boundary: a child that exits of its own accord between the grace
    /// elapsing and the `SIGKILL` landing reports its own status.
    /// Escalation proceeds even if the child ignores `SIGTERM`. Unix only; Windows returns
    /// `Unsupported`. `grace` is relative; `Duration::ZERO` signals, polls once, then escalates.
    ///
    /// Dropping this future mid-grace cancels the exit watch (the `AsyncFd` deregisters and
    /// the fd closes) and performs no further signalling — the child stays owned, and
    /// `Drop`'s teardown still applies.
    ///
    /// A watch failure does not strand the child between the soft signal and the escalation:
    /// the kill and reap still run (an unobservable grace escalates immediately), and the
    /// watch error is surfaced afterward. If the escalation itself fails, its error wins and
    /// the child stays owned (`Drop`'s teardown still applies).
    ///
    /// # Runtime
    ///
    /// Needs a runtime with the IO **and** time drivers enabled (the `#[tokio::main]` /
    /// `#[tokio::test]` defaults) — on a hand-built runtime missing either, tokio panics
    /// rather than returning a typed error.
    pub async fn graceful_shutdown(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        crate::wait::terminate(self.id())?;
        // A watch failure must not strand the child between the soft signal and the
        // escalation — kill and reap still run (grace unobservable => escalate now); the
        // watch error surfaces only after they succeed (a kill/reap error wins — deliberate
        // subsumption, mirroring kill_tree's both-fail disposition).
        let watch = crate::tokio::wait::grace_wait(self.id(), grace).await;
        if !matches!(watch, Ok(true)) {
            self.kill()?; // escalate; an Err returns HERE, subsuming any watch Err
        }
        let status = self.wait().await?;
        watch?;
        Ok(status)
    }

    /// Cooperative-then-forced shutdown of the contained tree: send the group its graceful
    /// signal (`SIGTERM` via `killpg`/cgroup, or `CTRL_BREAK` to the job/console group), wait
    /// up to `grace` for the **root** to exit, then hard-sweep any survivors and reap the root.
    /// Returns the root's `ExitStatus`. Requires an actionable containment mechanism (errors
    /// `Unsupported` otherwise — use [`graceful_shutdown`](Child::graceful_shutdown) for a lone
    /// child). Works on all platforms.
    ///
    /// The grace-wait is **non-reaping** (watches the root's exit without collecting it), so the
    /// subsequent hard sweep runs while the root's pid — and thus the `killpg` group id — is
    /// still valid; reaping first could let `killpg` hit a recycled group. The sweep is
    /// unconditional but a no-op once the tree has drained, so a graceful exit's status is
    /// preserved (the lone backstop no-ops on the already-dead root).
    ///
    /// Dropping this future mid-grace cancels the exit watch (on all platforms — the Windows
    /// watcher is released via its cancel event) and performs no further signalling — the
    /// child stays owned, and `Drop`'s teardown still applies.
    ///
    /// A grace-watch failure does not strand the tree between the soft signal and the sweep:
    /// the hard sweep and reap still run (an unobservable grace escalates immediately), and
    /// the watch error is surfaced afterward. A sweep failure supersedes even a graceful root
    /// exit — survivors may remain, so its error wins: a root whose exit was already observed
    /// is still reaped first; on a live root the error propagates unreaped (the child stays
    /// owned, `Drop`'s teardown applies).
    ///
    /// # Runtime
    ///
    /// On Unix, needs a runtime with the IO **and** time drivers enabled (the
    /// `#[tokio::main]` / `#[tokio::test]` defaults) — missing either, tokio panics rather
    /// than returning a typed error. On Windows the grace-wait runs on the blocking pool:
    /// each in-flight call occupies one blocking-pool thread for up to `grace` — size the
    /// pool accordingly for many long concurrent shutdowns.
    pub async fn graceful_shutdown_tree(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        // terminate_tree's own require_contained guard fires before any signal, so an
        // uncontained child errors up front.
        self.terminate_tree()?;
        // Watch-Err ordering: sweep + reap first, then surface (see graceful_shutdown above).
        let watch = crate::tokio::wait::grace_wait(self.id(), grace).await;
        // The sweep is unconditional — a gracefully-exited root does NOT mean the descendants
        // drained (the survivor-sweep scenario). A sweep Err subsumes any watch Err; it must
        // propagate before the reap on a LIVE root (waiting unswept would hang), but once the
        // root's exit was observed, the reap runs first so no zombie is stranded.
        if let Err(sweep) = self.kill_tree() {
            if matches!(watch, Ok(true)) {
                // The root is a zombie — this reap cannot hang. The sweep Err stays the
                // verdict either way: a reap Err here must not mask the live-survivors failure.
                let _ = self.wait().await;
            }
            return Err(sweep);
        }
        let status = self.wait().await?;
        watch?;
        Ok(status)
    }
}
```

- [ ] **Step 4b: Watch-failure ordering — both paths, both surfaces.** Mirror the async
ordering (escalate-then-surface on a watch `Err`) into the sync twins, and make all four
sites testable via a shared watch fault seam (take-semantics pattern).

In `src/child/graceful.rs`, both methods' docs gain the same watch-failure paragraph as their
async twins, the lone doc gains the same boundary caveat (a self-exit between the grace
elapsing and the `SIGKILL` reports its own status), the tree doc gains the
sweep-failure-supersedes sentence, and the bodies become:

```rust
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<ExitStatus, Error> {
        crate::wait::terminate(self.id)?; // SIGTERM (Windows: Unsupported, early return)
        // A watch failure must not strand the child between the soft signal and the
        // escalation — kill and reap still run (grace unobservable => escalate now); the
        // watch error surfaces only after they succeed (a kill/reap error wins — deliberate
        // subsumption, mirroring kill_tree's both-fail disposition).
        let watch = self.wait_timeout(grace);
        if let Ok(Some(status)) = &watch {
            return Ok(*status); // exited within grace (already reaped by wait_timeout)
        }
        self.shared.kill().map_err(Error::Io)?; // an Err returns HERE, subsuming any watch Err
        let status = self.wait()?;
        watch?;
        Ok(status)
    }

    pub fn graceful_shutdown_tree(&self, grace: Duration) -> Result<ExitStatus, Error> {
        // Fail fast before sending any signal. terminate_tree/kill_tree re-check this guard
        // internally; the redundancy is intentional so an uncontained child errors up front.
        self.require_contained()?;
        self.terminate_tree()?; // group SIGTERM / CTRL_BREAK (signal-only)
        // Watch-Err ordering: sweep + reap first, then surface (see graceful_shutdown above).
        let watch = crate::wait::block_until_exit(self.id, Some(grace)); // NON-reaping grace-wait on root
        // The sweep is unconditional — a gracefully-exited root does NOT mean the descendants
        // drained (the survivor-sweep scenario). A sweep Err subsumes any watch Err; it must
        // propagate before the reap on a LIVE root (waiting unswept would hang), but once the
        // root's exit was observed, the reap runs first so no zombie is stranded.
        if let Err(sweep) = self.kill_tree() {
            if matches!(watch, Ok(true)) {
                // The root is a zombie — this reap cannot hang. The sweep Err stays the
                // verdict either way: a reap Err here must not mask the live-survivors failure.
                let _ = self.wait();
            }
            return Err(sweep);
        }
        let status = self.wait()?;
        watch?;
        Ok(status)
    }
```

In `src/wait.rs`, add the shared seam and consume it at the head of `block_until_exit`:

```rust
/// Force the NEXT grace-watch on THIS thread to fail (consumed by `block_until_exit`,
/// `Child::wait_timeout`, and `tokio::wait::grace_wait`), so the watch-error escalation
/// ordering is testable. Same take-semantics contract as the treewalk fault seam.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    thread_local! {
        static FORCE_WATCH_ERROR: Cell<bool> = const { Cell::new(false) };
    }
    pub(crate) fn set_force_watch_error(on: bool) {
        FORCE_WATCH_ERROR.with(|f| f.set(on));
    }
    pub(crate) fn take_force_watch_error() -> bool {
        FORCE_WATCH_ERROR.with(|f| f.replace(false))
    }
    pub(crate) fn armed() -> bool {
        FORCE_WATCH_ERROR.with(|f| f.get())
    }
    pub(crate) fn forced_watch_error() -> crate::error::Error {
        crate::error::Error::Io(std::io::Error::other("forced grace-watch failure (test seam)"))
    }
}
```

```rust
pub(crate) fn block_until_exit(id: ProcessId, timeout: Option<Duration>) -> Result<bool, Error> {
    #[cfg(test)]
    if fault::take_force_watch_error() {
        return Err(fault::forced_watch_error());
    }
    // ... existing body unchanged ...
```

and the same 4-line head goes at the top of BOTH cfg arms of `grace_wait` in
`src/tokio/wait.rs` (via `crate::wait::fault::...` — the async fn body runs on the arming
thread, so take semantics hold under the current-thread `#[tokio::test]` runtime) AND at the
top of `Child::wait_timeout` in `src/child/lifecycle.rs` (the sync LONE path's watch goes
through shared_child's `wait_deadline`, not `block_until_exit`, so it needs its own seam
head).

Tests — create `src/child/graceful_tests.rs` (declare at the bottom of `src/child/graceful.rs`
with `#[cfg(test)] #[path = "graceful_tests.rs"] mod graceful_tests;`):

```rust
//! Unit tests for the graceful trio's watch-failure ordering (the fault seam is pub(crate),
//! unreachable from tests/).

use std::time::Duration;

use crate::wait::fault;

// A watch failure must not strand the tree between the soft signal and the hard sweep: the
// sweep and reap still run, then the watch error surfaces. The reap is proven by identity on
// LINUX, where /proc keeps a zombie exists()-visible; macOS's proc_pidinfo does not see
// zombies (identity.rs), so the assert is Linux-gated — the ordering under test is the same
// straight-line body everywhere, and Linux pins it.
#[test]
fn graceful_tree_watch_error_still_sweeps_and_reaps() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect_err("the watch error must surface");
    assert!(!fault::armed(), "seam not consumed — the watch did not run on this thread");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    #[cfg(target_os = "linux")]
    assert!(!id.exists(), "root must be swept AND reaped despite the watch error (on Linux a zombie would still exist)");
    let status = child.wait().expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

// The LONE-path twin of the same invariant (Unix-gated: graceful_shutdown is Unsupported on
// Windows before the watch runs). With the old `wait_timeout(grace)?` shape the child would
// die by our SIGTERM but stay a zombie — `exists()` catches exactly that on Linux (macOS's
// proc_pidinfo does not see zombies, so the assert is Linux-gated).
#[cfg(unix)]
#[test]
fn graceful_lone_watch_error_still_escalates_and_reaps() {
    let mut cmd = crate::Command::new();
    cmd.args(["sleep", "30"]);
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
        .expect_err("the watch error must surface");
    assert!(!fault::armed(), "seam not consumed — the watch did not run on this thread");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    #[cfg(target_os = "linux")]
    assert!(!id.exists(), "child must be killed AND reaped despite the watch error (on Linux a zombie would still exist)");
    let status = child.wait().expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "escalated child cannot report success, got {status:?}");
}
```

and its async twin `src/tokio/child/graceful_tests.rs` (declared the same way at the bottom of
`src/tokio/child/graceful.rs`):

```rust
//! Async twin of `child/graceful_tests.rs` — watch-failure ordering via the shared seam.

use std::time::Duration;

use crate::wait::fault;

#[tokio::test]
async fn async_graceful_tree_watch_error_still_sweeps_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(!fault::armed(), "seam not consumed — the watch did not run on this thread");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    #[cfg(target_os = "linux")]
    assert!(!id.exists(), "root must be swept AND reaped despite the watch error (on Linux a zombie would still exist)");
    let status = child.wait().await.expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_lone_watch_error_still_escalates_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sleep", "30"]);
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(!fault::armed(), "seam not consumed — the watch did not run on this thread");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    #[cfg(target_os = "linux")]
    assert!(!id.exists(), "child must be killed AND reaped despite the watch error (on Linux a zombie would still exist)");
    let status = child.wait().await.expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "escalated child cannot report success, got {status:?}");
}
```

(The `!id.exists()` reap discriminator is LINUX-only: Windows has no zombie state, and
macOS's proc_pidinfo does not see zombies either — on both, the assert would pass vacuously
even if the reap were skipped, so it is gated to the one platform where it discriminates.
The ordering under test is the same platform-independent source line everywhere; Linux pins
it. On the happy paths all four bodies behave exactly as before.)

Run: `cargo test --locked --lib graceful_tests && cargo test --locked --features tokio --lib graceful`
Expected: PASS (2 sync stranding tests; sync + async with the feature).

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --locked --features tokio --test tokio_control`
Expected: PASS (Windows host: Unix-gated cases skipped; the two `windows`-gated `Unsupported` cases plus both all-OS tree cases run).

- [ ] **Step 6: Update `TODO.md`** — the Plan-10 deferrals below are the USER's recorded scope
decisions, not implementer choices: the owned-control/foreign split is the user's Plan-9
scoping answer (2026-07-05, "Split: owned control first, foreign next"), and the fd ≥ 3 /
merge-into-pipe deferrals carry over verbatim from the Plan-8 TODO approved at the 2026-07-05
squash-merge of Plan 8; the user re-confirmed this full deferral list on 2026-07-13. Replace
the "Lifecycle / async (from Plan 8)" section body with exactly:

```markdown
The async mirror shipped as an I/O foundation only; remaining items deferred to Plan 10:

- [x] (Plan 9) Async `contain_with`/`nesting` builder modes.
- [ ] Async parent-end access for fd ≥ 3 via `AsyncFd` (the async API rejects fd ≥ 3 at spawn).
- [ ] Async merge-into-a-piped-target (rejected as `Unsupported`, mirroring the foundation subset).
- [x] (Plan 9) Async explicit control: `kill`/`kill_tree`/`terminate_tree` + the graceful trio
      (`terminate`/`graceful_shutdown`/`graceful_shutdown_tree`), on a reactor-native grace-wait
      (`AsyncFd` pidfd / kqueue; Windows: event-cancellable blocking wait — no pollable
      process handle).
- [ ] Async foreign `Process` (introspect/wait/kill on a non-owned process).
```

- [ ] **Step 7: Full regression + lint**

Run: `cargo test --locked --features tokio && cargo test --locked && cargo test --locked --release && cargo +stable fmt --check && cargo clippy --locked --features tokio --all-targets && cargo clippy --locked --all-targets`
Expected: all green, zero warnings. Then the WSL run from Global Constraints — the escalation, cancellation, and surviving-grandchild tests are Unix-only, so WSL is their real gate.

- [ ] **Step 8: Commit**

```bash
git add src/tokio/child.rs src/tokio/child/graceful.rs src/tokio/child/graceful_tests.rs src/child/graceful.rs src/child/graceful_tests.rs src/child/lifecycle.rs src/wait.rs src/tokio/wait.rs testbin/main.rs tests/tokio_control.rs tests/common/mod.rs tests/graceful.rs TODO.md
git commit -m "feat: async graceful-escalation trio (terminate / graceful_shutdown / graceful_shutdown_tree) on the reactor-native grace-wait"
```

---

## Panel dispositions (settled — re-raise only with new evidence)

Each decline names its disproof or the settled decision it would re-litigate.

- **`kill_tree` both-fail `.and` subsumption** — USER-DISPOSITIONED 2026-07-13, accepted
  as-is: byte-for-byte mirror of the shipped sync `Child::kill_tree` (`src/child.rs:122-130`);
  the precedence is stated in both rustdocs; the crate has no logging facility, a both-fail
  `debug_assert` would panic on a legitimate environmental double-failure, and a multi-cause
  `Error` variant is a public-API change outside Plan 9's scope. This disposition EXTENDS to
  the analogous subsumption sites in the graceful bodies (lone `kill()?`/watch, tree
  `kill_tree` Err/watch, and the sweep-over-reap precedence on an exited root) — each is
  marked by an inline comment citing this precedent (round-16 confirmation).
- **`terminate_tree` TreeWalk best-effort observability** — USER-DISPOSITIONED 2026-07-13,
  accepted as-is: the doc mirrors the shipped sync contract verbatim (`src/child.rs:132-137`);
  the crate has no logging facility, and `kill_tree` is the documented guaranteed teardown.
- **`classify_pidfd_ready` unclassified branch** — the `None` branch signals re-await,
  matching tokio's documented `ready()` false positive and macOS's spurious-wake loop; pinned
  by `unclassified_readiness_retries_never_a_false_verdict`. The `debug_assert(false)`
  proposal stays declined (documented benign wake, not a contract violation).
- **`signal_cancel` failure disposition** — RESOLVED (round 14): the earlier
  "bounded consequence" claim was false under an unbounded grace. `SetEvent` on a live owned
  event has no documented failure mode, and a hypothetical failure would silently degrade the
  cancellation contract to an unbounded park — so the assert is now LOUD in every build.
- **treewalk fault seam = test-only control-flow fork** — declined: re-litigates the user's
  recorded seam decision (2026-07-05) and the shipped Plan-8 pattern (`src/child/spawn.rs`);
  unarmed, the test build's `hard_kill` takes the identical branches.
- **decoy test scripted drain** — declined: the parameterized drain is the prescribed
  composition seam; the target is alive until cycle 1, so the first NOTE_EXIT can only be the
  decoy's (verifier-confirmed); the receipt dance is single-sourced via `arm_note_exit_on`.
  Cycle 1 deliberately consumes the decoy event and reports "no exit" — the real drain's own
  `Ok(None)` branch is unit-tested (`drain_reports_none_when_no_event_pending`), and an
  organically spurious wake is unforcible (round-5 proof).
- **`WAIT_FAILED` branch untested** — declined: forcing it requires a deliberately corrupted
  handle, and closing a stale handle value in a threaded test process can strike an unrelated
  recycled handle (a real hazard the crate's own `close()` hygiene exists to prevent); the
  branch is the recorded unforcible-kernel-error class and is two straight lines after the
  capture-before-close fix.
- **TODO deferral provenance** — user-confirmed twice (dated citations inline in Step 6; a
  direct re-confirmation 2026-07-13); raised three times without contesting the citations
  themselves.
- **Execution-time extensions (2026-07-13):** (1) the watch-error ordering fix was mirrored
  into the shipped FOREIGN `Process::graceful_shutdown{,_tree}` (`src/process/graceful.rs`),
  which shared the stranding bug class — bugs are fixed where found, and the "foreign next"
  split defers the ASYNC foreign surface, not known defects in the shipped sync one; seam
  stranding twins added in `src/process/graceful_tests.rs`. (2) The LONE async
  `graceful_shutdown` doc's "(on all platforms — Windows watcher…)" parenthetical was
  corrected to its Unix-only reality (the lone op is `Unsupported` on Windows before any
  watch exists); the tree doc keeps the all-platforms wording. (3) Task-1 step's expected
  test count corrected to 7 unix / 6 windows (stale prose vs the step's own 7-test block).
- **`classify_pidfd_ready` synthetic-only coverage** — declined: POLLERR is unforcible on a
  real pidfd (the round-6 recorded rationale for factoring the classifier); the real-event
  AsyncFd path is covered end-to-end by the four `grace_wait` tests and the decoy composition
  test.
- **JoinError classification** — resolved in code (round 10): `is_cancelled()` gets its own
  arm with a distinct "runtime shutting down" message, so a shutdown-cancelled watcher is no
  longer indistinguishable from a real wait failure. The final catch-all is acknowledged as
  PRESENTLY-DEAD code reachable only through the type system (panic|cancelled are tokio's
  only variants today; no exhaustive-matchable interface exists) — kept so a future variant
  surfaces as an `Err`, never a false success, with a `debug_assert(false)` tripwire (round
  16, mirroring the unexpected-wait-verdict arm: dependency evolution is a debug-time signal,
  not an environmental failure).
- **Linux false-positive retry loop unbounded** — declined by rule: each iteration consumes a
  REAL reactor wake (no busy spin — `clear_ready` parks the next await), and the user's
  standing rules forbid arbitrary loop limits; a cap would convert a benign wake into a false
  verdict.
- **watch `Ok(false)`/`Err` conflation at the escalation branch** — declined: escalating on
  an unobservable grace IS the user-affirmed stranding invariant (rounds 10–11); the branch
  comment and both rustdocs state it, and the `Err` is re-surfaced after the reap.
- **builder request-level test is a getter/setter round-trip** — declined: it is the verbatim
  twin of the shipped sync `contain_with_and_nesting_recorded`, and the round-8 panel itself
  prescribed exactly this request-level mirror; behavior-level coverage is the TreeWalk
  teardown integration test.
- **prose test counts in run steps** — declined: step expectations are execution checkpoints
  for the implementer (this plan's established style), not assertions; drift fails the step
  loudly at execution time.
- **fault-seam tests prove control flow, not real backend failures** — declined: the real
  watch failure modes (pidfd POLLERR, kqueue `EV_ERROR`, `WAIT_FAILED`) are kernel-unforcible
  (the recorded round-6/7 rationale for the classifier/drain unit seams, which cover those
  branches synthetically); the stranding tests pin the ORDERING contract of the trio bodies,
  which is what can regress. Same seam class the user chose for the `kill_tree` backstop.
- **single-poll ordering assumption** — resolved for the lone Unix cancellation test with a
  real event: the `control-block-ack-term` child acks SIGTERM over the control socket, so the
  test OBSERVES that the first poll delivered the signal (no await-point assumption). For the
  tree/Windows twins the send is the same straight-line code before the first await
  (`terminate_tree` is a plain call in the same body), pinned by the lone test; duplicating
  ack plumbing through console-handler machinery adds surface without new information. The
  control-socket channel is the suite's established observation primitive — every testbin
  mode exists solely for tests. A refactor that moved the send past the first await fails
  LOUDLY: the lone test hangs on its ack read at the harness bound.
- **`AsyncFd` registration Err vs missing-driver panic** — declined: the distinction rests on
  tokio's DOCUMENTED behavior (the `AsyncFd` rustdoc "Panics" section names the
  missing-runtime/driver case), not internals; the comment and the graceful methods' Runtime
  docs record it.
- **escalation-skeleton per-surface copies** — USER-AFFIRMED 2026-07-13, explicitly covering
  the lone/tree axis and the round-13 "per-color helper" intermediate: the copies stay. The
  four bodies are not uniform (sync-lone's watch reaps on the graceful path and early-returns;
  async-lone escalates conditionally; the trees sweep unconditionally), so a shared per-color
  core needs a closure per differing step to save ~3 straight lines per site; every copy is
  pinned by its own stranding test plus the mirrored suites.
- **both-fail precedence test for `kill_tree`** — declined: the precedence is
  `Result::and`'s documented stdlib short-circuit; forcing a deterministic simultaneous
  group+backstop failure would need fault seams inside tokio's `start_kill` and the mechanism
  kill, leaving no crate-owned logic under test. The chosen combinator is pinned by rustdoc
  ("the group error is returned") on both surfaces.
- **cancel-vs-timeout verdicts folded** — declined: both ARE the contract verdict "not
  exited"; on the cancel path the caller has dropped the future and the value is unread. The
  branch comment states the fold.
- **long-grace deferred-real-exit boundary test** — declined: deferring a real exit behind a
  parked watch requires time-based synchronization (forbidden); arm-before-exit is covered
  race-tolerantly by `grace_wait_true_when_child_dies_mid_wait`, and spurious-then-real
  composition is covered where a spurious cycle is forcible (the macOS decoy test; on Linux
  the false-positive branch is the unit-tested classifier retry).
- **poll-once cancellation idiom** — declined: manual poll-once + drop is the DETERMINISTIC
  cancellation harness (the runtime and reactor are live inside `#[tokio::test]`; only the
  scheduling is test-controlled). "Real" runtime-driven cancellation (`select!`/`abort`)
  cannot assert cancelled-MID-GRACE without racing the poll count — the exact
  timing-dependence class the round-9 panel required removing. Dropping the future IS the
  production cancellation mechanism (`select!` drops the loser the same way).
- **Windows `SignalOnDrop` composition under real cancellation** — covered end-to-end by test
  teardown: `#[tokio::test]`'s `Runtime::drop` joins blocking tasks, so a broken release
  hangs the Windows tree-cancel test loudly at shutdown (comment added at the test). The
  release primitive itself has direct pre-signaled and mid-wait unit tests.
