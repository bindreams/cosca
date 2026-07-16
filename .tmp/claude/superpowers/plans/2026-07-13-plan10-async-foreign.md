# Plan 10 — Async Parity Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three user-confirmed async deferrals — `subprocess::tokio::Process` (foreign control), fd ≥ 3 async parent ends (Unix), and merge-into-piped-target on all platforms.

**Architecture:** `tokio::Process` wraps the sync `Process` (introspection delegates synchronously; only the death-watch and graceful pair are async, on a new unbounded `tokio::wait::wait_exit` extracted from `grace_wait`). fd ≥ 3 rides the existing shared `resolve_stdio` core: `Deferred` pipe ownership narrows to std slots, so fd ≥ 3 pipes produce parent ends that the async `Child` hands out as `tokio::net::unix::pipe::{Receiver,Sender}`. Merge-into-piped-target is pre-resolved in the async spawn itself (we own the target pipe; tokio's internal pipes cannot be shared): std pipe on Unix, an overlapped named-pipe pair (std's own child-stdio technique) on Windows, surfaced through new opaque `ChildStdout`/`ChildStderr`/`ChildStdin` wrapper streams.

**Tech Stack:** Rust (MSRV 1.87), tokio `["process","rt","io-util","macros","net","time"]` (unchanged — `net` already covers `unix::pipe` AND `windows::named_pipe`), plus NEW deps `log = "0.4"` (debug/warn traces; user-approved) and windows-only `getrandom` (unpredictable pipe names — std parity).

## Global Constraints

- Spec: `.tmp/claude/superpowers/specs/2026-07-13-plan10-async-foreign-design.md`. Sync sources of truth to mirror: `src/process.rs` + `src/process/graceful.rs` (foreign surface), `src/child/spawn.rs:40-110` (fd ≥ 3 + command-fds ordering), `tests/process.rs` + `tests/graceful.rs` `process_*` (foreign scenarios), `tests/spawn_io.rs` fd/merge tests.
- **Two dependency changes only:** `log = "0.4"` is ADDED (user-approved 2026-07-14, "generally pro-logging"; the facade is a no-op unless a consumer installs a logger) for the trace sites this plan carries, and `getrandom` (windows-only, `std` feature) is ADDED for the unpredictable merge-pipe names (std randomizes its anon-pipe names for the same reason; round-4 panel). Everything else rides tokio's already-enabled `net` feature (`unix::pipe`, `windows::named_pipe`) and std — no other Cargo.toml changes.
- **No-time-sync test discipline:** death/exit proven only by control-socket EOF/ConnectionReset, pipe events, or an inspected `ExitStatus` on an owned handle; `SIG_IGN` + `Duration::ZERO` for deterministic escalation; generous graces are failure bounds on already-guaranteed events; never sleep/poll/wall-clock.
- **Watch-error non-stranding invariant** (carried from Plan 9): the async foreign graceful pair mirrors the sync foreign bodies exactly — escalate first, then surface the watch `Err`; a kill/sweep `Err` subsumes the watch `Err`. Covered by seam-forced stranding twins.
- Foreign ops never reap and never return an `ExitStatus`; platform gating mirrors sync verbatim (lone terminate/graceful + soft-tree Unix-only; `kill_tree` all-OS; fd ≥ 3 Unix-only).
- **command-fds hook ordering is load-bearing** (`src/child/spawn.rs:72-110`): `containment::prepare` MUST run before `fd_mappings` is registered, so the cgroup pre_exec's fd cannot be clobbered by command-fds' dup2. The async spawn mirrors this order exactly.
- The shared `resolve_stdio` core stays runtime-agnostic: no tokio types or async-only branches inside `src/child/spawn.rs`; async-only wiring lives in `src/tokio/spawn.rs`.
- Before every commit: `cargo +stable fmt --check`, `cargo clippy --locked --features tokio --all-targets`, `cargo clippy --locked --all-targets` clean; plus the cross-target compile gate `cargo clippy --locked --features tokio --all-targets --target aarch64-apple-darwin` (macOS runtime is CI-only).
- After each task, run the suites on WSL: `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Users/bindreams/src/subprocess && export CARGO_TARGET_DIR=/tmp/sp-target && cargo test --locked --features tokio && cargo test --locked'` (fd ≥ 3, Unix merges, and every signal-path test never run on the Windows host). Pipe long outputs to files under `.tmp/claude/`, never `| tail`.
- Doc comments mirror the sync methods' docs, adjusted for async; single-line commit messages; TDD per the steps.
- **Recorded decisions (2026-07-13, user):** Windows merge implemented head-on via the overlapped named-pipe pair — shipping it Unix-only is a retreat only the user can approve. Introspection on `tokio::Process` stays sync (no false coloring). tokio pipe/named-pipe types over hand-rolled wrappers. KERN_PROC zombie-identity fix (issues #2/#3) stays OUT (queued follow-up).

---

### Task 1: `tokio::Process` + the unbounded `wait_exit`

**Files:**
- Modify: `src/tokio/wait.rs` (extract `wait_exit`; move the Windows `SignalOnDrop`/join body into a shared `blocking_watch`)
- Modify: `src/wait/windows.rs` (`block_until_exit_or_cancel` grace becomes `Option<Duration>`; `None => INFINITE`)
- Modify: `src/tokio/wait_tests.rs` (adjust the two cancel-test call sites; add `wait_exit` tests)
- Create: `src/tokio/process.rs` + `src/tokio/process/graceful.rs` + `src/tokio/process/graceful_tests.rs`
- Modify: `src/tokio.rs` (declare + re-export `Process`)
- Create: `tests/tokio_foreign.rs`

**Interfaces:**
- Consumes: `crate::process::Process` (all sync methods), `crate::wait::{terminate, kill}`, `crate::containment::treewalk` via the sync delegations, `crate::tokio::wait::grace_wait(ProcessId, Duration) -> Result<bool, Error>` (existing), `crate::wait::backend::block_until_exit_or_cancel` (Windows), test helpers `spawn_control_async`/`spawn_tree_async` (tests/common).
- Produces (Tasks 2–3 do not depend on this task): `pub(crate) async fn tokio::wait::wait_exit(ProcessId) -> Result<(), Error>` (unbounded, non-reaping, cancellable); `subprocess::tokio::Process` with `from_id/from_pid/current/id/is_alive/parent/children/kill/terminate/kill_tree/terminate_tree` (sync delegations) and `async wait/wait_timeout/graceful_shutdown/graceful_shutdown_tree`.

- [ ] **Step 1: Widen the Windows cancellable wait to an optional grace** — in `src/wait/windows.rs`, change the signature and the `ms` mapping of `block_until_exit_or_cancel` (everything else in the fn is unchanged):

```rust
/// `block_until_exit`, releasable early: returns `Ok(false)` as soon as `cancel` is signaled
/// (the process wins a tie — it is the lower wait index). `Ok(true)` = exited within `grace`;
/// `None` = unbounded.
pub(crate) fn block_until_exit_or_cancel(
    id: ProcessId,
    grace: Option<Duration>,
    cancel: &OwnedHandle,
) -> Result<bool, Error> {
```

and the `ms` computation:

```rust
    let ms = match grace {
        None => INFINITE,
        // Capped at INFINITE-1 (~49.7 days) — the cancel event releases large graces early;
        // a debug_assert flags the rare clamp.
        Some(d) => {
            let clamped = d.as_millis().min((INFINITE - 1) as u128) as u32;
            debug_assert!(
                d.as_millis() <= (INFINITE - 1) as u128,
                "Windows grace clamped to INFINITE-1 ms (~49.7 days): {}",
                d.as_secs()
            );
            clamped
        }
    };
```

Fix the two unit-test call sites in `src/tokio/wait_tests.rs` (`cancel_event_releases_the_blocking_wait`, `cancel_event_signaled_mid_wait_releases_the_blocking_wait`): `Duration::MAX` becomes `None`, comments updated to match; their loud-hang failure mode is unchanged.

Update the doc comments on `grace_wait`:

```rust
/// `Ok(true)` = the process exited within `grace`; `Ok(false)` = still alive at the deadline.
/// Non-reaping and signal-free; identity-verified (a stale/recycled id reports exited).
/// `Duration::ZERO` performs the sync backend's one-shot non-blocking probe.
///
/// **Windows:** Graces >= ~49.7 days (`INFINITE - 1` ms) are silently clamped to that cap —
/// a platform limit. A debug_assert surfaces this clamping in tests. On production, the clamp
/// is silent; a use case needing a genuinely unbounded watch composes `wait()` (unbounded,
/// cancellable) with its own escalation instead of a grace.
```

- [ ] **Step 2: Extract `wait_exit` in `src/tokio/wait.rs`.** On Unix, the seam head MOVES from `grace_wait` into `wait_exit` (grace_wait inherits it transitively — one consumption per watch); on Windows, both public entries keep a seam head and share one private body:

```rust
/// Resolve when the process exits — UNBOUNDED, non-reaping, signal-free, identity-verified
/// (a stale/recycled id reports exited immediately). Cancellable: dropping the future
/// deregisters the watch on Unix; on Windows the drop-guard's cancel event releases the
/// blocking watcher promptly.
#[cfg(unix)]
pub(crate) async fn wait_exit(id: ProcessId) -> Result<(), Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    exit_watch(id).await
}

/// `Ok(true)` = the process exited within `grace`; `Ok(false)` = still alive at the deadline.
/// Non-reaping and signal-free; identity-verified (a stale/recycled id reports exited).
/// `Duration::ZERO` performs the sync backend's one-shot non-blocking probe.
#[cfg(unix)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    if grace.is_zero() {
        // Delegates to the sync ZERO probe (bounded-instant, safe from async); consumes the
        // fault seam there.
        return crate::wait::block_until_exit(id, Some(Duration::ZERO));
    }
    match ::tokio::time::timeout(grace, wait_exit(id)).await {
        Ok(watch) => watch.map(|()| true),
        Err(_elapsed) => Ok(false),
    }
}
```

Windows: rename the existing `grace_wait` body (the `SignalOnDrop` struct, cancel-event setup, `spawn_blocking`, and the full `JoinError` match — moved verbatim; the closure passes `grace` through to `block_until_exit_or_cancel`) into:

```rust
#[cfg(windows)]
async fn blocking_watch(id: ProcessId, grace: Option<Duration>) -> Result<bool, Error> {
    // ... the former grace_wait body ...
}
```

and the two public entries become:

```rust
#[cfg(windows)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    blocking_watch(id, Some(grace)).await
}

#[cfg(windows)]
pub(crate) async fn wait_exit(id: ProcessId) -> Result<(), Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    // An unbounded watch (`None` => INFINITE) has no timeout path, and cancel-at-drop never
    // RESOLVES the future (it is gone) — so a resolved watch means exit. If that contract
    // ever broke, re-watching — not returning — preserves the postcondition (the Unix
    // exit_watch's false-positive re-await idiom); the debug_assert trips it in tests.
    loop {
        let exited = blocking_watch(id, None).await?;
        debug_assert!(exited, "an unbounded watch resolved without an exit");
        if exited {
            return Ok(());
        }
        log::warn!("unbounded watch for {id:?} resolved without an exit; re-watching");
    }
}
```

Update the seam doc in `src/wait.rs` (`fault` module) to name the entry points: "consumed by `block_until_exit`, `Child::wait_timeout`, and `tokio::wait::{grace_wait, wait_exit}`".

- [ ] **Step 3: Write the failing `wait_exit` unit tests** — append to `src/tokio/wait_tests.rs` (module is declared inside `wait.rs`, so `use super::wait_exit;` — add to the existing import):

```rust
#[tokio::test]
async fn wait_exit_resolves_for_exited_unreaped_child() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    child.kill().expect("kill");
    // NOT reaped: the exit event precedes the call, so the unbounded watch must resolve.
    wait_exit(id).await.expect("wait_exit");
    child.wait().expect("reap");
}

#[tokio::test]
async fn wait_exit_resolves_when_child_dies_mid_wait() {
    // Arm on a LIVE child; our own kill is the real exit event. Race-tolerant either side.
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let watch = ::tokio::spawn(wait_exit(id));
    child.kill().expect("kill mid-wait");
    watch.await.expect("join").expect("wait_exit");
    child.wait().expect("reap");
}

#[tokio::test]
async fn grace_wait_zero_reports_an_observed_exit() {
    // The ZERO one-shot probe must see an already-exited (zombie) child — the sync/async
    // parity case a plain timeout(ZERO, ..) gets wrong (the AsyncFd readiness of a zombie
    // needs a reactor round-trip the zero timer would win against).
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    child.kill().expect("kill");
    // Observe the exit as a real event WITHOUT reaping: wait for it via the unbounded watch
    // (30 s-class bound is the harness), then probe at ZERO.
    wait_exit(id).await.expect("exit observed");
    assert!(
        grace_wait(id, Duration::ZERO).await.expect("zero probe"),
        "an observed-exited child must report exited at ZERO grace"
    );
    child.wait().expect("reap");
}

#[tokio::test]
async fn wait_exit_cancel_leaves_child_untouched() {
    use std::future::Future;
    // Poll the unbounded watch exactly once (arms it), then drop — the watch is signal-free,
    // so the child must still be alive; it dies only by the test's own kill.
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    {
        let mut fut = std::pin::pin!(wait_exit(id));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("unbounded watch resolved at first poll on a live child: {r:?}");
        }
    } // <- future dropped here; on Windows the drop-guard releases the blocking watcher
    assert!(id.is_alive(), "a cancelled watch must not affect the child");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

// Proves release without a timeout: the watcher signals a channel when it returns; recv()
// blocks until that happens.
#[cfg(windows)]
#[tokio::test]
async fn wait_exit_drop_releases_the_windows_watcher() {
    use std::future::Future;
    let (tx, rx) = std::sync::mpsc::channel();
    super::fault_observer::install_release_observer(tx);
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    {
        let mut fut = std::pin::pin!(wait_exit(id));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("unbounded watch resolved at first poll on a live child: {r:?}");
        }
    } // <- drop signals the cancel event
    rx.recv().expect("the blocking watcher must return after the drop released it");
    assert!(id.is_alive(), "release must be signal-free");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}
```

The observer seam (add to `src/tokio/wait.rs`, Windows-only, test-only):

```rust
/// Deliberate test scaffolding (the `wait::fault` pattern): signals when the blocking
/// watcher RETURNS, so a test can prove drop-release with a plain `recv()` — the
/// no-time-sync alternative to observing teardown timing. Absent from non-test builds.
#[cfg(all(test, windows))]
pub(crate) mod fault_observer {
    use std::sync::mpsc::Sender;
    use std::sync::Mutex;
    static RELEASE_TX: Mutex<Option<Sender<()>>> = Mutex::new(None);
    pub(crate) fn install_release_observer(tx: Sender<()>) {
        *RELEASE_TX.lock().unwrap() = Some(tx);
    }
    pub(crate) fn notify_released() {
        if let Some(tx) = RELEASE_TX.lock().unwrap().as_ref() {
            let _ = tx.send(());
        }
    }
}
```

and inside `blocking_watch`'s `spawn_blocking` closure, after the wait returns:

```rust
        let result = crate::wait::backend::block_until_exit_or_cancel(id, grace, &cancel);
        #[cfg(test)]
        fault_observer::notify_released();
        result
```

(In non-test builds the closure body is just the wait call — the observer lines are
`cfg(test)`-gated; on non-Windows the module does not exist.)

Run: `cargo test --locked --features tokio --lib wait_tests`
Expected: COMPILE FAIL (`wait_exit` not defined) before Step 2 is applied; with Steps 1–2 in place: PASS. (TDD note: write this step's tests FIRST, watch them fail to compile, then apply Steps 1–2.)

- [ ] **Step 4: Write the failing integration tests** — create `tests/tokio_foreign.rs`, mirroring `tests/process.rs` + the `process_*` cases of `tests/graceful.rs`:

```rust
//! Async foreign `Process` integration tests — mirrors tests/process.rs and the process_*
//! cases of tests/graceful.rs. Same death-proof discipline: control-socket EOF or an
//! inspected ExitStatus on an OWNED handle — never sleep/poll/wall-clock.
#![cfg(feature = "tokio")]

#[path = "common/mod.rs"]
mod common;

use std::io::Read;

use subprocess::tokio::Process;

fn expect_eof(who: &str, s: &mut std::net::TcpStream) {
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("{who} not torn down: {other:?}"),
    }
}

#[tokio::test]
async fn async_foreign_wait_resolves_on_exit() {
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    let watch = ::tokio::spawn(async move { p.wait().await });
    child.kill().expect("kill");
    expect_eof("blocker", &mut sock);
    watch.await.expect("join").expect("foreign wait resolves on the real exit");
    let _ = child.wait();
}

#[tokio::test]
async fn async_foreign_wait_timeout_zero_is_deterministic() {
    let (child, _sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    assert!(!p.wait_timeout(std::time::Duration::ZERO).await.expect("poll"), "live child at ZERO");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

#[tokio::test]
async fn async_foreign_wait_timeout_observes_an_exit() {
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    child.kill().expect("kill");
    expect_eof("blocker", &mut sock); // real exit event precedes the wait
    assert!(
        p.wait_timeout(std::time::Duration::from_secs(30)).await.expect("wait"),
        "exited child must report exited (30 s is the failure bound)"
    );
    child.wait().expect("reap");
}

#[tokio::test]
async fn async_foreign_introspection_delegates() {
    let (child, _sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    assert_eq!(p.id(), child.id());
    assert!(p.is_alive());
    assert_eq!(Process::from_id(p.id()).expect("round-trip").id(), p.id());
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

#[tokio::test]
async fn async_foreign_kill_terminates_the_process() {
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    p.kill().expect("foreign kill");
    expect_eof("blocker", &mut sock);
    let status = child.wait().expect("reap");
    assert!(!status.success(), "killed child cannot report success, got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_foreign_terminate_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    p.terminate().expect("foreign terminate");
    expect_eof("blocker", &mut sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_foreign_graceful_shutdown_graceful_path() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    p.graceful_shutdown(Duration::from_secs(30)).await.expect("foreign graceful");
    expect_eof("blocker", &mut sock);
    let status = child.wait().expect("reap"); // owned handle reaps; SIGTERM = graceful
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_foreign_graceful_shutdown_escalates() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // SIG_IGN child + ZERO grace: provably alive at the single poll => deterministic
    // escalation; SIGKILL is the only terminating signal it can receive.
    let (child, mut sock) = common::spawn_control("control-block-ignore-term", &["R"], false);
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    p.graceful_shutdown(Duration::ZERO).await.expect("foreign escalates");
    expect_eof("blocker", &mut sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

#[tokio::test]
async fn async_foreign_kill_tree_tears_down_tree() {
    let (child, mut socks) = common::spawn_grandchild(false);
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    p.kill_tree().expect("kill_tree");
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
    let _ = child.wait();
}

#[cfg(unix)]
#[tokio::test]
async fn async_foreign_graceful_shutdown_tree_tears_down_tree() {
    use std::time::Duration;
    let (child, mut socks) = common::spawn_grandchild(false);
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    p.graceful_shutdown_tree(Duration::from_secs(30)).await.expect("foreign tree graceful");
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
    let _ = child.wait();
}

#[cfg(windows)]
#[tokio::test]
async fn async_foreign_unix_only_ops_are_unsupported_on_windows() {
    use std::time::Duration;
    let (child, _sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).expect("resolves");
    assert!(matches!(p.terminate(), Err(subprocess::error::Error::Unsupported { .. })));
    assert!(matches!(
        p.graceful_shutdown(Duration::from_secs(1)).await,
        Err(subprocess::error::Error::Unsupported { .. })
    ));
    assert!(matches!(p.terminate_tree(), Err(subprocess::error::Error::Unsupported { .. })));
    assert!(matches!(
        p.graceful_shutdown_tree(Duration::from_secs(1)).await,
        Err(subprocess::error::Error::Unsupported { .. })
    ));
    child.kill().expect("cleanup");
    let _ = child.wait();
}
```

Run: `cargo test --locked --features tokio --test tokio_foreign`
Expected: COMPILE FAIL — `subprocess::tokio::Process` does not exist.

- [ ] **Step 5: Implement `tokio::Process`** — create `src/tokio/process.rs`:

```rust
//! Async mirror of the foreign [`Process`](crate::Process). Introspection delegates
//! synchronously; only the death-watch and the graceful pair are async (`tokio::wait`).
//! NO stdio (we do not own its pipes); every operation re-verifies identity; nothing here
//! reaps (the real parent collects the zombie).

use std::time::Duration;

use crate::error::Error;
use crate::identity::{ProcessId, RawPid};
use crate::process::Recursive;

#[path = "process/graceful.rs"]
mod graceful;

/// An async handle to a foreign process identified by `(pid, start_token)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Process {
    inner: crate::process::Process,
}

impl From<crate::process::Process> for Process {
    fn from(inner: crate::process::Process) -> Process {
        Process { inner }
    }
}

impl Process {
    /// Resolve a foreign process by a saved identity. `None` if that exact identity is
    /// gone or the pid was recycled.
    pub fn from_id(id: ProcessId) -> Option<Process> {
        crate::process::Process::from_id(id).map(Process::from)
    }

    /// Resolve the process currently holding `pid`. `None` if no live process has it.
    pub fn from_pid(pid: RawPid) -> Option<Process> {
        crate::process::Process::from_pid(pid).map(Process::from)
    }

    /// This process's own handle. Infallible.
    pub fn current() -> Process {
        Process::from(crate::process::Process::current())
    }

    /// The stable identity (`(pid, start_token)`).
    pub fn id(&self) -> ProcessId {
        self.inner.id()
    }

    /// Whether the process is still running (zombie-exclusive; see [`ProcessId::is_alive`]).
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    /// The parent process, by identity (see [`Process::parent`](crate::Process::parent) for
    /// the identity-guard contract).
    pub fn parent(&self) -> Option<Process> {
        self.inner.parent().map(Process::from)
    }

    /// The process's children (see [`Process::children`](crate::Process::children)).
    pub fn children(&self, recursive: Recursive) -> Vec<Process> {
        self.inner.children(recursive).into_iter().map(Process::from).collect()
    }

    /// Resolve when the process exits. Death-watch — yields no `ExitStatus` (we are not its
    /// parent). Non-reaping and signal-free; `Err` only on a watch failure (incl.
    /// `Unsupported` on Linux < 5.3). Dropping the future cancels the watch on every
    /// platform (the Windows watcher is released via its cancel event).
    ///
    /// # Runtime
    ///
    /// Needs a runtime with the IO driver enabled on Unix (the `#[tokio::main]` /
    /// `#[tokio::test]` defaults) — missing it, tokio panics rather than returning a typed
    /// error. On Windows the watch runs on the blocking pool (one thread per in-flight wait).
    pub async fn wait(&self) -> Result<(), Error> {
        crate::tokio::wait::wait_exit(self.inner.id()).await
    }

    /// Wait up to `timeout` for the process to exit. `Ok(true)` = exited; `Ok(false)` =
    /// still alive at expiry. `Duration::ZERO` polls once. Non-reaping; cancellation and
    /// runtime requirements as on [`wait`](Process::wait) (Unix additionally needs the time
    /// driver).
    pub async fn wait_timeout(&self, timeout: Duration) -> Result<bool, Error> {
        crate::tokio::wait::grace_wait(self.inner.id(), timeout).await
    }

    /// Hard-kill the process by identity (see [`Process::kill`](crate::Process::kill) for
    /// the per-OS race-freedom contract).
    pub fn kill(&self) -> Result<(), Error> {
        self.inner.kill()
    }

    /// Send `SIGTERM` (signal-only, identity-bound). Unix only; Windows returns
    /// `Unsupported`.
    pub fn terminate(&self) -> Result<(), Error> {
        self.inner.terminate()
    }

    /// Best-effort hard identity-walk sweep of the tree (all platforms; the `TreeWalk`
    /// contract — see [`Process::kill_tree`](crate::Process::kill_tree)).
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.inner.kill_tree()
    }

    /// Best-effort graceful (`SIGTERM`) identity-walk sweep. Unix only; Windows returns
    /// `Unsupported` (see [`Process::terminate_tree`](crate::Process::terminate_tree)).
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.inner.terminate_tree()
    }
}
```

and `src/tokio/process/graceful.rs`:

```rust
//! Async foreign graceful shutdown — mirrors `src/process/graceful.rs` on the
//! reactor-native grace-wait. No reap anywhere (the real parent collects the zombie).

use std::time::Duration;

use super::Process;
use crate::error::Error;

impl Process {
    /// Cooperative-then-forced lone shutdown of the foreign process: `SIGTERM`, wait up to
    /// `grace`, then `SIGKILL` if it has not exited. No `ExitStatus`. Escalation proceeds
    /// even if `SIGTERM` is ignored. Unix only; Windows returns `Unsupported`. `grace` is
    /// relative; `ZERO` polls once, then escalates.
    ///
    /// A watch failure surfaces only after the kill runs; a kill error wins over it.
    /// Dropping this future mid-grace cancels the watch and performs no further signalling.
    ///
    /// # Runtime
    ///
    /// Needs the IO **and** time drivers on Unix (the `#[tokio::main]`/`#[tokio::test]`
    /// defaults) — missing either, tokio panics rather than returning a typed error.
    pub async fn graceful_shutdown(&self, grace: Duration) -> Result<(), Error> {
        crate::wait::terminate(self.id())?;
        // Watch failure escalates now (kill still runs); a kill Err wins — mirrors the
        // sync twin's subsumption.
        let watch = crate::tokio::wait::grace_wait(self.id(), grace).await;
        if matches!(watch, Ok(true)) {
            return Ok(()); // exited within grace
        }
        // Hard SIGKILL (no reap — not the parent). If the watch failed, log it before
        // returning the kill error, so both failures leave a trace.
        if let Err(ref e) = watch {
            log::debug!("graceful_shutdown watch error before kill escalation (subsumed): {e}");
        }
        crate::wait::kill(self.id())?;
        watch?;
        Ok(())
    }

    /// Cooperative-then-forced shutdown of the foreign process's tree: `SIGTERM`-walk, wait
    /// up to `grace` for the **root** to exit, then a hard identity-walk sweep. Best-effort
    /// (the `TreeWalk` contract); no `ExitStatus`. Unix only (Windows `terminate_tree` is
    /// `Unsupported`).
    ///
    /// A grace-watch failure does not strand the tree: the hard sweep still runs, and the
    /// watch error is surfaced afterward; a sweep failure would win over it. Dropping this
    /// future mid-grace cancels the watch and performs no further signalling. Runtime
    /// requirements as on [`graceful_shutdown`](Process::graceful_shutdown).
    pub async fn graceful_shutdown_tree(&self, grace: Duration) -> Result<(), Error> {
        self.terminate_tree()?; // SIGTERM-walk (Windows: Unsupported, early return)
        let watch = crate::tokio::wait::grace_wait(self.id(), grace).await;
        // The sweep is unconditional — a gracefully-exited root does NOT mean the
        // descendants drained. If the watch failed, log it before the sweep so both
        // failures leave a trace.
        if let Err(ref e) = watch {
            log::debug!("graceful_shutdown_tree watch error before kill_tree sweep (may be subsumed): {e}");
        }
        // There is no reap to order against (the real parent collects the zombie).
        self.kill_tree()?;
        watch?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
```

Declare + re-export in `src/tokio.rs` (next to the existing declarations / `pub use`s):

```rust
#[path = "tokio/process.rs"]
mod process;
```
```rust
pub use process::Process;
```

- [ ] **Step 6: The async foreign stranding twins** — create `src/tokio/process/graceful_tests.rs`, mirroring `src/process/graceful_tests.rs` (read it first — same child recipes, same seam):

```rust
//! Async twins of `process/graceful_tests.rs` — watch-failure ordering via the shared seam.
//! Unix-only: both foreign soft ops are `Unsupported` on Windows before any watch runs. The
//! foreign surface is non-reaping, so the Child twins' reap discriminator does not exist
//! here; the child IGNORES `SIGTERM`, making the escalation's `SIGKILL` the only signal that
//! can terminate it — the owned std handle's reaped status proves the escalation ran.
#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use crate::wait::fault;

/// A std child that ignores `SIGTERM`: `trap '' TERM` before `exec`, and ignored dispositions
/// survive the exec. The readiness byte on stdout proves the trap is installed before any
/// signal is sent (a real pipe event, not a sleep). Byte-identical to the sync twins' helper
/// in `src/process/graceful_tests.rs`.
fn spawn_term_ignoring_sleeper() -> std::process::Child {
    let mut child = std::process::Command::new("sh")
        .args(["-c", "trap '' TERM; echo r; exec sleep 30"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut buf = [0u8; 1];
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_exact(&mut buf)
        .expect("readiness byte");
    child
}

#[tokio::test]
async fn async_foreign_graceful_watch_error_still_escalates() {
    let mut child = spawn_term_ignoring_sleeper();
    let p = crate::tokio::Process::from_pid(child.id()).expect("resolves");
    fault::set_force_watch_error(true);
    let err = p
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(!fault::armed(), "seam not consumed — the watch did not run on this thread");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    // Death proof via the OWNED handle: SIGTERM is ignored, so only the escalation's SIGKILL
    // can have terminated it.
    let status = child.wait().expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "child must be force-killed despite the watch error, got {status:?}"
    );
}

#[tokio::test]
async fn async_foreign_graceful_tree_watch_error_still_sweeps() {
    let mut child = spawn_term_ignoring_sleeper();
    let p = crate::tokio::Process::from_pid(child.id()).expect("resolves");
    fault::set_force_watch_error(true);
    let err = p
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(!fault::armed(), "seam not consumed — the watch did not run on this thread");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    let status = child.wait().expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "root must be swept despite the watch error, got {status:?}"
    );
}
```

- [ ] **Step 7: Run to verify pass**

Run: `cargo test --locked --features tokio --lib wait_tests && cargo test --locked --features tokio --lib process && cargo test --locked --features tokio --test tokio_foreign`
Expected: PASS on the host (Windows-runnable subset); the Unix-gated cases compile.

- [ ] **Step 8: Full regression + lint + WSL**

Run: `cargo test --locked --features tokio && cargo test --locked && cargo +stable fmt --check && cargo clippy --locked --features tokio --all-targets && cargo clippy --locked --all-targets && cargo clippy --locked --features tokio --all-targets --target aarch64-apple-darwin`
Expected: all green, zero warnings. Then the WSL run from Global Constraints (the Unix foreign scenarios' real gate).

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock src/tokio/wait.rs src/tokio/wait_tests.rs src/wait/windows.rs src/tokio/process.rs src/tokio/process/graceful.rs src/tokio/process/graceful_tests.rs src/tokio.rs tests/tokio_foreign.rs
git commit -m "feat: async foreign Process (introspect/wait/kill/graceful) on an unbounded cancellable wait_exit"
```

---

### Task 2: fd ≥ 3 async parent ends (Unix)

**Files:**
- Modify: `src/child/spawn.rs` (narrow `Deferred`'s pipe-skip and merge-into-pipe rejection to std slots; update the `Deferred` doc)
- Modify: `src/tokio/spawn.rs` (Unix: resolve fd ≥ 3 slots + command-fds wiring AFTER `prepare`; Windows: keep the typed rejection)
- Modify: `src/tokio/child.rs` (store fd ≥ 3 parent ends; `fd_read_end`/`fd_write_end`)
- Modify: `tests/tokio_io.rs` (append the fd ≥ 3 tests)

**Interfaces:**
- Consumes: `resolve_stdio(fds, slots, PipeOwnership) -> ResolvedStdioEnds`, `ParentEnd::{Reader, Writer}` (src/child.rs), `command_fds::{CommandFdExt, FdMapping}`, `tokio::net::unix::pipe::{Receiver, Sender}` (`from_owned_fd`: checks pipe-ness/access, sets non-blocking itself, panics outside an IO-enabled runtime).
- Produces (Task 3 relies on the `Deferred` narrowing): `tokio::Child::fd_read_end(fd) -> Option<pipe::Receiver>` and `fd_write_end(fd) -> Option<pipe::Sender>` (Unix-only, `#[cfg(unix)]`); async `Child::from_parts` gains a `pipes: BTreeMap<Fd, ParentEnd>` parameter.

- [ ] **Step 1: Write the failing tests** — append to `tests/tokio_io.rs` (imports as the file already uses; `subprocess::Fd`):

```rust
// Arbitrary fd (n>=3) — Unix only, wired via command-fds (async mirror of spawn_io.rs) =====

/// Async twin of sync `unix_fd3_pipe_round_trips`: the testbin's `fd3-echo` mode reads fd 3
/// and copies it to stdout. Write a known payload into the parent write end, close it (EOF),
/// read stdout to EOF — no timers, fully deterministic.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd3_pipe_round_trips() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-echo"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::pipe_in()).expect("fd 3 pipe_in");
    let mut child = cmd.spawn().expect("spawn with fd 3");
    let mut stdout = child.stdout().expect("stdout reader");
    let mut fd3_writer = child.fd_write_end(subprocess::Fd::from(3)).expect("fd 3 writer");

    fd3_writer.write_all(b"hello fd3").await.expect("write to fd 3");
    drop(fd3_writer); // EOF on the child's fd 3 read end

    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).await.expect("read stdout");
    drop(stdout);
    let _ = child.wait().await;

    assert_eq!(buf, b"hello fd3");
}

/// Async twin of sync `unix_fd3_null_is_accepted`: fd 3 as `Stdio::null()` spawns, the child
/// reads immediate EOF from /dev/null and produces no output, exiting cleanly.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd3_null_is_accepted() {
    use tokio::io::AsyncReadExt;
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-echo"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::null()).expect("fd 3 null");
    let mut child = cmd.spawn().expect("spawn with null fd 3");
    let mut stdout = child.stdout().expect("stdout reader");
    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).await.expect("read stdout");
    let status = child.wait().await.expect("reap");
    assert!(buf.is_empty(), "null fd 3 is immediate EOF — no echo, got {buf:?}");
    assert_eq!(status.code(), Some(0));
}

/// Async twin of sync `arbitrary_fd_is_unsupported_on_windows`: config attaches fine, spawn
/// rejects with the sync path's typed error.
#[cfg(windows)]
#[tokio::test]
async fn async_fd3_is_unsupported_on_windows() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.fd(3, subprocess::Stdio::pipe_out()).unwrap(); // attaches fine
    let err = cmd.spawn().unwrap_err(); // but spawn rejects it on Windows
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }));
}
```

And the `fd_read_end` direction (pipe_out: child writes, parent reads via `fd_read_end`; testbin's existing `fd3-write` mode writes its `args[2]` token to fd 3 and flushes):

```rust
/// fd 3 as pipe_out: the testbin's `fd3-write` mode writes a token to fd 3; the parent
/// reads it back via the reactor-registered `fd_read_end`.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd3_pipe_out_delivers_child_bytes() {
    use tokio::io::AsyncReadExt;
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-write", "fd3-token"]);
    cmd.fd(3, subprocess::Stdio::pipe_out()).expect("fd 3 pipe_out");
    let mut child = cmd.spawn().expect("spawn with fd 3 out");
    let mut fd3_reader = child.fd_read_end(subprocess::Fd::from(3)).expect("fd 3 reader");
    let mut buf = Vec::new();
    fd3_reader.read_to_end(&mut buf).await.expect("read fd 3");
    let _ = child.wait().await;
    assert_eq!(buf, b"fd3-token");
}

/// A wrong-direction accessor must NOT consume the stashed end (the put-back arm): after
/// the mismatched take returns `None`, the correctly-directioned accessor still yields a
/// WORKING end — proven by a full round-trip, both directions.
#[cfg(unix)]
#[tokio::test]
async fn async_fd3_wrong_direction_take_puts_the_end_back() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // pipe_in: the read-accessor first (wrong) must not lose the write end.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-echo"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::pipe_in()).expect("fd 3 pipe_in");
    let mut child = cmd.spawn().expect("spawn");
    assert!(child.fd_read_end(subprocess::Fd::from(3)).is_none(), "wrong direction is None");
    let mut w = child
        .fd_write_end(subprocess::Fd::from(3))
        .expect("the write end survives the wrong-direction take");
    w.write_all(b"put-back").await.expect("write");
    drop(w);
    let mut buf = Vec::new();
    child.stdout().expect("stdout").read_to_end(&mut buf).await.expect("read");
    let _ = child.wait().await;
    assert_eq!(buf, b"put-back");

    // pipe_out: the write-accessor first (wrong) must not lose the read end.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-write", "still-here"]);
    cmd.fd(3, subprocess::Stdio::pipe_out()).expect("fd 3 pipe_out");
    let mut child = cmd.spawn().expect("spawn");
    assert!(child.fd_write_end(subprocess::Fd::from(3)).is_none(), "wrong direction is None");
    let mut r = child
        .fd_read_end(subprocess::Fd::from(3))
        .expect("the read end survives the wrong-direction take");
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).await.expect("read fd 3");
    let _ = child.wait().await;
    assert_eq!(buf, b"still-here");
}
```

(Cross-check the two mirrored Unix twins against their sync sources in `tests/spawn_io.rs` — same testbin modes and argv.)

Run: `cargo test --locked --features tokio --test tokio_io`
Expected: COMPILE FAIL — `fd_read_end`/`fd_write_end` do not exist on the async `Child`. (On Unix the spawn would also still reject fd ≥ 3.)

- [ ] **Step 2: Narrow `Deferred` to std slots** — in `src/child/spawn.rs`:

The `PipeOwnership::Deferred` doc becomes:

```rust
    /// Async: tokio owns the piped STD ends (0/1/2) — those slots are left out of the
    /// resolved child ends (the caller assigns `Stdio::piped()`), and a merge into a piped
    /// STD target is rejected (its end is tokio's, not ours to dup). fd >= 3 pipes are OURS
    /// on every path: they resolve like `Owned` and produce parent ends.
```

First pass, the pipe-skip arm:

```rust
            Some(ResolvedStdio::Pipe(_)) if matches!(pipe, PipeOwnership::Deferred) && slot.raw() < 3 => continue,
```

Second pass, the merge rejection condition:

```rust
            if matches!(pipe, PipeOwnership::Deferred)
                && target.raw() < 3
                && matches!(fds.get(target), Some(ResolvedStdio::Pipe(_)))
            {
```

(An fd ≥ 3 merge target now has a child end of ours, so merging into it just works via the existing dup pass. The sync path is untouched: `Owned` never hits either condition.)

- [ ] **Step 3: Accept fd ≥ 3 in the async spawn (Unix)** — in `src/tokio/spawn.rs`, replace the unconditional rejection loop with a Windows-only one, and mirror the sync slot construction + command-fds tail:

```rust
    // fd >= 3 is Unix-only (command-fds), exactly as on the sync path — Windows rejects it
    // with the sync spawn's strings VERBATIM (op has no "async" prefix; the detail cites
    // the raw backend) so the two paths report identically:
    #[cfg(windows)]
    for slot in fds.keys() {
        if slot.raw() >= 3 {
            return Err(Error::Unsupported {
                op: format!("{slot}"),
                platform: std::env::consts::OS,
                detail: "arbitrary descriptors (>= 3) require the raw backend (Plan 4)".into(),
            });
        }
    }
```

(Copy the exact `op`/`detail` from the sync rejection in `src/child/spawn.rs` — the
strings above reproduce it; if the file drifted, the SYNC source wins. The
`fd_ge_3_is_rejected` / `arbitrary_fd_is_unsupported_on_windows` sync tests match only the
`Unsupported` variant, so the string swap breaks nothing.)

The slot list mirrors the sync `all_slots` construction (`src/child/spawn.rs:50-57`):

```rust
    let std_slots = [Fd::STDIN, Fd::STDOUT, Fd::STDERR];
    let all_slots: Vec<Fd> = {
        let mut v = std_slots.to_vec();
        v.extend(fds.keys().copied().filter(|f| f.raw() >= 3));
        v
    };
    let (mut child_ends, parent_ends) = resolve_stdio(&fds, &all_slots, PipeOwnership::Deferred)?;
    // Deferred skips only the piped STD slots; every parent end here is an fd >= 3 pipe's.
    debug_assert!(
        parent_ends.keys().all(|f| f.raw() >= 3),
        "Deferred pipe ownership must only produce fd >= 3 parent ends"
    );
```

After the existing `let prepared = crate::containment::prepare(...)` line and BEFORE `tcmd.spawn()`, wire command-fds on the inner std command — the ordering comment and block mirror `src/child/spawn.rs:87-110` verbatim (prepare's pre_exec hooks MUST be registered before `fd_mappings`, so command-fds' dup2 runs last in the child):

```rust
    // On Unix, hand n>=3 child ends to command-fds — registered AFTER `prepare` so its dup2
    // pre_exec runs LAST in the child (see the ordering rationale in child/spawn.rs).
    #[cfg(unix)]
    {
        use command_fds::{CommandFdExt, FdMapping};

        let mappings: Vec<FdMapping> = child_ends
            .into_iter()
            .map(|(fd, owned)| FdMapping {
                parent_fd: owned,
                child_fd: fd.raw(),
            })
            .collect();
        if !mappings.is_empty() {
            tcmd.as_std_mut()
                .fd_mappings(mappings)
                .expect("child fd numbers are unique (BTreeMap keys)");
        }
    }
```

(The existing std-slot assignment loop `child_ends.remove(&slot)` runs before this, so `child_ends` holds exactly the fd ≥ 3 ends by then — same consumption order as sync. On Windows the invariant is enforced BY CONSTRUCTION, not by an assert-plus-comment pair: the slot list itself is platform-gated —

```rust
    #[cfg(unix)]
    let all_slots: Vec<Fd> = {
        let mut v = std_slots.to_vec();
        v.extend(fds.keys().copied().filter(|f| f.raw() >= 3));
        v
    };
    // Windows: fd >= 3 was rejected above, and the slot list NEVER includes fd >= 3 — a
    // stray end cannot exist by construction, so no assert/drop pairing to keep in sync.
    #[cfg(windows)]
    let all_slots: Vec<Fd> = std_slots.to_vec();
```

so the earlier `all_slots` construction in this step is replaced by this cfg'd pair, and the Windows branch needs no `child_ends` epilogue at all.)

Pass `parent_ends` into the child: `Child::from_parts(child, id, attached, kill_on_drop, containment, parent_ends)`.

- [ ] **Step 4: Store + hand out the async fd ends** — in `src/tokio/child.rs`: add the field and parameter (`pipes: BTreeMap<Fd, crate::child::ParentEnd>` — import `std::collections::BTreeMap`, `crate::stdio::Fd`, `crate::child::ParentEnd`; both are already `pub(crate)` — no visibility changes needed). There is exactly ONE `from_parts` call site to update (`src/tokio/spawn.rs:114`, the success path — both error paths use `reap_now` and are unchanged). Then add:

```rust
    /// Take the parent's read end of the pipe on child descriptor `fd` (configured via
    /// `Command::fd(n, Stdio::pipe_out())`), as a reactor-registered pipe. Unix only.
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled (the pipe registers with the
    /// reactor).
    ///
    /// # Returns
    ///
    /// `Some(receiver)` on success. `None` if the fd was not configured as a piped read end,
    /// if it was already taken, or if reactor registration failed (a contract violation:
    /// debug_assert + `log::warn!`; the dropped end closes the fd, so the child observes
    /// EPIPE on its write end — a visible failure, never a hang).
    #[cfg(unix)]
    pub fn fd_read_end(&mut self, fd: impl Into<crate::stdio::Fd>) -> Option<::tokio::net::unix::pipe::Receiver> {
        use std::os::fd::OwnedFd;
        let fd = fd.into();
        match self.pipes.remove(&fd)? {
            crate::child::ParentEnd::Reader(r) => {
                match ::tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(r)) {
                    Ok(recv) => Some(recv),
                    // Reactor registration failure — a contract violation for an
                    // our-own-pipe end (see docstring).
                    Err(e) => {
                        debug_assert!(false, "own pipe end failed tokio conversion: {e}");
                        log::warn!("fd {fd} read end dropped: tokio conversion failed ({e}); the child will see EPIPE on writes");
                        None
                    }
                }
            }
            end => {
                self.pipes.insert(fd, end); // wrong direction — put it back (sync mirror)
                None
            }
        }
    }

    /// Take the parent's write end of the pipe on child descriptor `fd` (configured via
    /// `Command::fd(n, Stdio::pipe_in())`). Unix only.
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled (the pipe registers with the
    /// reactor).
    ///
    /// # Returns
    ///
    /// `Some(sender)` on success. `None` if the fd was not configured as a piped write end,
    /// if it was already taken, or if reactor registration failed (a contract violation:
    /// debug_assert + `log::warn!`; the dropped end closes the fd, so the child observes
    /// EOF on its read end — a visible failure, never a hang).
    #[cfg(unix)]
    pub fn fd_write_end(&mut self, fd: impl Into<crate::stdio::Fd>) -> Option<::tokio::net::unix::pipe::Sender> {
        use std::os::fd::OwnedFd;
        let fd = fd.into();
        match self.pipes.remove(&fd)? {
            crate::child::ParentEnd::Writer(w) => {
                match ::tokio::net::unix::pipe::Sender::from_owned_fd(OwnedFd::from(w)) {
                    Ok(send) => Some(send),
                    Err(e) => {
                        debug_assert!(false, "own pipe end failed tokio conversion: {e}");
                        log::warn!("fd {fd} write end dropped: tokio conversion failed ({e}); the child will see EOF on reads");
                        None
                    }
                }
            }
            end => {
                self.pipes.insert(fd, end);
                None
            }
        }
    }
```

(Adjust `fd_read_end`'s `# Panics` doc: the only panic is tokio's documented missing-IO-driver
one; a conversion failure is a debug tripwire + `log::warn!` + release `None`. Behavioral
mirror of the sync accessors in `src/child.rs` otherwise — read them and match the doc/return
conventions.)

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --locked --features tokio --test tokio_io`
Expected: PASS on the host (Unix-gated fd tests skipped; the Windows `Unsupported` test runs). Then the WSL run — the real gate for the fd tests.

- [ ] **Step 6: Full regression + lint + WSL + commit**

Run the Global Constraints suite battery (host + cross-target + WSL). Then:

```bash
git add src/child/spawn.rs src/tokio/spawn.rs src/tokio/child.rs tests/tokio_io.rs
git commit -m "feat: async fd>=3 parent ends on Unix via tokio pipe Receiver/Sender"
```

---

### Task 3: Merge-into-piped-target on the async API (all platforms)

**Files:**
- Create: `src/tokio/stdio.rs` (opaque `ChildStdin`/`ChildStdout`/`ChildStderr` wrapper streams + the Windows overlapped pipe pair via tokio's PUBLIC named-pipe API — no raw FFI, no `unsafe`)
- Create: `src/tokio/stdio_tests.rs` (Windows pipe-pair unit tests: real-child E2E read + squatted-name rejection)
- Modify: `src/tokio/spawn.rs` (pre-resolve piped merge targets as our-owned pipes)
- Modify: `src/tokio/child.rs` (accessors return the wrappers; store owned std-slot parent ends)
- Modify: `src/tokio/pump.rs` (unchanged logic — compiles against the wrappers)
- Modify: `src/child/spawn.rs` (verify `dup` is `pub(crate)` — already is; no changes needed)
- Modify: `src/tokio.rs` (declare `stdio`; re-export the three stream types)
- Modify: `tests/tokio_io.rs` (merge tests)
- Modify: `testbin/main.rs` (add the `stdin-echo` mode)
- Modify: `Cargo.toml` (windows-only `getrandom` for pipe-name randomness)
- Modify: `TODO.md`

**Interfaces:**
- Consumes: `resolve_stdio` (with Task 2's narrowed `Deferred`), `crate::child::spawn::dup` (already `pub(crate)`), `ParentEnd` (already `pub(crate)`), std pipes (`std::io::pipe()`), `tokio::net::unix::pipe::Receiver`, `tokio::net::windows::named_pipe::{ServerOptions, NamedPipeServer}` (all safe public API).
- Produces: `subprocess::tokio::{ChildStdin, ChildStdout, ChildStderr}` implementing `AsyncWrite`/`AsyncRead`; `Child::{stdin, stdout, stderr}` return them; async `Stdio::merge(target)` into a piped std target works on all platforms.

**Stated tradeoff (merge pre-pass vs extending `resolve_stdio` — settled rounds 1–2):** the
Windows owned merge-target pipe is a tokio type (`NamedPipeServer`) and the shared core must
stay runtime-agnostic (Global Constraints), so the pre-pass lives in `src/tokio/spawn.rs`,
bounded to piped merge targets, with the core's `Deferred` rejection guarding every
unhandled shape.

**Dependency evaluation (recorded):** `tokio-anon-pipe` (0.1.1) was evaluated — right
technique (unique-named overlapped pipe, `first_pipe_instance` + `reject_remote_clients`) but
it builds BOTH ends async for in-process use and has no inheritable child end, so it cannot
feed child stdio. tokio's own public `ServerOptions` provides the same server end first-party,
and `std::fs::OpenOptions` opens the synchronous client end (std's spawn duplicates stdio
handles inheritable itself) — no new crate, no raw FFI, no new windows-crate features.

- [ ] **Step 1: Write the failing tests** — append to `tests/tokio_io.rs`, mirroring `tests/spawn_io.rs` `merge_stderr_onto_stdout_combines_output` (read it first and reuse its exact testbin mode and byte counts). Also add a `stdin-echo` mode to `testbin/main.rs` (copy stdin to stdout to EOF — `tee-both` minus the stderr side; needed by the In-direction test below):

```rust
#[tokio::test]
async fn async_merge_stderr_onto_stdout_combines_output() {
    use tokio::io::AsyncReadExt;
    let mut cmd = subprocess::tokio::Command::new();
    // Same scenario as sync merge_stderr_onto_stdout_combines_output (tests/spawn_io.rs):
    // emit 3 bytes to stdout, 2 to stderr; merged, all 5 arrive on the one stdout pipe.
    // (Copy the sync test's exact mode + argv.)
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "2"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT)).expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn merged");
    let mut reader = child.stdout().expect("merged stdout reader");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.expect("read merged");
    drop(reader);
    let _ = child.wait().await;
    // All 5 bytes arrive; order between stdout/stderr is unspecified, but the COUNTS are
    // exact — a regression that drops stderr and doubles stdout cannot pass.
    assert_eq!(buf.len(), 5, "expected 5 bytes (3 stdout + 2 stderr merged), got {buf:?}");
    assert_eq!(buf.iter().filter(|&&b| b == b'o').count(), 3, "3 stdout bytes, got {buf:?}");
    assert_eq!(buf.iter().filter(|&&b| b == b'e').count(), 2, "2 stderr bytes, got {buf:?}");
}

#[tokio::test]
async fn async_merge_into_unpiped_targets_still_works() {
    // Regression: merge into null stays on the existing (non-owned) path.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "2"]);
    cmd.stdout(subprocess::Stdio::null()).expect("stdout null");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT)).expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn");
    let status = child.wait().await.expect("reap");
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn async_communicate_reads_a_merged_stream() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "2"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT)).expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn");
    let out = child.communicate(None).await.expect("communicate");
    assert_eq!(out.stdout.len(), 5, "merged bytes arrive on stdout, got {:?}", out.stdout);
    assert!(out.stderr.is_empty(), "stderr was merged away");
}

#[tokio::test]
async fn async_merged_stream_accessor_has_take_semantics() {
    // stdout() as a piped merge target: first take yields the reader, second is None
    // (take semantics, matching the tokio-owned branch).
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "2"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT)).expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn");
    let first = child.stdout();
    assert!(first.is_some(), "first stdout() take yields the merged reader");
    assert!(child.stdout().is_none(), "second stdout() take must be None (take semantics)");
    // The MERGING slot (stderr) has no stream of its own: tokio's stderr was never piped.
    assert!(child.stderr().is_none(), "a merged-away slot yields no stream");
    drop(first); // close the parent end so the child's writes cannot block forever
    let _ = child.wait().await;
}

#[tokio::test]
async fn async_non_merged_stream_accessor_has_take_semantics() {
    // Regression test: stdin, stdout, stderr's take-semantics when NOT merge targets.
    // (The pre-pass skips slots it assigns; this ensures stdin/stdout/stderr still behave
    // correctly for non-merge configurations.)
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "5", "0"]);
    cmd.stdin(subprocess::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::null()).expect("stderr null");
    let mut child = cmd.spawn().expect("spawn");
    
    // Each slot's take-semantics: first call returns Some, second returns None.
    assert!(child.stdin().is_some(), "first stdin() take");
    assert!(child.stdin().is_none(), "second stdin() take is None");
    assert!(child.stdout().is_some(), "first stdout() take");
    assert!(child.stdout().is_none(), "second stdout() take is None");
    assert!(child.stderr().is_none(), "stderr is null, so takes are always None");
    
    let _ = child.wait().await;
}

#[tokio::test]
async fn async_plain_piped_stream_accessor_has_take_semantics() {
    // The tokio-owned (non-merge) branch's take-semantics: stdout piped (no merge), so
    // tokio owns the internal pipe. Verifies parity with the merge-owned case above.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "0"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let first = child.stdout();
    assert!(first.is_some(), "first take yields the tokio-owned reader");
    assert!(child.stdout().is_none(), "second take must be None (take semantics)");
    // PARITY: this behavior MUST match async_merged_stream_accessor_has_take_semantics's
    // first-take-yields, second-take-is-None pattern — both owned and merged merge-target
    // stdout() have identical take-semantics.
    drop(first);
    let _ = child.wait().await;
}

/// In-direction merge target on ALL platforms: stdin is piped and stderr merges into it,
/// so the pre-pass owns stdin's pipe (tokio cannot share its internal one). The child never
/// touches its (read-oriented) stderr handle; the new `stdin-echo` testbin mode copies fd 0
/// to stdout. Parent writes via the OWNED stdin path (Windows `WinOwnedWrite`; Unix
/// `pipe::Sender`), EOF by drop — the echo proves delivery.
#[tokio::test]
async fn async_merge_into_piped_stdin_feeds_the_merged_child() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "stdin-echo"]);
    cmd.stdin(subprocess::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDIN)).expect("stderr merges into stdin");
    let mut child = cmd.spawn().expect("spawn merged-stdin child");
    let mut stdin = child.stdin().expect("owned stdin writer");
    stdin.write_all(b"in-merge-e2e").await.expect("write");
    drop(stdin); // buffered data is delivered first, then EOF (verified teardown order)
    let mut buf = Vec::new();
    child.stdout().expect("stdout reader").read_to_end(&mut buf).await.expect("read echo");
    let _ = child.wait().await;
    assert_eq!(buf, b"in-merge-e2e");
}

/// fd >= 3 as a merge SOURCE into a piped Out target: the pre-pass routes the dup'd write
/// end through command-fds (never silently dropped). testbin's `fd3-write` emits its token
/// on fd 3 — a dup of stdout's owned pipe — so the token arrives on the stdout reader.
#[cfg(unix)]
#[tokio::test]
async fn async_fd3_source_merges_into_piped_stdout() {
    use tokio::io::AsyncReadExt;
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-write", "fd3-merged"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::merge(subprocess::Fd::STDOUT)).expect("fd 3 merges into stdout");
    let mut child = cmd.spawn().expect("spawn");
    let mut buf = Vec::new();
    child.stdout().expect("stdout reader").read_to_end(&mut buf).await.expect("read");
    let _ = child.wait().await;
    assert_eq!(buf, b"fd3-merged");
}

/// fd >= 3 as a merge SOURCE into a piped In target (one parent writer, several child read
/// fds — the user-decided shape): fd 3 is a dup of the owned stdin read end; testbin's
/// `fd3-echo` copies fd 3 to stdout, so the parent's stdin writes round-trip through the DUP.
#[cfg(unix)]
#[tokio::test]
async fn async_fd3_source_merges_into_piped_stdin() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-echo"]);
    cmd.stdin(subprocess::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::merge(subprocess::Fd::STDIN)).expect("fd 3 merges into stdin");
    let mut child = cmd.spawn().expect("spawn");
    let mut stdin = child.stdin().expect("stdin writer");
    stdin.write_all(b"via-the-dup").await.expect("write");
    drop(stdin); // the parent writer is the ONLY write end — drop is EOF for the child
    let mut buf = Vec::new();
    child.stdout().expect("stdout reader").read_to_end(&mut buf).await.expect("read");
    let _ = child.wait().await;
    assert_eq!(buf, b"via-the-dup");
}
```

Run: `cargo test --locked --features tokio --test tokio_io`
Expected: the merge tests FAIL — `spawn` returns the `Unsupported` merge rejection.

- [ ] **Step 2: The opaque stream wrappers** — create `src/tokio/stdio.rs`:

```rust
//! Opaque async child-stream types. Each wraps EITHER tokio's own child stream (tokio-owned
//! std pipes — the default) OR an our-owned reactor-registered pipe end (merge-into-piped
//! targets, where tokio's internal pipe cannot be shared) — std's `ChildStdout` opacity
//! pattern. Public API: `AsyncRead`/`AsyncWrite` only.

use std::pin::Pin;
use std::task::{Context, Poll};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
type OwnedRead = ::tokio::net::unix::pipe::Receiver;
#[cfg(windows)]
type OwnedRead = WinOwnedRead; // Connecting/Ready state machine (see below)

/// The child's stdin (write end). Dropping it closes the pipe (EOF to the child).
pub struct ChildStdin {
    pub(super) inner: InInner,
}

pub(super) enum InInner {
    Tokio(::tokio::process::ChildStdin),
    /// An our-owned merge-target write end (a piped In target with mergers), reactor-registered.
    Owned(OwnedWrite),
}

#[cfg(unix)]
type OwnedWrite = ::tokio::net::unix::pipe::Sender;
#[cfg(windows)]
type OwnedWrite = WinOwnedWrite; // Connecting/Ready state machine (see below)

/// The child's stdout (read end).
pub struct ChildStdout {
    pub(super) inner: OutInner,
}

/// The child's stderr (read end).
pub struct ChildStderr {
    pub(super) inner: OutInner,
}

pub(super) enum OutInner {
    Stdout(::tokio::process::ChildStdout),
    Stderr(::tokio::process::ChildStderr),
    /// An our-owned merge-target pipe end, reactor-registered.
    Owned(OwnedRead),
}

impl AsyncWrite for ChildStdin {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match &mut self.inner {
            InInner::Tokio(s) => Pin::new(s).poll_write(cx, buf),
            InInner::Owned(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            InInner::Tokio(s) => Pin::new(s).poll_flush(cx),
            InInner::Owned(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            InInner::Tokio(s) => Pin::new(s).poll_shutdown(cx),
            InInner::Owned(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// (Windows: `WinOwnedRead` and `WinOwnedWrite` are thin wrappers over ONE shared
// `ConnectingPipe` state machine — the connect transition and JoinError taxonomy exist
// exactly once.)

impl OutInner {
    fn poll_read_inner(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self {
            OutInner::Stdout(s) => Pin::new(s).poll_read(cx, buf),
            OutInner::Stderr(s) => Pin::new(s).poll_read(cx, buf),
            OutInner::Owned(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncRead for ChildStdout {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_read_inner(cx, buf)
    }
}
impl AsyncRead for ChildStderr {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_read_inner(cx, buf)
    }
}

impl std::fmt::Debug for ChildStdin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildStdin").finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ChildStdout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildStdout").finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ChildStderr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildStderr").finish_non_exhaustive()
    }
}
```

Declare in `src/tokio.rs`: `#[path = "tokio/stdio.rs"] mod stdio;` + `pub use stdio::{ChildStderr, ChildStdin, ChildStdout};`

Change the accessors in `src/tokio/child.rs` (and add the owned-end stash, filled by Step 4):

```rust
    pub fn stdin(&mut self) -> Option<super::stdio::ChildStdin> {
        if let Some(owned) = self.take_owned_in(crate::stdio::Fd::STDIN) {
            return Some(super::stdio::ChildStdin { inner: owned });
        }
        self.child
            .stdin
            .take()
            .map(|s| super::stdio::ChildStdin { inner: super::stdio::InInner::Tokio(s) })
    }
    pub fn stdout(&mut self) -> Option<super::stdio::ChildStdout> {
        if let Some(owned) = self.take_owned_out(crate::stdio::Fd::STDOUT) {
            return Some(super::stdio::ChildStdout { inner: owned });
        }
        self.child
            .stdout
            .take()
            .map(|s| super::stdio::ChildStdout { inner: super::stdio::OutInner::Stdout(s) })
    }
    pub fn stderr(&mut self) -> Option<super::stdio::ChildStderr> {
        if let Some(owned) = self.take_owned_out(crate::stdio::Fd::STDERR) {
            return Some(super::stdio::ChildStderr { inner: owned });
        }
        self.child
            .stderr
            .take()
            .map(|s| super::stdio::ChildStderr { inner: super::stdio::OutInner::Stderr(s) })
    }
```

`take_owned_out(fd) -> Option<OutInner>` is a plain `BTreeMap::remove` yielding the platform `OwnedRead`, wrapped in `OutInner::Owned` — Unix converts the stashed `ParentEnd::Reader` via `pipe::Receiver::from_owned_fd(OwnedFd::from(reader))` (debug-tripwire-then-`None` on failure, the Task-2 disposition); Windows yields the stashed `WinOwnedRead` DIRECTLY — the `NamedPipeServer` and its connect task were created at spawn, inside the runtime, so no conversion (and no `from_raw_handle`, which would double-register the IOCP handle) exists here. `communicate` in `src/tokio/pump.rs` keeps compiling unchanged (the wrappers are `AsyncRead`/`AsyncWrite`); `tests/tokio_io.rs`'s existing uses of `child.stdout()` keep compiling (still `AsyncRead`).

- [ ] **Step 3: The Windows overlapped pipe pair — via tokio's PUBLIC named-pipe API** (no
raw FFI, no `unsafe`, no new windows-crate features). Std's own child-stdio pipes are
uniquely-named named pipes with an overlapped parent end; tokio's `ServerOptions` creates
exactly that end first-party, and `std::fs::OpenOptions` opens the synchronous client end
(std's spawn duplicates stdio handles inheritable itself, so no inheritance flag is needed
on our side).

**Verified empirically (2026-07-14 and 2026-07-16) and pinned by this step's unit tests:**
(a) WITHOUT `connect()`, server-end reads NEVER complete (hang) even after the client wrote —
the connect is mandatory; (b) with the client already opened, `server.connect()` resolves
`Ready(Ok(()))` at the FIRST poll (`ERROR_PIPE_CONNECTED`); (c) a squatted name makes
`first_pipe_instance(true)` creation fail `PermissionDenied` — it can never silently attach;
(d) there is NO retry loop — any `PermissionDenied` (squatter or ACL denial) is terminal and
surfaces as a typed error; spinning cannot fix either cause; (e) the full pair → connect →
real child writes → server `read_to_end` E2E works; (f) connect armed with NO client yet is
genuinely `Pending` and completes via a reactor wakeup when a client opens — BOTH connect
worlds are verified, no timing assumption; (g) the single client slot (`max_instances(1)`)
is EXCLUSIVE — a second client open fails with raw OS error 231 (`ERROR_PIPE_BUSY`; its
`ErrorKind` is unstable `Uncategorized`, so tests assert the raw code); (h) In-direction:
DROPPING the server end delivers buffered data first, then clean EOF to the client (the
teardown is processed via the runtime — the standard don't-block-the-reactor rule applies),
whereas `disconnect()` DISCARDS buffered data and is never used.

Add to `src/tokio/stdio.rs` (Windows-gated):

```rust
/// An "anonymous" pipe with an overlapped, reactor-registered parent end (std's `anon_pipe`
/// technique via tokio's PUBLIC API): a uniquely named server end (ours) + a sync
/// `OpenOptions` client end (the child's; std's spawn duplicates stdio handles inheritable
/// itself). Out-direction: parent reads, child writes. Any failure surfaces as a typed
/// `Err` — no retry. Call inside the runtime.
#[cfg(windows)]
pub(crate) fn overlapped_out_pipe(
) -> Result<(::tokio::net::windows::named_pipe::NamedPipeServer, std::os::windows::io::OwnedHandle), crate::error::Error> {
    overlapped_pipe(false)
}

/// The In-direction twin: parent writes (outbound server), child reads. Dropping the server
/// end delivers buffered data first, then clean EOF to the client — verified; `disconnect()`
/// would DISCARD buffered data and is deliberately never used.
#[cfg(windows)]
pub(crate) fn overlapped_in_pipe(
) -> Result<(::tokio::net::windows::named_pipe::NamedPipeServer, std::os::windows::io::OwnedHandle), crate::error::Error> {
    overlapped_pipe(true)
}

/// Unique, UNPREDICTABLE name: pid + counter (in-process uniqueness independent of the RNG)
/// + a 64-bit `getrandom` component — std parity (std randomizes its anon-pipe names): an
/// unpredictable name turns squatting/slot-stealing from name arithmetic into an
/// enumeration race.
#[cfg(windows)]
fn overlapped_pipe(
    parent_writes: bool,
) -> Result<(::tokio::net::windows::named_pipe::NamedPipeServer, std::os::windows::io::OwnedHandle), crate::error::Error> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|e| crate::error::Error::Io(std::io::Error::other(e)))?;
    let name = format!(
        r"\\.\pipe\subprocess.{}.{}.{:016x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        u64::from_ne_bytes(r)
    );
    overlapped_pipe_named(&name, parent_writes)
}

/// The name-parameterized core (split so the unit tests can pin the squat, slot-theft, and
/// connect-state contracts against a name they control).
#[cfg(windows)]
pub(crate) fn overlapped_pipe_named(
    name: &str,
    parent_writes: bool,
) -> Result<(::tokio::net::windows::named_pipe::NamedPipeServer, std::os::windows::io::OwnedHandle), crate::error::Error> {
    use ::tokio::net::windows::named_pipe::ServerOptions;

    let server = ServerOptions::new()
        .access_inbound(!parent_writes)
        .access_outbound(parent_writes)
        .first_pipe_instance(true) // a squatted name FAILS here — never silently attach
        .reject_remote_clients(true)
        .max_instances(1)
        .create(name)
        .map_err(|e| {
            // Terminal either way (no retry). PermissionDenied is squat-suspected — the
            // security-relevant case — and logs at warn; anything else at debug.
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                log::warn!("merge-target pipe name {name} already claimed (squat suspected) or ACL-denied: {e}");
            } else {
                log::debug!("merge-target pipe creation failed for {name}: {e}");
            }
            crate::error::Error::Io(std::io::Error::new(
                e.kind(),
                format!("creating merge-target pipe {name}: {e} (PermissionDenied means the name is already claimed — never attached — or creation is denied)"),
            ))
        })?;
    let client = open_client_slot(name, parent_writes)?;
    // The IOCP server has no I/O completions until `ConnectNamedPipe` runs; the caller
    // awaits that in `connect_task` before any read or write.
    Ok((server, client))
}

/// Claim the pipe's SINGLE client slot, immediately after creation and before the name is
/// ever handed anywhere (split out so the slot-theft test drives the production claim
/// path). `max_instances(1)` makes the slot exclusive: if a hostile local client wins the
/// create->open race, THIS open fails (`ERROR_PIPE_BUSY`, verified) and spawn errors out
/// before any child exists or any byte moves — the parent can never read a stranger's
/// bytes, and the worst case is a typed spawn failure. Conversely, once this open
/// succeeds, `first_pipe_instance` + `max_instances(1)` guarantee both handles belong to
/// our own pipe.
#[cfg(windows)]
pub(crate) fn open_client_slot(
    name: &str,
    parent_writes: bool,
) -> Result<std::os::windows::io::OwnedHandle, crate::error::Error> {
    std::fs::OpenOptions::new()
        .read(parent_writes)
        .write(!parent_writes)
        .open(name)
        .map(std::os::windows::io::OwnedHandle::from)
        .map_err(|e| {
            log::warn!("merge-target pipe {name}: client-slot open failed ({e}); slot theft suspected");
            crate::error::Error::Io(std::io::Error::new(
                e.kind(),
                format!("claiming merge-target pipe client slot {name}: {e}"),
            ))
        })
}

/// Spawn the mandatory connect as a real task; the returned `JoinHandle` is itself a future
/// that the stream wrapper polls to completion before its first I/O (`WinOwnedRead` /
/// `WinOwnedWrite`).
#[cfg(windows)]
pub(crate) fn connect_task(
    server: ::tokio::net::windows::named_pipe::NamedPipeServer,
) -> ::tokio::task::JoinHandle<std::io::Result<::tokio::net::windows::named_pipe::NamedPipeServer>> {
    ::tokio::spawn(async move { server.connect().await.map(|()| server) })
}

/// The ONE Connecting/Ready state machine both owned-stream directions share: drives the
/// spawned `ConnectNamedPipe` task to completion, then yields the reactor-registered
/// server. The connect transition and the JoinError taxonomy exist exactly here — never
/// duplicated per direction.
#[cfg(windows)]
pub(super) enum ConnectingPipe {
    Connecting(::tokio::task::JoinHandle<std::io::Result<::tokio::net::windows::named_pipe::NamedPipeServer>>),
    Ready(::tokio::net::windows::named_pipe::NamedPipeServer),
}

#[cfg(windows)]
impl ConnectingPipe {
    /// Drive Connecting -> Ready; yields a borrow of the connected server.
    fn poll_ready_server(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<&mut ::tokio::net::windows::named_pipe::NamedPipeServer>> {
        loop {
            match self {
                ConnectingPipe::Connecting(handle) => match Pin::new(handle).poll(cx) {
                    Poll::Ready(Ok(Ok(server))) => *self = ConnectingPipe::Ready(server),
                    Poll::Ready(Ok(Err(e))) => return Poll::Ready(Err(e)),
                    // A panicked/cancelled connect task is a bug surfaced as an error,
                    // never a false EOF (mirrors the grace_wait JoinError taxonomy).
                    Poll::Ready(Err(join)) => return Poll::Ready(Err(std::io::Error::other(join))),
                    Poll::Pending => return Poll::Pending,
                },
                ConnectingPipe::Ready(server) => return Poll::Ready(Ok(server)),
            }
        }
    }
}

/// The Windows owned read end (Out-direction merge target).
#[cfg(windows)]
pub(super) struct WinOwnedRead(pub(super) ConnectingPipe);

#[cfg(windows)]
impl WinOwnedRead {
    fn poll_read_inner(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let server = std::task::ready!(self.0.poll_ready_server(cx))?;
        Pin::new(server).poll_read(cx, buf)
    }
}

/// The Windows owned WRITE end (In-direction merge target). Dropping it (either state)
/// closes the server handle, which delivers any buffered data first and THEN clean EOF to
/// the child (verified); `disconnect()` is deliberately never called — it DISCARDS
/// buffered data. A drop while still `Connecting` detaches the task, which completes the
/// connect and drops the server — teardown, not a leak.
#[cfg(windows)]
pub(super) struct WinOwnedWrite(pub(super) ConnectingPipe);

#[cfg(windows)]
impl WinOwnedWrite {
    fn poll_write_inner(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let server = std::task::ready!(self.0.poll_ready_server(cx))?;
        Pin::new(server).poll_write(cx, buf)
    }
    // poll_flush_inner / poll_shutdown_inner: the identical two-liner, delegating to the
    // server's poll_flush / poll_shutdown.
}
```

(`use std::future::Future;` joins the imports. `OutInner::Owned`'s Windows type is
`WinOwnedRead` (its `poll_read` arm delegates to `poll_read_inner`); `InInner::Owned`'s is
`WinOwnedWrite` (its `poll_write`/`poll_flush`/`poll_shutdown` arms delegate to the
`*_inner` trio).)

Unit tests — create `src/tokio/stdio_tests.rs` (declared inside `stdio.rs` with the crate's
`#[cfg(test)] #[path = ...]` pattern), Windows-gated; these permanently pin the empirical
findings (a)–(h) in CI:

```rust
//! Unit tests for the Windows overlapped merge-target pipe (the fns are pub(crate)).
#![cfg(windows)]

use tokio::io::AsyncReadExt;

// The full Out-direction production shape: pair -> (connect via connect_task's underlying
// await) -> a REAL child writes on the client end -> the server end reads to EOF. Pins the
// connect-mandatory contract: without the connect, this read never completes.
#[tokio::test]
async fn overlapped_pipe_reads_a_real_childs_output() {
    let (server, client) = super::overlapped_out_pipe().expect("pipe pair");
    // The production seam: connect_task genuinely awaits the mandatory connect (immediate
    // here — the client is already open).
    let mut server = super::connect_task(server).await.expect("join").expect("connect");
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "echo overlapped-e2e"])
        .stdout(std::process::Stdio::from(client))
        .spawn()
        .expect("spawn writer child");
    let mut buf = Vec::new();
    server.read_to_end(&mut buf).await.expect("read to EOF");
    child.wait().expect("reap");
    assert_eq!(String::from_utf8_lossy(&buf).trim(), "overlapped-e2e");
}

// The In-direction production shape: the parent writes through the outbound server; the
// client end is a real child's stdin (findstr "^" echoes every line). Dropping the server
// delivers the buffered payload THEN clean EOF — the fact ChildStdin's drop contract rests
// on. The child's stdout is read via spawn_blocking so the runtime keeps ticking (the
// server teardown is processed via the runtime).
#[tokio::test]
async fn overlapped_in_pipe_feeds_a_real_childs_input() {
    use tokio::io::AsyncWriteExt;
    let (server, client) = super::overlapped_in_pipe().expect("pipe pair");
    let mut server = super::connect_task(server).await.expect("join").expect("connect");
    let mut child = std::process::Command::new("findstr")
        .arg("^")
        .stdin(std::process::Stdio::from(client))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn reader child");
    server.write_all(b"in-e2e\r\n").await.expect("write");
    drop(server); // buffered data first, then EOF (never disconnect(): it discards)
    let mut stdout = child.stdout.take().expect("piped stdout");
    let out = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut s = String::new();
        stdout.read_to_string(&mut s).expect("read child stdout");
        s
    })
    .await
    .expect("join");
    child.wait().expect("reap");
    assert_eq!(out.trim(), "in-e2e");
}

// A squatted name must ERROR (never attach to the stranger's pipe) in BOTH orientations:
// first_pipe_instance makes the second create fail PermissionDenied.
#[tokio::test]
async fn overlapped_pipe_never_attaches_to_a_squatted_name() {
    let name = format!(r"\\.\pipe\subprocess-test-squat.{}", std::process::id());
    let _squatter = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .expect("squat the name");
    for parent_writes in [false, true] {
        let err = super::overlapped_pipe_named(&name, parent_writes).expect_err("must not attach");
        assert!(
            matches!(&err, crate::error::Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "squatted name must surface PermissionDenied (parent_writes={parent_writes}), got {err:?}"
        );
    }
}

// max_instances(1) slot exclusivity — the fact that closes the create->open client race —
// asserted through the CRATE'S OWN claim path: after a thief takes the single client slot,
// the production `open_client_slot` must fail typed (never a silent wrong-attach), exactly
// what `overlapped_pipe_named` does when it loses the race.
#[tokio::test]
async fn overlapped_pipe_client_slot_is_exclusive() {
    let name = format!(r"\\.\pipe\subprocess-test-slot.{}", std::process::id());
    // The same instance overlapped_pipe_named creates (Out orientation).
    let _server = tokio::net::windows::named_pipe::ServerOptions::new()
        .access_inbound(true)
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .create(&name)
        .expect("create");
    let _thief = std::fs::OpenOptions::new().write(true).open(&name).expect("thief takes the slot");
    let err = super::open_client_slot(&name, false)
        .expect_err("a stolen slot must fail our claim, never silently attach");
    // ERROR_PIPE_BUSY (231) has no stable ErrorKind mapping — assert the raw code (verified).
    assert!(
        matches!(&err, crate::error::Error::Io(e) if e.raw_os_error() == Some(231)),
        "ERROR_PIPE_BUSY through the production claim path, got {err:?}"
    );
}

// The OTHER connect world: armed with NO client, connect is genuinely Pending (asserted,
// not assumed), and a late client open completes it via a reactor wakeup. Together with
// the two E2E tests above (client-already-open => immediate), BOTH connect worlds are
// pinned — no timing assumption.
#[tokio::test]
async fn overlapped_pipe_connect_pending_completes_on_late_client_open() {
    use std::future::Future;
    use std::io::Write;
    let name = format!(r"\\.\pipe\subprocess-test-pending.{}", std::process::id());
    let mut server = tokio::net::windows::named_pipe::ServerOptions::new()
        .access_inbound(true)
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .create(&name)
        .expect("create");
    {
        let mut connect = std::pin::pin!(server.connect());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            connect.as_mut().poll(&mut cx).is_pending(),
            "no client exists yet — ConnectNamedPipe must be genuinely pending"
        );
        let mut client = std::fs::OpenOptions::new().write(true).open(&name).expect("late client");
        connect.as_mut().await.expect("connect completes via the reactor wakeup");
        client.write_all(b"pending-path").expect("client write");
    } // client dropped => EOF
    let mut buf = Vec::new();
    server.read_to_end(&mut buf).await.expect("read to EOF");
    assert_eq!(buf, b"pending-path");
}
```

(Cargo.toml gains `getrandom` under `[target.'cfg(windows)'.dependencies]` (with its `std`
feature, for the `io::Error` conversion) — the pipe-name randomness above; tokio `net` is
already enabled and no windows-crate items are used. A `PermissionDenied` from a fresh
random name means a squatter or an ACL denial — both are surface-worthy errors, so there is
deliberately no retry: spinning cannot fix either cause, and a bounded retry would be an
arbitrary cap.)

- [ ] **Step 4: Pre-resolve piped merge targets in the async spawn** — in `src/tokio/spawn.rs`, BEFORE the `resolve_stdio` call: detect std slots that are (a) configured `Pipe(_)` (EITHER direction — user decision 2026-07-14: least surprise, no gratuitous `Unsupported` cavities; sync permits both) and (b) the target of at least one `Merge` from another configured slot. For each such target: create OUR pipe —
  - `Direction::Out` target (stderr/stdout capture): Unix `std::io::pipe()`; Windows `super::stdio::overlapped_out_pipe()` + `connect_task` (created here, INSIDE the runtime). The CHILD gets the write end; the parent read end is stashed.
  - `Direction::In` target (one parent writer feeding several child read fds): Unix `std::io::pipe()` with the ends swapped (child reads, parent writes); Windows `super::stdio::overlapped_in_pipe()` + `connect_task` (both written out in Step 3).

  Record parent ends in a `BTreeMap<Fd, OwnedStd>` stash (`OwnedStd` = a small cfg'd enum local to the tokio module: Unix `ParentEnd`; Windows `WinOwnedRead`/`WinOwnedWrite`), and REMOVE the target and its merging slots from the map handed to `resolve_stdio`, assigning child ends: the target slot and each merging STD slot (raw < 3) get `StdStdio::from(child_end)` / `StdStdio::from(dup(&child_end)?)` (`crate::child::spawn::dup`, already `pub(crate)`). A merging slot with `raw() >= 3` (Unix only — Windows rejected fd ≥ 3 earlier) is NOT assignable as std stdio: push `(slot, dup(&child_end)?)` onto the fd ≥ 3 child-ends collection that Step 3's command-fds block consumes, so it is dup2'd into the child like any other fd ≥ 3 end — sync parity, never silently dropped. The stash rides into `Child::from_parts` next to Task 2's `pipes` map.

`take_owned_out(fd)` / `take_owned_in(fd)` in `src/tokio/child.rs` are plain
`BTreeMap::remove`s with TAKE semantics — first call moves the owned end out (`Some`);
every later call returns `None`, exactly matching the tokio-owned branch's `Option::take`.
The Unix variants convert via `pipe::Receiver::from_owned_fd` / `pipe::Sender::from_owned_fd`
with the Task-2 disposition on a conversion failure (debug tripwire + `log::warn!` +
`None`); the Windows variants have no conversion (the `NamedPipeServer` and its connect
task were constructed at spawn — reconstructing via `from_raw_handle` would double-register
the IOCP handle). Pinned by `async_merged_stream_accessor_has_take_semantics` (Step 1).

Order of assembly inside spawn (unchanged otherwise): merge pre-pass → `resolve_stdio` → std-slot assignment loop (now skipping slots the pre-pass already assigned) → `prepare` → command-fds → spawn → identity → attach → `from_parts`.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --locked --features tokio --test tokio_io`
Expected: PASS on the host — including the merge tests (Windows exercises the overlapped pair in BOTH directions). Then WSL (Unix merge path + the fd ≥ 3 merge-source tests).

- [ ] **Step 6: Update `TODO.md`** — in the "Lifecycle / async (from Plan 8)" section, mark the two deferred bullets done and the foreign line done:

```markdown
- [x] (Plan 10) Async parent-end access for fd ≥ 3 via tokio pipe ends (Unix, mirroring sync).
- [x] (Plan 10) Async merge-into-a-piped-target (all platforms; Windows via an owned
      overlapped named-pipe pair).
- [x] (Plan 10) Async foreign `Process` (introspect/wait/kill/graceful on a non-owned process).
```

(Keep the section's surrounding text and the other bullets exactly as they are.)

- [ ] **Step 7: Full regression + lint + WSL + commit**

Run the Global Constraints battery (host both feature modes + release, fmt, clippy host + cross-target, WSL both suites).

```bash
git add Cargo.toml Cargo.lock src/tokio/stdio.rs src/tokio/stdio_tests.rs src/tokio/spawn.rs src/tokio/child.rs src/tokio/pump.rs src/child/spawn.rs src/tokio.rs tests/tokio_io.rs testbin/main.rs TODO.md
git commit -m "feat: async merge-into-piped-target on all platforms via owned pipes (tokio named-pipe server end on Windows)"
```

---

## Panel dispositions (settled — re-raise only with new evidence)

- **Merge pre-pass vs extending `resolve_stdio`** — declined (rounds 1–2): the stated
  tradeoff stands. The suggested caller-supplied pipe-factory hook would color the shared
  core with per-caller async pipe kinds — the exact thing Global Constraints forbid; the
  pre-pass is bounded to piped merge targets (both directions), and the core's retained
  `Deferred` rejection makes silent divergence impossible (any unhandled shape errors
  loudly, it cannot fall through).
- **Overlapped-pipe connect-state + collision handling** — RESOLVED empirically (probes
  2026-07-14 + 2026-07-16; facts (a)–(h) pinned by the Step-3 unit tests): connect is
  mandatory; BOTH connect worlds verified (client-already-open => first-poll Ready;
  no-client => genuinely Pending, completed by a reactor wakeup); the retry loop stays
  REMOVED — any `PermissionDenied` (squatter OR ACL denial) surfaces as a typed error;
  spinning cannot fix either cause.
- **Client-slot race (round 4, `create` -> client `open` window)** — closed FAIL-SHUT, not
  by timing: `max_instances(1)` makes the single client slot exclusive, so a hostile local
  client winning the race makes OUR open fail (`ERROR_PIPE_BUSY` 231, verified) before any
  child exists or any byte moves — the parent can never read a stranger's bytes; the worst
  case is a typed spawn failure (local DoS), and the name's 64-bit `getrandom` component
  (std parity) reduces even that to an enumeration race. Round 5: the claim is split into
  `open_client_slot` so the pin (`overlapped_pipe_client_slot_is_exclusive`) drives the
  PRODUCTION claim path, not a raw-OS stand-in.
- **`wait_exit` (Windows) false-resolve handling (round 4, +round 5)** — a resolved
  unbounded watch means exit by construction (no timeout path; cancel-at-drop never
  resolves), but the release path RE-WATCHES rather than trusting the cross-file contract
  (the Unix false-positive re-await idiom) — never a fabricated error, never a false
  'exited'; the debug_assert stays as the test-time tripwire, and each release-mode
  re-watch logs a `warn` so the impossible case leaves a trace.
- **Failure-trace severity (round 4)** — pipe-creation `PermissionDenied` logs `warn`
  (squat-suspected — the security case), other creation failures `debug`; a failed
  client-slot open logs `warn` (theft-suspected); `fd_read_end`/`fd_write_end` conversion
  failures log `warn` (they silently change observable child behavior).
- **`INFINITE-1` grace clamp disposition** — revised (round 3): the deliberate-cap comment is
  retained; additionally, a `debug_assert` flags the clamp at test time, and `grace_wait`'s
  doc warns of the ~49-day Windows platform limit.
- **`fd_read_end`/`fd_write_end` conversion-failure drop** — affirmed, revised round 4: the
  debug-tripwire disposition gains a `log::warn!` so the release-mode drop leaves a trace
  (the dropped end closes the fd — the child observes EOF/EPIPE, never a hang). Doc strings
  state all failure modes and consequences.
- **foreign lone watch-Err subsumed by a kill Err** — revised (round 3): the user-dispositioned
  subsumption precedent carries; additionally, if the watch fails before the kill, it is
  logged at debug level before returning the kill error — both failures leave a trace
  (backed by the REAL `log = "0.4"` dependency, user-approved 2026-07-14).
- **Round-3 connect/Pending findings** — RESOLVED structurally: the poll-once connect is
  gone; `connect_task` genuinely awaits `ConnectNamedPipe` on the runtime and the stream
  wrapper polls the `JoinHandle` before its first I/O. Round 4: both connect worlds are now
  TESTED (`overlapped_pipe_connect_pending_completes_on_late_client_open` + the E2E pair).
- **In-direction merge targets** — USER DECISION 2026-07-14 ("least surprise; fewer
  Unsupported cavities"): supported symmetrically. Round 4: fully written out —
  `overlapped_in_pipe` + `WinOwnedWrite` implementation (Step 3), the drop-EOF/never-
  `disconnect()` teardown contract (verified: `disconnect()` discards buffered data), and
  tests (`async_merge_into_piped_stdin_feeds_the_merged_child`,
  `overlapped_in_pipe_feeds_a_real_childs_input`, the both-orientation squat test).
- **fd ≥ 3 merge sources into piped std targets** — supported via the pre-pass routing dup'd
  ends into command-fds (sync parity); pinned by `async_fd3_source_merges_into_piped_stdout`
  and `async_fd3_source_merges_into_piped_stdin` (both written in Task 3 Step 1, round 4 —
  the earlier ledger claim predated the tests; the round-4 panel caught the gap).
- **`fault_observer` test scaffolding in `blocking_watch` (round 4)** — kept BY DESIGN: the
  suggested alternative (re-observing release via `is_alive` polling) is time-sync, which
  this repo forbids; the observer is `cfg(test)`-gated, uses a real sync primitive, and its
  module doc now states it is deliberate scaffolding (the `wait::fault` pattern).
- **Panel-authored plan mutations (round 3)** — adjudicated like subagent suggestions: kept
  the clamp assert/docs/log sites; FIXED the hallucinated `ProcessGroup::terminate`;
  SUPERSEDED the assert+linked-invariant block with the by-construction cfg'd slot list.
  Every panel run is now followed by a `git status/diff` check.
- **Round-4 conciseness cuts** — 25 adopted (several verbatim), 3 adopted-modified with the
  load-bearing clause kept (the empirical-provenance header, the pre-pass tradeoff record,
  the mutation-adjudication entry), 3 REJECTED by name: the `# Runtime` panic contract on
  `wait()` (public contract, Plan-9 doc parity) and the two graceful docstring
  error-ordering sentences (byte-parity with `src/process/graceful.rs:25`/`:85` — the
  "docs mirror sync" Global Constraint).
- **Round 5 (conditionally-approved — final round)** — all four conditions applied:
  `ConnectingPipe` extracted as the ONE shared connect state machine (`WinOwnedRead`/
  `WinOwnedWrite` are thin wrappers — no hand-synced copies); the `wait_exit` re-watch
  gained its release-mode `warn`; the slot-theft pin drives the production
  `open_client_slot`; the wrong-direction put-back arms gained a round-trip test
  (`async_fd3_wrong_direction_take_puts_the_end_back`). All six conciseness cuts adopted
  (one was already satisfied — the write-end arm carries no inline comment).
