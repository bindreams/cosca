# Plan 9 — Async owned control (tokio mirror, part 2)

Async control surface for `subprocess::tokio::Child`: explicit kill/tree ops plus the
graceful-escalation trio, mirroring the sync contracts exactly. Foreign async `Process` is
**Plan 10** (split decision recorded 2026-07-05).

## Scope

**In:** `tokio::Child::{kill, kill_tree, terminate, terminate_tree, graceful_shutdown,
graceful_shutdown_tree}`; the async grace-wait mechanism; async builder mirror of
`contain_with(mode)` + `nesting(nesting)` (rounds out the control story — tree-op semantics
depend on the containment mode, and mode-specific async tests need them; 2-method hand-mirror
per the recorded builder decision).

**Out (deferred):** async foreign `Process` (Plan 10); fd ≥ 3 `AsyncFd` parent ends;
merge-into-piped-target (both still rejected at spawn, unchanged from Plan 8).

## Architecture

Everything reuses Plan 5–8 primitives; the one new mechanism is the **reactor-native** async
grace-wait `tokio::wait::grace_wait(id, grace) -> Result<bool, Error>` (user decision
2026-07-05, revising the earlier spawn_blocking choice after the plan panel quantified its
cancellation cost — a dropped spawn_blocking watcher detaches and parks a blocking-pool thread
for up to `grace`):

- **Linux:** the existing identity-verified pidfd opener (`wait::backend::open_verified`, made
  `pub(crate)`) registered with the reactor via `AsyncFd` — readable = exited (POLLIN zombie /
  POLLHUP reaped), POLLERR = error, mirroring the sync backend. An empty/unclassified
  readiness (tokio's documented `ready()` false positive) re-awaits after `clear_ready` — the
  same spurious-wake discipline as the macOS loop (round-11 fix; the classifier returns a
  retry signal, never a false "exited" or a false watch failure).
- **macOS:** a **shared** arm primitive `wait::backend::arm_proc_exit(id) -> Option<Kqueue>`
  (kqueue `EVFILT_PROC|NOTE_EXIT`, `EV_RECEIPT` synchronous arm + identity re-verify — still on
  nix, whose `Kqueue` exposes its fd via `AsFd`) with two consumers: the sync `block_until_exit`
  consumes it, and the async watch registers the fd via `AsyncFd` (a 3-line `AsRawFd` adapter
  newtype). One definition of the subtle arm dance (the shape Linux already has via
  `open_verified`); no new `unsafe`. Async readiness can be spurious, so exit is concluded only
  on an actually drained `NOTE_EXIT` (`drain_proc_exit`; empty drain → `clear_ready` →
  re-await). The `EV_ERROR` disposition stays byte-identical to the current sync backend.
- **Windows:** no pollable process handle exists — a `spawn_blocking` watcher waits on
  `WaitForMultipleObjects([process_handle, cancel_event])` with the grace as the kernel wait's
  timeout; a drop-guard signals the manual-reset cancel event when the grace-wait future goes
  away, releasing the watcher promptly (user decision 2026-07-12, superseding the earlier
  detached-thread floor after the plan panel surfaced its costs — a blocking-pool thread parked
  ≤ grace and a `Runtime::drop` shutdown stall ≤ grace, since dropping a runtime joins detached
  blocking tasks). No new deps or features (`Win32_Security` etc. already enabled). A
  `JoinError` panic is propagated via `resume_unwind` (a panic in the watcher is a bug, not an
  I/O condition); a shutdown-cancelled watcher surfaces as a distinct "runtime shutting down"
  error rather than an opaque one. The drop-guard's `SetEvent` is asserted in EVERY build
  (round 14): it has no documented failure mode on a live owned event, and a silent failure
  would degrade cancellation to an unbounded park — a diagnosable panic beats a hung
  `Runtime::drop`; the assert yields during an unwind (no double-panic abort). The wait's
  `GetLastError` is captured BEFORE `CloseHandle` (round 15 — also fixes the same latent
  ordering in the shipped `block_until_exit`), and the `INFINITE-1` grace cap is deliberate:
  the cancel event is the release mechanism for large graces, the cap the last-resort bound.
- The grace bound is `tokio::time::timeout(grace, exit_watch)` — a failure bound on a genuine
  external event (child exit), the sanctioned timeout exception.
- **Features:** tokio gains `net` (solely for `AsyncFd`) and `time` (solely for the grace
  bound); both additive, no new crates. The Unix grace bound makes the graceful methods need
  the runtime's IO **and** time drivers (tokio panics on a runtime missing either — documented
  on both public methods, mirroring the spawn doc's runtime note); the Windows tree doc also
  names the blocking-pool sizing consequence (one thread per in-flight grace-wait, ≤ grace).
- **Cancellation:** dropping a graceful future mid-grace cancels the watch on every platform —
  on Unix the `AsyncFd` deregisters and the fd closes; on Windows the drop-guard's cancel
  event releases the blocking watcher promptly. The watch is non-reaping and signal-free: the
  child stays owned and `Drop`'s teardown still applies. Documented on both graceful methods
  and covered by deterministic poll-once-then-drop tests plus a pre-signaled-cancel release
  test on the Windows primitive.

## API

Only the graceful pair is genuinely `async` — the rest are signal-only/bounded calls and stay
plain `fn` (Plan-8 precedent: `try_wait`/`detach` are non-async). Receivers follow tokio-`Child`
convention (`&mut self` wherever the inner tokio child is driven; the sync `&self` counterparts
lean on `SharedChild`, which the async handle does not have):

| method | recv | composition | platforms |
|---|---|---|---|
| `fn kill(&mut self)` | `&mut` | `self.child.start_kill()` (handle-bound, no pid race) | all |
| `fn kill_tree(&mut self)` | `&mut` | `require_contained` → `attached.hard_kill()` → backstop `start_kill()` | all (contained) |
| `fn terminate(&self)` | `&` | `wait::terminate(self.id)` (SIGTERM, identity-bound) | Unix; Windows `Unsupported` |
| `fn terminate_tree(&self)` | `&` | `require_contained` → `attached.terminate(pid)` (signal-only) | all (contained) |
| `async fn graceful_shutdown(&mut self, grace) -> ExitStatus` | `&mut` | `wait::terminate` → grace-wait (an `Err` does not abort) → `start_kill` unless exit observed → `wait().await` (reap) → surface any watch `Err` | Unix; Windows `Unsupported` |
| `async fn graceful_shutdown_tree(&mut self, grace) -> ExitStatus` | `&mut` | `terminate_tree` (its guard fail-fasts before any signal; the sync original's extra top-level guard is dropped as behaviorally dead) → grace-wait (**non-reaping**; an `Err` does not abort) → `kill_tree` → `wait().await` (reap) → surface any watch `Err` | all (contained) |

All return `Result<_, Error>`; error contracts identical to sync: `require_contained` (a new
private guard on the async `Child`, mirroring sync `require_contained`) errors `Unsupported`
for `Containment::{None, Delegated}`; lone `terminate`/`graceful_shutdown` error `Unsupported`
on Windows via `wait::terminate` exactly as sync does.

Divergence from sync `graceful_shutdown`: sync reaps the graceful path via `wait_timeout`
(SharedChild); async grace-waits non-reaping then reaps via `wait().await` — on the graceful
path the child is already a zombie so the await returns immediately. Observable behavior
(returned `ExitStatus`, signal-distinguishes-forced) is identical.

## Ordering invariants (carried over; one added 2026-07-12)

- **Hard-sweep-before-reap:** `graceful_shutdown_tree` grace-waits with the non-reaping watch so
  `kill_tree` sweeps while the root pid (= `killpg` group id) is still valid; the reap is last.
- **Watch-failure escalation (added rounds 9–10, refined round 15):** a grace-watch `Err`
  cannot strand a signaled child — ALL FOUR graceful bodies (lone + tree, sync + async; the
  sync bodies are reordered to match) escalate and reap first, then surface the watch error
  (a kill/sweep/reap error wins — deliberate subsumption, mirroring `kill_tree`'s both-fail
  disposition, now also stated in both `kill_tree` rustdocs). Tree refinement: a sweep `Err`
  supersedes even an observed graceful root exit (survivors may remain) — the root is still
  reaped first when its exit was observed (the reap cannot hang on a zombie; a reap `Err`
  there is dropped so it cannot mask the live-survivors failure); on a live root the error
  propagates unreaped (`Drop` teardown applies). Lone caveat: the graceful/forced
  signal distinction is best-effort at the boundary (a self-exit between grace elapse and the
  `SIGKILL` reports its own status) — documented on both twins. Covered by four seam-forced stranding tests (shared
  `wait::fault` take-flag, consumed by `block_until_exit`, `Child::wait_timeout`, and
  `grace_wait`), with the reap proven by identity on Linux (`!id.exists()` — /proc keeps a
  zombie visible there; macOS's proc_pidinfo and Windows do not, so the assert is
  Linux-gated and Linux pins the platform-independent ordering).
- **No concurrent wait:** all composed ops take `&mut self`, so no `wait()` future can be in
  flight during teardown (statically enforced — stronger than the sync doc-contract).
- **Drop interplay:** unchanged. After a graceful op reaps, `Drop`'s `reap_now(done_ok=true)`
  observes tokio `Done` and no-ops; `block_until_exit` on the un-reaped owned child is safe
  (at most a zombie — the pattern sync `graceful_shutdown_tree` already uses).

## Files

- `src/tokio/child.rs` — `kill`, `kill_tree`, `terminate_tree`, `require_contained` (~40 lines).
- `src/tokio/wait.rs` (new) — `grace_wait` + the per-OS `exit_watch` arms; unit tests in
  `src/tokio/wait_tests.rs` (`grace_wait` is `pub(crate)`, unreachable from `tests/`).
- `src/tokio/child/graceful.rs` (new) — `terminate` + the two graceful ops. A **submodule of
  `tokio::child`** (exactly like sync `src/child/graceful.rs` under `child`), so it reaches the
  private `require_contained` and fields without widening their visibility.
- `src/child/graceful.rs` — the sync twins (lone + tree) are reordered to escalate-then-surface
  on a watch `Err` (the watch-failure invariant above); `src/wait.rs` gains the shared watch
  fault seam, consumed at the head of `block_until_exit`, `Child::wait_timeout`
  (`src/child/lifecycle.rs` — the sync lone path's watch), and both `grace_wait` arms;
  stranding-test twins in `src/child/graceful_tests.rs` + `src/tokio/child/graceful_tests.rs`.
- `src/tokio/command.rs` — `contain_with`, `nesting` mirrors (delegate to the sync builder).
- `src/wait/linux.rs` — `open_verified` becomes `pub(crate)`.
- `src/wait/macos.rs` — the existing nix arm sequence extracted into `pub(crate) arm_proc_exit`
  + `drain_proc_exit`, with the receipt dance single-sourced as `arm_note_exit_on(kq, pid)`
  (also arms the decoy in the composition test — no hand-rolled twin to drift);
  `block_until_exit` consumes the arm (`kill`/`terminate` unchanged).
- `src/wait/windows.rs` — `new_cancel_event` + `signal_cancel` + `block_until_exit_or_cancel`
  (the event-cancellable wait; the existing fns are unchanged).
- `src/containment.rs` + `src/child.rs` — the WHOLE `require_contained` guard (debug-assert +
  actionability check + error) is single-sourced as
  `containment::require_contained(Containment, &Attached)`; sync and async delegate.
- `src/containment/treewalk.rs` + `src/containment/dispatch_tests.rs` — a test-only fault seam
  (`force_root_kill_noop`) makes `kill_tree`'s handle backstop provably load-bearing, tested on
  BOTH the sync and async paths (recorded decision — matches the Plan-8 seam pattern).
- `testbin/main.rs` — also a Windows `control-block-ignore-break`/`spawn-grandchild-ignore-break`
  pair (handler returns TRUE), so the Windows hard sweep is provably load-bearing.
- `testbin/main.rs` — new `spawn-grandchild-ignore-term` mode (both tree members SIG_IGN
  SIGTERM), for the surviving-descendant escalation test.
- `tests/tokio_control.rs` (new) — see below.

## Testing

Mirror `tests/graceful.rs`'s `child_*` cases plus the sync lifecycle tree tests, async:
terminate-sends-SIGTERM; graceful path (exits within grace, status clean); escalation path
(`SIG_IGN` child + `Duration::ZERO` grace → forced, signal = KILL — deterministic, no timers);
tree teardown (grandchild death proven by control-socket EOF); tree graceful-root path;
**tree escalation with a surviving multi-member tree** (`spawn-grandchild-ignore-term`: both
members ignore SIGTERM, so the hard sweep — not the soft signal — tears down root AND
grandchild); **survivor sweep after a graceful root exit** (`spawn-grandchild-stubborn-child`:
the root honors SIGTERM but the grandchild ignores it — the exact case the sweep-before-reap
invariant protects; a sync twin keeps the suites scenario-aligned); **cancellation contract** (poll the graceful future exactly once via
`Waker::noop` with a `Duration::MAX` grace — the watch cannot time out and the never-exiting
target cannot exit on the soft signal, so a first-poll `Ready` can only be a genuine watch
failure, surfaced loudly rather than asserted as `Pending`; the lone Unix case uses a
SIGTERM-acking child (`control-block-ack-term`), so the single poll's signal delivery is
OBSERVED as a real event, not assumed — then drop it, prove the child is still alive and
dies only by the test's own kill); **watch-error stranding tests, all four graceful bodies**
(seam-forced watch `Err`: escalation and reap still run — reap proven by identity on Linux,
where zombies stay exists()-visible — then the error surfaces);
Windows `Unsupported` for lone ops; uncontained `Unsupported` for tree ops;
`contain_with(TreeWalk)`/`nesting` async spawn smoke + a request-level unit test (the recorded
mode/nesting values, mirroring sync `command_tests`); `grace_wait` unit tests
(exited-unreaped → true, live at ZERO → false, stale identity → true, pre-signaled AND
mid-wait cancel release the Windows wait — the latter proves race-insensitivity: every
interleaving must release). No-time-sync discipline
throughout: `grace` values in tests are `Duration::ZERO` (deterministic escalation) or generous
bounds on a child that exits via control socket — death is proven by EOF / inspected
`ExitStatus`, never by polling or sleeps.

## Recorded decisions (2026-07-05)

- **Hand-mirror parity (re-affirmed 2026-07-13 against a per-color escalate-helper
  intermediate, covering the lone/tree axis):** the async control surface hand-mirrors sync
  (like the Plan-8 builder decision; an executor-generic core rejected as disproportionate
  function-coloring). This
  explicitly covers the escalation policy skeleton (soft → non-reaping grace-wait → sweep →
  reap-last): the ~4-line sequence stays per-surface (sync Child / foreign Process / async
  Child / Plan-10 async Process) with the ordering invariant documented at each site — a
  closure-parameterized driver spanning sync and async execution is the rejected shape. The
  parity harness is the scenario-mirrored suites — `tests/tokio_control.rs` runs the same
  scenarios with the same assertions as `tests/graceful.rs`.
- **Backstop coverage:** a containment-layer fault seam (skip the root identity-kill) makes the
  `kill_tree` handle backstop deterministically testable, sync + async.

## Non-goals / rejected

- `RegisterWaitForSingleObject` for a reactor-like Windows watch: unsafe IOCP callback + lifetime
  management for the one platform without a pollable process handle — the event-cancellable
  `spawn_blocking` wait achieves prompt cancellation without it.
- `CancellationToken` integration: future dropping is the async cancellation idiom; a token adds
  API without new capability.
