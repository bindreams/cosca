# Plan 8 — async I/O foundation (tokio mirror, part 1): design

**Status:** approved 2026-06-26. First of a two-plan async mirror (Plan 8 = I/O foundation; Plan 9 = control + foreign). Builds on the complete sync surface (Plans 1–7, `main` `fbd8138`). Parent spec `2026-06-20-subprocess-design.md` §3 ("Both sync + async, over a pure runtime-agnostic core; tokio behind a feature flag"), §4 (three layers; sync/async split confined to the thinnest), §4 crate-layout (`tokio.rs + tokio/`, feature `tokio`).

## Goal

Mirror the sync owned-`Child` I/O surface in async: spawn (contained or not), async stdio, `wait`/`try_wait`/`status`, `communicate`/`output`, and a best-effort async `Drop` — built on `tokio::process`, reusing the runtime-agnostic core verbatim.

## Decisions (settled in brainstorming, with research)

- **Base = `tokio::process`** (symmetric with sync's `std::process` + `shared_child`; mature reaping + driverless async stdio; least novel code). Rejected: a from-scratch `AsyncFd`-over-pidfd layer (more risk; Windows handle isn't reactor-pollable anyway).
- **Split:** Plan 8 = I/O foundation; Plan 9 = explicit `kill`/`kill_tree`/`terminate_tree` + graceful trio + async foreign `Process`.
- **Four divergences from the sync API (all confirmed):**
  1. async `wait`/`try_wait`/`status` take **`&mut self`** (tokio's `Child` is `&mut self`); sync's `&self`-via-`shared_child` concurrency is expressed natively in async with `tokio::select!`. A shared `Mutex<Child>` is rejected — holding it across `.await` would serialize wait against kill.
  2. **No `wait_timeout`/`wait_deadline`** — compose `tokio::time::timeout(d, child.wait())` (YAGNI).
  3. **Arbitrary fd ≥ 3 (Unix): child-side mapping reused; an async *parent* pipe end is deferred to Plan 9** (needs `AsyncFd`). Plan 8 ships the three standard async streams.
  4. async **`Drop` is best-effort** (can't `.await`): tear down the contained tree via `attached.hard_kill()` (sync syscalls) + tokio's `kill_on_drop` for the root; document "prefer `.wait().await`". Matches tokio / async-process.
- **`id()` keeps the stable `ProcessId`** — never `None` after wait (rejecting tokio's `id() → None` footgun).

## Architecture

The parent spec's three-layer split holds: only Layer 3 (effect) forks sync vs async. The async layer **reuses verbatim** (no changes): `error`, `quote`, `stdio` (the `Fd`/`Stdio`/`ResolvedStdio` model), `identity` (+ all backends), **all** of `containment` (Job Object / cgroup / pgid / `TreeWalk` / `Attached` / `dispatch` / `enumerate`), `wait::{kill, terminate}`, `treewalk`, and the `Command` builder's input fields. The genuinely new code is the async owned handle.

### Module layout + feature

- `Cargo.toml`: `tokio = { version = "1", optional = true, features = ["process", "rt", "io-util", "macros"] }`; `[features] tokio = ["dep:tokio"]`. Additive; sync builds compile no runtime. (`macros` is required by the library — `communicate` uses `tokio::try_join!`, which is gated behind that feature. `AsyncFd` via the `net` feature lands in Plan 9.)
- `#[cfg(feature = "tokio")] pub mod tokio;` in `lib.rs` → `src/tokio.rs` + `src/tokio/{command,child,spawn,pump}.rs`, mirroring the sync `command.rs`/`child.rs`/`child/spawn.rs`/`child/pump.rs`. Inside the module the tokio *crate* is referred to as `::tokio`.
- The async `Command` builder hand-mirrors the sync builder's config methods (no compiler-enforced parity): a new sync builder method must be mirrored by hand. A delegation macro / parity test was judged disproportionate for this small, stable surface (recorded decision).

### Spawn core (the main integration work)

The sync spawn (`child/spawn.rs`) builds a `std::process::Command`, resolves each `Fd` to a child-side handle + parent pipe end (`std::io::pipe`), runs two-phase containment (`prepare` → spawn → `attach`), reads identity before adopting into `SharedChild`. Plan 8 **extracts the runtime-neutral resolution + build into a `pub(crate)` core operating on a `&mut std::process::Command`** (`build_std_command`, `resolve_non_merge`, `apply_env`, batch-script + Windows-fd≥3 rejection, the `prepare`/`attach` dispatch). The async spawn:

1. builds a `::tokio::process::Command`, reaches its inner std command via **`as_std_mut()`**, and applies the shared core — so `pre_exec` (pgroup/session/cgroup), `command-fds`, Windows creation-flags, and Job-Object assignment all reuse unchanged (tokio honors a std `Command`'s `pre_exec`/flags because it spawns that inner command);
2. for the three standard streams, sets tokio `Stdio::piped()` (so tokio yields async `ChildStdin`/`ChildStdout`/`ChildStderr`); for `file`/`null`/`inherit`/`merge`, sets `Stdio::from(child-side OwnedFd/Handle)` from our `ResolvedStdio`;
3. spawns, then **before any `try_wait`** reads `ProcessId::of(child.id())` (identity-before-reap, as the sync spawn already documents) and runs `attach`;
4. stores `{ ::tokio::process::Child, ProcessId, Attached, parent ends, kill_on_drop, containment }`.

No `shared_child`: tokio's `Child` is interior-concurrent for its own ops, and async concurrency uses `select!`.

## The async `Child` handle

```text
pub struct Child {           // subprocess::tokio::Child
    child: ::tokio::process::Child,   // wait handle + async stdio
    id: ProcessId,                    // stable identity (never None)
    attached: Attached,               // contained-tree teardown
    kill_on_drop: bool,
    containment: Containment,
    // The three standard async streams live inside `child` (taken via the accessors
    // below). file/null/inherit/merge carry no parent end; fd >= 3 parent ends are
    // deferred to Plan 9, so Plan 8 stores no separate pipe-end map.
}
```

- `id(&self) -> ProcessId`, `is_alive(&self) -> bool`, `containment(&self) -> Containment` — `&self`; identity/point-query.
- `stdin(&mut self) -> Option<::tokio::process::ChildStdin>`, `stdout(&mut self) -> Option<::tokio::process::ChildStdout>`, `stderr(&mut self) -> Option<::tokio::process::ChildStderr>` — take the async stream (driverless `AsyncWrite`/`AsyncRead`).
- `wait(&mut self) -> Result<ExitStatus>` (`.await`), `try_wait(&mut self) -> Result<Option<ExitStatus>>`, delegating to tokio (`Error::Io` on failure).
- `detach(&mut self)` — clear `kill_on_drop` and disarm `attached` (reuse the sync `Attached::disarm`).

## Async stdio

The thread-per-stream sync pump (`child/pump.rs`) is **deleted** in the async layer. Standard streams are tokio's `ChildStdin`/`ChildStdout`/`ChildStderr` — already `AsyncWrite`/`AsyncRead`, serviced by the reactor, no threads. `file`/`null`/`inherit`/`merge` carry no parent end (redirect only). Arbitrary fd ≥ 3 (Unix): the child-side `command-fds` mapping is reused (the child gets fd 3), but wrapping the *parent* end as async (`AsyncFd`) is deferred to Plan 9.

## Async `communicate` / `output`

`src/tokio/pump.rs`: async `communicate(input)` = `tokio::try_join!` over (write `input` to stdin then drop it for EOF), (`read_to_end` stdout), (`read_to_end` stderr), and (`wait`) — preserving the close-stdin-then-read-both anti-deadlock invariant with zero threads. `Command::output().await` / `status().await` / `read().await` spawn then drive this; `read` is `output` + UTF-8 decode (reuse the sync semantics). `Command::spawn()` is **non-async** (`-> Result<Child>`, like tokio). Free helpers `subprocess::tokio::{run, run_line}` mirror the sync ones.

## Async `Drop`

```text
impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop { return; } // detach()/kill_on_drop(false) opt out
        let _ = self.attached.hard_kill();   // contained tree — sync syscalls, OK in Drop
        reap_now(&mut self.child, self.id.pid(), /* done_ok */ true); // root: kill + BLOCKING reap
    }
}
```

`Drop` guarantees synchronous teardown, matching the sync `Child`: `attached.hard_kill()` sweeps the contained tree, then `reap_now` `start_kill`s the root and BLOCKS until it exits (`waitid(WEXITED|WNOWAIT)` on Unix, leaving tokio's field-drop to reap the zombie synchronously; `WaitForSingleObject(INFINITE)` on Windows). tokio's own `kill_on_drop` is left at its `false` default — subprocess's `Drop` is the SOLE teardown owner, so forwarding it would make tokio race `reap_now`. (This reverses the best-effort/`kill_on_drop(true)` model of an earlier draft — a user-confirmed reversal after plan review.)

## Reuse map

| Need | Reused from (verbatim) |
|---|---|
| error taxonomy | `error.rs` |
| quoting | `quote/*` |
| stdio model + `ResolvedStdio` resolution | `stdio.rs` (+ the extracted spawn-core resolution) |
| identity | `identity.rs` + backends |
| containment select/attach/teardown | `containment/*` (`dispatch`, `Attached`, `unix`, `cgroup`, `windows`, `treewalk`, `enumerate`) |
| `Command` builder input fields | `command.rs` (`CommandInput`/`EnvOp`/`ContainRequest`/fds) |
| identity-before-reap spawn ordering | `child/spawn.rs` (extracted) |
| `Attached::{hard_kill, disarm}` for Drop/detach | `containment/dispatch.rs` |

## File structure

- `Cargo.toml`: the `tokio` optional dep + feature.
- `src/lib.rs`: `#[cfg(feature = "tokio")] pub mod tokio;`.
- `src/child/spawn.rs` (modify): extract the runtime-neutral resolution/build/attach into `pub(crate)` items operating on `&mut std::process::Command`; the sync spawn keeps using them.
- `src/tokio.rs` (new): module root, re-exports `Command`, `Child`, `run`, `run_line`.
- `src/tokio/command.rs` (new): async `Command` (builder over shared `CommandInput`; `spawn`/`output`/`status`/`read`).
- `src/tokio/child.rs` (new): async `Child` + `Drop` + stdio accessors + `wait`/`try_wait`/`detach`.
- `src/tokio/spawn.rs` (new): async spawn over `::tokio::process::Command` + the shared core.
- `src/tokio/pump.rs` (new): async `communicate` (`try_join!`).
- `tests/common/mod.rs` (modify): a `#[cfg(feature = "tokio")]` async spawn helper (control child + accepted socket).
- `tests/tokio_io.rs` (new): `#[tokio::test]` integration tests.
- CI: add a `--features tokio` build/test step to the matrix (mirrors how `--features pty` was wired).

## Test strategy

`#[tokio::test]` (current-thread is fine). **No time-based synchronization** — death/EOF proven only by control-socket EOF/`ConnectionReset` or an inspected `ExitStatus`; `tokio::time::timeout` appears only as a failure bound on a genuine wait. Cover:

- async spawn + `status().await` exit code; `output().await` captures stdout/stderr; `read().await` decodes UTF-8.
- the three async streams: write to `stdin`, read `stdout`/`stderr` (`AsyncReadExt`/`AsyncWriteExt`).
- async `communicate` deadlock-safety: the `tee-both` testbin child (copies stdin → both stdout+stderr) completes via concurrent `try_join!` where a non-concurrent reader would deadlock.
- contained spawn + `Drop`: spawn `.contain()`ed, drop the handle, assert the tree EOFs (the `Attached::hard_kill` path).
- `id()` stability: identity equal before and after `wait().await`.
- macOS divergences (zombie/privileged `proc_pidinfo`) are not exercised by I/O tests; CI runs all 6 cells with `--features tokio`.

## Out of scope

- **Plan 9:** explicit async `kill`/`kill_tree`/`terminate_tree`; the graceful trio (`terminate`/`graceful_shutdown`/`graceful_shutdown_tree`, using `AsyncFd` over the pidfd/kqueue for the non-reaping grace-wait); async foreign `Process` (`from_id`/.../`wait`/`kill`/graceful/tree).
- **Deferred → `TODO.md`:** an async parent pipe end for arbitrary fd ≥ 3 (Unix); PTY async wiring.
