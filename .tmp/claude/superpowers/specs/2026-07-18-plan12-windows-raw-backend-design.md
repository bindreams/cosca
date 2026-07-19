# Plan 12 — Windows raw `CreateProcessW` backend (fd ≥ 3 + independent `executable`/`commandline`)

> **Status: LANDED** (2026-07-19, branch `azhukova/4`). All 9 tasks implemented and reviewed;
> the two Windows-only `Unsupported` rejections (`fd >= 3`, `executable()` + `commandline()`) are
> lifted on both the sync and async surfaces. Retained design limits: chained merges,
> `Stdio::inherit()` on `fd >= 3`, and `fd >= 3` for non-MSVCRT children.

Fulfils the deferred "Plan 4" spawn-engine item (`TODO.md:66`): a raw `CreateProcessW`
backend that lifts the two Windows-only `Unsupported` rejections `std::process` cannot
express — `fd(n)` for n ≥ 3, and `executable()` set alongside `commandline()` (and the
sibling `executable()`-alone argv[0] degradation). Delivered on BOTH the sync and async
surfaces in one plan, preserving the feature-equivalence invariant.

## Scope

**In:** (1) a raw `CreateProcessW` spawn path on Windows, **routed only when the std path
cannot express the request** — `executable()` is set, OR any `fd(n)` with n ≥ 3 is
configured — and otherwise left entirely on the existing std/tokio path (the 11 landed
plans' green tests are untouched by construction); (2) `fd ≥ 3` inheritance via the MSVCRT
`lpReserved2` fd-table smuggle so the child CRT sees numbered descriptors, with
inheritance scoped by `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
(**MSVC/UCRT children only**, per spec §divergence line 144); (3) independent
`lpApplicationName` / `lpCommandLine` so `executable()` + `commandline()` (and
`executable()` + argv) load the intended file while the child's argv[0] is the user's
intended name; (4) a process-handle abstraction so the raw child coexists with
`SharedChild` (sync) / `tokio::process::Child` (async); (5) raw-path program resolution
(PATH + PATHEXT) and environment-block construction, since `CreateProcessW` PATH-searches
neither a non-NULL `lpApplicationName` nor inherits env when we must apply env ops;
(6) containment/lifecycle integration (the raw path sets `CREATE_SUSPENDED` itself; the
existing `attach_job` Toolhelp-resume is reused unchanged); (7) async raw wait on the
existing Windows event-cancellable death-watch primitive; (8) flip the four `Unsupported`
rejection sites, update their error text, and mirror the test suite sync↔async.

**Out (kept `Unsupported`, agreed with user 2026-07-18):**
(a) **chained merges** (`merge → merge`) — the two-pass `resolve_stdio` still rejects them;
(b) **`Stdio::inherit()` on fd ≥ 3** — semantically undefined on Windows (the parent has no
fd ≥ 3), stays a loud `Unsupported`, not a silent drop;
(c) **non-MSVCRT children for fd ≥ 3** — the `lpReserved2` table is a CRT-private contract;
a child linking a foreign/no CRT cannot be served and this is documented as inherent, not a
bug. The Unix path, elevation, PTY, and \*BSD are unchanged (`TODO.md`).

## Architecture

### 1. Process-handle abstraction (`src/child.rs`, `src/tokio/child.rs`)

The sole structural cost. `SharedChild::new` requires a `std::process::Child`; a raw
`HANDLE` is neither that nor a `tokio::process::Child`. Introduce a thin backend enum whose
methods forward to the active arm, keeping every downstream call site (wait/kill/id/
containment/Drop) source-compatible:

- **Sync** — `Child.shared: SharedChild` becomes `Child.proc: ProcHandle`:
  `enum ProcHandle { Std(SharedChild), #[cfg(windows)] Raw(windows_raw::RawChild) }`
  forwarding `wait` / `try_wait` / `kill` / `id` and, on Windows, the raw process handle the
  containment attach + `kill_tree` backstop + `test_job_handle_contains_self` need (today via
  `AsRawHandle`; the `Raw` arm exposes it directly, no `OpenProcess`-by-pid round trip).
- **Async** — `Child.child: tokio::process::Child` becomes
  `enum ProcSource { Tokio(tokio::process::Child), #[cfg(windows)] Raw(RawAsyncChild) }`,
  forwarding `id` / `raw_handle` / `wait().await` / `try_wait` / `start_kill` and the
  stdin/stdout/stderr piped-end takers (the `Raw` arm holds our own overlapped ends).

On Unix the enum is a single-arm passthrough (zero behavior change; `#[cfg(windows)]` gates
the `Raw` variant so no Unix code sees it).

### 2. Raw spawn core (`src/child/spawn/windows_raw.rs`, new)

A `#[cfg(windows)]` module owning the `CreateProcessW` call, driven from a resolved
`Command`. Inputs it assembles:

- **`lpApplicationName`** — the resolved absolute executable path (§4). Set for EVERY raw
  spawn (research-brief line 131: always emit an explicit `lpApplicationName`; never let the
  OS parse the exe from the command line — that is the BatBadBut vector).
- **`lpCommandLine`** — built with the existing `quote::windows::join_wide`, argv[0] = the
  user's intended name (from `argv[0]`, or `first_token_wide(commandline)`), argv[1..]
  quoted. Mutable buffer (`CreateProcessW` may write to it).
- **`STARTUPINFOEXW`** — `STARTF_USESTDHANDLES` with `hStdInput/Output/Error` = the resolved
  0/1/2 child ends; `lpAttributeList` carries a single
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` naming EXACTLY {0,1,2 handles} ∪ {fd ≥ 3 handles}
  (§3), so `bInheritHandles = TRUE` leaks nothing else (research-brief line 188: unscoped
  inheritance leaks cross-child pipe ends → hangs).
- **`cbReserved2`/`lpReserved2`** — the MSVCRT fd table (§3) when any fd ≥ 3 is present.
- **`lpEnvironment`** (§4) + `CREATE_UNICODE_ENVIRONMENT`; **`lpCurrentDirectory`** = cwd.
- **`dwCreationFlags`** — `CREATE_UNICODE_ENVIRONMENT`, plus the containment flags (§5)
  folded in here rather than via std's `creation_flags`.

Handle hygiene: set `HANDLE_FLAG_INHERIT` on every listed child end immediately before
spawn; the parent keeps its own ends non-inheritable. Stdio child ends are produced by the
UNCHANGED `resolve_stdio` core (`PipeOwnership::Owned` sync / `Deferred`-equivalent async) —
the raw path reuses the same pipe/file/null/merge resolution, only the final wiring to the
OS differs. `PROCESS_INFORMATION` yields the process handle, thread handle, and pid.

### 3. fd ≥ 3 MSVCRT fd-table (`src/child/spawn/windows_raw/crt_fds.rs`, new)

The `lpReserved2` blob is the CRT's private inherited-fd table (prior art: CPython
`subprocess`/`_winapi`, libuv `process.c`, the `thaum` reference impl). Layout:

```
int   count;                 // number of fds, table covers fd 0..count-1
char  flags[count];          // per-fd CRT flags
HANDLE handles[count];       // per-fd OS handle (INVALID_HANDLE_VALUE for a gap)
```

We emit a table covering fd `0..=N` where `N` is the highest configured descriptor, so it
includes 0/1/2 (same handles as `STARTF_USESTDHANDLES`, belt-and-suspenders for CRTs that
read the table for 0/1/2) and each configured fd ≥ 3. Any interior slot the user did not
configure (e.g. fd 3 and fd 5 set but not fd 4) gets `INVALID_HANDLE_VALUE` + a zero flag
byte, so the child CRT treats it as closed. Per-fd flag byte =
`FOPEN | (FPIPE if a pipe | FDEV if a char device | 0)` (no `FTEXT` — binary). All listed
handles are also in the `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (§2), the only mechanism that
actually makes them inheritable under scoped inheritance. `cbReserved2 = sizeof(int) +
count*(1 + sizeof(HANDLE))`. Confined to the raw path; a foreign-CRT child is the documented
non-goal (Out §c).

### 4. Program resolution + environment block (`src/child/spawn/windows_raw/resolve.rs`, new)

- **Program resolution** — `CreateProcessW` does not PATH-search a non-NULL
  `lpApplicationName`, so the raw path must resolve a bare program name to an absolute path
  itself (std does this internally but never exposes the result). **Dependency evaluation
  (to confirm in the plan):** prefer the `which` crate (maintained, handles Windows PATHEXT +
  `App Paths`) over a hand-rolled search, per the add-a-dependency rule; validate against
  `std::process` parity with a test that resolves the same bare name both ways. If `which`'s
  search order diverges from std in a way a test catches, fall back to a minimal
  PATH+PATHEXT+cwd resolver and record the decline.
- **Environment block** — when env ops are present we build the `CREATE_UNICODE_ENVIRONMENT`
  block ourselves: start from the parent env, apply `Set`/`Remove`/`Clear` (case-insensitive
  keys, Windows semantics), sort case-insensitively, wide-encode, `\0`-separate,
  double-`\0`-terminate. No maintained crate exposes exactly std's block construction; this
  is a faithful local build (documented layout). When no env ops are present, pass NULL
  (inherit parent env) — the common case stays allocation-free.

### 5. Containment / lifecycle integration

The Windows containment mechanism is unchanged — only who sets the creation flags moves. For
a contained raw spawn, `windows_raw` folds `CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP`
into `dwCreationFlags` itself (the std path's `containment::prepare` → `set_root_flags`
mutates a `std::process::Command`, which the raw path does not use). Post-spawn,
`attach_job(proc_handle)` is reused VERBATIM: it assigns the job and resumes via the Toolhelp
thread walk keyed on pid. (The raw path also holds `PROCESS_INFORMATION.hThread` and COULD
resume it directly, but reusing `attach_job` unchanged keeps one resume path and one set of
tests; the thread handle is simply closed after `attach_job` returns.) `require_contained`,
`Attached`, `disarm`, `kill_tree`, `terminate_tree`, and the Drop teardown are untouched.

### 6. `RawChild` lifecycle (sync, in `windows_raw.rs`)

Owns `OwnedHandle` (process) + pid. `wait` = `WaitForSingleObject(INFINITE)` then
`GetExitCodeProcess` → `ExitStatus` (via `ExitStatusExt`); `try_wait` = `WaitForSingleObject(0)`
`WAIT_TIMEOUT` → `None`; `kill` = `TerminateProcess`, mapping the already-exited error to
`Ok(())` for parity with `std`/`shared_child`; `id` = the pid. Thread-safe waiting is
inherent on Windows (many threads may wait one handle; exit code is idempotent), so
`RawChild` does NOT need `shared_child` — it is used through `&self` like the `Std` arm.
`Drop` requires nothing beyond closing the handle (the existing `Child::drop` orchestrates
kill+reap through the enum).

### 7. `RawAsyncChild` (async, `src/tokio/spawn/windows_raw.rs`, new)

The hard half. Holds the process `OwnedHandle` + pid + our overlapped parent ends. `wait`/
`try_wait` reuse the SAME Windows death-watch primitive the async foreign `Process` already
uses (`src/tokio/wait.rs` + `src/wait/windows.rs` — the "event-cancellable blocking wait, no
pollable process handle" noted in `TODO.md:83`): a cancellation-safe `wait().await` over the
handle, `try_wait` a zero-timeout poll. `start_kill`/`kill` = `TerminateProcess`. The spawn
itself is synchronous (raw `CreateProcessW`, then identity read + `attach_job` before any
await — mirroring the existing async spawn's "identity before await" ordering), so no reactor
interaction occurs until the first `wait`. Stdio for the async raw path reuses the existing
overlapped-pipe machinery (`src/tokio/stdio.rs`) for parent ends; fd ≥ 3 async parent ends
mirror the Unix fd ≥ 3 accessor surface already shipped in Plan 10.

### 8. Routing predicate (`src/child/spawn.rs`, `src/tokio/spawn.rs`)

A single `#[cfg(windows)]` predicate, evaluated after `fds` is taken:
`needs_raw = cmd.executable_path().is_some() || fds.keys().any(|f| f.raw() >= 3)`.
When false → the existing std/tokio path, byte-for-byte. When true → the raw path. The four
current rejection sites (`child/spawn.rs:29`, `:279`; `tokio/spawn.rs:34`; and the
`build_from_commandline` Windows arm) are replaced by this branch. `Stdio::inherit()` on
fd ≥ 3 (Out §b) is still rejected inside `resolve_stdio`/`inherit_end` — reached only if the
user pairs inherit with an fd ≥ 3 slot, and it stays loud.

### 9. Cargo / `windows` crate features

Add to the existing `windows` dependency (already `0.62`): `CreateProcessW`,
`STARTUPINFOEXW`, `PROC_THREAD_ATTRIBUTE_LIST` +
`InitializeProcThreadAttributeList`/`UpdateProcThreadAttribute`/`DeleteProcThreadAttributeList`,
`GetExitCodeProcess`, `WaitForSingleObject`, `PROCESS_INFORMATION` — most live under
`Win32_System_Threading` (already enabled); enable any missing sibling feature (e.g.
`Win32_Storage_FileSystem` for `HANDLE_FLAG_INHERIT`/`SetHandleInformation` if not already
in scope). New crate dep: `which` (Windows-target, gated), pending the §4 parity check.

## Testing (TDD, sync ↔ async mirrored)

Every behavior is written test-first; each new integration test has a sync and a tokio twin.

- **fd ≥ 3 round-trip** — configure `fd(3, pipe)` (both directions) to a CRT child
  (`subprocess_testbin` gains a mode that reads/writes fd 3 via the CRT), assert the bytes
  cross. Exit proven by pipe EOF; no sleeps/polls/wall-clock (per the standing prohibition).
- **fd ≥ 3 to a file / null** — child writes fd 4 to a temp file; parent reads it back.
- **`executable()` ≠ argv[0]** — load one helper while argv[0] is a different name; the child
  reports its argv[0] and its own image path; assert they differ as configured. Covers
  `executable()` + `commandline()`, `executable()` + argv, and `executable()`-alone (the
  latter proving the pre-existing Windows argv[0] degradation is lifted).
- **Rejection flips** — the former `Unsupported` cases now succeed; the RETAINED rejections
  (chained merge, inherit-on-fd ≥ 3) still return `Unsupported` with updated text (no stale
  "raw backend (Plan 4)" wording).
- **Containment over the raw path** — a contained raw spawn is in our job
  (`test_job_handle_contains_self`), and `kill_tree` tears down an fd ≥ 3-wired tree.
- **Parity / no-regression** — the std path is unchanged when `needs_raw` is false (existing
  suite); a `which`-vs-std program-resolution parity test; run the full suite on Windows
  (host) and WSL (Unix untouched) before the branch CI.

## Recorded decisions

- **Scope = sync + async in one plan** (user, 2026-07-18) — preserves the feature-equivalence
  invariant rather than shipping a divergent surface.
- **Routing = hybrid, raw only when needed** — industry convergence (CPython/Go/libuv all
  fall to a raw path only when the common path can't express the request); minimises blast
  radius against 11 plans of green tests. Not punted to the user (decision-style: evidence,
  not a menu).
- **fd ≥ 3 semantic = `lpReserved2` numbered fds, MSVC/UCRT-only** — already settled by
  `specs/2026-06-20-subprocess-design.md:144`; this plan implements, it does not re-decide.
- **Deferred (user-agreed, 2026-07-18):** chained merges and inherit-on-fd ≥ 3 stay
  `Unsupported`; non-MSVCRT fd ≥ 3 is an inherent non-goal, documented not tracked-as-bug.
- **Workflow (CLAUDE.local.md):** GitHub issue → branch `azhukova/<issue#>` → PR → CI green;
  the issue/branch/PR (people-alerting) are batched for explicit user OK after design +
  implementation.
