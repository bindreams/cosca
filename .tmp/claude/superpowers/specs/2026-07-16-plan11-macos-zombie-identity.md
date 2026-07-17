# Plan 11 — macOS zombie-inclusive identity + queued follow-up sweep

Closes issue #2 (macOS identity resolution is zombie-blind) — which deflakes issue #3 and the
`async_unix_fd3_pipe_out_delivers_child_bytes` instance WITHOUT test-side masking — and
clears the small queued follow-ups now that `log` is a dependency.

## Scope

**In:** (1) the macOS identity backend becomes a HYBRID: `proc_pidinfo` (Apple's stable
public libproc API) stays the PRIMARY source for the common live path, and
`sysctl(KERN_PROC_PID)` / `kinfo_proc` is the FALLBACK on a libproc miss — exactly the
zombie case — making `start_token`/`exists()` zombie-INCLUSIVE (Linux parity);
`is_running` is UNCHANGED (a libproc miss is gone-or-zombie, both "not running" — its
zombie-EXCLUSIVE contract already holds);
(2) a logging sweep over the previously-declined "no logging facility" sites; (3) the
round-final reverify advisory comment trim (`tests/tokio_io.rs`); (4) a `getrandom` 0.3→0.4
bump attempt to dedupe the lockfile's dual majors.

**Out:** `containment/enumerate/macos.rs` stays on `proc_pidinfo`/`proc_listpids` — kill
paths act on LIVE processes and a zombie child needs no killing; enumeration
zombie-blindness has no observed failing scenario. Revisit only if a test proves a gap.
Elevation/PTY/*BSD: unchanged in `TODO.md`.

## Architecture

### 1. macOS identity backend (`src/identity/macos.rs` + new `src/identity/macos/kinfo.rs`)

HYBRID (round-4 panel): `proc_pidinfo` primary, `sysctl([CTL_KERN, KERN_PROC,
KERN_PROC_PID, pid])` / `kinfo_proc` fallback on a libproc miss. This confines the
UNDOCUMENTED kinfo_proc layout to exactly the zombie path: a hypothetical layout drift on
an end-user OS version degrades only zombie resolution (a token mismatch — today's
zombie-blind behavior), never live identity, which stays on the stable versioned ABI.
Both sources report the start time in µs (`start.tv_sec * 1e6 + tv_usec`); their equality
for a live process is CI-pinned by the value oracle and is the load-bearing cross-source
invariant (a live-captured token must match the same process's zombie-read token).
`is_running` and `created_at`: unchanged shipped bodies. Both sources carry the SAME
failure disposition (`contract_violation`, shared in `macos.rs`): expected misses (ESRCH;
EPERM for unprivileged cross-user queries, which the world-readable sysctl fallback then
resolves) are calm `None`s; other errnos or partial records are traced. The CI release
`--lib` lane is darwin-gated.

**Dependency evaluation (recorded):** libc does NOT define `kinfo_proc`/`extern_proc` for
apple targets (verified against libc 0.2.186 source; only the constants and `sysctl` exist);
nix has no darwin KERN_PROC surface; rust-psutil, sysinfo, and std itself all hand-define
the struct locally for exactly this purpose. No maintained crate exports it → a minimal
faithful local `#[repr(C)]` definition in `src/identity/macos/kinfo.rs` is the industry
approach (mach-typed fields substituted by equal-size primitives; `p_starttime` lives in
the head union `p_un`).

**Layout risk → CI-verified oracles** (macOS runtime is CI-only; the local loop is the
`aarch64-apple-darwin` cross-target compile, which also evaluates the compile-time 648/296
size asserts): (a) a size oracle — a REAL-buffer fetch must WRITE exactly
`size_of::<kinfo_proc>()` (a null-buffer probe is unusable: XNU inflates it by
KERN_PROCSLOP = 5×sizeof); (b) a value oracle — for a LIVE process (self), the
sysctl-derived token must equal the `proc_pidinfo`-derived token (`proc_pidinfo` survives
ONLY as this test oracle); (c) a transition oracle — the token captured while ALIVE must
still match the same process as an unreaped ZOMBIE, with the zombie state PINNED by
`waitid(WEXITED | WNOWAIT)` (EOF cannot order a zombie-exclusive check: fd teardown
precedes the SZOMB transition). sysctl EINTR retries per the codebase convention; a
non-EINTR errno or wrong-sized record is a traced contract violation (`contract_violation`:
warn first, debug tripwire second — the trace executes in every build mode; the
invalid-selector arm is seam-driven, and a new CI release `--lib` lane executes the calm
release arm with `debug_assertions` off).

**Acceptance test (all platforms, deterministic):** spawn a child that exits immediately,
prove the exit by reading its piped stdout to EOF (the write end closes at process exit),
do NOT reap, then `ProcessId::of(pid)`/`exists()` must resolve. Passes today on
Linux (procfs shows zombies) and Windows (the un-reaped `Child` holds the handle); passes
on macOS only with the fix — this is the class that produced both recorded CI flakes.

Un-gate the `#[cfg(target_os = "linux")]` test assertions whose gate reason was macOS
zombie-blindness (→ `cfg(unix)`; sync AND tokio graceful twins), and sweep the stale
macOS-source docs (`exists()`, the identity module doc, `assert_child_reaped`'s rationale).
The pid-1 EPERM test un-gates for its NON-ROOT branch only: XNU's launchd SIGKILL
protection is unverified and a wrong assumption panics the machine, so as root on
non-Linux the test refuses to signal pid 1 (loud refusal; CI runners are non-root).
`kinfo()`'s failure disposition: pid-gone is a bare `None`; a real sysctl errno or
wrong-sized record leaves a debug tripwire + `log::warn!` trace first.

### 2. Logging sweep (previously-declined sites, now that `log 0.4` exists)

| site | level | rationale |
|---|---|---|
| `wait/windows.rs signal_cancel` — SetEvent failed DURING unwind (assert deliberately skipped) | `error!` | cancellation contract degraded to a possible unbounded park; the one branch that is silent today |
| `containment/treewalk.rs` — impostor subtree drop; identity-changed kill skip | `debug!` | best-effort contract; normal under pid recycling but useful traces |
| `kill_tree` both-fail (sync `child.rs` + `tokio/child.rs`) — backstop error subsumed by group error | `debug!` | both failures leave a trace (Plan-10 principle) |
| owned graceful lone+tree (sync + tokio) — watch `Err` subsumed by a kill/sweep/reap `Err` | `debug!` | parity with the Plan-10 FOREIGN graceful bodies, which already log this |

### 3. Cosmetics

`tests/tokio_io.rs` non-merge take-semantics comment trimmed per the reverify advisory.
`getrandom` 0.3 → 0.4 (windows-only dep) if its API/features still fit (`fill`, std-error
conversion); on success the lockfile's 0.3 entry disappears (tempfile's 0.4 dev-dep
remains). If 0.4 does not fit, keep 0.3 and record the decline.

## Testing

New: the all-platform zombie-resolution integration test; the two macOS layout/value
oracles (unit tests, CI-run). Un-gated: the formerly Linux-only zombie-exists assertions
(now `cfg(unix)`). Deflaked (no changes): the issue-#3 `sid-report` scenario and the fd3
spawn-identity class — the race disappears at the source. No sleeps/polls/wall-clock
anywhere; exits proven by pipe EOF.

## Recorded decisions

- Follow-up queue policy (user 2026-07-13): these items run as their own plan behind
  Plan 10.
- No test-side masking of the identity race (recorded on issue #3) — the fix is at the
  source.
- Enumeration stays proc_pidinfo (out of scope, rationale above) — presented as a
  non-goal, revisited on evidence.
