# Plan 10 — Async parity completion: foreign `Process`, fd ≥ 3, merge-into-pipe

Closes the three user-confirmed deferrals from Plans 8–9: `subprocess::tokio::Process`
(foreign control from async), async parent ends for fd ≥ 3, and merging stderr/stdout into a
piped target on the async API. Approved 2026-07-13 (including the Windows-merge-head-on
recommendation).

## Scope

**In:** `tokio::Process` (introspect / async wait / kill / graceful, mirroring sync
`Process`); `pub(crate) tokio::wait::wait_exit` (unbounded exit watch, refactored out of
`grace_wait`); async `Command::fd(slot, Stdio)` acceptance for fd ≥ 3 on Unix with
`tokio::net::unix::pipe::{Receiver, Sender}` parent ends; async merge-into-piped-target on
ALL platforms and BOTH target directions (user 2026-07-14: least surprise — Out for
stderr/stdout capture, In for one-writer-feeds-multiple-read-fds; fd ≥ 3 merge SOURCES ride
command-fds; Unix: owned pipes + `pipe::{Receiver,Sender}`; Windows: owned overlapped
named-pipe pairs, std's own child-stdio technique). NEW dependencies: `log = "0.4"`
(user-approved; debug/warn traces at subsumed-error, pipe-creation, and conversion-failure
sites) and windows-only `getrandom` (unpredictable pipe names, std parity).

**Out:** the macOS zombie-inclusive identity fix (issues #2/#3, `sysctl KERN_PROC`) — queued
behind Plan 10 per the user's follow-up policy (2026-07-13: back of the queue unless it folds
cleanly; it does not — CI-only iteration). Elevation, PTY wiring, *BSD: unchanged in
`TODO.md`.

## Architecture

### 1. `tokio::Process` (`src/tokio/process.rs`)

The established wrapper pattern (`tokio::Command`/`Child` precedent): an inner sync
`Process`. Introspection delegates synchronously — `from_id`/`from_pid`/`current` return
`Option<tokio::Process>`; `id`/`is_alive` delegate; `parent`/`children(Recursive)` delegate
and re-wrap. These are instant proc queries; `async` would be false coloring. Signal-only
ops (`kill`, `terminate`, `kill_tree`, `terminate_tree`) are plain `fn` delegations with the
sync platform gating (lone + soft-tree Unix-only via the same error paths; `kill_tree`
all-OS). Foreign ops return `()` — a foreign process yields no `ExitStatus` (sync precedent).

The genuinely async surface:

| method | composition |
|---|---|
| `async fn wait(&self) -> Result<(), Error>` | `tokio::wait::wait_exit(self.id())` — non-reaping, unbounded, identity-verified (stale id ⇒ already exited ⇒ `Ok`) |
| `async fn wait_timeout(&self, timeout) -> Result<bool, Error>` | `tokio::wait::grace_wait(self.id(), timeout)` — at `ZERO`, `grace_wait` performs the sync backend's one-shot non-blocking probe (a zombie's `AsyncFd` readiness needs a reactor round-trip that a zero timer would win against; round-1 panel), keeping the "ZERO polls once" contract byte-compatible with sync |
| `async fn graceful_shutdown(&self, grace) -> Result<(), Error>` | mirror of sync foreign body on `grace_wait`: terminate → watch → kill unless exited → surface watch `Err` (non-stranding invariant; no reap — foreign) |
| `async fn graceful_shutdown_tree(&self, grace) -> Result<(), Error>` | mirror of sync foreign tree body: terminate_tree → watch → kill_tree (unconditional; its `Err` subsumes the watch `Err`) → surface watch `Err` |

Cancellation contract mirrors Plan 9: dropping `wait`/graceful futures cancels the watch on
every platform (Unix `AsyncFd` deregisters; the Windows watcher is released via its cancel
event — the Plan-9 `SignalOnDrop` guard already makes even an UNBOUNDED blocking watch
drop-safe). Runtime requirements documented as on the owned methods (IO + time drivers on
Unix; blocking-pool note on Windows tree ops).

### 2. `wait_exit` refactor (`src/tokio/wait.rs`)

Extract `pub(crate) async fn wait_exit(id: ProcessId) -> Result<(), Error>` — the existing
per-platform `exit_watch` arms, unbounded; `grace_wait(id, grace)` becomes
`timeout(grace, wait_exit(id))` on Unix and the existing cancellable blocking wait on
Windows with `None => INFINITE` grace mapping for the unbounded case (the deliberate
`INFINITE-1` cap stays for bounded graces; a true-unbounded foreign `wait` uses `INFINITE` —
release remains the cancel event, matching `block_until_exit`'s `None => INFINITE`
contract). The shared `wait::fault` seam head moves with the entry point so the stranding
seam still covers every watch consumer.

### 3. fd ≥ 3 async parent ends (Unix-only, sync parity)

Async spawn stops rejecting fd ≥ 3 on Unix; Windows keeps the typed `Unsupported` exactly as
sync does (`command-fds` is Unix-only). The shared `resolve_stdio` core already produces the
parent `PipeReader`/`PipeWriter` ends; the async `Child` converts on handout:
`fd_read_end(fd) -> Option<tokio::net::unix::pipe::Receiver>` /
`fd_write_end(fd) -> Option<pipe::Sender>` via `from_owned_fd` — verified against tokio
docs: it checks pipe-ness and access mode, sets non-blocking itself, and panics outside an
IO-enabled runtime (consistent with the crate's documented runtime notes). No hand-rolled
`AsyncFd` newtypes; no new crates (`net` feature already enabled by Plan 9).

### 4. Merge-into-piped-target (all platforms)

Lifting the `Deferred`-strategy rejection means the crate owns the merge target's pipe (both
child slots receive dups of one write end; tokio's internally-created pipes cannot be
shared). Per-OS:

- **Unix:** `std::io::pipe()` owned pair; both child slots get dup'd write ends via the
  existing `resolve_stdio` merge machinery; the parent read end is wrapped in
  `pipe::Receiver::from_owned_fd` and pumped by the async pump in place of the tokio child
  handle for that slot.
- **Windows (user decision 2026-07-13 — head-on, not Unix-only):** an owned overlapped
  named-pipe pair, the exact technique std's `anon_pipe` uses for child stdio — built
  entirely from PUBLIC safe APIs (round-1 panel + dependency evaluation): tokio's
  `ServerOptions` creates the uniquely-named server end (`first_pipe_instance` +
  `reject_remote_clients` + `max_instances(1)` — the security options are requirements, not
  choices), and `std::fs::OpenOptions` opens the synchronous client end for the child slots
  (std's spawn duplicates stdio handles inheritable itself). Empirically verified on the dev
  host (probes 2026-07-14 + 2026-07-16) and pinned by unit tests: the server surfaces NO
  I/O completions until `ConnectNamedPipe` runs (reads hang without it), so the connect is
  spawned as a REAL task (`connect_task`; the stream wrapper polls its `JoinHandle` before
  first I/O) — BOTH connect worlds verified (client-already-open resolves first-poll,
  `ERROR_PIPE_CONNECTED`; no-client is genuinely Pending and completes on a reactor wakeup).
  Names are `pid.counter.random64` (`getrandom`, std parity — unpredictability turns
  squat/slot-theft DoS into an enumeration race); no collision retry: any `PermissionDenied`
  (squatter or ACL denial — the squat case verified to error, not attach) surfaces as a
  typed error. The client-slot race is closed FAIL-SHUT: `max_instances(1)` makes the
  single client slot exclusive, so a hostile client winning the create→open window makes
  OUR open fail (`ERROR_PIPE_BUSY`, verified) before any child spawns or any byte moves —
  never data mis-attribution, at worst a typed spawn failure. In-direction teardown: DROP
  of the server delivers buffered data then clean EOF to the client (verified);
  `disconnect()` DISCARDS buffered data and is never used. NO raw FFI, no `unsafe`, no
  windows-crate features (`tokio-anon-pipe` evaluated: right technique, but both ends
  async/in-process — no inheritable child end). Both pipe ORIENTATIONS are implemented
  (`overlapped_out_pipe` / `overlapped_in_pipe` over one direction-parameterized core);
  `WinOwnedRead`/`WinOwnedWrite` are thin wrappers over ONE shared `ConnectingPipe`
  connect state machine. **Recorded fallback:** if
  implementation/review proves the pair disproportionate, merge ships Unix-only with the
  typed `Unsupported` on Windows — a retreat only the user can approve.
- The seam surfaces as PUBLIC opaque stream types (std's `ChildStdout` opacity pattern):
  `subprocess::tokio::{ChildStdin, ChildStdout, ChildStderr}` implementing
  `AsyncWrite`/`AsyncRead`, each wrapping either tokio's child stream (the default) or the
  our-owned merge-target end. `Child::{stdin, stdout, stderr}` return them (a
  signature change from Plan 8's direct tokio types — unpublished crate, no compat
  concern); `communicate` and existing tests compile unchanged against the traits.

## Invariants (carried, unchanged)

- Watch-error non-stranding on the foreign async graceful pair (mirrors the Plan-9 foreign
  sync bodies; covered by a seam-forced stranding twin).
- Foreign ops never reap and never return a status; identity-verified signaling throughout.
- No-time-sync test discipline; generous graces are failure bounds; `Duration::ZERO`
  deterministic escalation; unbounded waits are cancellable by construction.
- Error contracts: platform-unsupported ops are typed `Unsupported`, never silent degrades.

## Files

- `src/tokio/process.rs` (new) + `src/tokio/process/graceful.rs` (new, submodule pattern) +
  unit-test siblings; declared in `src/tokio.rs`; re-exported like sync `Process`.
- `src/tokio/wait.rs` — `wait_exit` extraction; Windows unbounded-grace mapping.
- `src/tokio/spawn.rs` — fd ≥ 3 acceptance (Unix), merge-target owned-pipe wiring.
- `src/tokio/child.rs` — `fd_read_end`/`fd_write_end` (Unix), merged-slot pump handoff.
- `src/tokio/pump.rs` — generic-`AsyncRead` seam for the merged slot.
- `src/stdio.rs`/`src/child/spawn.rs` shared core — only if the merge-target ownership
  switch needs a new `resolve_stdio` strategy variant (prefer reusing `Owned`).
- `src/wait/windows.rs` — `None => INFINITE` unbounded variant for the cancellable wait.
- Windows overlapped pipe pair + wrapper streams: `src/tokio/stdio.rs` (new; no `unsafe`,
  no windows-crate features) + `src/tokio/stdio_tests.rs`.
- `Cargo.toml` — `log = "0.4"`; windows-only `getrandom`; tokio features unchanged.
- `testbin/main.rs` — new `stdin-echo` mode (In-direction merge E2E).
- `tests/tokio_foreign.rs` (new), fd ≥ 3 + merge cases appended to the async IO/spawn
  suites; testbin reuse (existing modes suffice — foreign scenarios mirror
  `tests/graceful.rs` `process_*` and lifecycle cases).

## Testing

Scenario-mirrored suites (the recorded parity harness): `tests/tokio_foreign.rs` runs the
sync foreign scenarios async — terminate/graceful/escalation (`SIG_IGN` + `ZERO`),
`kill_tree` teardown by EOF, unsupported-op gating per platform, plus: an unbounded
`wait()` resolution test (kill-then-wait, failure-bounded), a poll-once-then-drop
cancellation test for `wait()` (no duration involved; `is_alive` is the discriminator —
the watch is signal-free, so the target must still be alive after the drop), and a foreign
async stranding twin via the shared seam. fd ≥ 3: async echo-through-fd tests mirroring
sync `spawn_io`'s, Windows `Unsupported` check, and both fd ≥ 3 merge-SOURCE round-trips
(into piped stdout and into piped stdin). Merge: async merge-into-pipe output tests
mirroring the sync merge cases on ALL platforms (interleaved stderr/stdout capture proven
by content, not timing) plus the In-direction target E2E (`stdin-echo` testbin mode).
Windows pipe unit tests pin the empirical facts: connect-mandatory E2E in both
orientations, the genuinely-Pending connect completed by a reactor wakeup, squat rejection
in both orientations, and client-slot exclusivity (`ERROR_PIPE_BUSY` on a stolen slot). No
sleeps, polls, or wall-clock synchronization anywhere.

## Recorded decisions (2026-07-13)

- **Windows merge head-on** (user): owned overlapped named-pipe pair rather than Unix-only
  shipping; retreat requires a user decision.
- **Introspection stays sync** on `tokio::Process` — no false function coloring.
- **tokio pipe types over hand-rolled wrappers** (`pipe::Receiver`/`Sender`,
  `named_pipe`) — the dependency-first rule; verified `from_owned_fd` semantics.
- **KERN_PROC fix queued behind Plan 10** (user follow-up policy; issues #2/#3).

## Non-goals / rejected

- Async elevation / PTY / *BSD — `TODO.md`, unchanged.
- An `ExitStatus`-returning foreign wait — a foreign process has no reapable status
  (sync precedent, unchanged).
- Making `parent`/`children` async — proc-table queries are synchronous reads.
