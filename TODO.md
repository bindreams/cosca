# TODO

Deferred work, captured during design (2026-06-20). Converted to tickets at first push.
Design spec: `.tmp/claude/superpowers/specs/2026-06-20-subprocess-design.md`.

## CI provisioning required (cgroup v2 live test)

The live cgroup v2 integration test (`linux_cgroup_v2_kill_tree_reaps_the_grandchild` in
`tests/spawn_io.rs`) is gated behind `SUBPROCESS_TEST_CGROUP=1`. It is a no-op when the
variable is absent, and FAILS loudly when the variable is set but a usable delegated
cgroup v2 slice is unavailable.

To run the live test in CI:

- Provision a delegated cgroup v2 slice (e.g. run the job under a systemd user slice,
  or with `--cgroupns private` + cgroup delegation). The process must be able to
  `mkdir` under its own cgroup path.
- Set `SUBPROCESS_TEST_CGROUP=1` in the CI environment for the Linux job.
- Verify kernel ≥ 5.14 (for `cgroup.kill` support).

## CI provisioning required (elevation live tier)

The live elevation tests (`tests/elevation.rs`) are gated behind
`SUBPROCESS_TEST_ELEVATION`: a true no-op when absent, FAIL LOUDLY when set but
elevation is unavailable (identical to `SUBPROCESS_TEST_CGROUP`).

- **Linux:** provision passwordless `sudo` for the job user (a `NOPASSWD:ALL`
  sudoers drop-in), then set `SUBPROCESS_TEST_ELEVATION=1`. The tests spawn
  `id -u` elevated and assert `0`; `Auth::NonInteractive` is used so no prompt
  blocks. `doas` is optional; `Backend::Auto` resolves `sudo` > `doas`.
  - The `Auth::Stdin` and `Auth::Askpass` live tests need
    `SUBPROCESS_TEST_ELEVATION_PASSWORD` set to the job user's sudo password
    (use a NON-`NOPASSWD` sudoers entry for that user so `sudo -S`/`-A` actually
    read the credential).
  - The real-PTY controlling-terminal test runs only under `--features pty`
    (the existing `pty` CI leg); it needs no elevation.
  - The universal-teardown test asserts an unprivileged parent's `kill()` of its
    elevated child either returns the typed `Unkillable` (direct-exec backends:
    `doas`/`run0`/`sudo` without `Defaults use_pty`, where the tracked child IS
    root) or succeeds (`sudo` WITH `use_pty`, where the tracked child is sudo's
    same-uid monitor and root runs under a pty grandchild); in both cases `Drop`
    must not hang. Tearing down that pty grandchild is the deferred teardown
    contract below.
  - The run0 unit-propagation test additionally requires
    `SUBPROCESS_TEST_ELEVATION_RUN0=1`, a `run0`-capable context, and a polkit
    rule granting the job user the run0 action passwordless (run0 authenticates
    via polkit; `--no-ask-password` suppresses the prompt and fails loud without
    such a rule — it does not provide cached-credential non-interactive auth the
    way `sudo -n` does).
- **Windows:** `ShellExecuteEx(runas)` always shows a UAC prompt on an
  interactive desktop, so the live Windows tier (sync AND the
  `#[cfg(all(windows, feature = "tokio"))]` async twin) is a **documented
  manual-run tier** — run on a machine with UAC auto-approve (admin-approval-mode
  off) or a self-hosted elevated runner, with `SUBPROCESS_TEST_ELEVATION=1` and
  `SUBPROCESS_TEST_ELEVATION_MARKER_DIR` pointing at an admin-only-writable dir
  (e.g. `C:\Windows\System32\subprocess-ci`). The `Unkillable`/no-hang-Drop test
  runs under the same tier. Not run on hosted GitHub runners.

## Elevation (the headline differentiator — after core)

- [x] Elevate to Admin/root: declarative elevation on the builder + pure `Host::plan(target) -> Transition` planner (cross-tested on all OS); per-OS effect layer rejects wrong-platform variants. (Delivered on branch `azhukova/6`, issue #6.)
- [x] POSIX backends: runtime-detected, ordered, overridable (`Auto` = `sudo` > `doas`; explicit `run0`/`pkexec`); auth-strategy enum (Interactive/Stdin/Askpass/NonInteractive/Gui); env as a security boundary (clean default, denylist `EnvSanitizer`, backend-native forwarding — no `env` wrapper). NOTE: `run0` is EXCLUDED from `Auto` (it spawns a PID-1-parented transient unit that breaks the `Child` identity/kill/contain contract); it is explicit-only with forced `--pipe` and `.contain()`+run0 → `Unsupported`.
- [x] Windows: `ShellExecuteEx("runas")` UAC path; detection via `TokenElevation` + `TokenIntegrityLevel` (aligned RID read). Honest capability contract: captured stdio / `.env` / `.contain` / `fd>=3` on an elevated Windows child are loud `Unsupported` (the broker below lifts these).
- [ ] Run as a specific user (`CreateProcessWithLogonW`/`AsUser` chain on Windows; `sudo -u`/`su` on POSIX); credential handling.
- [ ] Elevate to SYSTEM (`NT AUTHORITY\SYSTEM`): SeDebug/SeImpersonate token duplication, service, or SYSTEM scheduled task — separate consent/installer story.
- [ ] De-elevation / privilege drop: POSIX `setgroups`→`setresgid`→`setresuid` (verify-by-regain); Windows linked-token de-elevation (the recovered hole 9-step minefield).
- [ ] Elevated broker/helper for elevation-WITH-piping: bundled signed helper EXE + named-pipe/UDS bridge (gsudo/deelevate/PsExec/MS-sudo pattern); secured pipe namespace + peer verification + constrained proxy; packaging + signing story. macOS GUI elevation (osascript / `SMAppService`). Tiered/degrading capture (inherit → true pipes → file fallback) with the in-effect mode queryable.
- [ ] Teardown contract for un-killable elevated children (sudo ≥1.9.14 pty/monitor won't relay SIGKILL): graceful-only + drain-then-abandon of never-EOF readers.
- [ ] Reference: qodana-cli `sudo/` dir (Apache-2.0) — inspect for POSIX elevation patterns.

## Introspection

- [ ] Full psutil-style system-wide enumeration: `process_iter()`, system-wide `parent()`/`children()`, cached `(pid,start_token)` registry, `oneshot` snapshot batching, `wait_procs(timeout)->(gone,alive)`.

## Identity (follow-ups from Plan 2)

- [x] Add a `cfg(unix)` real-zombie integration test asserting `is_alive()==false` for an un-reaped exited child (exercises Linux `/proc` state `Z` and macOS `pbi_status==SZOMB` at RUNTIME). Needs Plan 6's foreign-wait primitive to deterministically observe a zombie without reaping. Decision logic is already host-tested on Linux via `running_from_stat`; macOS is a single `!= SZOMB`.

## Stdio / PTY

- [ ] Full PTY wiring behind `pty` feature (`portable-pty`): ConPTY drain quirks (never-EOF until close, single-threaded close deadlock, output VT/CSI/OSC scrubbing, input-pipe write-end lifetime), mixed stdout/stderr-PTY via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. (`Stdio::pty()` variant exists in v1.)

## Pipelines

- [ ] Tree-contained, async pipelines (duct/`subprocess`-style `Expression`/`.pipe()`) — the literal ecosystem gap.

## Persistence

- [ ] Identity persistence for crash recovery: atomic schema-versioned `(pid,start_token)` records (`tempfile` `NamedTempFile`→`sync_all`→`persist`, `serde(deny_unknown_fields)` + `SCHEMA_VERSION`, fail-soft load). `serde` feature.

## Platforms

- [ ] \*BSD tier (FreeBSD/OpenBSD/NetBSD).

## Ecosystem / housekeeping

- [ ] Migrate hole `stepstool`/`kill-group`/`bridge`/`relaunch`/`handle-holders` to depend on this crate; dedup the 3 `CommandLineToArgvW` quoters and the multiple `OwnedHandle` re-rolls.
- [ ] Choose published crate name (`subprocess` is taken on crates.io).
- [ ] Settle license line for the ported qodana shlex (Apache-2.0, user-authored) — attribution header / NOTICE.
- [ ] Re-validate own-containment vs `process-wrap` dependency, and `cgroups-rs` vs thin direct cgroup-fs impl.

## Spawn engine (from Plan 4, delivered in Plan 12)

- [x] (Plan 12) Raw `CreateProcessW` backend (sync + async) supporting independent `executable` + `commandline` and `fd >= 3` on Windows — `lpApplicationName` set independently of `lpCommandLine`, argv[0] preserved, and `fd >= 3` smuggled via the MSVCRT `lpReserved2` fd-table.

Retained deferrals (agreed with user; permanent design limits, not bugs): chained merges (`merge -> merge`), `Stdio::inherit()` on `fd >= 3` (no defined parent stream), and `fd >= 3` for non-MSVCRT children (the `lpReserved2` table is a CRT-private contract — inherent).

## Lifecycle / graceful shutdown (from Plan 5)

- [x] (Plan 7) Graceful-escalation trio — deferred from Plan 5: `terminate()` (Unix-only lone `SIGTERM`), `graceful_shutdown(Duration)` (lone soft→hard escalation), `graceful_shutdown_tree(Duration)` (tree soft→hard escalation). Race-free implementation needs Plan-6 primitives: `pidfd_send_signal` (Linux identity-bound signal — closes lone `terminate`'s check-then-act PID-reuse race against a concurrent reap; macOS has no equivalent) and a non-reaping wait-with-timeout (so a tree hard-sweep runs BEFORE the root is reaped, avoiding the `killpg`-after-reap race that `shared_child`'s reaping wait can't). Settled design (Plan-6 blueprint): lone graceful is Unix-only (Windows has no single-process graceful primitive — group-scoped `CTRL_BREAK` only); grace is a relative `Duration` (matches Python/.NET/Go); escalation proceeds past a failed soft signal.

## Lifecycle / async (from Plan 8)

The async mirror shipped as an I/O foundation only; remaining items deferred to Plan 10:

- [x] (Plan 9) Async `contain_with`/`nesting` builder modes.
- [x] (Plan 10) Async parent-end access for fd ≥ 3 via tokio pipe ends (Unix, mirroring sync).
- [x] (Plan 10) Async merge-into-a-piped-target (all platforms; Windows via an owned
      overlapped named-pipe pair).
- [x] (Plan 9) Async explicit control: `kill`/`kill_tree`/`terminate_tree` + the graceful trio
      (`terminate`/`graceful_shutdown`/`graceful_shutdown_tree`), on a reactor-native grace-wait
      (`AsyncFd` pidfd / kqueue; Windows: event-cancellable blocking wait — no pollable
      process handle).
- [x] (Plan 10) Async foreign `Process` (introspect/wait/kill/graceful on a non-owned process).

## Hardening / tech-debt (from foundation review)

- [ ] Before publish, exclude or feature-gate `subprocess_testbin` so the test helper isn't shipped in the published crate.
- [ ] When FFI lands (containment/identity/wait plans), flip `[lints.rust] unsafe_op_in_unsafe_fn` from `warn` to `deny`.
- [ ] At the edition-2024 bump, convert the test-only `extern "system"` blocks (quote/windows_tests.rs) to `unsafe extern`.
- [ ] (Optional) Supplement the deterministic exhaustive never-panics/round-trip sweeps with a `proptest`/`cargo-fuzz` unbounded property for the quoting parsers.
- [ ] Unify the POSIX `split` Whitespace-state backslash handling with `backslash_unquoted` via an enum return (cosmetic DRY; behavior is correct and oracle-matched).
- [ ] (Plan 5 T5-1, DRY) Extract a shared `tests/common/mod.rs` control-spawn harness and migrate the duplicated sites: `tests/lifecycle.rs`'s `spawn_control` and `tests/spawn_io.rs`'s `spawn_contained_tree`/`spawn_session_tree`/`spawn_treewalk_tree` + the escapee (4 sites). Deferred from Plan 5 (consolidating would pull Plan-4 test files into Plan-5 scope).
