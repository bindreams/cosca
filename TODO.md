# TODO

Deferred work, captured during design (2026-06-20). Converted to tickets at first push.
Design spec: `.tmp/claude/superpowers/specs/2026-06-20-subprocess-design.md`.

## Elevation (the headline differentiator — after core)

- [ ] Elevate to Admin/root: declarative `Privilege` on the builder + pure `Host::plan(target) -> Transition` planner (cross-tested on all OS); per-OS effect layer rejects wrong-platform variants. Reuse hole `xtask/src/privilege` architecture; salvage stepstool's `prime_sudo` (TTY-gated), `preserve_env_arg`, `{SudoNotFound,AuthFailed,NoTty}` taxonomy.
- [ ] POSIX backends: runtime-detected, ordered, overridable (`run0` > `sudo` > `doas`; GUI `pkexec`); auth-strategy enum (Interactive/Stdin/Askpass/NonInteractive/Gui); env as a security boundary (clean default, allowlist, deny `LD_PRELOAD`/`DYLD_*`/...).
- [ ] Windows: `ShellExecuteEx("runas")` UAC path; detection via `TokenElevationType` + `TokenIntegrityLevel` (RID range-compare).
- [ ] Run as a specific user (`CreateProcessWithLogonW`/`AsUser` chain on Windows; `sudo -u`/`su` on POSIX); credential handling.
- [ ] Elevate to SYSTEM (`NT AUTHORITY\SYSTEM`): SeDebug/SeImpersonate token duplication, service, or SYSTEM scheduled task — separate consent/installer story.
- [ ] De-elevation / privilege drop: POSIX `setgroups`→`setresgid`→`setresuid` (verify-by-regain); Windows linked-token de-elevation (the recovered hole 9-step minefield).
- [ ] Elevated broker/helper for elevation-WITH-piping: bundled signed helper EXE + named-pipe/UDS bridge (gsudo/deelevate/PsExec/MS-sudo pattern); secured pipe namespace + peer verification + constrained proxy; packaging + signing story. macOS GUI elevation (osascript / `SMAppService`). Tiered/degrading capture (inherit → true pipes → file fallback) with the in-effect mode queryable.
- [ ] Teardown contract for un-killable elevated children (sudo ≥1.9.14 pty/monitor won't relay SIGKILL): graceful-only + drain-then-abandon of never-EOF readers.
- [ ] Reference: qodana-cli `sudo/` dir (Apache-2.0) — inspect for POSIX elevation patterns.

## Introspection

- [ ] Full psutil-style system-wide enumeration: `process_iter()`, system-wide `parent()`/`children()`, cached `(pid,start_token)` registry, `oneshot` snapshot batching, `wait_procs(timeout)->(gone,alive)`.

## Identity (follow-ups from Plan 2)

- [ ] Add a `cfg(unix)` real-zombie integration test asserting `is_alive()==false` for an un-reaped exited child (exercises Linux `/proc` state `Z` and macOS `pbi_status==SZOMB` at RUNTIME). Needs Plan 6's foreign-wait primitive to deterministically observe a zombie without reaping. Decision logic is already host-tested on Linux via `running_from_stat`; macOS is a single `!= SZOMB`.

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

## Spawn engine (from Plan 4)

- [ ] (Plan 4) Implement raw backend (CreateProcess/execve) to support independent `executable` + `commandline` on Windows — std has no stable API to set `lpApplicationName` independently of `lpCommandLine`, so the std-only backend forces `argv[0]` to equal the executable when both are set.

## Hardening / tech-debt (from foundation review)

- [ ] Before publish, exclude or feature-gate `subprocess_testbin` so the test helper isn't shipped in the published crate.
- [ ] When FFI lands (containment/identity/wait plans), flip `[lints.rust] unsafe_op_in_unsafe_fn` from `warn` to `deny`.
- [ ] At the edition-2024 bump, convert the test-only `extern "system"` blocks (quote/windows_tests.rs) to `unsafe extern`.
- [ ] (Optional) Supplement the deterministic exhaustive never-panics/round-trip sweeps with a `proptest`/`cargo-fuzz` unbounded property for the quoting parsers.
- [ ] Unify the POSIX `split` Whitespace-state backslash handling with `backslash_unquoted` via an enum return (cosmetic DRY; behavior is correct and oracle-matched).
