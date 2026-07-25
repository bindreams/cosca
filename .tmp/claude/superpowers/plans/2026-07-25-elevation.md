# Elevation (elevate-to-admin/root) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add cross-platform, DX-honest privilege elevation to the `subprocess` crate — a declarative `.elevate()` builder that wraps the CHILD (never the caller) via POSIX `sudo`/`run0`/`doas`/`pkexec` or Windows `ShellExecuteEx("runas")`, with a pure cross-OS planner, an env security boundary, and a queryable achieved-state report, in full sync + async parity.

**Architecture:** A pure `Host::plan(target, backend, auth) -> Transition` planner (plain data `Host`, no syscalls, cross-OS-testable) is the SINGLE validation choke point: it validates the whole Auth×backend×platform matrix BEFORE any already-elevated short-circuit, so verdicts never depend on ambient privilege. Two effect layers consume it and trust the transition: POSIX **rewrites** the request into a NON-DESTRUCTIVE derived backend command (the caller's `Command` is left untouched, so reuse never double-wraps) and reuses the existing spawn path; Windows is a **distinct** `ShellExecuteEx` spawn backend returning a reduced `Child` (wait/exit-code/kill only, with a non-blocking kill for the higher-integrity child). Every capability gap is a loud `Error::Unsupported` (structural) or `Error::Elevation` (runtime), never a silent lie; the achieved disposition is reported via `Child::elevation() -> Option<ElevationReport>`, which is `Some(..)` iff elevation was REQUESTED.

**Tech Stack:** Rust 1.87 (edition 2021), `thiserror` 2, `log` 0.4, `shared_child` 1, `zeroize` 1 (new), `nix` 0.31 / `libc` 0.2 (POSIX detect + `/dev/tty` + `faccessat`), `windows` 0.62 (token + ShellExecuteEx + COM), `tokio` 1 (async, `tokio` feature). Uses `std::io::pipe` (stable in 1.87) for the `Auth::Stdin` password channel. Reuses the crate's own `crate::quote::windows::join_wide` for Windows command-line construction and the raw-backend `RawChild`/`RawAsyncChild` handle wrappers (extended with a non-blocking `runas` kill mode).

## Global Constraints

- Rust edition 2021, `rust-version = "1.87"`. No new MSRV bump. `std::io::pipe` is stable as of 1.87 and is used for the `Auth::Stdin` channel.
- Dependency versions (verbatim from `Cargo.toml`): `thiserror = "2"`, `shared_child = { version = "1", features = ["timeout"] }`, `log = "0.4"`, `tokio = { version = "1", optional = true, features = ["process","rt","io-util","macros","net","sync","time"] }`, `tempfile = "3"` (dev), `libc = "0.2"`, `nix = { version = "0.31", features = ["signal","process","event"] }` (UNCHANGED — the exec-bit check uses `libc::faccessat(AT_FDCWD, _, X_OK, AT_EACCESS)` and the tty probe uses `libc::open("/dev/tty", O_RDWR|O_CLOEXEC|O_NONBLOCK)`), `windows = "0.62"`. NEW: `zeroize = "1"`.
- Module style: `foo.rs` + `foo/` subdir (NOT `mod.rs`). Unit tests in a SEPARATE sibling `foo_tests.rs`, included via `#[cfg(test)] #[path = "foo_tests.rs"] mod foo_tests;`. Debug asserts encouraged. `#[cfg(unix)]` / `#[cfg(windows)]` gating for platform effect code; pure code compiles everywhere.
- Async is gated behind the `tokio` feature; every async task's tests run under `--features tokio`.
- Builder methods are flat and return `&mut Command`, mirroring `.contain()` / `.contain_with()` / `.nesting()`.
- `Error::Unsupported` = "can never work on this platform"; `Error::Elevation` = "could work but failed now." Never conflate.
- `cargo clippy --all-targets --locked -- -D warnings` (prek.toml:26) is a hard gate on every commit: NO `dead_code`, NO `unused_mut`, NO unused imports may land. Each task must be clippy-clean on the platform(s) it compiles for.
- Live privilege-gain tests are gated behind `SUBPROCESS_TEST_ELEVATION`: a true no-op when the var is absent, and FAIL LOUDLY when it is set but elevation is unavailable (mirror `SUBPROCESS_TEST_CGROUP` in `tests/spawn_io.rs`). Pure argv/rewrite/planner tests are UNGATED, inject a resolved backend path or a fake `Host`, and never shell out to a real backend or silently skip.
- Detection/identity tests never assume ambient privilege: they compare `is_elevated()` against an independent ground truth (`geteuid()==0` on unix; the integrity-level invariant on windows) or branch on the detected state.
- Commit messages are single-line (repo rule; see `git log`).
- Work stays on branch `azhukova/6` (issue #6). Never push to `main`.
- DEFERRED — do NOT implement: run-as-user, elevate-to-SYSTEM, de-elevation, signed broker/piping, un-killable-child teardown, macOS GUI elevation.

### Per-task green matrix (which commits build on which platform)

| Task | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| 1 Error taxonomy | ✓ | ✓ | ✓ | pure |
| 2 Secret | ✓ | ✓ | ✓ | pure |
| 3 Public enums | ✓ | ✓ | ✓ | pure |
| 4 Planner happy path | ✓ | ✓ | ✓ | pure (fake Host) |
| 5 Planner rejection matrix | ✓ | ✓ | ✓ | pure |
| 6 EnvSanitizer | ✓ | ✓ | ✓ | pure |
| 7 POSIX build_argv | ✓ | ✓ | ✓ | pure; module is cfg(unix) but argv logic host-tested on any unix |
| 8 Command builder | ✓ | ✓ | ✓ | pure |
| 9 POSIX detection | ✓ | ✓ | n/a (cfg(unix)) | `/dev/tty` + `faccessat` |
| 10 `spawn_unelevated` extraction | ✓ | ✓ | ✓ | pure refactor; full `cargo test --lib` regression |
| 11 POSIX effect rewrite + Child field | ✓ | ✓ | ✓ (Child field cross-platform; rewrite cfg(unix)) | non-destructive derived command |
| 12 Windows detection + integrity + deps + identity helper | ✓ (compiles; windows arms inert) | ✓ | ✓ | |
| 13 Windows reject gate | n/a arms | n/a arms | ✓ | |
| 14 Windows `launch_runas` + `spawn_elevated` + non-blocking runas kill | ✓ (shared drop refactor compiles; windows arms inert) | ✓ | ✓ | RawChild `runas` flag + `ProcHandle::teardown_on_drop` + `Child::drop` are cross-platform |
| 15 `spawn()` elevation branch (fd-take reorder) | ✓ | ✓ | ✓ | references Tasks 11 + 14 — both already landed |
| 16 Async parity | ✓ | ✓ | ✓ | `--features tokio` |
| 17 Live gated tests + testbin | ✓ | ✓ | ✓ | ungated = no-op |
| 18 TODO.md | ✓ | ✓ | ✓ | docs |
| 19 PR + CI | — | — | — | workflow |

The one ordering rule the sequence enforces: nothing forward-references a later task. Windows detection (12), the reject gate (13), and the Windows `spawn_elevated` (14) all land BEFORE the `spawn()` branch (15) that calls them; the `spawn_unelevated` extraction (10) and POSIX `rewrite` (11) land before that same branch. Task 14 also lands the RawChild `runas` flag, `ProcHandle::teardown_on_drop`, and the `Child::drop` change (the non-blocking runas kill) — all consumed by Task 15's Windows `spawn_elevated` continuation and by every `Child` drop.

---

## File Structure

**Create:**
- `src/elevation.rs` — public surface: `is_elevated()`, enums (`Backend`, `Auth`, `ElevatedStdio`, `ElevatedVia`, `Privilege`), `Secret`, `ElevationReport`, crate-internal `ElevationRequest`, module wiring + re-exports.
- `src/elevation_tests.rs` — unit tests for the public surface (enum defaults, `Secret` redaction, `is_elevated` ground-truth detection).
- `src/elevation/plan.rs` — PURE `Host` / `BackendSet` / `Os` / `Transition` + `Host::detect()` + `Host::plan()`.
- `src/elevation/plan_tests.rs` — cross-OS planner + full rejection-matrix tests (fake `Host` on any runner).
- `src/elevation/sanitize.rs` — `EnvSanitizer`, `DEFAULT_DENYLIST`, `apply()`.
- `src/elevation/sanitize_tests.rs` — denylist / keep / allowlist / filter / none tests.
- `src/elevation/posix.rs` — `#[cfg(unix)]`: `detect()`, `is_elevated()`, `controlling_terminal_present()`, `resolve_on_path`/`resolve_in_path_var`, pure `build_argv()`, non-destructive `rewrite()` / `rewrite_with_host()`.
- `src/elevation/posix_tests.rs` — argv-construction + rewrite + path-resolution tests (no backend install needed).
- `src/elevation/windows.rs` — `#[cfg(windows)]`: `detect()`, `is_elevated()`, `integrity_level()`, `reject_unsupported_config()`, `launch_runas()` / `launch_runas_with_host()`, `spawn_elevated()`.
- `src/elevation/windows_tests.rs` — detection + rejection + host-injected gate tests (no UAC needed).
- `tests/elevation.rs` — gated live integration tests (sync + async) + ungated cross-process probes.

**Modify:**
- `Cargo.toml` — add `zeroize = "1"`; extend `[target.'cfg(windows)'.dependencies] windows` feature list.
- `src/error.rs` (+ `src/error_tests.rs`) — add `ElevationErrorKind` and `Error::Elevation`.
- `src/lib.rs` — `pub mod elevation;`.
- `src/identity/windows.rs` — `pub(crate) fn windows_identity_from_handle`.
- `src/command.rs` (+ `src/command_tests.rs`) — the four builder methods + `ElevationRequest` field + `elevation_request()` / `set_input_argv()` / `set_env_ops()` / `set_contain()`.
- `src/child.rs` — `elevation: Option<ElevationReport>` field, `set_elevation()`, `elevation()`; `Drop` uses `ProcHandle::teardown_on_drop`.
- `src/child/proc_handle.rs` — `teardown_on_drop()` dispatcher.
- `src/child/spawn/windows_raw/proc.rs` — `RawChild` gains a `runas` flag, `new_runas()`, and a non-blocking `teardown_on_drop()`.
- `src/child/spawn.rs` — extract `spawn_unelevated`; add the elevation branch to `spawn()`.
- `src/tokio/command.rs` — mirror the four builder methods.
- `src/tokio/child.rs` — `elevation` field + `set_elevation()` + `elevation()`.
- `src/tokio/spawn.rs` — async elevation branch (POSIX derived-command recursion; Windows in-tokio child build).
- `src/tokio/spawn/windows_raw.rs` — `RawAsyncChild` gains a `runas` flag, `new_runas()`, and a non-blocking `reap_blocking()`.
- `testbin/main.rs` — `is-elevated-report`, `controlling-terminal`, and `write-marker` subcommands for live tests.
- `TODO.md` — CI provisioning note for the elevation live tier.

### Capability matrix (the honest contract this plan enforces)

| Capability | sudo | doas | pkexec | run0 (explicit) | Windows (`runas`) |
|---|---|---|---|---|---|
| Elevate a child; wait; exit code; kill | ✓ | ✓ | ✓ | ✓ (targets the run0 client) | ✓ (kill best-effort — higher-integrity child may be unkillable; honest error, never a hang) |
| Captured stdio, fd 0-2 | ✓ | ✓ | ✓ | ✓ (forced `--pipe`) | ✗ `Unsupported` |
| `fd ≥ 3` | ✗ `Unsupported` | ✗ `Unsupported` | ✗ `Unsupported` | ✗ `Unsupported` |
| Forward env (`.env`, sanitized) | ✓ (`--preserve-env`, set in sudo's own env) | ✗ `Unsupported` | ✗ `Unsupported` | ✓ (`--setenv=K=V`) | ✗ `Unsupported` |
| `.env_remove()` / `.env_clear()` | ✗ `Unsupported` | ✗ `Unsupported` | ✗ `Unsupported` | ✗ `Unsupported` | ✗ `Unsupported` |
| `.contain()` + elevate | ✓ | ✓ | ✓ | ✗ `Unsupported` | ✗ `Unsupported` |

---

### Task 1: Elevation error taxonomy

**Files:**
- Modify: `src/error.rs`
- Test: `src/error_tests.rs`

**Interfaces:**
- Produces: `ElevationErrorKind::{BackendUnavailable, AuthFailed, AuthDeclined, NoTty, Untracked}` (Debug, Clone, Copy, PartialEq, Eq); `Error::Elevation { kind: ElevationErrorKind, detail: String }`.

`Untracked` covers the "runas succeeded but we could not resolve/manage the child" case (Task 14): auth SUCCEEDED, so it must not report as `AuthFailed`. Its `Display` is NEUTRAL — it must not assert the child "was terminated", because the caller-visible `detail` reports terminated-vs-still-running honestly (Task 14 sets it from the actual `TerminateProcess` result).

- [ ] **Step 1: Write the failing test** — append to `src/error_tests.rs`:

```rust
#[test]
fn elevation_error_displays_kind_and_detail() {
    use crate::error::ElevationErrorKind;
    let e = Error::Elevation {
        kind: ElevationErrorKind::NoTty,
        detail: "interactive auth requested with no controlling terminal".into(),
    };
    let s = e.to_string();
    assert!(s.contains("no controlling terminal"), "{s}");
    assert!(matches!(e, Error::Elevation { kind: ElevationErrorKind::NoTty, .. }));
}

#[test]
fn elevation_error_kinds_have_distinct_messages() {
    use crate::error::ElevationErrorKind::*;
    let all = [BackendUnavailable, AuthFailed, AuthDeclined, NoTty, Untracked];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.to_string(), b.to_string(), "{a:?} vs {b:?}");
        }
    }
}

#[test]
fn untracked_message_does_not_assert_termination() {
    // The kind's Display is neutral; termination status lives in `detail` (Task 14).
    use crate::error::ElevationErrorKind::Untracked;
    let s = Untracked.to_string();
    assert!(!s.contains("terminated"), "Untracked Display must not claim termination: {s}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib error_tests::elevation error_tests::untracked`
Expected: FAIL — `no variant named Elevation`, `no module ElevationErrorKind`.

- [ ] **Step 3: Write minimal implementation** — in `src/error.rs`, add the enum before `Error` and the variant inside `Error`:

```rust
/// Runtime elevation failures — "could work here but failed now" (contrast
/// [`Error::Unsupported`], which is "can never work on this platform").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ElevationErrorKind {
    /// The requested (or auto-detected) backend is not on PATH, or the resolved
    /// backend could not be executed.
    #[error("no usable elevation backend is available")]
    BackendUnavailable,
    /// Wrong password, or `sudo -n` found no cached credential, or the launch failed.
    #[error("elevation authentication failed")]
    AuthFailed,
    /// The UAC / GUI prompt was cancelled by the user (Windows `ERROR_CANCELLED`).
    #[error("elevation prompt was declined")]
    AuthDeclined,
    /// Interactive auth requested but there is no controlling terminal to prompt on.
    #[error("no controlling terminal for interactive elevation")]
    NoTty,
    /// The elevated child launched, but the parent could not resolve its identity to
    /// manage it. Whether it was terminated is reported in the error `detail`.
    #[error("elevated child launched but could not be tracked")]
    Untracked,
}
```

Inside `pub enum Error`, after the `Containment` variant:

```rust
    /// Privilege elevation could not be completed at runtime.
    #[error("elevation failed ({kind}): {detail}")]
    Elevation {
        kind: ElevationErrorKind,
        detail: String,
    },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib error_tests::elevation error_tests::untracked`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/error.rs src/error_tests.rs
git commit -m "feat: add Error::Elevation and ElevationErrorKind taxonomy"
```

---

### Task 2: `Secret` (zeroized password wrapper)

**Files:**
- Modify: `Cargo.toml`
- Create: `src/elevation.rs`, `src/elevation_tests.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `subprocess::elevation::Secret` — wraps a password; `Debug` is redacted; zeroized on drop; `Clone`; constructed via `Secret::new(impl Into<Vec<u8>>)`; bytes via `Secret::expose(&self) -> &[u8]`.

- [ ] **Step 1: Write the failing test** — create `src/elevation_tests.rs`:

```rust
use super::Secret;

#[test]
fn secret_debug_is_redacted() {
    let s = Secret::new("hunter2");
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("hunter2"), "Secret Debug must not leak the value: {dbg}");
    assert!(dbg.contains("Secret"), "{dbg}");
}

#[test]
fn secret_exposes_bytes_for_the_effect_layer() {
    let s = Secret::new("pw");
    assert_eq!(s.expose(), b"pw");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation_tests::secret`
Expected: FAIL — `unresolved module elevation` / `cannot find type Secret`.

- [ ] **Step 3: Write minimal implementation**

In `Cargo.toml`, under `[dependencies]` (after `log = "0.4"`):

```toml
# Zeroize the password held for Auth::Stdin so it never lingers in freed memory.
zeroize = "1"
```

Create `src/elevation.rs`:

```rust
//! Cross-platform privilege elevation. Elevation wraps the CHILD (a
//! `sudo`/`run0`/`doas`/`pkexec` prefix on POSIX; `ShellExecuteEx("runas")` on
//! Windows), never the calling process. See the pure planner in [`plan`].

use zeroize::Zeroize;

/// A password supplied for [`Auth::Stdin`]. Zeroized on drop; its `Debug` is
/// redacted so it never reaches a log line. `expose` is the only readout, used
/// by the POSIX effect layer to feed `sudo -S`.
#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Secret {
        Secret(bytes.into())
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
#[path = "elevation_tests.rs"]
mod elevation_tests;
```

In `src/lib.rs`, after `pub mod containment;`:

```rust
pub mod elevation;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib elevation_tests::secret`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/elevation.rs src/elevation_tests.rs
git commit -m "feat: add zeroized Secret for Auth::Stdin"
```

---

### Task 3: Public enums, `ElevationReport`, `ElevatedVia`, and `ElevationRequest`

**Files:**
- Modify: `src/elevation.rs`, `src/elevation_tests.rs`

**Interfaces:**
- Produces:
  - `pub enum Backend { Auto, Run0, Sudo, Doas, Pkexec }` — Debug, Clone, Copy, PartialEq, Eq; `Default = Auto`.
  - `pub enum Auth { Interactive, NonInteractive, Askpass(PathBuf), Stdin(Secret), Gui }` — Debug, Clone; `Default = Interactive`.
  - `pub enum ElevatedStdio { Passthrough, OwnConsole }` — Debug, Clone, Copy, PartialEq, Eq, `#[non_exhaustive]`.
  - `pub enum ElevatedVia { Wrapped(Backend), WindowsUac, AlreadyElevated }` — Debug, Clone, PartialEq, Eq.
  - `pub enum Privilege { Unprivileged, Elevated }` — Debug, Clone, Copy, PartialEq, Eq, `#[non_exhaustive]`.
  - `pub struct ElevationReport { via: ElevatedVia, stripped_env: Vec<OsString>, stdio: ElevatedStdio }` — Debug, Clone; public fields.
  - `pub(crate) struct ElevationRequest { enabled: bool, backend: Backend, auth: Auth, sanitizer: EnvSanitizer }` — Debug; `Default`.

`ElevatedStdio` is `{Passthrough, OwnConsole}` — the deferred broker (`Piped`) and a future `SW_HIDE` knob (`Hidden`) are non-breaking additions under `#[non_exhaustive]`. `ElevatedVia::WindowsUac` is a DEDICATED variant for Windows runas — it does NOT reuse `Backend::Auto`, which is a POSIX resolution concept.

- [ ] **Step 1: Write the failing test** — append to `src/elevation_tests.rs`:

```rust
use super::{Auth, Backend, ElevatedStdio, ElevatedVia, ElevationReport, Privilege};

#[test]
fn backend_defaults_to_auto() {
    assert_eq!(Backend::default(), Backend::Auto);
}

#[test]
fn auth_defaults_to_interactive() {
    assert!(matches!(Auth::default(), Auth::Interactive));
}

#[test]
fn privilege_variants_are_distinct() {
    assert_ne!(Privilege::Unprivileged, Privilege::Elevated);
}

#[test]
fn elevated_via_distinguishes_windows_uac_from_wrapped() {
    assert_ne!(ElevatedVia::WindowsUac, ElevatedVia::Wrapped(Backend::Sudo));
    assert_ne!(ElevatedVia::WindowsUac, ElevatedVia::AlreadyElevated);
}

#[test]
fn elevation_report_holds_achieved_state() {
    let r = ElevationReport {
        via: ElevatedVia::Wrapped(Backend::Sudo),
        stripped_env: vec!["LD_PRELOAD".into()],
        stdio: ElevatedStdio::Passthrough,
    };
    assert_eq!(r.via, ElevatedVia::Wrapped(Backend::Sudo));
    assert_eq!(r.stripped_env, vec![std::ffi::OsString::from("LD_PRELOAD")]);
    assert_eq!(r.stdio, ElevatedStdio::Passthrough);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation_tests`
Expected: FAIL — `cannot find type Backend/Auth/Privilege/ElevatedVia/ElevationReport`.

- [ ] **Step 3: Write minimal implementation** — in `src/elevation.rs`, add above the `Secret` definition:

```rust
use std::ffi::OsString;
use std::path::PathBuf;

pub mod plan;
pub mod sanitize;

pub use sanitize::EnvSanitizer;

/// Which elevation program runs. `Auto` (default) detects among the CLI backends
/// only — order `sudo` > `doas`. `run0` and `pkexec`/graphical elevation are
/// explicit-only (`run0` spawns a PID-1-parented unit, not our descendant; a
/// library must not pop a polkit dialog unbidden).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    #[default]
    Auto,
    Run0,
    Sudo,
    Doas,
    Pkexec,
}

/// How the backend authenticates. `Interactive` (default) prompts on the
/// controlling TTY; with no controlling terminal it is a loud
/// [`crate::error::ElevationErrorKind::NoTty`].
#[derive(Debug, Clone, Default)]
pub enum Auth {
    #[default]
    Interactive,
    NonInteractive,
    Askpass(PathBuf),
    Stdin(Secret),
    Gui,
}

/// How stdio was ACTUALLY wired for an elevated child — reported, never faked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElevatedStdio {
    /// POSIX: the child's stdio (fds 0-2) is wired exactly as the `Command`
    /// configured it (`sudo`/`run0`/`doas`/`pkexec` pass those fds straight
    /// through). fd >= 3 on an elevated POSIX child is `Unsupported`, not
    /// silently dropped.
    Passthrough,
    /// Windows `runas`: the child received its OWN console; the parent's streams
    /// were not shared, regardless of any `inherit()` request.
    OwnConsole,
}

/// How elevation was achieved. Distinct from [`Backend`]: `WindowsUac` is the
/// dedicated Windows runas disposition (NOT `Backend::Auto`, a POSIX concept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevatedVia {
    /// A POSIX backend wrapped the child (the resolved backend that ran).
    Wrapped(Backend),
    /// Windows `ShellExecuteEx("runas")` elevated the child through UAC.
    WindowsUac,
    /// The process was already elevated, so no wrapper was needed.
    AlreadyElevated,
}

/// The planner's privilege target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Privilege {
    Unprivileged,
    Elevated,
}

/// Achieved elevation state, queried via [`crate::Child::elevation`], mirroring
/// [`crate::Child::containment`]. Present iff elevation was requested.
#[derive(Debug, Clone)]
pub struct ElevationReport {
    pub via: ElevatedVia,
    /// Vars the sanitizer dropped before forwarding (also `log`ged).
    pub stripped_env: Vec<OsString>,
    pub stdio: ElevatedStdio,
}

/// The resolved elevation request carried on a [`crate::Command`] (crate-internal),
/// mirroring `ContainRequest`.
#[derive(Debug)]
pub(crate) struct ElevationRequest {
    pub enabled: bool,
    pub backend: Backend,
    pub auth: Auth,
    pub sanitizer: EnvSanitizer,
}

impl Default for ElevationRequest {
    fn default() -> ElevationRequest {
        ElevationRequest {
            enabled: false,
            backend: Backend::Auto,
            auth: Auth::Interactive,
            sanitizer: EnvSanitizer::default(),
        }
    }
}
```

> Note: `pub mod sanitize;` and `pub mod plan;` are declared here but land in Tasks 4–6. Add stub files now so the crate compiles: create `src/elevation/sanitize.rs` containing only `#[derive(Debug, Default)] pub struct EnvSanitizer;` and `src/elevation/plan.rs` empty. Tasks 4–6 flesh them out.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib elevation_tests`
Expected: PASS (all elevation_tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation.rs src/elevation_tests.rs src/elevation/plan.rs src/elevation/sanitize.rs
git commit -m "feat: elevation public enums, ElevatedVia, ElevationReport, ElevationRequest"
```

---

### Task 4: Pure planner — `Host` + happy-path `plan()`

**Files:**
- Modify: `src/elevation/plan.rs`
- Create: `src/elevation/plan_tests.rs`

**Interfaces:**
- Consumes: `super::{Auth, Backend, Privilege}`.
- Produces:
  - `pub enum Os { Unix, Windows }` — Debug, Clone, Copy, PartialEq, Eq.
  - `pub struct BackendSet { run0: Option<PathBuf>, sudo: Option<PathBuf>, doas: Option<PathBuf>, pkexec: Option<PathBuf> }` — Debug, Clone, Default, PartialEq, Eq — holds the RESOLVED ABSOLUTE path per backend (`None` = absent). This threads the CWD-hijack-proof absolute path from detection → plan → rewrite → argv[0].
  - `pub struct Host { elevated: bool, has_tty: bool, available: BackendSet, os: Os }` — Debug, Clone.
  - `pub enum Transition { RunAsIs, ElevatePosix { backend: Backend, path: PathBuf, auth: Auth }, ElevateWindows { auth: Auth }, Reject { error: Error } }` — Debug only (Error is not PartialEq).
  - `impl Host { pub fn plan(&self, target: Privilege, backend: Backend, auth: Auth) -> Transition }`.

`Backend::Auto` resolves `sudo` > `doas` — `run0` is EXCLUDED from Auto (its transient PID-1-parented unit is not our descendant, so it cannot honor the `Child` contract as a default). `pkexec` is never auto-selected.

- [ ] **Step 1: Write the failing test** — create `src/elevation/plan_tests.rs`:

```rust
use super::{BackendSet, Host, Os, Transition};
use crate::elevation::{Auth, Backend, Privilege};
use std::path::PathBuf;

fn all_backends() -> BackendSet {
    BackendSet {
        run0: Some(PathBuf::from("/usr/bin/run0")),
        sudo: Some(PathBuf::from("/usr/bin/sudo")),
        doas: Some(PathBuf::from("/usr/bin/doas")),
        pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
    }
}

fn unix_host(available: BackendSet, elevated: bool, has_tty: bool) -> Host {
    Host { elevated, has_tty, available, os: Os::Unix }
}

#[test]
fn unprivileged_target_runs_as_is() {
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Unprivileged, Backend::Auto, Auth::Interactive),
        Transition::RunAsIs
    ));
}

#[test]
fn already_elevated_runs_as_is() {
    let h = unix_host(all_backends(), true, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::RunAsIs
    ));
}

#[test]
fn auto_prefers_sudo_then_doas() {
    // run0 present but Auto ignores it -> sudo.
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevatePosix { backend: Backend::Sudo, .. }
    ));
    // only doas -> doas
    let h = unix_host(
        BackendSet { run0: None, sudo: None, doas: Some(PathBuf::from("/usr/bin/doas")), pkexec: None },
        false,
        true,
    );
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevatePosix { backend: Backend::Doas, .. }
    ));
}

#[test]
fn auto_never_selects_run0_or_pkexec() {
    // Only run0 + pkexec available: Auto must reject (BackendUnavailable), not pick either.
    let h = unix_host(
        BackendSet {
            run0: Some(PathBuf::from("/usr/bin/run0")),
            sudo: None,
            doas: None,
            pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
        },
        false,
        true,
    );
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::Reject { .. }
    ));
}

#[test]
fn resolved_transition_carries_the_absolute_backend_path() {
    let h = unix_host(all_backends(), false, true);
    match h.plan(Privilege::Elevated, Backend::Doas, Auth::Interactive) {
        Transition::ElevatePosix { backend: Backend::Doas, path, .. } => {
            assert_eq!(path, PathBuf::from("/usr/bin/doas"));
        }
        other => panic!("expected doas ElevatePosix, got {other:?}"),
    }
}

#[test]
#[ignore = "windows arm lands in Task 5"]
fn windows_unprivileged_elevates_via_uac() {
    let h = Host { elevated: false, has_tty: false, available: BackendSet::default(), os: Os::Windows };
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevateWindows { .. }
    ));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib plan_tests`
Expected: FAIL — `cannot find type Host/BackendSet/Os/Transition`.

- [ ] **Step 3: Write minimal implementation** — replace the stub `src/elevation/plan.rs`:

```rust
//! The PURE elevation planner: plain-data [`Host`] + a syscall-free
//! [`Host::plan`]. A Linux test constructs a Windows-shaped `Host` and asserts
//! the Windows decision — the `Containment` host-testing pattern.

use std::path::{Path, PathBuf};

use super::{Auth, Backend, Privilege};
use crate::error::{ElevationErrorKind, Error};

/// Which OS the effect layer will use. Data, not `cfg!`, so `plan` is cross-tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Unix,
    Windows,
}

/// The resolved absolute path of each CLI backend on PATH (`None` = absent),
/// filled by `detect` (checking the exec bit, skipping empty PATH elements) and
/// faked in tests. Carrying the ABSOLUTE path is what closes the CWD-hijack hole:
/// the validated path is exactly the one argv[0] emits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendSet {
    pub run0: Option<PathBuf>,
    pub sudo: Option<PathBuf>,
    pub doas: Option<PathBuf>,
    pub pkexec: Option<PathBuf>,
}

impl BackendSet {
    /// The resolved absolute path for `backend`; `Auto` maps to sudo-then-doas.
    pub(crate) fn path(&self, backend: Backend) -> Option<&Path> {
        match backend {
            Backend::Run0 => self.run0.as_deref(),
            Backend::Sudo => self.sudo.as_deref(),
            Backend::Doas => self.doas.as_deref(),
            Backend::Pkexec => self.pkexec.as_deref(),
            Backend::Auto => self.sudo.as_deref().or(self.doas.as_deref()),
        }
    }
}

/// Ambient privilege facts, resolved once by [`Host::detect`].
#[derive(Debug, Clone)]
pub struct Host {
    pub elevated: bool,
    pub has_tty: bool,
    pub available: BackendSet,
    pub os: Os,
}

/// The planner's decision. Not `PartialEq` — `Reject` wraps a non-comparable
/// [`Error`]; tests use `matches!` and inspect fields.
#[derive(Debug)]
pub enum Transition {
    RunAsIs,
    ElevatePosix { backend: Backend, path: PathBuf, auth: Auth },
    ElevateWindows { auth: Auth },
    Reject { error: Error },
}

impl Host {
    pub fn detect() -> Host {
        // Task 4 ships a self-contained body so this task compiles on every
        // platform; Tasks 9/12 replace it with the real per-OS dispatch.
        Host {
            elevated: false,
            has_tty: false,
            available: BackendSet::default(),
            os: if cfg!(windows) { Os::Windows } else { Os::Unix },
        }
    }

    pub fn plan(&self, target: Privilege, backend: Backend, auth: Auth) -> Transition {
        if target != Privilege::Elevated {
            return Transition::RunAsIs;
        }
        self.resolve_posix(backend, auth)
    }

    fn resolve_posix(&self, backend: Backend, auth: Auth) -> Transition {
        let (resolved, path) = match backend {
            Backend::Auto => {
                if let Some(p) = self.available.sudo.as_deref() {
                    (Backend::Sudo, p.to_path_buf())
                } else if let Some(p) = self.available.doas.as_deref() {
                    (Backend::Doas, p.to_path_buf())
                } else {
                    return reject_backend_unavailable("no sudo/doas on PATH for Backend::Auto");
                }
            }
            explicit => match self.available.path(explicit) {
                Some(p) => (explicit, p.to_path_buf()),
                None => {
                    return reject_backend_unavailable(&format!("forced backend {explicit:?} is not on PATH"));
                }
            },
        };
        Transition::ElevatePosix { backend: resolved, path, auth }
    }
}

fn reject_backend_unavailable(detail: &str) -> Transition {
    Transition::Reject {
        error: Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            detail: detail.into(),
        },
    }
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod plan_tests;
```

> This happy-path form omits the Windows arm and the rejection matrix (Task 5). The Windows planner test is written RED here and marked `#[ignore]`; Task 5 introduces `plan_windows`/`structural_*` and removes the attribute.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib plan_tests`
Expected: PASS (the non-Windows tests; the Windows test is `#[ignore]` until Task 5).

- [ ] **Step 5: Commit**

```bash
git add src/elevation/plan.rs src/elevation/plan_tests.rs
git commit -m "feat: pure elevation planner with sudo>doas Auto resolution and resolved paths"
```

---

### Task 5: Planner rejection matrix — the single validation choke point

**Files:**
- Modify: `src/elevation/plan.rs`, `src/elevation/plan_tests.rs`

**Interfaces:**
- Consumes: `Host::plan` from Task 4.
- Produces: `plan()` validates the FULL Auth×backend×platform matrix BEFORE the already-elevated short-circuit; adds `structural_posix`, `structural_windows`; POSIX resolution now also enforces the Askpass/Stdin-needs-sudo and NoTty preconditions.

**The choke-point contract:**

1. `target != Elevated` → `RunAsIs`.
2. **Structural validation** (privilege-independent, BEFORE the elevated short-circuit): impossible `(backend, auth)` combos → `Reject { Unsupported }`.
3. **Already-elevated short-circuit**: structurally valid + `self.elevated` → `RunAsIs`.
4. **Resolution** (only when actually elevating): backend availability (`BackendUnavailable`), Auto→concrete, Askpass/Stdin-needs-sudo (`Unsupported`), and the `NoTty` precondition.

Structural rejections — POSIX: `Gui` with any non-`Pkexec` backend → `Unsupported`; `Pkexec` with any non-`Gui` auth → `Unsupported`; `Askpass` with a backend other than `Sudo`/`Auto` → `Unsupported`; `Stdin` with a backend other than `Sudo`/`Auto` → `Unsupported`.
Structural rejections — Windows: `backend != Auto` → `Unsupported`; `auth ∈ {NonInteractive, Askpass, Stdin}` → `Unsupported`.
Resolution rejections — POSIX: `Auto` resolving to a non-`Sudo` backend while `auth ∈ {Askpass, Stdin}` → `Unsupported`; `Interactive && !has_tty` → `Elevation { NoTty }`.

- [ ] **Step 1: Write the failing test** — append to `src/elevation/plan_tests.rs`, and remove the `#[ignore]` from `windows_unprivileged_elevates_via_uac`:

```rust
use crate::error::{ElevationErrorKind, Error};

fn reject_error(t: Transition) -> Error {
    match t {
        Transition::Reject { error } => error,
        other => panic!("expected Reject, got {other:?}"),
    }
}

fn is_unsupported(t: Transition) -> bool {
    matches!(t, Transition::Reject { error: Error::Unsupported { .. } })
}

fn win_host(elevated: bool) -> Host {
    Host { elevated, has_tty: false, available: BackendSet::default(), os: Os::Windows }
}

#[test]
fn structural_posix_matrix_is_privilege_independent() {
    let cases: &[(Backend, Auth)] = &[
        (Backend::Doas, Auth::Askpass(PathBuf::from("/x"))),
        (Backend::Run0, Auth::Askpass(PathBuf::from("/x"))),
        (Backend::Doas, Auth::Stdin(crate::elevation::Secret::new("p"))),
        (Backend::Run0, Auth::Stdin(crate::elevation::Secret::new("p"))),
        (Backend::Pkexec, Auth::Interactive),
        (Backend::Pkexec, Auth::NonInteractive),
        (Backend::Pkexec, Auth::Askpass(PathBuf::from("/x"))),
        (Backend::Sudo, Auth::Gui),
        (Backend::Doas, Auth::Gui),
        (Backend::Run0, Auth::Gui),
        (Backend::Auto, Auth::Gui),
    ];
    for (backend, auth) in cases {
        for elevated in [false, true] {
            let h = unix_host(all_backends(), elevated, true);
            assert!(
                is_unsupported(h.plan(Privilege::Elevated, *backend, auth.clone())),
                "expected Unsupported for {backend:?} + {auth:?} (elevated={elevated})",
            );
        }
    }
}

#[test]
fn structural_windows_matrix_is_privilege_independent() {
    for elevated in [false, true] {
        assert!(is_unsupported(win_host(elevated).plan(Privilege::Elevated, Backend::Sudo, Auth::Interactive)));
        assert!(is_unsupported(win_host(elevated).plan(Privilege::Elevated, Backend::Auto, Auth::NonInteractive)));
        assert!(is_unsupported(win_host(elevated).plan(Privilege::Elevated, Backend::Auto, Auth::Askpass(PathBuf::from("/x")))));
        assert!(is_unsupported(win_host(elevated).plan(Privilege::Elevated, Backend::Auto, Auth::Stdin(crate::elevation::Secret::new("p")))));
    }
}

#[test]
fn windows_accepts_only_interactive_and_gui() {
    assert!(matches!(
        win_host(false).plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevateWindows { .. }
    ));
    assert!(matches!(
        win_host(false).plan(Privilege::Elevated, Backend::Auto, Auth::Gui),
        Transition::ElevateWindows { .. }
    ));
}

#[test]
fn interactive_without_tty_is_no_tty() {
    let h = unix_host(all_backends(), false, /* has_tty */ false);
    let e = reject_error(h.plan(Privilege::Elevated, Backend::Sudo, Auth::Interactive));
    assert!(matches!(e, Error::Elevation { kind: ElevationErrorKind::NoTty, .. }), "{e}");
}

#[test]
fn noninteractive_without_tty_is_allowed() {
    let h = unix_host(all_backends(), false, false);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Sudo, Auth::NonInteractive),
        Transition::ElevatePosix { backend: Backend::Sudo, .. }
    ));
}

#[test]
fn auto_resolving_to_doas_rejects_stdin() {
    let h = unix_host(
        BackendSet { run0: None, sudo: None, doas: Some(PathBuf::from("/usr/bin/doas")), pkexec: None },
        false,
        true,
    );
    assert!(is_unsupported(h.plan(Privilege::Elevated, Backend::Auto, Auth::Stdin(crate::elevation::Secret::new("p")))));
}

#[test]
fn pkexec_with_gui_is_accepted() {
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Pkexec, Auth::Gui),
        Transition::ElevatePosix { backend: Backend::Pkexec, .. }
    ));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib plan_tests`
Expected: FAIL — structural matrix, windows arm, NoTty, and Auto-resolves-doas-rejects-stdin all unimplemented.

- [ ] **Step 3: Write minimal implementation** — rewrite `plan` and add the helpers in `src/elevation/plan.rs`:

```rust
    pub fn plan(&self, target: Privilege, backend: Backend, auth: Auth) -> Transition {
        if target != Privilege::Elevated {
            return Transition::RunAsIs;
        }
        // Structural matrix — privilege-independent, BEFORE the already-elevated
        // short-circuit, so an impossible combo never passes under root.
        let structural = match self.os {
            Os::Windows => structural_windows(backend, &auth),
            Os::Unix => structural_posix(backend, &auth),
        };
        if let Some(error) = structural {
            return Transition::Reject { error };
        }
        if self.elevated {
            return Transition::RunAsIs;
        }
        match self.os {
            Os::Windows => Transition::ElevateWindows { auth },
            Os::Unix => self.resolve_posix(backend, auth),
        }
    }
```

Replace `resolve_posix` with the resolution-precondition-enforcing form:

```rust
    fn resolve_posix(&self, backend: Backend, auth: Auth) -> Transition {
        let (resolved, path) = match backend {
            Backend::Auto => {
                if let Some(p) = self.available.sudo.as_deref() {
                    (Backend::Sudo, p.to_path_buf())
                } else if let Some(p) = self.available.doas.as_deref() {
                    (Backend::Doas, p.to_path_buf())
                } else {
                    return reject_backend_unavailable("no sudo/doas on PATH for Backend::Auto");
                }
            }
            explicit => match self.available.path(explicit) {
                Some(p) => (explicit, p.to_path_buf()),
                None => {
                    return reject_backend_unavailable(&format!("forced backend {explicit:?} is not on PATH"));
                }
            },
        };
        if resolved != Backend::Sudo && matches!(auth, Auth::Askpass(_) | Auth::Stdin(_)) {
            return Transition::Reject {
                error: Error::Unsupported {
                    op: format!("{resolved:?} + {}", if matches!(auth, Auth::Askpass(_)) { "Askpass" } else { "Stdin" }),
                    platform: "unix",
                    detail: "Askpass and Stdin auth are sudo-only; Backend::Auto resolved to a non-sudo backend".into(),
                },
            };
        }
        if matches!(auth, Auth::Interactive) && !self.has_tty {
            return Transition::Reject {
                error: Error::Elevation {
                    kind: ElevationErrorKind::NoTty,
                    detail: "Auth::Interactive requires a controlling terminal; use \
                             Auth::NonInteractive / Askpass / Stdin, or run from a TTY"
                        .into(),
                },
            };
        }
        Transition::ElevatePosix { backend: resolved, path, auth }
    }
```

Add the two structural validators as free functions:

```rust
fn structural_posix(backend: Backend, auth: &Auth) -> Option<Error> {
    let unsupported = |op: String, detail: &str| {
        Some(Error::Unsupported { op, platform: "unix", detail: detail.into() })
    };
    if matches!(auth, Auth::Gui) && backend != Backend::Pkexec {
        return unsupported(
            format!("{backend:?} + Auth::Gui"),
            "graphical (Gui) auth is only available through Backend::Pkexec",
        );
    }
    if backend == Backend::Pkexec && !matches!(auth, Auth::Gui) {
        return unsupported(
            "pkexec + non-Gui auth".into(),
            "pkexec is the graphical backend; pair it with Auth::Gui",
        );
    }
    if matches!(auth, Auth::Askpass(_)) && !matches!(backend, Backend::Sudo | Backend::Auto) {
        return unsupported(
            format!("{backend:?} + Askpass"),
            "askpass auth is sudo-only; run0/doas/pkexec have no askpass mechanism",
        );
    }
    if matches!(auth, Auth::Stdin(_)) && !matches!(backend, Backend::Sudo | Backend::Auto) {
        return unsupported(
            format!("{backend:?} + Stdin"),
            "Stdin (sudo -S) auth is sudo-only; doas has no -S and non-sudo targets would leak the password",
        );
    }
    None
}

fn structural_windows(backend: Backend, auth: &Auth) -> Option<Error> {
    if backend != Backend::Auto {
        return Some(Error::Unsupported {
            op: format!("elevation backend {backend:?}"),
            platform: "windows",
            detail: "POSIX elevation backends do not exist on Windows; use Backend::Auto (ShellExecuteEx runas)".into(),
        });
    }
    if matches!(auth, Auth::NonInteractive | Auth::Askpass(_) | Auth::Stdin(_)) {
        return Some(Error::Unsupported {
            op: "runas + non-interactive/askpass/stdin auth".into(),
            platform: "windows",
            detail: "ShellExecuteEx(runas) has no non-interactive, askpass, or stdin-credential mechanism; \
                     use Auth::Interactive or Auth::Gui (both map to the UAC consent gate)".into(),
        });
    }
    None
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib plan_tests`
Expected: PASS (all plan_tests, including the un-ignored Windows arm).

- [ ] **Step 5: Commit**

```bash
git add src/elevation/plan.rs src/elevation/plan_tests.rs
git commit -m "feat: planner is the single validation choke point (full Auth x backend x platform matrix)"
```

---

### Task 6: `EnvSanitizer` + default denylist (keep is additive-within-policy)

**Files:**
- Modify: `src/elevation/sanitize.rs`
- Create: `src/elevation/sanitize_tests.rs`

**Interfaces:**
- Produces:
  - `pub struct EnvSanitizer` — Debug (manual), Default (denylist, no holes).
  - `EnvSanitizer::default()`, `.keep<I, S: Into<OsString>>(self, keys) -> Self`, `EnvSanitizer::filter<F: Fn(&OsStr, &OsStr) -> bool + Send + Sync + 'static>(f) -> Self` (return `true` to KEEP), `EnvSanitizer::allowlist<I>(keys) -> Self`, `EnvSanitizer::none() -> Self`.
  - `pub(crate) fn apply(&self, env: Vec<(OsString, OsString)>) -> (Vec<(OsString, OsString)>, Vec<OsString>)` — `(kept, stripped)`, both sorted by key; every strip `log`ged at info.
  - `pub(crate) const DEFAULT_DENYLIST: &[&str]`.

**`keep` is additive WITHIN the current policy — never a silent downgrade.** On a denylist it adds holes; on an allowlist it WIDENS the allowlist; on a filter it wraps the closure to also keep the named keys; on `none` it is a no-op. It must NEVER convert a fail-closed `allowlist(…)` into a fail-open denylist.

- [ ] **Step 1: Write the failing test** — create `src/elevation/sanitize_tests.rs`:

```rust
use super::EnvSanitizer;
use std::ffi::OsString;

fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|(k, v)| (OsString::from(*k), OsString::from(*v))).collect()
}

fn keys(v: &[(OsString, OsString)]) -> Vec<String> {
    v.iter().map(|(k, _)| k.to_string_lossy().into_owned()).collect()
}

#[test]
fn default_strips_the_loader_family_and_injection_set() {
    let s = EnvSanitizer::default();
    let (kept, stripped) = s.apply(env(&[
        ("PATH", "/usr/bin"),
        ("LD_PRELOAD", "/evil.so"),
        ("LD_BIND_NOW", "1"),
        ("DYLD_INSERT_LIBRARIES", "/e.dylib"),
        ("IFS", " "),
        ("MY_APP_CONFIG", "ok"),
    ]));
    assert_eq!(keys(&kept), vec!["MY_APP_CONFIG", "PATH"]);
    let mut got = keys(&stripped);
    got.sort();
    assert_eq!(got, vec!["DYLD_INSERT_LIBRARIES", "IFS", "LD_BIND_NOW", "LD_PRELOAD"]);
}

#[test]
fn keep_pokes_a_hole_in_a_denylist() {
    let s = EnvSanitizer::default().keep(["LD_LIBRARY_PATH"]);
    let (kept, stripped) = s.apply(env(&[("LD_LIBRARY_PATH", "/opt/lib"), ("LD_PRELOAD", "/e.so")]));
    assert_eq!(keys(&kept), vec!["LD_LIBRARY_PATH"]);
    assert_eq!(keys(&stripped), vec!["LD_PRELOAD"]);
}

#[test]
fn keep_widens_an_allowlist_and_never_downgrades_it() {
    let s = EnvSanitizer::allowlist(["PATH"]).keep(["LANG"]);
    let (kept, stripped) = s.apply(env(&[("PATH", "/b"), ("LANG", "C"), ("MY_APP_CONFIG", "x")]));
    assert_eq!(keys(&kept), vec!["LANG", "PATH"]);
    assert_eq!(keys(&stripped), vec!["MY_APP_CONFIG"]);
}

#[test]
fn keep_on_a_filter_widens_it() {
    let s = EnvSanitizer::filter(|k, _v| k == "PATH").keep(["LANG"]);
    let (kept, stripped) = s.apply(env(&[("PATH", "/b"), ("LANG", "C"), ("OTHER", "x")]));
    assert_eq!(keys(&kept), vec!["LANG", "PATH"]);
    assert_eq!(keys(&stripped), vec!["OTHER"]);
}

#[test]
fn allowlist_is_fail_closed() {
    let s = EnvSanitizer::allowlist(["PATH", "LANG"]);
    let (kept, stripped) = s.apply(env(&[("PATH", "/b"), ("LANG", "C"), ("MY_APP_CONFIG", "x")]));
    assert_eq!(keys(&kept), vec!["LANG", "PATH"]);
    assert_eq!(keys(&stripped), vec!["MY_APP_CONFIG"]);
}

#[test]
fn none_keeps_everything() {
    let s = EnvSanitizer::none();
    let (kept, stripped) = s.apply(env(&[("LD_PRELOAD", "/e.so")]));
    assert_eq!(keys(&kept), vec!["LD_PRELOAD"]);
    assert!(stripped.is_empty());
}

#[test]
fn filter_runs_the_closure() {
    let s = EnvSanitizer::filter(|k, _v| k != "SECRET");
    let (kept, stripped) = s.apply(env(&[("SECRET", "x"), ("PATH", "/b")]));
    assert_eq!(keys(&kept), vec!["PATH"]);
    assert_eq!(keys(&stripped), vec!["SECRET"]);
}
```

> Kept/stripped order is sorted-by-key: `apply` sorts its output for deterministic argv construction downstream.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib sanitize_tests`
Expected: FAIL — the stub `EnvSanitizer` has no `keep`/`filter`/`allowlist`/`none`/`apply`.

- [ ] **Step 3: Write minimal implementation** — replace the stub `src/elevation/sanitize.rs`:

```rust
//! The env consent gradient (layer 2): a denylist over the vars the user
//! *deliberately* forwards past the backend's env_reset scrub.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

/// Loader/injection footguns that would otherwise be re-injected past `ld.so`'s
/// setuid scrub (load-bearing for run0's `--setenv`, defense-in-depth for sudo's
/// `--preserve-env`). Prefix families are matched in [`is_denied`].
pub(crate) const DEFAULT_DENYLIST: &[&str] = &[
    "IFS", "BASH_ENV", "ENV", "PS4", "TERMINFO", "TERMCAP", "HOSTALIASES", "RES_OPTIONS", "LIBPATH",
    "SHLIB_PATH", "GCONV_PATH", "PYTHONPATH", "PERL5LIB", "NODE_OPTIONS",
];
const DENYLIST_PREFIXES: &[&str] = &["LD_", "DYLD_", "_RLD", "LDR_"];

fn is_denied(key: &OsStr) -> bool {
    let k = key.to_string_lossy();
    DENYLIST_PREFIXES.iter().any(|p| k.starts_with(p)) || DEFAULT_DENYLIST.contains(&k.as_ref())
}

enum Policy {
    Denylist { keep: BTreeSet<OsString> },
    Allowlist { allow: BTreeSet<OsString> },
    Filter(Box<dyn Fn(&OsStr, &OsStr) -> bool + Send + Sync + 'static>),
    None,
}

/// A sanitizer policy over the explicitly-forwarded env set.
pub struct EnvSanitizer {
    policy: Policy,
}

impl Default for EnvSanitizer {
    fn default() -> EnvSanitizer {
        EnvSanitizer { policy: Policy::Denylist { keep: BTreeSet::new() } }
    }
}

impl std::fmt::Debug for EnvSanitizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match &self.policy {
            Policy::Denylist { .. } => "Denylist",
            Policy::Allowlist { .. } => "Allowlist",
            Policy::Filter(_) => "Filter",
            Policy::None => "None",
        };
        f.debug_struct("EnvSanitizer").field("policy", &name).finish()
    }
}

impl EnvSanitizer {
    /// Additively keep `keys`, WITHIN the current policy — never a downgrade.
    pub fn keep<I, S>(mut self, keys: I) -> EnvSanitizer
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let extra: BTreeSet<OsString> = keys.into_iter().map(Into::into).collect();
        self.policy = match self.policy {
            Policy::Denylist { mut keep } => {
                keep.extend(extra);
                Policy::Denylist { keep }
            }
            Policy::Allowlist { mut allow } => {
                allow.extend(extra);
                Policy::Allowlist { allow }
            }
            Policy::Filter(f) => Policy::Filter(Box::new(move |k, v| extra.contains(k) || f(k, v))),
            Policy::None => Policy::None,
        };
        self
    }

    /// Opt-in, fail-closed: forward ONLY these keys.
    pub fn allowlist<I, S>(keys: I) -> EnvSanitizer
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        EnvSanitizer { policy: Policy::Allowlist { allow: keys.into_iter().map(Into::into).collect() } }
    }

    /// Arbitrary predicate: return `true` to KEEP the var.
    pub fn filter<F>(f: F) -> EnvSanitizer
    where
        F: Fn(&OsStr, &OsStr) -> bool + Send + Sync + 'static,
    {
        EnvSanitizer { policy: Policy::Filter(Box::new(f)) }
    }

    /// The full foot-gun: forward everything (greppable in source).
    pub fn none() -> EnvSanitizer {
        EnvSanitizer { policy: Policy::None }
    }

    /// Partition `env` into `(kept, stripped)`, both sorted by key.
    pub(crate) fn apply(&self, env: Vec<(OsString, OsString)>) -> (Vec<(OsString, OsString)>, Vec<OsString>) {
        let mut kept: Vec<(OsString, OsString)> = Vec::new();
        let mut stripped: Vec<OsString> = Vec::new();
        for (k, v) in env {
            let keep = match &self.policy {
                Policy::None => true,
                Policy::Allowlist { allow } => allow.contains(&k),
                Policy::Filter(f) => f(&k, &v),
                Policy::Denylist { keep } => keep.contains(&k) || !is_denied(&k),
            };
            if keep {
                kept.push((k, v));
            } else {
                log::info!("sanitize_env dropped {} before elevating", k.to_string_lossy());
                stripped.push(k);
            }
        }
        kept.sort_by(|a, b| a.0.cmp(&b.0));
        stripped.sort();
        (kept, stripped)
    }
}

#[cfg(test)]
#[path = "sanitize_tests.rs"]
mod sanitize_tests;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib sanitize_tests`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation/sanitize.rs src/elevation/sanitize_tests.rs
git commit -m "feat: EnvSanitizer consent gradient; keep is additive-within-policy"
```

---

### Task 7: POSIX argv construction (pure, backend-path-injected, backend-native env)

**Files:**
- Create: `src/elevation/posix.rs`, `src/elevation/posix_tests.rs`
- Modify: `src/elevation.rs` (declare `#[cfg(unix)] pub mod posix;`)

**Interfaces:**
- Consumes: `super::{Auth, Backend}`, `crate::error::Error`.
- Produces: `pub(crate) fn build_argv(backend, backend_path: &OsStr, auth, program: &OsStr, args: &[OsString], env: &[(OsString, OsString)]) -> Result<Vec<OsString>, Error>` — the full elevated argv. **argv[0] is the injected RESOLVED ABSOLUTE `backend_path`.** Pure — no installed backend required.

**Argv rules (spec + Decision 1 — the `env K=V` wrapper is GONE):**
- argv[0] = `backend_path` (absolute); no `env` binary anywhere, so no unqualified-`env` PATH-hijack hole.
- Per-backend auth flags: `Sudo` → `-n`/`-S`/`-A` (NonInteractive/Stdin/Askpass); `Doas` → `-n` (NonInteractive); `Run0` → `--no-ask-password` (NonInteractive). Structurally-invalid combos never reach here.
- **Backend-native env forwarding:**
  - `Sudo`: names the forwarded (sanitized) vars in **`--preserve-env=NAME,…`** (the VALUES are set in the sudo child's own env by the rewrite, Task 11 — never in argv). Each NAME is validated to `[A-Za-z_][A-Za-z0-9_]*`; a comma/`=`/non-ASCII name → `Error::Unsupported` (no lossy comma-join). No `--preserve-env` flag when the forwarded set is empty.
  - `Run0`: one **`--setenv=NAME=VALUE`** per var (name-validated the same way; run0 carries values in argv — no setuid scrub applies, and the sanitizer denylist is the load-bearing wall against loader vars reaching PID 1).
  - `Doas`/`Pkexec`: NO env-forwarding mechanism — the rewrite rejects `.env()` for these before `build_argv` is reached, so `build_argv` `debug_assert!`s the env is empty.
- `run0` forces `--pipe` (honest `Passthrough`, not a silent pty merge).
- A **`--` terminator** precedes the program on every backend, so a program path containing `=` or a leading `-` is not mis-parsed.
- `Backend::Auto` is `unreachable!()` — the planner resolves it before `build_argv` is called.

- [ ] **Step 1: Write the failing test** — create `src/elevation/posix_tests.rs`:

```rust
use super::build_argv;
use crate::elevation::{Auth, Backend};
use std::ffi::{OsStr, OsString};

fn s(v: &[&str]) -> Vec<OsString> {
    v.iter().map(|x| OsString::from(*x)).collect()
}
fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|(k, v)| (OsString::from(*k), OsString::from(*v))).collect()
}

#[test]
fn sudo_noninteractive_names_env_in_preserve_env_with_terminator() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::NonInteractive,
        OsStr::new("/usr/bin/systemctl"),
        &s(&["restart", "nginx"]),
        &env(&[("FOO", "bar")]),
    )
    .unwrap();
    assert_eq!(
        argv,
        s(&["/usr/bin/sudo", "-n", "--preserve-env=FOO", "--", "/usr/bin/systemctl", "restart", "nginx"])
    );
    // The VALUE never appears in argv (it is set in sudo's own env by the rewrite).
    assert!(!argv.iter().any(|a| a.to_string_lossy().contains("bar")));
}

#[test]
fn sudo_preserve_env_joins_multiple_names() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A", "1"), ("B", "2")])).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-n", "--preserve-env=A,B", "--", "id"]));
}

#[test]
fn sudo_interactive_no_env_has_no_flags() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Interactive, OsStr::new("id"), &s(&["-u"]), &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "--", "id", "-u"]));
}

#[test]
fn sudo_stdin_uses_dash_s() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Stdin(crate::elevation::Secret::new("pw")), OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-S", "--", "id"]));
}

#[test]
fn sudo_askpass_uses_dash_a() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Askpass("/usr/bin/ssh-askpass".into()), OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/sudo", "-A", "--", "id"]));
}

#[test]
fn sudo_rejects_an_unforwardable_env_name() {
    for bad in [("A,B", "1"), ("A=C", "1"), ("PÄTH", "1"), ("", "1"), ("1BAD", "1")] {
        let r = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[bad]));
        assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })), "expected reject for {bad:?}");
    }
}

#[test]
fn doas_noninteractive_no_env_emits_dash_n() {
    let argv = build_argv(Backend::Doas, OsStr::new("/usr/bin/doas"), &Auth::NonInteractive, OsStr::new("id"), &s(&["-u"]), &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/doas", "-n", "--", "id", "-u"]));
}

#[test]
fn run0_forces_pipe_and_forwards_env_via_setenv() {
    let argv = build_argv(Backend::Run0, OsStr::new("/usr/bin/run0"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A", "1"), ("B", "2")])).unwrap();
    assert_eq!(argv, s(&["/usr/bin/run0", "--pipe", "--no-ask-password", "--setenv=A=1", "--setenv=B=2", "--", "id"]));
}

#[test]
fn run0_rejects_an_unforwardable_env_name() {
    let r = build_argv(Backend::Run0, OsStr::new("/usr/bin/run0"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A=B", "1")]));
    assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })));
}

#[test]
fn pkexec_gui_no_env() {
    let argv = build_argv(Backend::Pkexec, OsStr::new("/usr/bin/pkexec"), &Auth::Gui, OsStr::new("id"), &[], &[]).unwrap();
    assert_eq!(argv, s(&["/usr/bin/pkexec", "--", "id"]));
}

#[test]
fn terminator_protects_a_program_with_equals_or_leading_dash() {
    let eq = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("/opt/we=ird"), &[], &[]).unwrap();
    assert_eq!(eq, s(&["/usr/bin/sudo", "-n", "--", "/opt/we=ird"]));
    let dash = build_argv(Backend::Doas, OsStr::new("/usr/bin/doas"), &Auth::Interactive, OsStr::new("-prog"), &[], &[]).unwrap();
    assert_eq!(dash, s(&["/usr/bin/doas", "--", "-prog"]));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation::posix` (Unix runner)
Expected: FAIL — module `posix` / `build_argv` not found.

- [ ] **Step 3: Write minimal implementation** — create `src/elevation/posix.rs`:

```rust
//! POSIX elevation effect layer (`cfg(unix)`): backend detection, pure argv
//! construction, non-destructive command rewrite, and the controlling-terminal probe.

use std::ffi::{OsStr, OsString};

use super::{Auth, Backend};
use crate::error::Error;

/// A valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`, ASCII only. A name
/// with a comma / `=` / non-ASCII byte has no lossless place in `--preserve-env`'s
/// comma-joined list or `--setenv=NAME=VALUE`.
fn valid_env_name(k: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let b = k.as_bytes();
    match b.first() {
        Some(&c) if c == b'_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    b.iter().all(|&c| c == b'_' || c.is_ascii_alphanumeric())
}

fn unsupported_env_name(k: &OsStr) -> Error {
    Error::Unsupported {
        op: "forwarding an env var with an unusual name across elevation".into(),
        platform: "unix",
        detail: format!("env var name {k:?} is not [A-Za-z_][A-Za-z0-9_]*; it cannot be forwarded losslessly"),
    }
}

/// `--preserve-env=A,B,…` (names validated; values are set in the backend's own env).
fn preserve_env_flag(env: &[(OsString, OsString)]) -> Result<OsString, Error> {
    let mut flag = OsString::from("--preserve-env=");
    for (i, (k, _)) in env.iter().enumerate() {
        if !valid_env_name(k) {
            return Err(unsupported_env_name(k));
        }
        if i > 0 {
            flag.push(",");
        }
        flag.push(k);
    }
    Ok(flag)
}

/// Build the full elevated argv. argv[0] is the injected ABSOLUTE `backend_path`.
/// `env` MUST be pre-sanitized and sorted (see [`super::sanitize::EnvSanitizer::apply`]).
/// Pure — no installed backend required.
pub(crate) fn build_argv(
    backend: Backend,
    backend_path: &OsStr,
    auth: &Auth,
    program: &OsStr,
    args: &[OsString],
    env: &[(OsString, OsString)],
) -> Result<Vec<OsString>, Error> {
    let mut argv: Vec<OsString> = vec![backend_path.to_os_string()];
    match backend {
        Backend::Sudo => {
            match auth {
                Auth::NonInteractive => argv.push("-n".into()),
                Auth::Stdin(_) => argv.push("-S".into()),
                Auth::Askpass(_) => argv.push("-A".into()),
                Auth::Interactive | Auth::Gui => {}
            }
            if !env.is_empty() {
                argv.push(preserve_env_flag(env)?);
            }
        }
        Backend::Doas => {
            debug_assert!(env.is_empty(), "doas forwards no env; the rewrite rejects .env() for doas");
            if matches!(auth, Auth::NonInteractive) {
                argv.push("-n".into());
            }
        }
        Backend::Pkexec => {
            debug_assert!(env.is_empty(), "pkexec forwards no env; the rewrite rejects .env() for pkexec");
        }
        Backend::Run0 => {
            argv.push("--pipe".into());
            if matches!(auth, Auth::NonInteractive) {
                argv.push("--no-ask-password".into());
            }
            for (k, v) in env {
                if !valid_env_name(k) {
                    return Err(unsupported_env_name(k));
                }
                let mut a = OsString::from("--setenv=");
                a.push(k);
                a.push("=");
                a.push(v);
                argv.push(a);
            }
        }
        Backend::Auto => unreachable!("build_argv received unresolved Backend::Auto; the planner resolves Auto"),
    }
    // Terminate option/assignment parsing before the program.
    argv.push("--".into());
    argv.push(program.to_os_string());
    argv.extend(args.iter().cloned());
    Ok(argv)
}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
```

In `src/elevation.rs`, after `pub mod sanitize;`:

```rust
#[cfg(unix)]
#[path = "elevation/posix.rs"]
pub mod posix;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib elevation::posix`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation.rs src/elevation/posix.rs src/elevation/posix_tests.rs
git commit -m "feat: pure POSIX elevated-argv (abs path, --preserve-env/--setenv, -- terminator, run0 --pipe)"
```

---

### Task 8: `Command` builder methods

**Files:**
- Modify: `src/command.rs`, `src/command_tests.rs`

**Interfaces:**
- Consumes: `crate::elevation::{Auth, Backend, ElevationRequest, EnvSanitizer}`, `crate::containment::ContainRequest`.
- Produces on `Command`: `.elevate()`, `.elevation_backend(Backend)`, `.elevation_auth(Auth)`, `.sanitize_env(EnvSanitizer)` (each returns `&mut Command` and sets `enabled = true`); `pub(crate) fn elevation_request(&self) -> &ElevationRequest`, `pub(crate) fn set_input_argv(&mut self, argv: Vec<OsString>)`, `pub(crate) fn set_env_ops(&mut self, ops: Vec<EnvOp>)`, `pub(crate) fn set_contain(&mut self, req: ContainRequest)`.

`set_input_argv` replaces `input` and clears `executable` (the rewritten argv is self-contained). `set_env_ops` replaces the recorded env ops. `set_contain` copies the contain request onto the DERIVED command the POSIX rewrite builds (Task 11), so `.contain()` + sudo/doas still contains the subtree.

- [ ] **Step 1: Write the failing test** — append to `src/command_tests.rs`:

```rust
#[test]
fn elevate_enables_with_defaults() {
    let mut c = Command::new();
    c.args(["id", "-u"]).elevate();
    let req = c.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Auto);
    assert!(matches!(req.auth, crate::elevation::Auth::Interactive));
}

#[test]
fn elevation_overrides_apply_and_enable() {
    let mut c = Command::new();
    c.arg("id")
        .elevation_backend(crate::elevation::Backend::Doas)
        .elevation_auth(crate::elevation::Auth::NonInteractive);
    let req = c.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Doas);
    assert!(matches!(req.auth, crate::elevation::Auth::NonInteractive));
}

#[test]
fn command_without_elevate_is_disabled() {
    let c = Command::new();
    assert!(!c.elevation_request().enabled);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib command_tests::elev`
Expected: FAIL — no method `elevate` / `elevation_request`.

- [ ] **Step 3: Write minimal implementation** — in `src/command.rs`:

Add the field to `struct Command` (after `contain: ContainRequest,`):

```rust
    contain: ContainRequest,
    elevation: crate::elevation::ElevationRequest,
```

In `impl Default for Command`, add `elevation: crate::elevation::ElevationRequest::default(),`.

Add the methods after `nesting`:

```rust
    /// Run this child elevated (admin/root). Sugar for `Backend::Auto` +
    /// `Auth::Interactive` + the default `EnvSanitizer`. Elevation wraps the
    /// CHILD, never this process.
    pub fn elevate(&mut self) -> &mut Command {
        self.elevation.enabled = true;
        self
    }

    /// Force a specific elevation backend (implies `.elevate()`).
    pub fn elevation_backend(&mut self, backend: crate::elevation::Backend) -> &mut Command {
        self.elevation.enabled = true;
        self.elevation.backend = backend;
        self
    }

    /// Choose the elevation auth strategy (implies `.elevate()`).
    pub fn elevation_auth(&mut self, auth: crate::elevation::Auth) -> &mut Command {
        self.elevation.enabled = true;
        self.elevation.auth = auth;
        self
    }

    /// Replace the env sanitizer applied to explicitly-forwarded vars (implies `.elevate()`).
    pub fn sanitize_env(&mut self, sanitizer: crate::elevation::EnvSanitizer) -> &mut Command {
        self.elevation.enabled = true;
        self.elevation.sanitizer = sanitizer;
        self
    }

    pub(crate) fn elevation_request(&self) -> &crate::elevation::ElevationRequest {
        &self.elevation
    }

    pub(crate) fn set_input_argv(&mut self, argv: Vec<OsString>) {
        self.input = CommandInput::Argv(argv);
        self.executable = None;
    }

    pub(crate) fn set_env_ops(&mut self, ops: Vec<EnvOp>) {
        self.env_ops = ops;
    }

    pub(crate) fn set_contain(&mut self, req: ContainRequest) {
        self.contain = req;
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib command_tests::elev`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/command.rs src/command_tests.rs
git commit -m "feat: Command elevation builder methods and derived-command mutators"
```

---

### Task 9: POSIX detection (`detect` / `is_elevated` / `controlling_terminal_present` / path resolution)

**Files:**
- Modify: `src/elevation/posix.rs`, `src/elevation.rs`, `src/elevation_tests.rs`, `src/elevation/posix_tests.rs`, `src/elevation/plan.rs`

**Interfaces:**
- Produces: `#[cfg(unix)] pub(super) fn detect() -> Host`; `#[cfg(unix)] pub(super) fn is_elevated() -> bool`; `#[doc(hidden)] pub fn controlling_terminal_present() -> bool`; `pub(super) fn resolve_on_path(program: &str) -> Option<PathBuf>` + the pure `pub(super) fn resolve_in_path_var(path_var: &OsStr, program: &str) -> Option<PathBuf>`; the public `crate::elevation::is_elevated() -> bool` dispatcher (Unix arm now real).

**Correctness fixes (findings woven in):**
- Backend availability records the RESOLVED ABSOLUTE path, checking the exec bit via `libc::faccessat(AT_FDCWD, path, X_OK, AT_EACCESS)` — the EFFECTIVE-ids answer, not the real-ids `access`. The check is a best-effort HINT (check-then-act); a real exec failure of the resolved backend is surfaced as `BackendUnavailable` at spawn (Task 15), not a raw `Io` error.
- Path resolution SKIPS empty PATH elements (an empty element means CWD — never resolve a backend from CWD). The pure `resolve_in_path_var` (which takes the PATH string) is `pub(super)` and unit-tested directly, so this is covered without env-mutation races.
- `has_tty` probes the **controlling terminal** via `libc::open("/dev/tty", O_RDWR|O_CLOEXEC|O_NONBLOCK)` then close — NOT `isatty(STDIN)`. `O_NONBLOCK` keeps the probe from blocking on a carrier-less serial console (it only needs the open to succeed). Exposed as `#[doc(hidden)] pub fn` so the `setsid` negative case is cross-process testable (Task 17).

- [ ] **Step 1: Write the failing test** — replace the placeholder `is_elevated` test in `src/elevation_tests.rs` with the ground-truth form, and add the unix ones:

```rust
#[cfg(unix)]
#[test]
fn is_elevated_matches_effective_uid_ground_truth() {
    // Never assume ambient privilege; compare against an independent syscall.
    // SAFETY: geteuid has no preconditions and never fails.
    let euid0 = unsafe { libc::geteuid() } == 0;
    assert_eq!(super::is_elevated(), euid0, "is_elevated disagreed with geteuid()==0");
}

#[cfg(unix)]
#[test]
fn detect_reports_unix_os() {
    let h = super::plan::Host::detect();
    assert_eq!(h.os, super::plan::Os::Unix);
}
```

And append the path-resolution tests to `src/elevation/posix_tests.rs`:

```rust
#[cfg(unix)]
#[test]
fn resolve_skips_a_non_executable_same_named_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("sudo");
    std::fs::write(&f, b"not exec").unwrap(); // mode 0644 — no exec bit
    let got = super::resolve_in_path_var(dir.path().as_os_str(), "sudo");
    assert_eq!(got, None, "a non-executable file named sudo must be skipped");
}

#[cfg(unix)]
#[test]
fn empty_path_element_is_not_resolved_from_cwd() {
    use std::os::unix::fs::PermissionsExt;
    // CWD is process-global; serialize this test's chdir with a real lock (not a timing hack).
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = CWD_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let sudo = dir.path().join("sudo");
    std::fs::write(&sudo, b"#!/bin/sh\ntrue\n").unwrap();
    std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
    let saved = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    // A single empty PATH element must be skipped, never treated as "." (CWD).
    let got = super::resolve_in_path_var(std::ffi::OsStr::new(""), "sudo");
    std::env::set_current_dir(&saved).unwrap();
    assert_eq!(got, None, "an empty PATH element resolved a backend from CWD");
}
```

> The `controlling_terminal_present` probe's stdin-independence is covered cross-process in Task 17 (a testbin child with fd0 redirected), which actually redirects the descriptor rather than asserting vacuously in-process.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation_tests elevation::posix`
Expected: FAIL — `is_elevated` / `resolve_in_path_var` not found.

- [ ] **Step 3: Write minimal implementation** — append to `src/elevation/posix.rs`:

```rust
use std::path::{Path, PathBuf};

use super::plan::{BackendSet, Host, Os};

pub(super) fn is_elevated() -> bool {
    // SAFETY: geteuid has no preconditions and never fails.
    unsafe { libc::geteuid() == 0 }
}

/// Does this session have a controlling terminal? Probes `/dev/tty` directly —
/// which resolves to the controlling terminal regardless of stdin redirection and
/// fails once a process has none (e.g. after `setsid`). `O_NONBLOCK` avoids
/// blocking on a carrier-less serial console; the probe only needs the open to
/// succeed. `isatty(stdin)` answers a different question and is wrong for both cases.
#[doc(hidden)]
pub fn controlling_terminal_present() -> bool {
    // SAFETY: open/close of a fixed path; the fd is closed on the success path.
    unsafe {
        let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK);
        if fd < 0 {
            return false;
        }
        libc::close(fd);
        true
    }
}

/// A best-effort HINT that `path` is an executable file for the EFFECTIVE ids.
/// `faccessat(AT_EACCESS)` answers for the ids that will actually exec (unlike
/// `access`, which uses the real ids); a real exec failure is still surfaced as
/// `BackendUnavailable` at spawn time.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: faccessat with a valid NUL-terminated path; a read-only permission query.
    path.is_file()
        && unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 }
}

/// Resolve `program` to its ABSOLUTE path on `$PATH`.
pub(super) fn resolve_on_path(program: &str) -> Option<PathBuf> {
    resolve_in_path_var(&std::env::var_os("PATH")?, program)
}

/// PURE path resolution over an explicit PATH value: check the exec bit and SKIP
/// empty elements (an empty element is CWD — never resolve a backend there).
pub(super) fn resolve_in_path_var(path_var: &OsStr, program: &str) -> Option<PathBuf> {
    std::env::split_paths(path_var).find_map(|dir| {
        if dir.as_os_str().is_empty() {
            return None; // empty element = CWD; never resolve here
        }
        let cand = dir.join(program);
        is_executable(&cand).then_some(cand)
    })
}

pub(super) fn detect() -> Host {
    Host {
        elevated: is_elevated(),
        has_tty: controlling_terminal_present(),
        available: BackendSet {
            run0: resolve_on_path("run0"),
            sudo: resolve_on_path("sudo"),
            doas: resolve_on_path("doas"),
            pkexec: resolve_on_path("pkexec"),
        },
        os: Os::Unix,
    }
}
```

In `src/elevation/plan.rs`, restore the real `detect()` dispatch (replacing the Task-4 self-contained stub):

```rust
    pub fn detect() -> Host {
        #[cfg(unix)]
        {
            super::posix::detect()
        }
        #[cfg(windows)]
        {
            super::windows::detect()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Host { elevated: false, has_tty: false, available: BackendSet::default(), os: Os::Unix }
        }
    }
```

> The `#[cfg(windows)]` arm references `super::windows::detect`, which lands in Task 12. On a Unix build only the unix arm compiles; on a Windows build Task 12 must be in place. Because Task 9 lands before Task 12, keep the windows arm compiling on Windows by sequencing: on a Windows-only checkout between Tasks 9 and 12 the crate would not build, so run the Windows leg of CI only from Task 12 onward (the green matrix marks Task 9 as `n/a` on Windows). The `plan_tests` never call `detect`.

In `src/elevation.rs`, add the public dispatcher:

```rust
/// Is the CURRENT process already elevated (root on Unix, an elevated token on
/// Windows)? A free function — no spawn needed.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        posix::is_elevated()
    }
    #[cfg(windows)]
    {
        windows::is_elevated()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib elevation_tests elevation::posix`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/elevation.rs src/elevation/posix.rs src/elevation/plan.rs src/elevation_tests.rs src/elevation/posix_tests.rs
git commit -m "feat: POSIX detection (euid, /dev/tty O_NONBLOCK probe, faccessat abs-path resolution)"
```

---

### Task 10: Extract `spawn_unelevated` (pure refactor, its own TDD step)

**Files:**
- Modify: `src/child/spawn.rs`

**Interfaces:**
- Produces: `pub(crate) fn spawn_unelevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, Error>` — the non-elevated spawn core (everything from `std::mem::take(cmd.fds_mut())` onward). `spawn()` becomes a thin wrapper. This lands BEFORE any elevation branch so Task 15's `spawn()` branch (spawning a DERIVED command) and Task 14's Windows already-elevated arm can both re-enter the normal spawn path without re-entering the elevation branch.

This is a pure refactor: no behavior change. Its regression guard is a FULL `cargo test --lib` run.

**Concrete before/after of `spawn()` (`src/child/spawn.rs`):**

Before:
```rust
pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let fds = std::mem::take(cmd.fds_mut());
    let kill_on_drop = cmd.kill_on_drop_flag();
    // ... entire body ...
    Ok(Child::from_parts(
        ProcHandle::Std(shared), id, parent_ends, kill_on_drop, containment, attached,
    ))
}
```

After:
```rust
pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let kill_on_drop = cmd.kill_on_drop_flag();
    spawn_unelevated(cmd, kill_on_drop)
}

/// The non-elevated spawn core: resolve stdio, wire program/args, spawn, attach,
/// read identity, adopt. Shared by the ordinary path and the elevation paths'
/// already-elevated / derived-command continuations (which must spawn without
/// re-entering the elevation branch).
pub(crate) fn spawn_unelevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, Error> {
    let fds = std::mem::take(cmd.fds_mut());
    // ... entire body, verbatim ...
    Ok(Child::from_parts(
        ProcHandle::Std(shared), id, parent_ends, kill_on_drop, containment, attached,
    ))
}
```

Only two edits: (1) move `let kill_on_drop = cmd.kill_on_drop_flag();` up into `spawn()` and pass it in; (2) rename the old function body to `spawn_unelevated` and give `spawn()` the two-line wrapper. The `let fds = std::mem::take(...)` line moves into `spawn_unelevated` unchanged.

- [ ] **Step 1: Write the failing test** — append to `src/child/spawn_tests.rs`:

```rust
#[test]
fn spawn_unelevated_runs_a_plain_child() {
    let mut c = crate::command::Command::new();
    #[cfg(unix)]
    c.args(["true"]);
    #[cfg(windows)]
    c.args(["cmd", "/C", "exit 0"]);
    let kill_on_drop = c.kill_on_drop_flag();
    let mut child = super::spawn_unelevated(&mut c, kill_on_drop).expect("spawn");
    assert!(child.wait().expect("wait").success());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib spawn_tests::spawn_unelevated_runs_a_plain_child`
Expected: FAIL — `spawn_unelevated` not found.

- [ ] **Step 3: Write minimal implementation** — perform the extraction exactly as the before/after above.

- [ ] **Step 4: Run test to verify it passes** — and run the FULL unit suite to prove the refactor changed nothing:

Run: `cargo test --lib`
Expected: PASS (entire library suite — the refactor's regression gate).

- [ ] **Step 5: Commit**

```bash
git add src/child/spawn.rs src/child/spawn_tests.rs
git commit -m "refactor: extract spawn_unelevated as the shared non-elevated spawn core"
```

---

### Task 11: POSIX effect integration — non-destructive `rewrite` + `Child::elevation()`

**Files:**
- Modify: `src/elevation/posix.rs`, `src/child.rs`, `src/elevation/posix_tests.rs`

**Interfaces:**
- Produces:
  - `pub(crate) struct PendingPassword` — carries the pipe write-end + `Secret`; `write_after_spawn(self) -> Result<(), Error>` delivers the password AFTER spawn.
  - `pub(crate) struct PosixRewrite { derived: Option<Command>, report: Option<ElevationReport>, password_write: Option<PendingPassword> }`.
  - `#[cfg(unix)] pub(crate) fn rewrite(cmd: &Command) -> Result<PosixRewrite, Error>` = `rewrite_with_host(cmd, &Host::detect())`.
  - `#[cfg(unix)] pub(crate) fn rewrite_with_host(cmd: &mut Command, host: &Host) -> Result<PosixRewrite, Error>` — builds a DERIVED backend command; PURE given `host`.
  - On `Child`: `pub(crate) fn set_elevation(&mut self, r: Option<ElevationReport>)`, `pub fn elevation(&self) -> Option<ElevationReport>`.

**Structural decisions woven in:**
- **Decision 4 — non-destructive.** `rewrite_with_host` builds a fresh DERIVED `Command` (backend argv + rebuilt env + transferred cwd/contain/kill_on_drop/stdio) and returns it in `PosixRewrite.derived`; the caller's `Command` `input()`/`env_ops()` are left UNTOUCHED, so a second spawn never double-wraps. The caller's fd 0-2 stdio is MOVED into the derived command (`ResolvedStdio::File` is not `Clone`; the ordinary spawn path likewise consumes fds).
- **Decision 1 — backend-native env.** sudo's forwarded vars are set in the DERIVED command's own env (`EnvOp::Set`) and named in `--preserve-env` by `build_argv`. run0 forwards via `--setenv`. `.env()` with doas/pkexec → `Unsupported`. `.env_remove()`/`.env_clear()` (any backend) → `Unsupported` (the backend builds the base env; the crate can add but not subtract). `SUDO_ASKPASS` is set on the derived env for `Auth::Askpass`.
- **Decision 2 — deferred password.** `Auth::Stdin` wires the derived fd0 to a fresh pipe's READ end (`Stdio::from_file`, so it resolves to `ResolvedStdio::File`); the password is NOT written here. The write-end + `Secret` ride out in `password_write`, and Task 15/16 call `write_after_spawn` once the child (draining via `sudo -S`) exists — the write completes for any secret length. A caller-configured fd0 → `Unsupported`.
- **Decision 5 — fd≥3.** Any `fd >= 3` on an elevated POSIX command → `Unsupported` (mirrors the Windows gate; the backend's `closefrom` / run0's PID-1 reparent drops it).
- **f7897d84.** The impossible `Transition::ElevateWindows` arm is `unreachable!()`, not a misleading `BackendUnavailable` `Err`.
- `Backend::Run0` + `.contain()` → `Unsupported`. `commandline()` / a distinct-argv0 `executable()` elevated → `Unsupported`. Report `via: Wrapped(backend)`, `stdio: Passthrough`; `RunAsIs` (requested but already elevated) → `Some(via: AlreadyElevated)` with `derived: None`.

- [ ] **Step 1: Write the failing test** — append to `src/elevation/posix_tests.rs`:

```rust
#[cfg(unix)]
mod rewrite_tests {
    use crate::command::{Command, CommandInput, EnvOp};
    use crate::elevation::plan::{BackendSet, Host, Os};
    use crate::elevation::{Auth, Backend, ElevatedVia};
    use crate::error::Error;
    use crate::stdio::{Fd, ResolvedStdio, Stdio};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn sudo_host() -> Host {
        Host {
            elevated: false,
            has_tty: true,
            available: BackendSet {
                run0: None,
                sudo: Some(PathBuf::from("/usr/bin/sudo")),
                doas: Some(PathBuf::from("/usr/bin/doas")),
                pkexec: None,
            },
            os: Os::Unix,
        }
    }

    fn derived_argv(rw: &super::PosixRewrite) -> Vec<OsString> {
        match rw.derived.as_ref().expect("derived").input() {
            CommandInput::Argv(v) => v.clone(),
            other => panic!("expected Argv, got {other:?}"),
        }
    }

    #[test]
    fn rewrite_is_nondestructive_and_reports_wrapped_backend() {
        let mut c = Command::new();
        c.args(["id", "-u"])
            .env("LD_PRELOAD", "/evil.so")
            .env("FOO", "bar")
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        let rw = super::rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        let report = rw.report.as_ref().expect("report");
        assert_eq!(report.via, ElevatedVia::Wrapped(Backend::Sudo));
        assert_eq!(report.stripped_env, vec![OsString::from("LD_PRELOAD")]);
        let a = derived_argv(&rw);
        assert_eq!(a[0], OsString::from("/usr/bin/sudo"));
        assert!(a.contains(&OsString::from("--preserve-env=FOO")));
        // Value is set in sudo's own env, never in argv; LD_PRELOAD is stripped everywhere.
        assert!(!a.iter().any(|x| x.to_string_lossy().contains("bar")));
        assert!(!a.iter().any(|x| x.to_string_lossy().contains("LD_PRELOAD")));
        let derived = rw.derived.as_ref().unwrap();
        assert!(derived.env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, v) if k == "FOO" && v == "bar")));
        assert!(!derived.env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, _) if k == "LD_PRELOAD")));
        // The caller's Command is untouched (no double-wrap on reuse).
        assert!(matches!(c.input(), CommandInput::Argv(v) if v == &[OsString::from("id"), OsString::from("-u")]));
        assert_eq!(c.env_ops().len(), 2, "caller env ops must be intact");
    }

    #[test]
    fn rewrite_twice_yields_identical_derived_argv() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        let a1 = derived_argv(&super::rewrite_with_host(&mut c, &sudo_host()).unwrap());
        let a2 = derived_argv(&super::rewrite_with_host(&mut c, &sudo_host()).unwrap());
        assert_eq!(a1, a2, "reusing an elevated Command must not double-wrap");
    }

    #[test]
    fn env_remove_or_clear_plus_elevate_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"]).env_clear().env("KEEP", "1").elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        assert!(matches!(super::rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
        let mut c2 = Command::new();
        c2.args(["id"]).env("A", "1").env_remove("A").elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        assert!(matches!(super::rewrite_with_host(&mut c2, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn doas_or_pkexec_with_env_is_unsupported() {
        let doas_host = Host {
            available: BackendSet { run0: None, sudo: None, doas: Some(PathBuf::from("/usr/bin/doas")), pkexec: None },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"]).env("A", "1").elevation_backend(Backend::Doas).elevation_auth(Auth::NonInteractive);
        assert!(matches!(super::rewrite_with_host(&mut c, &doas_host), Err(Error::Unsupported { .. })));

        let pk_host = Host {
            available: BackendSet { run0: None, sudo: None, doas: None, pkexec: Some(PathBuf::from("/usr/bin/pkexec")) },
            ..sudo_host()
        };
        let mut c2 = Command::new();
        c2.args(["id"]).env("A", "1").elevation_backend(Backend::Pkexec).elevation_auth(Auth::Gui);
        assert!(matches!(super::rewrite_with_host(&mut c2, &pk_host), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn run0_forwards_env_via_setenv() {
        let host = Host {
            available: BackendSet { run0: Some(PathBuf::from("/usr/bin/run0")), sudo: None, doas: None, pkexec: None },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"]).env("A", "1").elevation_backend(Backend::Run0).elevation_auth(Auth::NonInteractive);
        let rw = super::rewrite_with_host(&mut c, &host).expect("rewrite");
        assert!(derived_argv(&rw).contains(&OsString::from("--setenv=A=1")));
        assert!(!rw.derived.as_ref().unwrap().env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, _) if k == "A")));
    }

    #[test]
    fn askpass_path_is_carried_in_the_backend_env() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Askpass(PathBuf::from("/usr/bin/ssh-askpass")));
        let rw = super::rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        assert!(rw.derived.as_ref().unwrap().env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, v) if k == "SUDO_ASKPASS" && v == "/usr/bin/ssh-askpass")));
    }

    #[test]
    fn stdin_auth_wires_fd0_to_a_file_and_defers_the_write() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Stdin(crate::elevation::Secret::new("pw")));
        let rw = super::rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        // Stdio::from_file(reader) resolves to ResolvedStdio::File(_).
        assert!(matches!(rw.derived.as_ref().unwrap().fds().get(&Fd::STDIN), Some(ResolvedStdio::File(_))));
        assert!(rw.password_write.is_some(), "the password write is deferred to after spawn");
    }

    #[test]
    fn stdin_auth_with_caller_configured_fd0_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Stdin(crate::elevation::Secret::new("pw")));
        c.stdin(Stdio::pipe()).unwrap();
        assert!(matches!(super::rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn fd_ge_3_elevated_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        c.fd(3, Stdio::pipe_out()).unwrap();
        assert!(matches!(super::rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn run0_plus_contain_is_unsupported() {
        let host = Host {
            available: BackendSet { run0: Some(PathBuf::from("/usr/bin/run0")), sudo: None, doas: None, pkexec: None },
            ..sudo_host()
        };
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Run0).elevation_auth(Auth::NonInteractive).contain();
        assert!(matches!(super::rewrite_with_host(&mut c, &host), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn commandline_elevated_is_unsupported() {
        let mut c = Command::new();
        c.commandline("id -u").elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        assert!(matches!(super::rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn distinct_argv0_with_executable_is_unsupported() {
        let mut c = Command::new();
        c.executable("/bin/busybox").args(["sh", "-c", "true"])
            .elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        assert!(matches!(super::rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation::posix::posix_tests::rewrite_tests`
Expected: FAIL — `rewrite_with_host` not found.

- [ ] **Step 3: Write minimal implementation** — append to `src/elevation/posix.rs`. (`Error` is already imported at the module top from Task 7; import only the additional items here.)

```rust
use std::fs::File;
use std::os::fd::OwnedFd;

use zeroize::Zeroize;

use crate::command::{Command, CommandInput, EnvOp};
use crate::elevation::plan::{Host, Transition};
use crate::elevation::{ElevatedStdio, ElevatedVia, ElevationReport, Privilege, Secret};
use crate::error::ElevationErrorKind;
use crate::stdio::{Fd, Stdio};

/// The `Auth::Stdin` password channel: the pipe write-end plus the secret, written
/// AFTER spawn (the child is then draining via `sudo -S`, so the write completes for
/// any secret length — no kernel pipe-buffer assumption).
pub(crate) struct PendingPassword {
    writer: std::io::PipeWriter,
    secret: Secret,
}

impl PendingPassword {
    /// Deliver the password + newline, then EOF. Errors are logged at debug and
    /// propagated as `Error::Elevation` (never a silently-swallowed write).
    pub(crate) fn write_after_spawn(mut self) -> Result<(), Error> {
        use std::io::Write;
        let mut bytes = self.secret.expose().to_vec();
        bytes.push(b'\n');
        let res = self.writer.write_all(&bytes);
        bytes.zeroize();
        drop(self.writer); // EOF after the password line
        if let Err(e) = res {
            log::debug!("failed to deliver the elevation password after spawn: {e}");
            return Err(Error::Elevation {
                kind: ElevationErrorKind::AuthFailed,
                detail: format!("could not deliver the sudo -S password: {e}"),
            });
        }
        Ok(())
    }
}

/// Outcome of a POSIX rewrite. `derived` is the backend command to spawn (`None` iff
/// already elevated — spawn the original unchanged). `report` is attached to the
/// resulting `Child`. `password_write` is delivered after spawn.
pub(crate) struct PosixRewrite {
    pub derived: Option<Command>,
    pub report: Option<ElevationReport>,
    pub password_write: Option<PendingPassword>,
}

/// Collect the explicitly-`Set` env into an ordered (k,v) list (later `Set`s win).
/// `Remove`/`Clear` are rejected before this runs, so only `Set` survives.
fn explicit_set_env(ops: &[EnvOp]) -> Vec<(OsString, OsString)> {
    let mut map: std::collections::BTreeMap<OsString, OsString> = std::collections::BTreeMap::new();
    for op in ops {
        if let EnvOp::Set(k, v) = op {
            map.insert(k.clone(), v.clone());
        }
    }
    map.into_iter().collect()
}

/// Program + args, honoring `executable()`. An argv[0] distinct from a set
/// `executable()` cannot survive the backend wrapper → `Unsupported`.
fn program_and_args(cmd: &Command) -> Result<(OsString, Vec<OsString>), Error> {
    let CommandInput::Argv(argv) = cmd.input() else {
        return Err(Error::Unsupported {
            op: "elevation of a commandline() command".into(),
            platform: "unix",
            detail: "elevation requires an argv command (set .args([...])); a raw command line cannot be safely wrapped".into(),
        });
    };
    if argv.is_empty() {
        return Err(Error::Unsupported {
            op: "elevation of an empty command".into(),
            platform: "unix",
            detail: "set a program via .args([...]) before .elevate()".into(),
        });
    }
    match cmd.executable_path() {
        Some(exe) => {
            if argv[0].as_os_str() != exe.as_os_str() {
                return Err(Error::Unsupported {
                    op: "elevation with an argv[0] distinct from executable()".into(),
                    platform: "unix",
                    detail: "the backend runs the loaded file with argv[0] = its path; a separate argv[0] cannot survive elevation".into(),
                });
            }
            Ok((exe.as_os_str().to_os_string(), argv[1..].to_vec()))
        }
        None => Ok((argv[0].clone(), argv[1..].to_vec())),
    }
}

/// Detect-then-plan-then-rewrite. Thin wrapper over the pure form.
pub(crate) fn rewrite(cmd: &mut Command) -> Result<PosixRewrite, Error> {
    rewrite_with_host(cmd, &Host::detect())
}

/// PURE given `host`: plan + sanitize + build a DERIVED backend command. The
/// caller's `Command` `input`/`env_ops` are left untouched (Decision 4).
pub(crate) fn rewrite_with_host(cmd: &mut Command, host: &Host) -> Result<PosixRewrite, Error> {
    let req = cmd.elevation_request();
    let (backend, path, auth) = match host.plan(Privilege::Elevated, req.backend, req.auth.clone()) {
        Transition::RunAsIs => {
            // Requested but already elevated — no wrapper, but still reported.
            return Ok(PosixRewrite {
                derived: None,
                report: Some(ElevationReport {
                    via: ElevatedVia::AlreadyElevated,
                    stripped_env: Vec::new(),
                    stdio: ElevatedStdio::Passthrough,
                }),
                password_write: None,
            });
        }
        Transition::Reject { error } => return Err(error),
        Transition::ElevateWindows { .. } => unreachable!("planner never yields ElevateWindows on a unix host"),
        Transition::ElevatePosix { backend, path, auth } => (backend, path, auth),
    };

    // --- validation (before moving anything out of the caller's Command) ---
    if backend == Backend::Run0 && cmd.contain_request().mode.is_some() {
        return Err(Error::Unsupported {
            op: ".contain() + Backend::Run0".into(),
            platform: "unix",
            detail: "run0 runs the target as a PID 1-parented transient unit outside our cgroup; containment cannot span it".into(),
        });
    }
    if cmd.fds().keys().any(|f| f.raw() >= 3) {
        return Err(Error::Unsupported {
            op: "fd >= 3 on an elevated POSIX child".into(),
            platform: "unix",
            detail: "sudo/pkexec closefrom and run0's PID-1 reparent drop fds > 2; fd >= 3 needs the (deferred) broker".into(),
        });
    }
    let ops = cmd.env_ops();
    if ops.iter().any(|o| matches!(o, EnvOp::Remove(_) | EnvOp::Clear)) {
        return Err(Error::Unsupported {
            op: ".env_remove()/.env_clear() + elevate".into(),
            platform: "unix",
            detail: "the backend builds the elevated base environment; the crate can add but not subtract from it".into(),
        });
    }
    let has_set = ops.iter().any(|o| matches!(o, EnvOp::Set(..)));
    if has_set && matches!(backend, Backend::Doas | Backend::Pkexec) {
        return Err(Error::Unsupported {
            op: format!(".env() + Backend::{backend:?}"),
            platform: "unix",
            detail: "doas and pkexec expose no environment-forwarding mechanism; .env()/.envs() cannot cross them".into(),
        });
    }
    let (program, args) = program_and_args(cmd)?;
    let (kept, stripped) = req.sanitizer.apply(explicit_set_env(ops));
    let argv = build_argv(backend, path.as_os_str(), &auth, &program, &args, &kept)?;

    // --- build the DERIVED command (the caller's Command stays intact) ---
    let mut derived = Command::new();
    derived.set_input_argv(argv);
    let mut new_ops: Vec<EnvOp> = Vec::new();
    if backend == Backend::Sudo {
        // sudo preserves these from its OWN env (named in --preserve-env); run0 carried
        // them in argv already; doas/pkexec were rejected above.
        for (k, v) in &kept {
            new_ops.push(EnvOp::Set(k.clone(), v.clone()));
        }
    }
    if let Auth::Askpass(p) = &auth {
        new_ops.push(EnvOp::Set(OsString::from("SUDO_ASKPASS"), p.as_os_str().to_os_string()));
    }
    derived.set_env_ops(new_ops);
    if let Some(d) = cmd.cwd() {
        derived.current_dir(d);
    }
    derived.set_contain(cmd.contain_request());
    derived.kill_on_drop(cmd.kill_on_drop_flag());

    // Auth::Stdin: wire the derived fd0 to a fresh pipe's read end; write the password
    // AFTER spawn (Decision 2).
    let mut password_write = None;
    if let Auth::Stdin(secret) = &auth {
        if cmd.fds().contains_key(&Fd::STDIN) {
            return Err(Error::Unsupported {
                op: "Auth::Stdin with a caller-configured stdin".into(),
                platform: "unix",
                detail: "Auth::Stdin consumes fd0 to feed sudo -S the password; do not also configure stdin".into(),
            });
        }
        let (reader, writer) = std::io::pipe().map_err(Error::Io)?;
        let reader_file = File::from(OwnedFd::from(reader));
        derived.stdin(Stdio::from_file(reader_file))?;
        password_write = Some(PendingPassword { writer, secret: secret.clone() });
    }

    // Move the caller's fd 0-2 stdio into the derived command (File is not Clone). Skip
    // fd0 when Auth::Stdin already wired it to the pipe read end.
    for (slot, resolved) in std::mem::take(cmd.fds_mut()) {
        if password_write.is_some() && slot == Fd::STDIN {
            continue;
        }
        derived.fds_mut().insert(slot, resolved);
    }

    Ok(PosixRewrite {
        derived: Some(derived),
        report: Some(ElevationReport {
            via: ElevatedVia::Wrapped(backend),
            stripped_env: stripped,
            stdio: ElevatedStdio::Passthrough,
        }),
        password_write,
    })
}
```

In `src/child.rs`, add the field + accessors. Add to `struct Child`: `elevation: Option<crate::elevation::ElevationReport>,`. In `from_parts`, add `elevation: None,` to the struct literal. Then:

```rust
    pub(crate) fn set_elevation(&mut self, report: Option<crate::elevation::ElevationReport>) {
        self.elevation = report;
    }
    /// The achieved elevation state, or `None` if elevation was not requested
    /// (mirrors [`Child::containment`]).
    pub fn elevation(&self) -> Option<crate::elevation::ElevationReport> {
        self.elevation.clone()
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib elevation::posix::posix_tests::rewrite_tests`
Then: `cargo test --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/elevation/posix.rs src/child.rs src/elevation/posix_tests.rs
git commit -m "feat: non-destructive POSIX elevation rewrite (derived command) + Child::elevation report"
```

---

### Task 12: Windows detection + integrity + deps + identity-from-handle helper

**Files:**
- Modify: `Cargo.toml`, `src/elevation.rs`, `src/identity/windows.rs`
- Create: `src/elevation/windows.rs`, `src/elevation/windows_tests.rs`

**Interfaces:**
- Produces: `#[cfg(windows)] pub(super) fn detect() -> Host`; `#[cfg(windows)] pub(super) fn is_elevated() -> bool`; `#[cfg(windows)] pub(super) fn integrity_level() -> Option<u32>` (the integrity RID; USED by `detect` for a debug log AND asserted in tests, so never dead code); `pub(crate) fn crate::identity::windows::windows_identity_from_handle(handle, pid) -> Option<ProcessId>`.

**Correctness fixes woven in:**
- `TOKEN_MANDATORY_LABEL` is read from an 8-byte-ALIGNED buffer (`Vec<u64>`), and the `Sid` pointer field is read via `addr_of!` + `read_unaligned` — never forming a misaligned reference.
- `integrity_level` is wired into `detect` (debug log) so it is not dead code under `-D warnings`.
- **dc2568da:** every token-query FAILURE path in `is_elevated`/`integrity_level` LOGS (distinguishing "determined not-elevated" from "could-not-determine, assuming not-elevated").

Windows dep features: ADD `Win32_System_SystemServices` (integrity RID constants), `Win32_System_Com` (CoInitializeEx — Task 14), `Win32_System_Registry` (the `HKEY` field of `SHELLEXECUTEINFOW` — Task 14), `Win32_UI_Shell` + `Win32_UI_WindowsAndMessaging` (ShellExecuteEx — Task 14). Keep the existing 7.

- [ ] **Step 1: Write the failing test** — create `src/elevation/windows_tests.rs`:

```rust
#[test]
fn detect_reports_windows_os() {
    let h = crate::elevation::plan::Host::detect();
    assert_eq!(h.os, crate::elevation::plan::Os::Windows);
}

#[test]
fn is_elevated_agrees_with_integrity_level() {
    // Privilege-independent invariant (never assume ambient privilege): a full
    // (elevated) token runs at High+ integrity; a filtered token is Medium. This
    // cross-checks TokenElevation against the independent TokenIntegrityLevel class.
    use windows::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
    let elevated = super::is_elevated();
    if let Some(rid) = super::integrity_level() {
        let high = rid >= SECURITY_MANDATORY_HIGH_RID as u32;
        assert_eq!(elevated, high, "TokenElevation ({elevated}) disagrees with integrity RID {rid:#x} vs High");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (Windows runner): `cargo test --lib elevation::windows`
Expected: FAIL — module `windows` not found.

- [ ] **Step 3: Write minimal implementation**

In `Cargo.toml`, extend the windows feature list (add five features to the existing seven):

```toml
windows = { version = "0.62", features = [
    "Win32_Foundation",
    "Win32_Storage_FileSystem",
    "Win32_System_Threading",
    "Win32_System_JobObjects",
    "Win32_System_Console",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_Security",
    "Win32_System_SystemServices",
    "Win32_System_Com",
    "Win32_System_Registry",
    "Win32_UI_Shell",
    "Win32_UI_WindowsAndMessaging",
] }
```

Create `src/elevation/windows.rs`:

```rust
//! Windows elevation effect layer (`cfg(windows)`): token-based detection and the
//! `ShellExecuteEx("runas")` reduced-child spawn.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation, TokenIntegrityLevel,
    TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::plan::{BackendSet, Host, Os};

struct OwnedToken(HANDLE);
impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: a token handle owned by this guard, closed exactly once.
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

fn open_process_token() -> Option<OwnedToken> {
    // SAFETY: standard token query; the handle is wrapped in a guard.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        Some(OwnedToken(token))
    }
}

pub(super) fn is_elevated() -> bool {
    let Some(token) = open_process_token() else {
        log::warn!("could not open the process token to query elevation; assuming not elevated");
        return false;
    };
    // SAFETY: fixed-size TOKEN_ELEVATION query on a live token.
    unsafe {
        let mut e = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut e as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok();
        if !ok {
            log::warn!("TokenElevation query failed; assuming not elevated");
            return false;
        }
        e.TokenIsElevated != 0
    }
}

/// The current token's integrity RID (e.g. Medium/High), or `None` if unreadable.
pub(super) fn integrity_level() -> Option<u32> {
    let token = open_process_token()?;
    // SAFETY: two-call GetTokenInformation into an 8-byte-aligned buffer;
    // TOKEN_MANDATORY_LABEL's Sid pointer field requires 8-byte alignment, so a
    // Vec<u64> backing avoids the align-1 UB a Vec<u8> would cause. The Sid pointer
    // is read via addr_of! + read_unaligned — never a misaligned reference.
    unsafe {
        let mut ret = 0u32;
        let _ = GetTokenInformation(token.0, TokenIntegrityLevel, None, 0, &mut ret);
        if ret == 0 {
            log::debug!("could not size the integrity-level token info; integrity unknown");
            return None;
        }
        let words = (ret as usize).div_ceil(8);
        let mut buf = vec![0u64; words];
        let cap = (words * 8) as u32;
        if let Err(e) = GetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            cap,
            &mut ret,
        ) {
            log::debug!("TokenIntegrityLevel query failed: {e:?}; integrity unknown");
            return None;
        }
        let label_ptr = buf.as_ptr() as *const TOKEN_MANDATORY_LABEL;
        let sid = std::ptr::read_unaligned(std::ptr::addr_of!((*label_ptr).Label.Sid));
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() || *count_ptr == 0 {
            return None;
        }
        let last = (*count_ptr as u32) - 1;
        Some(*GetSidSubAuthority(sid, last))
    }
}

pub(super) fn detect() -> Host {
    if let Some(rid) = integrity_level() {
        log::debug!("current process integrity RID = 0x{rid:04x}");
    }
    Host {
        elevated: is_elevated(),
        has_tty: false, // Windows never prompts on a TTY — UAC is a GUI gate.
        available: BackendSet::default(),
        os: Os::Windows,
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
```

In `src/elevation.rs`, after the `#[cfg(unix)] pub mod posix;` block:

```rust
#[cfg(windows)]
#[path = "elevation/windows.rs"]
pub mod windows;
```

In `src/identity/windows.rs`, add the crate helper next to `creation_token` (deriving identity from an ALREADY-OPEN handle — no second `OpenProcess`):

```rust
/// Build a `ProcessId` from an already-open Windows process handle and its pid,
/// reusing the creation-token read. Avoids a second `OpenProcess` (which can fail
/// and would otherwise force dropping a live elevated child).
pub(crate) fn windows_identity_from_handle(
    handle: HANDLE,
    pid: crate::identity::RawPid,
) -> Option<crate::identity::ProcessId> {
    let start = creation_token(handle)?;
    Some(crate::identity::ProcessId { pid, start })
}
```

> Confirm at code time: `creation_token` is `pub(super)` in `src/identity/windows.rs` and returns the `StartToken` that `ProcessId { pid, start }` expects; `HANDLE` is already imported there. If `ProcessId`'s fields are private to `identity.rs`, add a `pub(crate) fn from_parts(pid, start)` constructor in `identity.rs` and call it here instead of the struct literal.

- [ ] **Step 4: Run test to verify it passes**

Run (Windows): `cargo test --lib elevation::windows`
Expected: PASS (2 tests). Also `cargo clippy --all-targets --locked -- -D warnings` clean (integrity_level is used by detect).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/elevation.rs src/elevation/windows.rs src/elevation/windows_tests.rs src/identity/windows.rs
git commit -m "feat: Windows elevation detection (aligned integrity read, logged failures) + identity-from-handle"
```

---

### Task 13: Windows honest-contract rejection gate

**Files:**
- Modify: `src/elevation/windows.rs`, `src/elevation/windows_tests.rs`

**Interfaces:**
- Produces: `#[cfg(windows)] pub(crate) fn reject_unsupported_config(cmd: &Command) -> Result<(), Error>`.

**The gate rejects EVERY non-`Inherit` stdio slot AND every fd >= 3** (ShellExecuteEx passes NO handles), plus any explicit `.env()` and `.contain()`. It does NOT special-case `Pipe` on fd<3 — `File`, `Merge`, `Null`, and fd>=3 are equally un-satisfiable across the integrity boundary.

- [ ] **Step 1: Write the failing test** — append to `src/elevation/windows_tests.rs`:

```rust
use crate::command::Command;
use crate::error::Error;
use crate::stdio::Stdio;

fn is_unsupported<T>(r: Result<T, Error>) -> bool {
    matches!(r, Err(Error::Unsupported { .. }))
}

#[test]
fn piped_stdio_is_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(Stdio::pipe()).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn null_and_merge_stdio_are_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdin(Stdio::null()).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));

    let mut c2 = Command::new();
    c2.args(["whoami"]).elevate();
    c2.stderr(Stdio::merge(crate::stdio::Fd::STDOUT)).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c2)));
}

#[test]
fn high_fd_is_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.fd(3, Stdio::pipe_out()).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn env_and_contain_are_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().env("FOO", "bar");
    assert!(is_unsupported(super::reject_unsupported_config(&c)));

    let mut c2 = Command::new();
    c2.args(["whoami"]).elevate().contain();
    assert!(is_unsupported(super::reject_unsupported_config(&c2)));
}

#[test]
fn inherit_only_is_accepted() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(Stdio::inherit()).unwrap();
    assert!(super::reject_unsupported_config(&c).is_ok());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (Windows): `cargo test --lib elevation::windows::windows_tests`
Expected: FAIL — `reject_unsupported_config` not found.

- [ ] **Step 3: Write minimal implementation** — append to `src/elevation/windows.rs`:

```rust
use crate::command::Command;
use crate::error::Error;
use crate::stdio::ResolvedStdio;

/// Enforce the honest capability matrix for Windows elevation. ShellExecuteEx(runas)
/// passes NO handles and no environment, and a Job Object cannot span the integrity
/// boundary — so every non-inherit slot, every fd >= 3, any explicit env, and
/// `.contain()` is a loud `Unsupported`, never a silent lie.
pub(crate) fn reject_unsupported_config(cmd: &Command) -> Result<(), Error> {
    let unsupported = |op: &str, detail: &str| {
        Err(Error::Unsupported { op: op.into(), platform: "windows", detail: detail.into() })
    };
    for (&slot, resolved) in cmd.fds() {
        if slot.raw() >= 3 {
            return unsupported(
                "fd >= 3 on an elevated Windows child",
                "runas exposes no descriptor-passing mechanism; fd >= 3 needs the (deferred) broker",
            );
        }
        if !matches!(resolved, ResolvedStdio::Inherit) {
            return unsupported(
                "captured/redirected stdio on an elevated Windows child",
                "runas exposes no stdio-handle mechanism; capture/redirect needs the (deferred) broker. \
                 Use inherit(), or elevate on POSIX.",
            );
        }
    }
    if !cmd.env_ops().is_empty() {
        return unsupported(
            "env forwarding to an elevated Windows child",
            "runas provides no environment mechanism; forwarding needs the (deferred) broker",
        );
    }
    if cmd.contain_request().mode.is_some() {
        return unsupported(
            ".contain() + elevate on Windows",
            "a Job Object cannot span the integrity boundary of a runas child (deferred)",
        );
    }
    Ok(())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run (Windows): `cargo test --lib elevation::windows::windows_tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/elevation/windows.rs src/elevation/windows_tests.rs
git commit -m "feat: Windows elevation reject gate (all non-inherit slots + fd>=3 + env + contain)"
```

---

### Task 14: Windows `launch_runas` + `spawn_elevated` + non-blocking runas kill

**Files:**
- Modify: `src/elevation/windows.rs`, `src/elevation/windows_tests.rs`, `src/child/spawn/windows_raw/proc.rs`, `src/child/proc_handle.rs`, `src/child.rs`

**Interfaces:**
- Produces:
  - `#[cfg(windows)] pub(crate) enum RunasOutcome { AlreadyElevated, Launched { proc: OwnedHandle, pid: u32, id: ProcessId, report: ElevationReport } }`.
  - `#[cfg(windows)] pub(crate) fn launch_runas(cmd: &mut Command) -> Result<RunasOutcome, Error>` = `launch_runas_with_host(cmd, &Host::detect())`.
  - `#[cfg(windows)] pub(crate) fn launch_runas_with_host(cmd: &mut Command, host: &Host) -> Result<RunasOutcome, Error>` — the Windows gate seam (mirrors `posix::rewrite_with_host`); tests inject a NON-elevated Host so the gate runs even on an already-elevated CI runner.
  - `#[cfg(windows)] pub(crate) fn spawn_elevated(cmd: &mut Command, kill_on_drop: bool) -> Result<crate::child::Child, Error>`.
  - `RawChild::new_runas(proc, pid)` + `RawChild::teardown_on_drop()`; `ProcHandle::teardown_on_drop()`; `Child::drop` uses it.

**Structural decisions woven in:**
- **Decision 3 — non-blocking runas kill.** `RawChild` gains a `runas: bool` flag. For a runas child (a higher-integrity process a medium parent cannot `PROCESS_TERMINATE`), `kill()` CHECKS the `TerminateProcess` result and on `ACCESS_DENIED` returns a real `Error` (or `Ok` if the child already exited) — it NEVER blocks in `wait()`. A new `teardown_on_drop()` (called by `Child::drop` via `ProcHandle::teardown_on_drop`) attempts terminate and, if the higher-integrity child cannot be killed, LOGS and moves on — never blocks. The old drop's unconditional `proc.wait()` is REPLACED by this dispatcher, so an unkillable elevated child cannot hang `Drop`.
- **Decision 6 — host seam.** `launch_runas_with_host` plans against the injected `host`; the gate tests drive it with a non-elevated Windows `Host`.
- **f7897d84.** The impossible `Transition::ElevatePosix` arm is `unreachable!()`.
- **5cf8665a — COM.** `CoInitializeEx` returning `S_OK` OR `S_FALSE` both require a matching `CoUninitialize` (`S_FALSE` = already-init WITH the refcount incremented); only `RPC_E_CHANGED_MODE` skips it.
- **0dd20e72/94ab6dc1 — Untracked honesty.** When identity is unresolvable, the code CHECKS the `TerminateProcess` result and reports terminated-vs-still-running in the error `detail` (the `Untracked` kind's Display stays neutral).
- `nShow`: `SW_SHOWNORMAL.0 as i32`. `lpDirectory` from `cmd.cwd()`. `ERROR_CANCELLED` → `AuthDeclined`. Identity from the OWNED handle via `GetProcessId` + `windows_identity_from_handle`.

- [ ] **Step 1: Write the failing test** — append to `src/elevation/windows_tests.rs` (the gate runs before UAC; drive it through the host seam):

```rust
fn non_elevated_win_host() -> crate::elevation::plan::Host {
    crate::elevation::plan::Host {
        elevated: false,
        has_tty: false,
        available: crate::elevation::plan::BackendSet::default(),
        os: crate::elevation::plan::Os::Windows,
    }
}

#[test]
fn launch_runas_rejects_bad_config_before_any_prompt() {
    // Must fail with Unsupported and never prompt — the gate runs before ShellExecuteEx.
    // Driven through the host seam so an elevated CI runner does not short-circuit to RunAsIs.
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(Stdio::pipe()).unwrap();
    assert!(is_unsupported(super::launch_runas_with_host(&mut c, &non_elevated_win_host())));
}

#[test]
fn commandline_elevated_is_unsupported_on_windows() {
    let mut c = Command::new();
    c.commandline("whoami").elevate();
    assert!(is_unsupported(super::launch_runas_with_host(&mut c, &non_elevated_win_host())));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (Windows): `cargo test --lib elevation::windows::windows_tests::launch_runas`
Expected: FAIL — `launch_runas_with_host` not found.

- [ ] **Step 3: Write minimal implementation**

First, the non-blocking runas kill in `src/child/spawn/windows_raw/proc.rs`. Add a `runas: bool` field to `RawChild`, a `new_runas` ctor, and `teardown_on_drop`; make `kill` flag-aware:

```rust
// struct RawChild gains:  runas: bool,

impl RawChild {
    pub(crate) fn new(proc: OwnedHandle, pid: u32) -> RawChild {
        RawChild { proc, pid, runas: false }
    }

    /// A `runas`-elevated child: a higher-integrity process a lower-integrity parent
    /// may be unable to `PROCESS_TERMINATE`. Its kill/teardown never block on it.
    pub(crate) fn new_runas(proc: OwnedHandle, pid: u32) -> RawChild {
        RawChild { proc, pid, runas: true }
    }

    /// Hard-kill the process. An already-exited child is success.
    pub(crate) fn kill(&self) -> io::Result<()> {
        // SAFETY: `handle` is our live, owned process handle; exit code 1 is the forced-kill code.
        match unsafe { TerminateProcess(self.handle(), 1) } {
            Ok(()) => Ok(()),
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {
                if self.runas {
                    // A higher-integrity runas child we cannot terminate. Do NOT block in wait():
                    // already-exited is success; still-running is a genuine kill denial.
                    match self.try_wait()? {
                        Some(_) => Ok(()),
                        None => Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED.0 as i32)),
                    }
                } else {
                    // Our own CreateProcessW child: the denial means exit is already underway;
                    // block on that real event to confirm it (never a timer).
                    self.wait()?;
                    Ok(())
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Best-effort `kill_on_drop` teardown. Non-runas: kill (an already-exiting child is
    /// confirmed via a blocking wait) then reap. Runas: attempt terminate; if the
    /// higher-integrity child cannot be killed, LOG and move on — NEVER block.
    pub(crate) fn teardown_on_drop(&self) {
        // SAFETY: `handle` is our live, owned process handle.
        match unsafe { TerminateProcess(self.handle(), 1) } {
            Ok(()) => {
                let _ = self.wait();
            }
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {
                if self.runas {
                    if !matches!(self.try_wait(), Ok(Some(_))) {
                        log::warn!(
                            "elevated child {} could not be terminated on drop (higher integrity); leaving it running",
                            self.pid
                        );
                    }
                } else {
                    let _ = self.wait();
                }
            }
            Err(e) => log::warn!("terminating child {} on drop failed: {e:?}", self.pid),
        }
    }
}
```

In `src/child/proc_handle.rs`, add the teardown dispatcher:

```rust
    /// Best-effort teardown for `kill_on_drop`: kill then reap. A `runas` child a
    /// lower-integrity parent cannot terminate is handled without blocking.
    pub(crate) fn teardown_on_drop(&self) {
        match self {
            ProcHandle::Std(s) => {
                let _ = s.kill();
                let _ = s.wait();
            }
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.teardown_on_drop(),
        }
    }
```

In `src/child.rs`, `Drop` becomes:

```rust
impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return; // detached / opted out
        }
        // Hard-kill the contained tree (if any), then tear the direct child down. The
        // teardown dispatcher preserves the Unix kill-before-wait order for the Std/Raw
        // paths and stays non-blocking for a possibly-unkillable runas child.
        let _ = self.attached.hard_kill();
        self.proc.teardown_on_drop();
    }
}
```

Now append the launch to `src/elevation/windows.rs`:

```rust
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK};
use windows::Win32::System::Com::{
    CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows::Win32::System::Threading::{GetProcessId, TerminateProcess};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::child::proc_handle::ProcHandle;
use crate::child::spawn::windows_raw::RawChild;
use crate::command::CommandInput;
use crate::containment::{Attached, Containment};
use crate::elevation::plan::{Host, Transition};
use crate::elevation::{ElevatedStdio, ElevatedVia, ElevationReport, Privilege};
use crate::error::ElevationErrorKind;
use crate::identity::ProcessId;

/// `ERROR_CANCELLED` (1223) as an HRESULT (0x800704C7) — the UAC-declined code.
const ERROR_CANCELLED_HRESULT: windows::core::HRESULT = windows::core::HRESULT(0x800704C7_u32 as i32);

fn wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// The outcome of a runas launch. `Launched` carries the owned handle, pid, stable
/// identity, and the report — the async path (Task 16) builds its own `Child` from these.
pub(crate) enum RunasOutcome {
    AlreadyElevated,
    Launched { proc: OwnedHandle, pid: u32, id: ProcessId, report: ElevationReport },
}

/// Balances a `CoInitializeEx` with `CoUninitialize` only when WE incremented the refcount.
struct ComInit {
    uninit: bool,
}
impl ComInit {
    fn init() -> Result<ComInit, Error> {
        // SAFETY: COM apartment init on the calling thread; balanced in Drop.
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        if hr == S_OK || hr == S_FALSE {
            // S_FALSE = already initialized on this thread WITH the refcount incremented,
            // so it still requires a matching CoUninitialize.
            Ok(ComInit { uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            // Already initialized in a different apartment model; we did NOT increment.
            Ok(ComInit { uninit: false })
        } else {
            Err(Error::Elevation {
                kind: ElevationErrorKind::AuthFailed,
                detail: format!("CoInitializeEx failed before ShellExecuteEx: {hr:?}"),
            })
        }
    }
}
impl Drop for ComInit {
    fn drop(&mut self) {
        if self.uninit {
            // SAFETY: balances our CoInitializeEx that incremented the refcount.
            unsafe { CoUninitialize() };
        }
    }
}

/// Program (loaded image) + the joined parameter line. Honors `executable()`; an
/// argv[0] distinct from a set `executable()` cannot be preserved by runas.
fn program_and_params(cmd: &Command) -> Result<(OsString, OsString), Error> {
    let CommandInput::Argv(argv) = cmd.input() else {
        return Err(Error::Unsupported {
            op: "elevation of a commandline() command".into(),
            platform: "windows",
            detail: "runas elevation requires an argv command (set .args([...]))".into(),
        });
    };
    if argv.is_empty() {
        return Err(Error::Unsupported {
            op: "elevation of an empty command".into(),
            platform: "windows",
            detail: "set a program via .args([...]) before .elevate()".into(),
        });
    }
    let program = match cmd.executable_path() {
        Some(exe) => {
            if argv[0].as_os_str() != exe.as_os_str() {
                return Err(Error::Unsupported {
                    op: "elevation with an argv[0] distinct from executable()".into(),
                    platform: "windows",
                    detail: "ShellExecuteEx(runas) cannot set an argv[0] independent of the loaded image".into(),
                });
            }
            exe.as_os_str().to_os_string()
        }
        None => argv[0].clone(),
    };
    let tail_wide: Vec<Vec<u16>> = argv[1..].iter().map(|a| a.encode_wide().collect()).collect();
    let tail_refs: Vec<&[u16]> = tail_wide.iter().map(|v| v.as_slice()).collect();
    let joined = crate::quote::windows::join_wide(&tail_refs);
    Ok((program, OsString::from_wide(&joined)))
}

pub(crate) fn launch_runas(cmd: &mut Command) -> Result<RunasOutcome, Error> {
    launch_runas_with_host(cmd, &Host::detect())
}

/// PURE given `host` (the Windows gate seam): plan, gate, then ShellExecuteEx(runas).
pub(crate) fn launch_runas_with_host(cmd: &mut Command, host: &Host) -> Result<RunasOutcome, Error> {
    let req = cmd.elevation_request();
    match host.plan(Privilege::Elevated, req.backend, req.auth.clone()) {
        Transition::RunAsIs => return Ok(RunasOutcome::AlreadyElevated),
        Transition::Reject { error } => return Err(error),
        Transition::ElevatePosix { .. } => unreachable!("planner never yields ElevatePosix on a windows host"),
        Transition::ElevateWindows { .. } => {}
    }
    reject_unsupported_config(cmd)?;

    let (program, params) = program_and_params(cmd)?;
    let dir = cmd.cwd().map(|d| wide_nul(d.as_os_str()));
    let file_w = wide_nul(program.as_os_str());
    let params_w = wide_nul(params.as_os_str());
    let verb_w = wide_nul(OsStr::new("runas"));

    let com = ComInit::init()?;
    // SAFETY: `info` is fully initialized with the correct cbSize; the wide buffers
    // outlive the call; SEE_MASK_NOCLOSEPROCESS yields an owned hProcess.
    let proc: OwnedHandle = unsafe {
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb_w.as_ptr()),
            lpFile: PCWSTR(file_w.as_ptr()),
            lpParameters: PCWSTR(params_w.as_ptr()),
            lpDirectory: dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
            nShow: SW_SHOWNORMAL.0 as i32,
            ..Default::default()
        };
        ShellExecuteExW(&mut info).map_err(|e| {
            if e.code() == ERROR_CANCELLED_HRESULT {
                Error::Elevation { kind: ElevationErrorKind::AuthDeclined, detail: "the UAC elevation prompt was declined".into() }
            } else {
                Error::Elevation { kind: ElevationErrorKind::AuthFailed, detail: format!("ShellExecuteEx(runas) failed: {e}") }
            }
        })?;
        if info.hProcess.is_invalid() {
            return Err(Error::Elevation {
                kind: ElevationErrorKind::AuthFailed,
                detail: "ShellExecuteEx(runas) returned no process handle".into(),
            });
        }
        OwnedHandle::from_raw_handle(info.hProcess.0 as std::os::windows::io::RawHandle)
    };
    drop(com);

    // Identity from the OWNED handle — no second OpenProcess.
    let handle = HANDLE(proc.as_raw_handle());
    // SAFETY: `handle` is our live, owned process handle.
    let pid = unsafe { GetProcessId(handle) };
    let id = if pid != 0 {
        crate::identity::windows::windows_identity_from_handle(handle, pid)
    } else {
        None
    };
    let Some(id) = id else {
        // Auth SUCCEEDED but we cannot track the child. Terminate it, and report the
        // ACTUAL outcome (terminated vs still-running) in the detail — the kind stays neutral.
        // SAFETY: `handle` is live; terminating our own launched child.
        let terminated = unsafe { TerminateProcess(handle, 1) }.is_ok();
        let detail = if terminated {
            "the elevated child launched but its identity could not be resolved; it was terminated".into()
        } else {
            format!("the elevated child (pid {pid}) launched but its identity could not be resolved and could not be terminated; it may still be running")
        };
        return Err(Error::Elevation { kind: ElevationErrorKind::Untracked, detail });
    };

    let report = ElevationReport {
        via: ElevatedVia::WindowsUac,
        stripped_env: Vec::new(),
        stdio: ElevatedStdio::OwnConsole,
    };
    Ok(RunasOutcome::Launched { proc, pid, id, report })
}

pub(crate) fn spawn_elevated(cmd: &mut Command, kill_on_drop: bool) -> Result<crate::child::Child, Error> {
    match launch_runas(cmd)? {
        RunasOutcome::AlreadyElevated => {
            let mut child = crate::child::spawn::spawn_unelevated(cmd, kill_on_drop)?;
            child.set_elevation(Some(ElevationReport {
                via: ElevatedVia::AlreadyElevated,
                stripped_env: Vec::new(),
                stdio: ElevatedStdio::Passthrough,
            }));
            Ok(child)
        }
        RunasOutcome::Launched { proc, pid, id, report } => {
            // A dedicated non-blocking-kill handle (RawChild::new_runas): a higher-integrity
            // child a medium parent cannot terminate never hangs Drop.
            let mut child = crate::child::Child::from_parts(
                ProcHandle::Raw(RawChild::new_runas(proc, pid)),
                id,
                BTreeMap::new(),
                kill_on_drop,
                Containment::None,
                Attached::None,
            );
            child.set_elevation(Some(report));
            Ok(child)
        }
    }
}
```

> Confirm at code time (patterns proven in `src/child/spawn/windows_raw/proc.rs`): the `RawChild` re-export path (`crate::child::spawn::windows_raw::RawChild`) and the `HANDLE(proc.as_raw_handle())` shape. `Child::from_parts` is `pub(crate)` (verified in `src/child.rs`). `ERROR_ACCESS_DENIED` is already imported in `proc.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run (Windows): `cargo test --lib elevation::windows`
Then run the FULL suite (the shared-drop change): `cargo test --lib` on Windows AND on Linux/macOS (the `ProcHandle::teardown_on_drop` + `Child::drop` edits compile and must regress-clean everywhere).
Expected: PASS. Also `cargo build --target x86_64-pc-windows-msvc` and `cargo clippy --all-targets --locked -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add src/elevation/windows.rs src/elevation/windows_tests.rs src/child/spawn/windows_raw/proc.rs src/child/proc_handle.rs src/child.rs
git commit -m "feat: Windows runas launch (plan-first host seam, COM S_FALSE fix, non-blocking runas kill, Untracked honesty)"
```

---

### Task 15: `spawn()` elevation branch (fd-take reorder)

**Files:**
- Modify: `src/child/spawn.rs`
- Test: `src/child/spawn_tests.rs`

**Interfaces:**
- Produces: `spawn()` runs the elevation branch BEFORE `spawn_unelevated`'s `std::mem::take(cmd.fds_mut())`, so the effect layers see `cmd.fds()` while it is still populated. POSIX spawns the DERIVED command (`rw.derived`) — or the original when `AlreadyElevated` — then delivers the deferred password. A NotFound/PermissionDenied spawn error of the derived command (whose program IS the backend) is remapped to `BackendUnavailable` (948c8e5c: the `faccessat` check is a hint; the exec failure is the truth). Windows delegates to `windows::spawn_elevated` (Task 14).

**Why the reorder matters:** if the branch ran after `mem::take`, the Windows reject gate would iterate an EMPTY `cmd.fds()` and pass vacuously (a silent lie), and the POSIX rewrite would move an empty fd set into the derived command. Running before `mem::take` fixes both.

- [ ] **Step 1: Write the failing test** — append to `src/child/spawn_tests.rs`:

```rust
#[cfg(windows)]
#[test]
fn elevated_pipe_routes_through_the_gate() {
    // Integration through the real spawn entrypoint. Branch on detected privilege
    // (never assume): unprivileged → the honest gate rejects a piped elevated child
    // before UAC; already-elevated → RunAsIs makes it an ordinary (allowed) spawn.
    let mut c = crate::command::Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(crate::stdio::Stdio::pipe()).unwrap();
    let r = super::spawn(&mut c);
    if crate::elevation::is_elevated() {
        let mut ch = r.expect("already-elevated piped whoami should spawn");
        let _ = ch.wait();
    } else {
        assert!(matches!(r, Err(crate::error::Error::Unsupported { .. })));
    }
}
```

(The POSIX "derived fd0 is the pipe read end" path is covered by `stdin_auth_wires_fd0_to_a_file_and_defers_the_write` in Task 11, which exercises the same `rewrite`.)

- [ ] **Step 2: Run test to verify it fails**

Run (Windows, unprivileged): `cargo test --lib spawn_tests::elevated_pipe_routes_through_the_gate`
Expected: FAIL — `spawn` does not yet route elevated commands.

- [ ] **Step 3: Write minimal implementation** — change `spawn()` in `src/child/spawn.rs` (post-Task-10 two-line wrapper) to:

```rust
pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let kill_on_drop = cmd.kill_on_drop_flag();
    // Elevation runs BEFORE spawn_unelevated's std::mem::take(cmd.fds_mut()), so the
    // effect layers see/modify cmd.fds() while it is still populated (the honest Windows
    // reject gate and the POSIX derived-command build both depend on it).
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            return crate::elevation::windows::spawn_elevated(cmd, kill_on_drop);
        }
        #[cfg(unix)]
        {
            let rw = crate::elevation::posix::rewrite(cmd)?;
            let mut child = match rw.derived {
                Some(mut derived) => match spawn_unelevated(&mut derived, kill_on_drop) {
                    Ok(c) => c,
                    // The derived program IS the backend, so a NotFound/PermissionDenied at
                    // spawn is the backend failing to exec — surface it as BackendUnavailable.
                    Err(Error::Io(e))
                        if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied) =>
                    {
                        return Err(Error::Elevation {
                            kind: crate::error::ElevationErrorKind::BackendUnavailable,
                            detail: format!("the elevation backend could not be executed: {e}"),
                        });
                    }
                    Err(e) => return Err(e),
                },
                None => spawn_unelevated(cmd, kill_on_drop)?, // AlreadyElevated: spawn the original
            };
            if let Some(pw) = rw.password_write {
                pw.write_after_spawn()?;
            }
            child.set_elevation(rw.report);
            return Ok(child);
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err(Error::Unsupported {
                op: "elevation".into(),
                platform: std::env::consts::OS,
                detail: "no elevation backend on this platform".into(),
            });
        }
    }
    spawn_unelevated(cmd, kill_on_drop)
}
```

Each `#[cfg]` arm is self-contained (returns), so there are no `unused_mut` / unused-binding warnings on any platform.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib` (Windows leg runs the new test; all legs regress-clean)
Expected: PASS. `cargo clippy --all-targets --locked -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add src/child/spawn.rs src/child/spawn_tests.rs
git commit -m "feat: spawn() elevation branch before fd-take (derived command, post-spawn password, backend-exec remap)"
```

---

### Task 16: Async (tokio) parity

**Files:**
- Modify: `src/tokio/command.rs`, `src/tokio/child.rs`, `src/tokio/spawn.rs`, `src/tokio/spawn/windows_raw.rs`
- Test: `src/tokio/command_tests.rs`

**Interfaces:**
- Produces on `tokio::Command`: `.elevate()`, `.elevation_backend(Backend)`, `.elevation_auth(Auth)`, `.sanitize_env(EnvSanitizer)` — forwarding to the inner sync `Command`.
- Produces on `tokio::Child`: `elevation: Option<ElevationReport>` field, `set_elevation`, `pub fn elevation(&self) -> Option<ElevationReport>`.
- Produces: an async spawn branch mirroring sync — POSIX rewrites into a DERIVED command and RECURSES into `spawn` (the derived command has elevation disabled, so no re-entry); the deferred password is written by a blocking `write_after_spawn` post-spawn (no `.await`). Windows uses `launch_runas`, and the async `Child` is built INSIDE `crate::tokio::spawn` via `RawAsyncChild::new_runas` (the non-blocking-kill async handle).
- Produces: `RawAsyncChild` gains a `runas` flag + `new_runas` + a non-blocking `reap_blocking` (Decision 3, async side).

- [ ] **Step 1: Write the failing test** — append to `src/tokio/command_tests.rs`:

```rust
#[test]
fn tokio_elevate_forwards_to_inner_request() {
    let mut c = Command::new();
    c.args(["id", "-u"]).elevation_backend(crate::elevation::Backend::Sudo);
    // command_tests is a child module of tokio::command, so it can read the private inner.
    let req = c.inner.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Sudo);
}

#[cfg(unix)]
#[tokio::test]
async fn tokio_child_elevation_is_none_without_elevate() {
    let mut c = Command::new();
    c.args(["true"]);
    let child = c.spawn().expect("spawn");
    assert!(child.elevation().is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --features tokio --lib tokio::command`
Expected: FAIL — no `elevation_backend` on `tokio::Command`; no `elevation()` on `tokio::Child`.

- [ ] **Step 3: Write minimal implementation**

In `src/tokio/command.rs`, after `nesting`:

```rust
    pub fn elevate(&mut self) -> &mut Command {
        self.inner.elevate();
        self
    }
    pub fn elevation_backend(&mut self, backend: crate::elevation::Backend) -> &mut Command {
        self.inner.elevation_backend(backend);
        self
    }
    pub fn elevation_auth(&mut self, auth: crate::elevation::Auth) -> &mut Command {
        self.inner.elevation_auth(auth);
        self
    }
    pub fn sanitize_env(&mut self, sanitizer: crate::elevation::EnvSanitizer) -> &mut Command {
        self.inner.sanitize_env(sanitizer);
        self
    }
```

In `src/tokio/child.rs`, add `elevation: Option<crate::elevation::ElevationReport>` to `struct Child`, init `elevation: None` in `from_parts`, and add:

```rust
    pub(crate) fn set_elevation(&mut self, report: Option<crate::elevation::ElevationReport>) {
        self.elevation = report;
    }
    pub fn elevation(&self) -> Option<crate::elevation::ElevationReport> {
        self.elevation.clone()
    }
```

In `src/tokio/spawn/windows_raw.rs`, give `RawAsyncChild` the `runas` flag + `new_runas` + a non-blocking `reap_blocking`:

```rust
// struct RawAsyncChild gains:  runas: bool,

impl RawAsyncChild {
    pub(crate) fn new(proc: OwnedHandle, pid: u32) -> RawAsyncChild {
        RawAsyncChild { /* existing fields */ runas: false, /* ... */ }
    }
    pub(crate) fn new_runas(proc: OwnedHandle, pid: u32) -> RawAsyncChild {
        RawAsyncChild { /* existing fields */ runas: true, /* ... */ }
    }

    /// Synchronous kill-then-reap for `Drop`. A runas child a lower-integrity parent
    /// cannot terminate is torn down best-effort WITHOUT blocking.
    pub(crate) fn reap_blocking(&mut self) {
        if self.exited.is_some() {
            return;
        }
        if self.runas {
            // SAFETY: our live, owned process handle.
            match unsafe { TerminateProcess(self.handle(), 1) } {
                Ok(()) => {
                    // It will exit; the wait is bounded by a real termination event.
                    // SAFETY: our live, owned process handle.
                    let _ = unsafe { WaitForSingleObject(self.handle(), INFINITE) };
                }
                Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {
                    if !matches!(self.try_wait(), Ok(Some(_))) {
                        log::warn!(
                            "elevated async child {} could not be terminated on drop; leaving it running",
                            self.pid
                        );
                    }
                }
                Err(e) => log::warn!("terminating elevated async child {} on drop failed: {e:?}", self.pid),
            }
            return;
        }
        let _ = self.start_kill();
        // SAFETY: our live, owned process handle; INFINITE is bounded by the kill above.
        let waited = unsafe { WaitForSingleObject(self.handle(), INFINITE) };
        debug_assert!(waited == WAIT_OBJECT_0, "raw async Drop did not observe child {} exit: {waited:?}", self.pid);
        let _ = waited;
    }
}
```

> `TerminateProcess`, `WaitForSingleObject`, `WAIT_OBJECT_0`, `INFINITE`, and `ERROR_ACCESS_DENIED` are already imported in this file (used by `start_kill`/`reap_blocking`/`try_wait`). Only `windows::core::HRESULT` may need adding.

In `src/tokio/spawn.rs`, move `let kill_on_drop = cmd.kill_on_drop_flag();` ABOVE the current `let mut fds = std::mem::take(cmd.fds_mut());`, insert the elevation branch there, and attach the report at the tail:

```rust
    let kill_on_drop = cmd.kill_on_drop_flag();
    // Elevation runs before fds are taken (mirrors sync). POSIX rewrites into a DERIVED
    // command and recurses (the derived command has elevation disabled → no re-entry);
    // Windows builds the async Child here (tokio::child::Child::from_parts is pub(super)).
    let mut elevation_report: Option<crate::elevation::ElevationReport> = None;
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            use crate::elevation::windows::{launch_runas, RunasOutcome};
            match launch_runas(cmd)? {
                RunasOutcome::Launched { proc, pid, id, report } => {
                    let raw = windows_raw::RawAsyncChild::new_runas(proc, pid);
                    let mut child = Child::from_parts(
                        ProcSource::Raw(raw),
                        id,
                        crate::containment::Attached::None,
                        kill_on_drop,
                        crate::containment::Containment::None,
                        super::child::FdPipes::new(),
                        std::collections::BTreeMap::new(),
                    );
                    child.set_elevation(Some(report));
                    return Ok(child);
                }
                RunasOutcome::AlreadyElevated => {
                    elevation_report = Some(crate::elevation::ElevationReport {
                        via: crate::elevation::ElevatedVia::AlreadyElevated,
                        stripped_env: Vec::new(),
                        stdio: crate::elevation::ElevatedStdio::Passthrough,
                    });
                    // fall through to the normal async spawn of the (already-elevated) cmd
                }
            }
        }
        #[cfg(unix)]
        {
            let rw = crate::elevation::posix::rewrite(cmd)?;
            if let Some(mut derived) = rw.derived {
                let mut child = match spawn(&mut derived) {
                    Ok(c) => c,
                    Err(Error::Io(e))
                        if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied) =>
                    {
                        return Err(Error::Elevation {
                            kind: crate::error::ElevationErrorKind::BackendUnavailable,
                            detail: format!("the elevation backend could not be executed: {e}"),
                        });
                    }
                    Err(e) => return Err(e),
                };
                if let Some(pw) = rw.password_write {
                    pw.write_after_spawn()?;
                }
                child.set_elevation(rw.report);
                return Ok(child);
            }
            elevation_report = rw.report; // AlreadyElevated: fall through
        }
    }
    let mut fds = std::mem::take(cmd.fds_mut());
    // ... existing async spawn body (routing, resolve, build) unchanged ...
```

Change the tail `Ok(Child::from_parts(...))` to attach the report:

```rust
    let mut child = Child::from_parts(
        ProcSource::Tokio(child),
        id,
        attached,
        kill_on_drop,
        containment,
        pipes,
        owned_std,
    );
    child.set_elevation(elevation_report);
    Ok(child)
```

`ProcSource` is imported via `use super::child::{reap_now, Child, ProcSource};`. Both the unix branch (`elevation_report = rw.report`) and the windows `AlreadyElevated` arm are compiled per platform, so `elevation_report`'s `mut` is always used (no `unused_mut`). The old `let kill_on_drop` at its former position is removed (moved up).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --features tokio --lib tokio::command`
Then: `cargo build --features tokio` on Unix and Windows; `cargo clippy --all-targets --features tokio --locked -- -D warnings`.
Expected: PASS, clean.

- [ ] **Step 5: Commit**

```bash
git add src/tokio/command.rs src/tokio/child.rs src/tokio/spawn.rs src/tokio/spawn/windows_raw.rs
git commit -m "feat: async elevation parity (derived-command recursion, post-spawn password, non-blocking runas kill)"
```

---

### Task 17: Live gated integration tests + testbin subcommands

**Files:**
- Create: `tests/elevation.rs`
- Modify: `testbin/main.rs`

**Interfaces:**
- Consumes: the full public surface (`Command::elevate`, `Child::elevation`, `elevation::is_elevated`, `posix::controlling_terminal_present`), sync + async.
- Produces: `testbin` subcommands `is-elevated-report` (prints `1`/`0`), `controlling-terminal` (prints `controlling_terminal_present()` as `1`/`0`), `write-marker <path>` (writes a byte, exit 0). Live privilege-gain tests are gated behind `SUBPROCESS_TEST_ELEVATION`; the `setsid` and stdin-redirection controlling-terminal tests are UNGATED (deterministic).

The controlling-terminal probe's stdin-independence is tested cross-process (a testbin child whose fd0 is actually redirected), fixing the previously vacuous in-process assertion. The `setsid` negative case is cross-process via the same subcommand. A gated run0 kill-propagation live test pins the client→unit teardown; the same gated run confirms the `--`-terminator corner case empirically.

- [ ] **Step 1: Write the failing test** — create `tests/elevation.rs`:

```rust
//! Live elevation tier — gated behind SUBPROCESS_TEST_ELEVATION (cgroup precedent):
//! a TRUE no-op when the var is absent, and FAILS LOUDLY when set but elevation is
//! unavailable. The pure tiers cover all logic unconditionally; only the privilege-gain
//! (and the cross-process controlling-terminal probes) run here.

use std::path::PathBuf;

fn gated() -> bool {
    std::env::var_os("SUBPROCESS_TEST_ELEVATION").is_some()
}

fn testbin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.push(if cfg!(windows) { "subprocess_testbin.exe" } else { "subprocess_testbin" });
    p
}

#[cfg(unix)]
#[test]
fn posix_elevated_child_runs_as_root_and_captures_uid() {
    if !gated() {
        return;
    }
    let mut c = subprocess::Command::new();
    c.args(["id", "-u"]).elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let out = c.output().expect("elevated output");
    assert!(out.status.success(), "elevated `id -u` failed: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0", "elevated child was not root");
}

#[cfg(unix)]
#[test]
fn posix_child_self_detects_elevation() {
    if !gated() {
        return;
    }
    let exe = testbin();
    let exe_str = exe.clone().into_os_string();
    let mut c = subprocess::Command::new();
    // executable() set AND argv[0] == the exe path, so no distinct-argv0 rejection.
    c.executable(&exe)
        .args([exe_str, "is-elevated-report".into()])
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let s = c.read().expect("read");
    assert_eq!(s.trim(), "1", "elevated testbin did not self-detect elevation");
}

// UNGATED: redirecting the child's fd0 must not change the /dev/tty probe (it consults
// the session's controlling terminal, not stdin). Non-vacuous — a buggy isatty(STDIN)
// impl would differ between the null and inherit runs on a real terminal.
#[cfg(unix)]
#[test]
fn controlling_terminal_probe_ignores_stdin_redirection() {
    let exe = testbin();
    let run = |stdin: subprocess::Stdio| -> String {
        let mut c = subprocess::Command::new();
        c.args([exe.clone().into_os_string(), "controlling-terminal".into()]);
        c.stdin(stdin).unwrap();
        c.stdout(subprocess::Stdio::pipe()).unwrap();
        let mut ch = c.spawn().expect("spawn");
        let out = ch.communicate(None).expect("communicate");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(
        run(subprocess::Stdio::null()),
        run(subprocess::Stdio::inherit()),
        "stdin redirection changed the controlling-terminal probe",
    );
}

// UNGATED: setsid detaches the controlling terminal, so the probe must report 0.
// Linux-only (macOS ships no `setsid` binary; the probe itself is tested cross-platform
// in the unit suite).
#[cfg(target_os = "linux")]
#[test]
fn controlling_terminal_probe_is_false_after_setsid() {
    let exe = testbin();
    let mut c = subprocess::Command::new();
    c.args(["setsid".into(), exe.into_os_string(), "controlling-terminal".into()]);
    let s = c.read().expect("read setsid child output");
    assert_eq!(s.trim(), "0", "controlling_terminal_present() must be false after setsid");
}

// GATED: run0 client -> unit kill propagation. Explicit Backend::Run0, long-lived child.
#[cfg(target_os = "linux")]
#[test]
fn run0_client_kill_propagates_to_the_unit() {
    if !gated() || std::env::var_os("SUBPROCESS_TEST_ELEVATION_RUN0").is_none() {
        return; // requires run0 + a root context that can spawn a transient unit.
    }
    let mut c = subprocess::Command::new();
    c.args(["sleep", "600"])
        .elevation_backend(subprocess::elevation::Backend::Run0)
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let mut child = c.spawn().expect("run0 spawn");
    let id = child.id();
    child.kill().expect("kill run0 client");
    child.wait().expect("wait run0 client");
    assert!(!id.is_alive(), "run0 client kill did not tear the elevated unit down");
}

#[cfg(windows)]
#[test]
fn windows_elevated_child_writes_admin_marker() {
    if !gated() {
        return;
    }
    let dir = std::env::var_os("SUBPROCESS_TEST_ELEVATION_MARKER_DIR")
        .map(PathBuf::from)
        .expect("SUBPROCESS_TEST_ELEVATION_MARKER_DIR must point at an admin-only writable dir");
    let marker = dir.join(format!("elev-{}.marker", std::process::id()));
    let exe = testbin();
    let mut c = subprocess::Command::new();
    c.executable(&exe).args([
        exe.clone().into_os_string(),
        "write-marker".into(),
        marker.clone().into_os_string(),
    ]);
    c.elevate();
    let child = c.spawn().expect("runas spawn");
    // Honest report: WindowsUac + OwnConsole (never a faked shared stream).
    let report = child.elevation().unwrap();
    assert_eq!(report.via, subprocess::elevation::ElevatedVia::WindowsUac);
    assert_eq!(report.stdio, subprocess::elevation::ElevatedStdio::OwnConsole);
    let status = child.wait().expect("wait");
    assert!(status.success(), "elevated marker write failed: {status:?}");
    assert!(marker.exists(), "elevated child did not create the admin-only marker");
    let _ = std::fs::remove_file(&marker);
}

#[cfg(all(unix, feature = "tokio"))]
#[tokio::test]
async fn async_posix_elevated_child_runs_as_root() {
    if !gated() {
        return;
    }
    let mut c = subprocess::tokio::Command::new();
    c.args(["id", "-u"]).elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let out = c.output().await.expect("async elevated output");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test elevation`
Expected on Linux: FAIL — `controlling_terminal_probe_is_false_after_setsid` / `controlling_terminal_probe_ignores_stdin_redirection` (testbin has no `controlling-terminal` subcommand → non-`0` output / spawn error).

- [ ] **Step 3: Write minimal implementation** — in `testbin/main.rs`, add the arms before the final `other =>`:

```rust
        "is-elevated-report" => {
            println!("{}", if subprocess::elevation::is_elevated() { "1" } else { "0" });
        }
        #[cfg(unix)]
        "controlling-terminal" => {
            let present = subprocess::elevation::posix::controlling_terminal_present();
            println!("{}", if present { "1" } else { "0" });
        }
        "write-marker" => {
            let path = &args[2];
            std::fs::write(path, b"1").expect("write marker");
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run (ungated): `cargo test --test elevation` and `cargo test --features tokio --test elevation`
Expected: PASS (privilege tests no-op; Linux `setsid` + stdin-redirection tests green).
Run (gated, Linux w/ passwordless sudo): `SUBPROCESS_TEST_ELEVATION=1 cargo test --test elevation`
Expected: PASS (root uid `0`, self-detect `1`). Confirm empirically that the `--`-terminator handling in Task 7 holds (the `id -u` under sudo still runs).

- [ ] **Step 5: Commit**

```bash
git add tests/elevation.rs testbin/main.rs
git commit -m "test: gated live elevation tier + ungated cross-process controlling-terminal probes"
```

---

### Task 18: `TODO.md` CI provisioning note

**Files:**
- Modify: `TODO.md`

- [ ] **Step 1: Write the change** — under the cgroup "CI provisioning required" section, add a sibling section:

```markdown
## CI provisioning required (elevation live tier)

The live elevation tests (`tests/elevation.rs`) are gated behind
`SUBPROCESS_TEST_ELEVATION`: a true no-op when absent, FAIL LOUDLY when set but
elevation is unavailable (identical to `SUBPROCESS_TEST_CGROUP`).

- **Linux:** provision passwordless `sudo` for the job user (a `NOPASSWD:ALL`
  sudoers drop-in), then set `SUBPROCESS_TEST_ELEVATION=1`. The tests spawn
  `id -u` elevated and assert `0`; `Auth::NonInteractive` is used so no prompt
  blocks. `doas` is optional; `Backend::Auto` resolves `sudo` > `doas`. The run0
  kill-propagation test additionally requires `SUBPROCESS_TEST_ELEVATION_RUN0=1`
  and a `run0`-capable context.
- **Windows:** `ShellExecuteEx(runas)` always shows a UAC prompt on an
  interactive desktop, so the live Windows tier is a **documented manual-run
  tier** — run on a machine with UAC auto-approve (admin-approval-mode off) or a
  self-hosted elevated runner, with `SUBPROCESS_TEST_ELEVATION=1` and
  `SUBPROCESS_TEST_ELEVATION_MARKER_DIR` pointing at an admin-only-writable dir
  (e.g. `C:\Windows\System32\subprocess-ci`). Not run on hosted GitHub runners.
```

- [ ] **Step 2: Verify** — `git diff TODO.md` shows the new section only.

- [ ] **Step 3: Commit**

```bash
git add TODO.md
git commit -m "docs: TODO CI provisioning note for the elevation live tier"
```

---

### Task 19: Open PR against main and verify CI

**Files:** none (workflow only).

- [ ] **Step 1: Confirm branch + clean tree**

Run: `git status` and `git branch --show-current`
Expected: on `azhukova/6`, working tree clean, all Task 1–18 commits present. Do NOT push to `main`.

- [ ] **Step 2: Push the branch**

```bash
git push -u origin azhukova/6
```

- [ ] **Step 3: Open the PR** (issue #6)

```bash
gh pr create --base main --head azhukova/6 \
  --title "feat: privilege elevation (admin/root vertical, sync + async)" \
  --body "Implements the elevation design spec (.tmp/claude/superpowers/specs/2026-07-25-elevation-design.md): pure Host::plan planner as the single validation choke point, EnvSanitizer boundary, POSIX sudo/run0/doas/pkexec backend-native rewrite (non-destructive derived command), Windows ShellExecuteEx(runas) reduced child with a non-blocking runas kill, queryable Child::elevation(), full sync+async parity. Live tier gated behind SUBPROCESS_TEST_ELEVATION. Closes #6."
```

- [ ] **Step 4: Verify CI** — use the `gh-ci` skill to watch the run to green:

Run: (via `gh-ci`) watch the PR's checks; confirm Lint + all Test matrix legs (linux/darwin/windows × amd64/arm64, base + `pty` + `tokio` features) pass.
Expected: all checks green. Do not merge — squash-merge happens on user approval only.

- [ ] **Step 5: Report** — post the PR URL and CI status back to the user; await approval for squash-merge.

---

## Self-Review

**1. Spec coverage:**

| Spec section | Task(s) |
|---|---|
| `is_elevated()` free fn (ground-truth tested) | 9 (unix), 12 (windows) |
| Flat builder: `.elevate/.elevation_backend/.elevation_auth/.sanitize_env` | 8 (sync), 16 (async) |
| `Backend`/`Auth`/`ElevatedStdio`/`ElevatedVia`/`Privilege`/`Secret` spellings | 2, 3 |
| `EnvSanitizer` consent gradient; keep additive-within-policy | 6 |
| Two-layer env (clean default + denylist over explicit `Set`; no `env` wrapper) | 6 + 7 (`--preserve-env`/`--setenv`) + 11 (`explicit_set_env`; doas/pkexec/`env_remove`/`env_clear` → Unsupported) |
| `ElevationReport { via, stripped_env, stdio }` + `Child::elevation()` = Some iff requested | 11 (sync), 14 (windows RunAsIs/UAC), 16 (async) |
| Pure `Host::plan` → `Transition`; single validation choke point | 4, 5 |
| Auto = sudo>doas; pkexec/Gui explicit | 4, 5 |
| Auth default Interactive; no controlling terminal → NoTty (`/dev/tty` `O_NONBLOCK` probe) | 5 (planner), 9 (probe) |
| Auth × backend × platform matrix (incl. Run0+Gui cell) | 5 |
| Error split: `Unsupported` (structural) vs `Elevation` (runtime, incl. `Untracked`, neutral Display) | 1, 5, 11, 13, 14 |
| POSIX backend-native argv (`--preserve-env`/`--setenv`, name validation, `--` terminator, run0 `--pipe`, abs argv[0]) | 7 |
| Non-destructive derived command (caller `Command` untouched; reuse never double-wraps) | 8 (`set_contain`), 11 |
| `Auth::Stdin` password written AFTER spawn (no pipe-buffer assumption); write errors propagated | 11 (pipe+PendingPassword), 15 (sync write), 16 (async write) |
| fd ≥ 3 elevated → Unsupported (POSIX + Windows) | 11 (posix), 13 (windows) |
| POSIX rewrite reuses existing spawn; `spawn_unelevated` core | 10, 11, 15 |
| Windows `ShellExecuteEx(runas)` reduced child; plan-first host seam; COM S_FALSE; lpDirectory; identity-from-handle; ERROR_CANCELLED→AuthDeclined | 14 |
| Non-blocking runas kill (kill/`teardown_on_drop`, honest error not a hang) sync+async | 14 (RawChild/ProcHandle/Child::drop), 16 (RawAsyncChild) |
| Windows capability matrix (all non-inherit slots + fd>=3 + env + contain → Unsupported; `OwnConsole`) | 13, 14 |
| run0 process model (explicit-only, `--pipe`, contain-reject, gated propagation test) | 4, 5, 7, 11, 17 |
| Detection tests (privilege-independent invariants) | 9, 12 |
| Live gated tier + ungated cross-process tty probes (stdin-redirection + setsid) | 17 |
| Async parity (builder, report, derived-command recursion, in-tokio Windows build, no `.await` for Stdin) | 16 |
| CI provisioning TODO | 18 |
| Branch/PR/CI workflow | 19 |
| zeroize dep; windows feature adds (SystemServices/Com/Registry/Shell/WindowsAndMessaging) | 2, 12 |

No spec section is unmapped.

**2. Placeholder scan:** No "TBD / similar to Task N / add error handling later" remain; every code step shows complete code. Three implementation seams are explicitly flagged (not hidden), all proven patterns in-repo: the `RawChild` import path + `HANDLE` cast shape (Task 14), the `identity::windows` `creation_token`/`ProcessId` field visibility (Task 12), and the async `RawAsyncChild` existing-field construction (Task 16). The `Auth::Stdin` password is fully delivered (post-spawn blocking write), not deferred.

**3. Type consistency (matches code + tests everywhere):**
- `Backend` (Auto/Run0/Sudo/Doas/Pkexec); `Auth` (Interactive/NonInteractive/Askpass/Stdin/Gui)
- `ElevatedStdio` (**Passthrough/OwnConsole** — `#[non_exhaustive]`); `ElevatedVia` (Wrapped(Backend)/WindowsUac/AlreadyElevated)
- `ElevationReport { via, stripped_env, stdio }`; `ElevationErrorKind` (BackendUnavailable/AuthFailed/AuthDeclined/NoTty/Untracked); `Privilege` (Unprivileged/Elevated)
- `Host { elevated, has_tty, available, os }`; `BackendSet { run0, sudo, doas, pkexec }` each `Option<PathBuf>`
- `Transition` (RunAsIs / ElevatePosix { backend, path, auth } / ElevateWindows { auth } / Reject { error })
- `ElevationRequest { enabled, backend, auth, sanitizer }`
- `build_argv(backend, backend_path, auth, program, args, env) -> Result<Vec<OsString>, Error>`
- `PosixRewrite { derived, report, password_write }`; `PendingPassword::write_after_spawn`; `rewrite` / `rewrite_with_host`
- `RunasOutcome { AlreadyElevated, Launched { proc, pid, id, report } }`; `launch_runas` / `launch_runas_with_host`; `spawn_elevated`
- `RawChild::new_runas` / `teardown_on_drop`; `ProcHandle::teardown_on_drop`; `RawAsyncChild::new_runas`
- `spawn_unelevated(cmd, kill_on_drop)`; `resolve_on_path` / `resolve_in_path_var`
- `Child::elevation` / `set_elevation` (sync + async); `controlling_terminal_present`; `integrity_level`; `windows_identity_from_handle`

All names are identical everywhere they appear.

**4. No forward references:** Windows detection (12), reject gate (13), and `spawn_elevated`/`launch_runas` + the RawChild/ProcHandle/Child::drop teardown (14) all land before the `spawn()` branch (15). `spawn_unelevated` (10) and POSIX `rewrite` (11) land before the same branch. The async branch (16) references only symbols from 11/14 plus its own `RawAsyncChild::new_runas`. `set_contain`/`set_input_argv`/`set_env_ops` (8) precede their sole consumer (11). `resolve_in_path_var` is defined and tested in the same task (9). Every task compiles on its target platform(s) at commit time.

