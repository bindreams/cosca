# Elevation (elevate-to-admin/root) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add cross-platform, DX-honest privilege elevation to the `subprocess` crate — a declarative `.elevate()` builder that wraps the CHILD (never the caller) via POSIX `sudo`/`run0`/`doas`/`pkexec` or Windows `ShellExecuteEx("runas")`, with a pure cross-OS planner, an env security boundary, and a queryable achieved-state report, in full sync + async parity.

**Architecture:** A pure `Host::plan(target, backend, auth) -> Transition` planner (plain data `Host`, no syscalls, cross-OS-testable) is the SINGLE validation choke point: it validates the whole Auth×backend×platform matrix BEFORE any already-elevated short-circuit, so verdicts never depend on ambient privilege. Two effect layers consume it and trust the transition: POSIX **rewrites** the `Command` into a backend invocation and reuses the existing spawn path unchanged; Windows is a **distinct** `ShellExecuteEx` spawn backend returning a reduced `Child` (wait/exit-code/kill only). Every capability gap is a loud `Error::Unsupported` (structural) or `Error::Elevation` (runtime), never a silent lie; the achieved disposition is reported via `Child::elevation() -> Option<ElevationReport>`, which is `Some(..)` iff elevation was REQUESTED.

**Tech Stack:** Rust 1.87 (edition 2021), `thiserror` 2, `log` 0.4, `shared_child` 1, `zeroize` 1 (new), `nix` 0.31 / `libc` 0.2 (POSIX detect + `/dev/tty` + `X_OK`), `windows` 0.62 (token + ShellExecuteEx + COM), `tokio` 1 (async, `tokio` feature). Reuses the crate's own `crate::quote::windows::join_wide` for Windows command-line construction and the raw-backend `RawChild`/`RawAsyncChild` handle wrappers.

## Global Constraints

- Rust edition 2021, `rust-version = "1.87"`. No new MSRV bump.
- Dependency versions (verbatim from `Cargo.toml`): `thiserror = "2"`, `shared_child = { version = "1", features = ["timeout"] }`, `log = "0.4"`, `tokio = { version = "1", optional = true, features = ["process","rt","io-util","macros","net","sync","time"] }`, `tempfile = "3"` (dev), `libc = "0.2"`, `nix = { version = "0.31", features = ["signal","process","event"] }` (UNCHANGED — the exec-bit check uses `libc::access(_, libc::X_OK)` and the tty probe uses `libc::open("/dev/tty")`), `windows = "0.62"`. NEW: `zeroize = "1"`.
- Module style: `foo.rs` + `foo/` subdir (NOT `mod.rs`). Unit tests in a SEPARATE sibling `foo_tests.rs`, included via `#[cfg(test)] #[path = "foo_tests.rs"] mod foo_tests;`. Debug asserts encouraged. `#[cfg(unix)]` / `#[cfg(windows)]` gating for platform effect code; pure code compiles everywhere.
- Async is gated behind the `tokio` feature; every async task's tests run under `--features tokio`.
- Builder methods are flat and return `&mut Command`, mirroring `.contain()` / `.contain_with()` / `.nesting()`.
- `Error::Unsupported` = "can never work on this platform"; `Error::Elevation` = "could work but failed now." Never conflate.
- `cargo clippy --all-targets --locked -- -D warnings` (prek.toml:26) is a hard gate on every commit: NO `dead_code`, NO `unused_mut`, NO unused imports may land. Each task must be clippy-clean on the platform(s) it compiles for.
- Live privilege-gain tests are gated behind `SUBPROCESS_TEST_ELEVATION`: a true no-op when the var is absent, and FAIL LOUDLY when it is set but elevation is unavailable (mirror `SUBPROCESS_TEST_CGROUP` in `tests/spawn_io.rs`). Pure argv/rewrite/planner tests are UNGATED and never shell out to a real backend.
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
| 9 POSIX detection | ✓ | ✓ | n/a (cfg(unix)) | `/dev/tty` + `X_OK` |
| 10 `spawn_unelevated` extraction | ✓ | ✓ | ✓ | pure refactor; full `cargo test --lib` regression |
| 11 POSIX effect rewrite + Child field | ✓ | ✓ | ✓ (Child field cross-platform; rewrite cfg(unix)) | |
| 12 Windows detection + integrity + deps + identity helper | ✓ (compiles; windows arms inert) | ✓ | ✓ | |
| 13 Windows reject gate | n/a arms | n/a arms | ✓ | |
| 14 Windows `launch_runas` + `spawn_elevated` | n/a arms | n/a arms | ✓ | |
| 15 `spawn()` elevation branch (fd-take reorder) | ✓ | ✓ | ✓ | references Tasks 11 + 14 — both already landed |
| 16 Async parity | ✓ | ✓ | ✓ | `--features tokio` |
| 17 Live gated tests + testbin | ✓ | ✓ | ✓ | ungated = no-op |
| 18 TODO.md | ✓ | ✓ | ✓ | docs |
| 19 PR + CI | — | — | — | workflow |

The one ordering rule the sequence enforces: nothing forward-references a later task. Windows detection (12), the reject gate (13), and the Windows `spawn_elevated` (14) all land BEFORE the `spawn()` branch (15) that calls them; the `spawn_unelevated` extraction (10) and POSIX `rewrite` (11) land before that same branch.

---

## File Structure

**Create:**
- `src/elevation.rs` — public surface: `is_elevated()`, enums (`Backend`, `Auth`, `ElevatedStdio`, `ElevatedVia`, `Privilege`), `Secret`, `ElevationReport`, crate-internal `ElevationRequest`, module wiring + re-exports.
- `src/elevation_tests.rs` — unit tests for the public surface (enum defaults, `Secret` redaction, `is_elevated` detection).
- `src/elevation/plan.rs` — PURE `Host` / `BackendSet` / `Os` / `Transition` + `Host::detect()` + `Host::plan()`.
- `src/elevation/plan_tests.rs` — cross-OS planner + full rejection-matrix tests (fake `Host` on any runner).
- `src/elevation/sanitize.rs` — `EnvSanitizer`, `DEFAULT_DENYLIST`, `apply()`.
- `src/elevation/sanitize_tests.rs` — denylist / keep / allowlist / filter / none tests.
- `src/elevation/posix.rs` — `#[cfg(unix)]`: `detect()`, `is_elevated()`, `controlling_terminal_present()`, pure `build_argv()`, `rewrite()` / `rewrite_with_host()`.
- `src/elevation/posix_tests.rs` — argv-construction + rewrite tests (no backend install needed).
- `src/elevation/windows.rs` — `#[cfg(windows)]`: `detect()`, `is_elevated()`, `integrity_level()`, `reject_unsupported_config()`, `launch_runas()`, `spawn_elevated()`.
- `src/elevation/windows_tests.rs` — detection + rejection tests (no UAC needed).
- `tests/elevation.rs` — gated live integration tests (sync + async).

**Modify:**
- `Cargo.toml` — add `zeroize = "1"`; extend `[target.'cfg(windows)'.dependencies] windows` feature list.
- `src/error.rs` (+ `src/error_tests.rs`) — add `ElevationErrorKind` and `Error::Elevation`.
- `src/lib.rs` — `pub mod elevation;`.
- `src/identity.rs` — `#[cfg(windows)] pub(crate) fn windows_identity_from_handle`.
- `src/command.rs` (+ `src/command_tests.rs`) — the four builder methods + `ElevationRequest` field + `elevation_request()` / `set_input_argv()` / `set_env_ops()`.
- `src/child.rs` — `elevation: Option<ElevationReport>` field, `set_elevation()`, `elevation()`.
- `src/child/spawn.rs` — extract `spawn_unelevated`; add the elevation branch to `spawn()`.
- `src/tokio/command.rs` — mirror the four builder methods.
- `src/tokio/child.rs` — `elevation` field + `set_elevation()` + `elevation()`.
- `src/tokio/spawn.rs` — async elevation branch.
- `testbin/main.rs` — `is-elevated-report`, `controlling-terminal`, and `write-marker` subcommands for live tests.
- `TODO.md` — CI provisioning note for the elevation live tier.

---

### Task 1: Elevation error taxonomy

**Files:**
- Modify: `src/error.rs`
- Test: `src/error_tests.rs`

**Interfaces:**
- Produces: `ElevationErrorKind::{BackendUnavailable, AuthFailed, AuthDeclined, NoTty, Untracked}` (Debug, Clone, Copy, PartialEq, Eq); `Error::Elevation { kind: ElevationErrorKind, detail: String }`.

`Untracked` covers the "runas succeeded but we could not resolve/manage the child" case (Task 14): auth SUCCEEDED, so it must not report as `AuthFailed`.

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib error_tests::elevation`
Expected: FAIL — `no variant named Elevation`, `no module ElevationErrorKind`.

- [ ] **Step 3: Write minimal implementation** — in `src/error.rs`, add the enum before `Error` and the variant inside `Error`:

```rust
/// Runtime elevation failures — "could work here but failed now" (contrast
/// [`Error::Unsupported`], which is "can never work on this platform").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ElevationErrorKind {
    /// The requested (or auto-detected) backend is not on PATH.
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
    /// manage it; the child was terminated rather than leaked.
    #[error("elevated child launched but could not be tracked; it was terminated")]
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

Run: `cargo test --lib error_tests::elevation`
Expected: PASS (2 tests).

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

`ElevatedStdio` is `{Passthrough, OwnConsole}` — the deferred broker (`Piped`) and a future `SW_HIDE` knob (`Hidden`) are non-breaking additions under `#[non_exhaustive]` (run0 may later need a pty-aware variant; `#[non_exhaustive]` covers it too). `ElevatedVia::WindowsUac` is a DEDICATED variant for Windows runas — it does NOT reuse `Backend::Auto`, which is a POSIX resolution concept and would misreport the Windows path.

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
    /// POSIX: the child's stdio is wired exactly as the `Command` configured it
    /// (`sudo`/`run0`/`doas`/`pkexec` pass fds straight through).
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
/// filled by `detect` (checking `X_OK`, skipping empty PATH elements) and faked
/// in tests. Carrying the ABSOLUTE path is what closes the CWD-hijack hole: the
/// validated path is exactly the one argv[0] emits.
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

> This happy-path form omits the Windows arm and the rejection matrix (Task 5) and stubs `detect` to route to `super::posix`/`super::windows` (Tasks 9/12). Until those land, the `#[cfg]` arms reference not-yet-existing modules on their platform; to keep THIS task self-compiling on all platforms, temporarily give `detect()` a self-contained body: `Host { elevated: false, has_tty: false, available: BackendSet::default(), os: if cfg!(windows) { Os::Windows } else { Os::Unix } }`. Tasks 9/12 restore the real dispatch. (The `plan_tests` never call `detect`.) Task 5 introduces `plan_windows`; the current `plan` calls only `resolve_posix`, so the Windows planner test in Step 1 (`windows_unprivileged_elevates_via_uac`) is written RED here and goes GREEN in Task 5 — mark it `#[ignore = "windows arm lands in Task 5"]` for this task and remove the attribute in Task 5.

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
- Produces: `plan()` validates the FULL Auth×backend×platform matrix BEFORE the already-elevated short-circuit; adds `plan_windows`, `structural_posix`, `structural_windows`; POSIX resolution now also enforces the Askpass/Stdin-needs-sudo and NoTty preconditions.

**The choke-point contract (spec "Auth × backend × platform validity"):**

`plan()` runs in this order:
1. `target != Elevated` → `RunAsIs` (not elevating — no validation needed).
2. **Structural validation** (privilege-independent, runs BEFORE the elevated short-circuit): impossible `(backend, auth)` combos → `Reject { Unsupported }`. This is what makes verdicts independent of ambient privilege.
3. **Already-elevated short-circuit**: structurally valid + `self.elevated` → `RunAsIs`.
4. **Resolution** (only when actually elevating): backend availability (`BackendUnavailable`), Auto→concrete, Askpass/Stdin-needs-sudo (`Unsupported`), and the `NoTty` precondition.

Structural rejections (step 2) — POSIX:
- `Gui` with any non-`Pkexec` backend → `Unsupported` (Gui is pkexec-only).
- `Pkexec` with any non-`Gui` auth → `Unsupported` (pkexec has no Interactive/NonInteractive/Askpass/Stdin form — including no non-interactive mode).
- `Askpass` with any backend other than `Sudo`/`Auto` → `Unsupported` (askpass is sudo-only).
- `Stdin` with any backend other than `Sudo`/`Auto` → `Unsupported` (feeding a password to a non-sudo target's stdin is a credential leak; doas has no `-S`).

Structural rejections (step 2) — Windows:
- `backend != Auto` → `Unsupported` (POSIX backends do not exist on Windows).
- `auth ∈ {NonInteractive, Askpass, Stdin}` → `Unsupported` (runas has no such mechanism; only `Interactive`/`Gui` reach the UAC gate).

Resolution rejections (step 4) — POSIX:
- `Auto` resolving to a non-`Sudo` backend while `auth ∈ {Askpass, Stdin}` → `Unsupported`.
- `Interactive && !has_tty` → `Elevation { NoTty }`.

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

// ---- Structural verdicts are IDENTICAL regardless of ambient privilege ----

#[test]
fn structural_posix_matrix_is_privilege_independent() {
    // (backend, auth) combos that can NEVER work — verdict must not depend on `elevated`.
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
        // wrong-platform backend
        assert!(is_unsupported(win_host(elevated).plan(Privilege::Elevated, Backend::Sudo, Auth::Interactive)));
        // runas has no non-interactive / askpass / stdin mechanism
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

// ---- Preconditions depend on environment (correctly) ----

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
    // Only doas present; Auto -> doas; Stdin needs sudo -> Unsupported at resolution.
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

Add `use std::path::PathBuf;` to `plan_tests.rs` if not already present.

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
        // Structurally valid and already elevated: no wrapper needed.
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
        // Askpass/Stdin are sudo-only; Auto may have resolved to doas.
        if resolved != Backend::Sudo && matches!(auth, Auth::Askpass(_) | Auth::Stdin(_)) {
            return Transition::Reject {
                error: Error::Unsupported {
                    op: format!("{resolved:?} + {}", if matches!(auth, Auth::Askpass(_)) { "Askpass" } else { "Stdin" }),
                    platform: "unix",
                    detail: "Askpass and Stdin auth are sudo-only; Backend::Auto resolved to a non-sudo backend".into(),
                },
            };
        }
        // Interactive prompting needs a controlling terminal.
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
    // Gui is pkexec-only.
    if matches!(auth, Auth::Gui) && backend != Backend::Pkexec {
        return unsupported(
            format!("{backend:?} + Auth::Gui"),
            "graphical (Gui) auth is only available through Backend::Pkexec",
        );
    }
    // pkexec has no non-graphical auth form (no Interactive/NonInteractive/Askpass/Stdin).
    if backend == Backend::Pkexec && !matches!(auth, Auth::Gui) {
        return unsupported(
            "pkexec + non-Gui auth".into(),
            "pkexec is the graphical backend; pair it with Auth::Gui",
        );
    }
    // Askpass is sudo-only (explicit non-sudo backends fail here; Auto is checked at resolution).
    if matches!(auth, Auth::Askpass(_)) && !matches!(backend, Backend::Sudo | Backend::Auto) {
        return unsupported(
            format!("{backend:?} + Askpass"),
            "askpass auth is sudo-only; run0/doas/pkexec have no askpass mechanism",
        );
    }
    // Stdin is sudo-only (feeding a password to a non-sudo target's stdin is a credential leak).
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

**`keep` is additive WITHIN the current policy — never a silent downgrade.** On a denylist it adds holes; on an allowlist it WIDENS the allowlist; on a filter it wraps the closure to also keep the named keys; on `none` it is a no-op (everything already kept). It must NEVER convert a fail-closed `allowlist(…)` into a fail-open denylist.

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
    // The paranoid choice (fail-closed allowlist) must STAY fail-closed after keep().
    let s = EnvSanitizer::allowlist(["PATH"]).keep(["LANG"]);
    let (kept, stripped) = s.apply(env(&[("PATH", "/b"), ("LANG", "C"), ("MY_APP_CONFIG", "x")]));
    assert_eq!(keys(&kept), vec!["LANG", "PATH"]);
    // MY_APP_CONFIG is still stripped — keep widened the allowlist, it did not open a denylist.
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

> Kept/stripped order in these asserts is sorted-by-key: `apply` sorts its output for deterministic argv construction downstream.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib sanitize_tests`
Expected: FAIL — the stub `EnvSanitizer` has no `keep`/`filter`/`allowlist`/`none`/`apply`.

- [ ] **Step 3: Write minimal implementation** — replace the stub `src/elevation/sanitize.rs`:

```rust
//! The env consent gradient (layer 2): a denylist over the vars the user
//! *deliberately* forwards past the backend's env_reset scrub.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

/// Loader/injection footguns that `sudo env K=V prog` would otherwise re-inject
/// past `ld.so`'s setuid scrub. Prefix families are matched in [`is_denied`].
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
    /// Denylist: adds holes. Allowlist: widens it. Filter: also keeps these keys.
    /// None: no-op (everything is already kept).
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
            Policy::Filter(f) => {
                Policy::Filter(Box::new(move |k, v| extra.contains(k) || f(k, v)))
            }
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

### Task 7: POSIX argv construction (pure, backend-path-injected)

**Files:**
- Create: `src/elevation/posix.rs`, `src/elevation/posix_tests.rs`
- Modify: `src/elevation.rs` (declare `#[cfg(unix)] pub mod posix;`)

**Interfaces:**
- Consumes: `super::{Auth, Backend}`.
- Produces: `pub(crate) fn build_argv(backend: Backend, backend_path: &OsStr, auth: &Auth, program: &OsStr, args: &[OsString], env: &[(OsString, OsString)]) -> Vec<OsString>` — the full elevated argv. **argv[0] is the injected RESOLVED ABSOLUTE `backend_path`**, so the validated path is exactly what execs (no re-resolution, no CWD hijack). Pure — no installed backend required, injection makes it fully testable.

**Argv rules (spec + findings):**
- argv[0] = `backend_path` (absolute).
- Per-backend auth flags: `Sudo` → `-n`/`-S`/`-A` (NonInteractive/Stdin/Askpass); `Doas` → `-n` (NonInteractive); `Run0` → `--no-ask-password` (NonInteractive). Structurally-invalid combos never reach here (the planner rejected them).
- **NO `--preserve-env`** (dropped: `env K=V prog` already sets vars after the backend's scrub; the flag is redundant and its comma-join is lossy for keys with commas / non-UTF8).
- Explicit env is threaded as `env K=V …` (sudo/doas/pkexec) or `--setenv=K=V` (run0).
- `run0` forces `--pipe` (honest `Passthrough`, not a silent pty merge).
- A **`--` terminator** precedes the program on every backend, so a program path containing `=` is not swallowed as an assignment and a `-`-leading program is not parsed as a flag.
- `Backend::Auto` is `unreachable!()` — the planner resolves it before rewrite ever calls `build_argv`.

> Empirical follow-up (not a blocker): whether `env` still disambiguates a `=`-containing program path despite the `--` terminator is pinned in the WSL/Linux live run (Task 17). The `--` is the correct, standard fix; the live run confirms the corner case.

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
fn sudo_noninteractive_threads_env_after_flag_with_terminator() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::NonInteractive,
        OsStr::new("/usr/bin/systemctl"),
        &s(&["restart", "nginx"]),
        &env(&[("FOO", "bar")]),
    );
    assert_eq!(
        argv,
        s(&["/usr/bin/sudo", "-n", "env", "FOO=bar", "--", "/usr/bin/systemctl", "restart", "nginx"])
    );
}

#[test]
fn sudo_interactive_has_no_auth_flag() {
    let argv = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::Interactive, OsStr::new("id"), &s(&["-u"]), &[]);
    assert_eq!(argv, s(&["/usr/bin/sudo", "env", "--", "id", "-u"]));
}

#[test]
fn sudo_stdin_uses_dash_s() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::Stdin(crate::elevation::Secret::new("pw")),
        OsStr::new("id"),
        &[],
        &[],
    );
    assert_eq!(argv, s(&["/usr/bin/sudo", "-S", "env", "--", "id"]));
}

#[test]
fn sudo_askpass_uses_dash_a() {
    let argv = build_argv(
        Backend::Sudo,
        OsStr::new("/usr/bin/sudo"),
        &Auth::Askpass("/usr/bin/ssh-askpass".into()),
        OsStr::new("id"),
        &[],
        &[],
    );
    assert_eq!(argv, s(&["/usr/bin/sudo", "-A", "env", "--", "id"]));
}

#[test]
fn doas_noninteractive_emits_dash_n() {
    let argv = build_argv(Backend::Doas, OsStr::new("/usr/bin/doas"), &Auth::NonInteractive, OsStr::new("id"), &s(&["-u"]), &env(&[("A", "1")]));
    assert_eq!(argv, s(&["/usr/bin/doas", "-n", "env", "A=1", "--", "id", "-u"]));
}

#[test]
fn run0_forces_pipe_and_emits_no_ask_password() {
    let argv = build_argv(Backend::Run0, OsStr::new("/usr/bin/run0"), &Auth::NonInteractive, OsStr::new("id"), &[], &env(&[("A", "1"), ("B", "2")]));
    assert_eq!(argv, s(&["/usr/bin/run0", "--pipe", "--no-ask-password", "--setenv=A=1", "--setenv=B=2", "--", "id"]));
}

#[test]
fn pkexec_gui_prefixes_env() {
    let argv = build_argv(Backend::Pkexec, OsStr::new("/usr/bin/pkexec"), &Auth::Gui, OsStr::new("id"), &[], &env(&[("A", "1")]));
    assert_eq!(argv, s(&["/usr/bin/pkexec", "env", "A=1", "--", "id"]));
}

#[test]
fn terminator_protects_a_program_with_equals_or_leading_dash() {
    let eq = build_argv(Backend::Sudo, OsStr::new("/usr/bin/sudo"), &Auth::NonInteractive, OsStr::new("/opt/we=ird"), &[], &[]);
    assert_eq!(eq, s(&["/usr/bin/sudo", "-n", "env", "--", "/opt/we=ird"]));
    let dash = build_argv(Backend::Doas, OsStr::new("/usr/bin/doas"), &Auth::Interactive, OsStr::new("-prog"), &[], &[]);
    assert_eq!(dash, s(&["/usr/bin/doas", "env", "--", "-prog"]));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation::posix` (Unix runner)
Expected: FAIL — module `posix` / `build_argv` not found.

- [ ] **Step 3: Write minimal implementation** — create `src/elevation/posix.rs`:

```rust
//! POSIX elevation effect layer (`cfg(unix)`): backend detection, pure argv
//! construction, command rewrite, and the controlling-terminal probe.

use std::ffi::{OsStr, OsString};

use super::{Auth, Backend};

/// `K=V` as an `OsString`.
fn kv(k: &OsStr, v: &OsStr) -> OsString {
    let mut s = k.to_os_string();
    s.push("=");
    s.push(v);
    s
}

/// Build the full elevated argv. argv[0] is the injected ABSOLUTE `backend_path`
/// (the validated path is exactly what execs). `env` MUST be pre-sanitized and
/// sorted (see [`super::sanitize::EnvSanitizer::apply`]). Pure — no installed
/// backend required.
pub(crate) fn build_argv(
    backend: Backend,
    backend_path: &OsStr,
    auth: &Auth,
    program: &OsStr,
    args: &[OsString],
    env: &[(OsString, OsString)],
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![backend_path.to_os_string()];
    match backend {
        Backend::Sudo => {
            match auth {
                Auth::NonInteractive => argv.push("-n".into()),
                Auth::Stdin(_) => argv.push("-S".into()),
                Auth::Askpass(_) => argv.push("-A".into()),
                Auth::Interactive | Auth::Gui => {}
            }
            argv.push("env".into());
            for (k, v) in env {
                argv.push(kv(k, v));
            }
        }
        Backend::Doas => {
            if matches!(auth, Auth::NonInteractive) {
                argv.push("-n".into());
            }
            argv.push("env".into());
            for (k, v) in env {
                argv.push(kv(k, v));
            }
        }
        Backend::Pkexec => {
            argv.push("env".into());
            for (k, v) in env {
                argv.push(kv(k, v));
            }
        }
        Backend::Run0 => {
            argv.push("--pipe".into());
            if matches!(auth, Auth::NonInteractive) {
                argv.push("--no-ask-password".into());
            }
            for (k, v) in env {
                let mut a = OsString::from("--setenv=");
                a.push(kv(k, v));
                argv.push(a);
            }
        }
        Backend::Auto => unreachable!("build_argv received unresolved Backend::Auto; the planner resolves Auto"),
    }
    // Terminate option/assignment parsing before the program.
    argv.push("--".into());
    argv.push(program.to_os_string());
    argv.extend(args.iter().cloned());
    argv
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
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation.rs src/elevation/posix.rs src/elevation/posix_tests.rs
git commit -m "feat: pure POSIX elevated-argv construction (abs path, -- terminator, run0 --pipe)"
```

---

### Task 8: `Command` builder methods

**Files:**
- Modify: `src/command.rs`, `src/command_tests.rs`

**Interfaces:**
- Consumes: `crate::elevation::{Auth, Backend, ElevationRequest, EnvSanitizer}`.
- Produces on `Command`: `.elevate()`, `.elevation_backend(Backend)`, `.elevation_auth(Auth)`, `.sanitize_env(EnvSanitizer)` (each returns `&mut Command` and sets `enabled = true`); `pub(crate) fn elevation_request(&self) -> &ElevationRequest`, `pub(crate) fn set_input_argv(&mut self, argv: Vec<OsString>)`, `pub(crate) fn set_env_ops(&mut self, ops: Vec<EnvOp>)`.

`set_input_argv` replaces `input` and clears `executable` (the rewritten argv is self-contained). `set_env_ops` replaces the recorded env ops (used by the POSIX rewrite to honor `.env_clear()` intent and carry `SUDO_ASKPASS`).

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib command_tests::elev`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/command.rs src/command_tests.rs
git commit -m "feat: Command elevation builder methods and rewrite mutators"
```

---

### Task 9: POSIX detection (`detect` / `is_elevated` / `controlling_terminal_present`)

**Files:**
- Modify: `src/elevation/posix.rs`, `src/elevation.rs`, `src/elevation_tests.rs`, `src/elevation/plan.rs`

**Interfaces:**
- Produces: `#[cfg(unix)] pub(super) fn detect() -> Host`; `#[cfg(unix)] pub(super) fn is_elevated() -> bool`; `#[doc(hidden)] pub fn controlling_terminal_present() -> bool`; the public `crate::elevation::is_elevated() -> bool` dispatcher (Unix arm now real).

**Two correctness fixes:**
- Backend availability records the RESOLVED ABSOLUTE path, checking `X_OK` via `libc::access` (not `is_file()`, which ignores the exec bit), and SKIPS empty PATH elements (an empty element means CWD — never resolve a backend from CWD).
- `has_tty` probes the **controlling terminal** via `libc::open("/dev/tty", O_RDWR|O_CLOEXEC)` then close — NOT `isatty(STDIN)`, which is wrong for a redirected-stdin pipeline (false negative) and for a post-`setsid` process (false positive). The probe is exposed as `#[doc(hidden)] pub fn controlling_terminal_present()` so the `setsid` negative case is cross-process testable (Task 17).

- [ ] **Step 1: Write the failing test** — append to `src/elevation_tests.rs`:

```rust
#[test]
fn is_elevated_is_false_in_the_unprivileged_test_process() {
    if std::env::var_os("SUBPROCESS_TEST_ELEVATION").is_some() {
        return; // an elevated live runner may legitimately be root/admin.
    }
    assert!(!super::is_elevated(), "unprivileged test process reported elevated");
}

#[cfg(unix)]
#[test]
fn detect_reports_unix_os() {
    let h = super::plan::Host::detect();
    assert_eq!(h.os, super::plan::Os::Unix);
}

#[cfg(unix)]
#[test]
fn controlling_terminal_probe_is_stable_across_stdin_redirection() {
    // The probe answers "does this session have a controlling terminal?", which does
    // not change when stdin is a pipe. We cannot assert its absolute value (CI may have
    // no controlling terminal), but redirecting stdin must not flip it.
    let before = super::posix::controlling_terminal_present();
    let _redirect = std::fs::File::open("/dev/null").unwrap();
    let after = super::posix::controlling_terminal_present();
    assert_eq!(before, after);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation_tests`
Expected: FAIL — `is_elevated` / `controlling_terminal_present` not found.

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
/// fails once a process has none (e.g. after `setsid`). `isatty(stdin)` answers a
/// different question and is wrong for both cases.
#[doc(hidden)]
pub fn controlling_terminal_present() -> bool {
    // SAFETY: open/close of a fixed path; the fd is closed on the success path.
    unsafe {
        let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if fd < 0 {
            return false;
        }
        libc::close(fd);
        true
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: access with a valid NUL-terminated path; a read-only permission query.
    path.is_file() && unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

/// Resolve `program` to its ABSOLUTE path on PATH, checking the exec bit and
/// skipping empty PATH elements (an empty element is CWD — never resolve there).
fn resolve_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        if dir.as_os_str().is_empty() {
            return None;
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

In `src/elevation/plan.rs`, restore the real `detect()` dispatch (replacing the Task-4 self-contained stub) so `#[cfg(unix)]` routes to `super::posix::detect()` and `#[cfg(windows)]` to `super::windows::detect()` (the windows arm compiles once Task 12 lands; on a Unix build only the unix arm is active).

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

Run: `cargo test --lib elevation_tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/elevation.rs src/elevation/posix.rs src/elevation/plan.rs src/elevation_tests.rs
git commit -m "feat: POSIX detection (euid, /dev/tty probe, X_OK absolute-path backend resolution)"
```

---

### Task 10: Extract `spawn_unelevated` (pure refactor, its own TDD step)

**Files:**
- Modify: `src/child/spawn.rs`

**Interfaces:**
- Produces: `pub(crate) fn spawn_unelevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, Error>` — the non-elevated spawn core (everything from `std::mem::take(cmd.fds_mut())` onward). `spawn()` becomes a thin wrapper. This lands BEFORE any elevation branch so Task 15's `spawn()` branch and Task 14's Windows already-elevated arm can both re-enter the normal spawn path without re-entering the elevation branch.

This is a pure refactor: no behavior change. Its regression guard is a FULL `cargo test --lib` run, not just elevation tests.

**Concrete before/after of `spawn()` (`src/child/spawn.rs`, current lines 22–24 and the trailing `Ok`):**

Before:
```rust
pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let fds = std::mem::take(cmd.fds_mut());
    let kill_on_drop = cmd.kill_on_drop_flag();

    // Windows routing. ...
    #[cfg(windows)]
    { /* ... */ }
    let mut std_cmd = build_std_command(cmd)?;
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
/// already-elevated / post-rewrite continuations (which must spawn without
/// re-entering the elevation branch).
pub(crate) fn spawn_unelevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, Error> {
    let fds = std::mem::take(cmd.fds_mut());

    // Windows routing. ...  (unchanged body, verbatim)
    #[cfg(windows)]
    { /* ... */ }
    let mut std_cmd = build_std_command(cmd)?;
    // ... entire body, verbatim ...
    Ok(Child::from_parts(
        ProcHandle::Std(shared), id, parent_ends, kill_on_drop, containment, attached,
    ))
}
```

Only two edits: (1) move `let kill_on_drop = cmd.kill_on_drop_flag();` up into `spawn()` and pass it in; (2) rename the old function body to `spawn_unelevated` and give `spawn()` the two-line wrapper. The `let fds = std::mem::take(...)` line moves into `spawn_unelevated` unchanged.

- [ ] **Step 1: Write the failing test** — the refactor is behavior-preserving; the guard is the EXISTING suite plus one explicit assertion that `spawn_unelevated` is the path `spawn` takes. Append to `src/child/spawn_tests.rs`:

```rust
#[test]
fn spawn_unelevated_runs_a_plain_child() {
    // spawn_unelevated is the non-elevated core; a trivial child must run through it.
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
Expected: PASS (entire library suite — this is the refactor's regression gate, not just the new test).

- [ ] **Step 5: Commit**

```bash
git add src/child/spawn.rs src/child/spawn_tests.rs
git commit -m "refactor: extract spawn_unelevated as the shared non-elevated spawn core"
```

---

### Task 11: POSIX effect integration — `rewrite` + `Child::elevation()`

**Files:**
- Modify: `src/elevation/posix.rs`, `src/child.rs`, `src/elevation/posix_tests.rs`

**Interfaces:**
- Produces:
  - `pub(crate) struct PosixRewrite { report: Option<ElevationReport> }`.
  - `#[cfg(unix)] pub(crate) fn rewrite(cmd: &mut Command) -> Result<PosixRewrite, Error>` = `rewrite_with_host(cmd, &Host::detect())`.
  - `#[cfg(unix)] pub(crate) fn rewrite_with_host(cmd, host: &Host) -> Result<PosixRewrite, Error>` — PURE given `host`, so argv/rewrite is testable WITHOUT a real backend (inject a fake-path `Host`; no silent skip).
  - On `Child`: `pub(crate) fn set_elevation(&mut self, r: Option<ElevationReport>)`, `pub fn elevation(&self) -> Option<ElevationReport>`.

**What `rewrite_with_host` does (findings woven in):**
- `RunAsIs` when requested → `report: Some(via: AlreadyElevated)` — a genuinely-elevated child is NEVER mis-reported as un-elevated (`Child::elevation()` is `Some` iff requested).
- `Reject { error }` → propagate.
- `ElevatePosix { backend, path, auth }`:
  - `Backend::Run0` + `.contain()` → `Error::Unsupported` (unit lives in its own scope cgroup).
  - `program_and_args` honors `executable_path()` as the program and keeps `executable` intact; a caller argv[0] distinct from `executable()` that the backend cannot preserve → `Error::Unsupported`.
  - `commandline()` (non-argv) elevated command → `Error::Unsupported`.
  - Sanitize the explicit env (`.env()` Set/Remove/Clear honored), thread via `build_argv` with the injected absolute `path`.
  - `Auth::Stdin` → the password is delivered NOW via a blocking write to a std pipe whose read end becomes fd0 (no post-spawn write, no `.await`). A caller-configured fd0 → `Error::Unsupported` (Stdin consumes fd0). Write errors are logged at debug and propagated as `Error::Elevation`.
  - `.env_clear()` intent is preserved: the rewritten backend command's env ops start with `Clear` if the user cleared, so the backend process itself starts from an empty environment.
  - `Auth::Askpass(path)` → `SUDO_ASKPASS=path` is set on the backend process env (survives the rewrite).
  - Report `via: Wrapped(backend)`, `stdio: Passthrough`.

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

    fn argv(c: &Command) -> Vec<OsString> {
        match c.input() {
            CommandInput::Argv(v) => v.clone(),
            other => panic!("expected Argv, got {other:?}"),
        }
    }

    #[test]
    fn rewrite_is_pure_and_reports_wrapped_backend() {
        let mut c = Command::new();
        c.args(["id", "-u"])
            .env("LD_PRELOAD", "/evil.so")
            .env("FOO", "bar")
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        let out = super::rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        let report = out.report.expect("report");
        assert_eq!(report.via, ElevatedVia::Wrapped(Backend::Sudo));
        assert_eq!(report.stripped_env, vec![OsString::from("LD_PRELOAD")]);
        let a = argv(&c);
        assert_eq!(a[0], OsString::from("/usr/bin/sudo"));
        assert!(a.contains(&OsString::from("FOO=bar")));
        assert!(!a.iter().any(|x| x.to_string_lossy().contains("LD_PRELOAD")));
    }

    #[test]
    fn env_clear_intent_is_preserved_on_the_backend() {
        let mut c = Command::new();
        c.args(["id"]).env_clear().env("KEEP", "1").elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        super::rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        // The backend process starts from an empty env; KEEP reaches the target via `env KEEP=1`.
        assert!(c.env_ops().iter().any(|o| matches!(o, EnvOp::Clear)));
        assert!(argv(&c).contains(&OsString::from("KEEP=1")));
    }

    #[test]
    fn set_then_remove_and_set_then_clear_thread_correctly() {
        let mut c = Command::new();
        c.args(["id"]).env("A", "1").env("B", "2").env_remove("A")
            .elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        super::rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        let a = argv(&c);
        assert!(a.contains(&OsString::from("B=2")));
        assert!(!a.iter().any(|x| *x == OsString::from("A=1")));

        let mut c2 = Command::new();
        c2.args(["id"]).env("A", "1").env_clear().env("C", "3")
            .elevation_backend(Backend::Sudo).elevation_auth(Auth::NonInteractive);
        super::rewrite_with_host(&mut c2, &sudo_host()).expect("rewrite");
        let a2 = argv(&c2);
        assert!(a2.contains(&OsString::from("C=3")));
        assert!(!a2.iter().any(|x| *x == OsString::from("A=1")));
    }

    #[test]
    fn askpass_path_is_carried_in_the_backend_env() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Askpass(PathBuf::from("/usr/bin/ssh-askpass")));
        super::rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        assert!(c.env_ops().iter().any(|o| matches!(o, EnvOp::Set(k, v) if k == "SUDO_ASKPASS" && v == "/usr/bin/ssh-askpass")));
    }

    #[test]
    fn stdin_auth_injects_a_stdin_pipe_and_consumes_fd0() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Stdin(crate::elevation::Secret::new("pw")));
        super::rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
        assert!(matches!(c.fds().get(&Fd::STDIN), Some(ResolvedStdio::Pipe(_))), "Auth::Stdin must wire fd0 to a pipe");
    }

    #[test]
    fn stdin_auth_with_caller_configured_fd0_is_unsupported() {
        let mut c = Command::new();
        c.args(["id"]).elevation_backend(Backend::Sudo).elevation_auth(Auth::Stdin(crate::elevation::Secret::new("pw")));
        c.stdin(Stdio::pipe()).unwrap();
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
        // argv[0]="sh" != executable "/bin/busybox" cannot survive the backend+env wrapper.
        assert!(matches!(super::rewrite_with_host(&mut c, &sudo_host()), Err(Error::Unsupported { .. })));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation::posix::posix_tests::rewrite_tests`
Expected: FAIL — `rewrite_with_host` not found.

- [ ] **Step 3: Write minimal implementation** — append to `src/elevation/posix.rs`:

```rust
use zeroize::Zeroize;

use crate::command::{Command, CommandInput, EnvOp};
use crate::elevation::plan::{Host, Transition};
use crate::elevation::{ElevatedStdio, ElevatedVia, ElevationReport, Privilege, Secret};
use crate::error::{ElevationErrorKind, Error};
use crate::stdio::{Fd, Stdio};

/// Outcome of a POSIX rewrite: the report to attach (`Some` iff elevation was requested).
pub(crate) struct PosixRewrite {
    pub report: Option<ElevationReport>,
}

/// Collect the explicitly-set env into an ordered (k,v) list, honoring later
/// `Remove`/`Clear` ops. Only surviving `Set` values remain.
fn explicit_env(ops: &[EnvOp]) -> Vec<(OsString, OsString)> {
    let mut map: std::collections::BTreeMap<OsString, OsString> = std::collections::BTreeMap::new();
    for op in ops {
        match op {
            EnvOp::Set(k, v) => {
                map.insert(k.clone(), v.clone());
            }
            EnvOp::Remove(k) => {
                map.remove(k);
            }
            EnvOp::Clear => map.clear(),
        }
    }
    map.into_iter().collect()
}

/// Program + args, honoring `executable()`. argv[0] distinct from a set
/// `executable()` cannot survive the backend+env wrapper → `Unsupported`.
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

/// Deliver the `Auth::Stdin` password to a fresh std pipe whose read end becomes
/// fd0. The blocking write happens NOW (before spawn), so no `.await` is needed
/// and no post-spawn writer is required. The password line fits the pipe buffer,
/// so the write completes without a reader.
fn deliver_password_to_stdin(cmd: &mut Command, secret: &Secret) -> Result<(), Error> {
    use std::io::Write;
    if cmd.fds().contains_key(&Fd::STDIN) {
        return Err(Error::Unsupported {
            op: "Auth::Stdin with a caller-configured stdin".into(),
            platform: "unix",
            detail: "Auth::Stdin consumes fd0 to feed sudo -S the password; do not also configure stdin".into(),
        });
    }
    let (reader, mut writer) = std::io::pipe().map_err(Error::Io)?;
    let mut bytes = secret.expose().to_vec();
    bytes.push(b'\n');
    let write = writer.write_all(&bytes);
    bytes.zeroize();
    if let Err(e) = write {
        log::debug!("failed to write the elevation password to the stdin pipe: {e}");
        return Err(Error::Elevation {
            kind: ElevationErrorKind::AuthFailed,
            detail: format!("could not deliver the sudo -S password: {e}"),
        });
    }
    drop(writer); // EOF after the password line
    let file = std::fs::File::from(std::os::unix::io::OwnedFd::from(reader));
    cmd.stdin(Stdio::from_file(file))?;
    Ok(())
}

/// Detect-then-plan-then-rewrite in place. Thin wrapper over the pure form.
pub(crate) fn rewrite(cmd: &mut Command) -> Result<PosixRewrite, Error> {
    rewrite_with_host(cmd, &Host::detect())
}

/// PURE given `host`: plan + sanitize + rewrite `cmd` into a backend invocation.
/// Testable without an installed backend (inject a fake-path `Host`).
pub(crate) fn rewrite_with_host(cmd: &mut Command, host: &Host) -> Result<PosixRewrite, Error> {
    let req = cmd.elevation_request();
    let (backend, path, auth) = match host.plan(Privilege::Elevated, req.backend, req.auth.clone()) {
        Transition::RunAsIs => {
            // Requested but already elevated — no wrapper, but still reported.
            return Ok(PosixRewrite {
                report: Some(ElevationReport {
                    via: ElevatedVia::AlreadyElevated,
                    stripped_env: Vec::new(),
                    stdio: ElevatedStdio::Passthrough,
                }),
            });
        }
        Transition::Reject { error } => return Err(error),
        Transition::ElevateWindows { .. } => {
            return Err(Error::Elevation {
                kind: ElevationErrorKind::BackendUnavailable,
                detail: "internal: Windows transition on a POSIX host".into(),
            })
        }
        Transition::ElevatePosix { backend, path, auth } => (backend, path, auth),
    };

    if backend == Backend::Run0 && cmd.contain_request().mode.is_some() {
        return Err(Error::Unsupported {
            op: ".contain() + Backend::Run0".into(),
            platform: "unix",
            detail: "run0 runs the target as a PID 1-parented transient unit outside our cgroup; containment cannot span it".into(),
        });
    }

    let (program, args) = program_and_args(cmd)?;
    let ops = cmd.env_ops();
    let had_clear = ops.iter().any(|o| matches!(o, EnvOp::Clear));
    let (kept, stripped) = req.sanitizer.apply(explicit_env(ops));
    let argv = build_argv(backend, path.as_os_str(), &auth, &program, &args, &kept);

    if let Auth::Stdin(secret) = &auth {
        deliver_password_to_stdin(cmd, secret)?;
    }

    // Rebuild the backend process env: honor .env_clear() (start empty), carry SUDO_ASKPASS.
    let mut new_ops: Vec<EnvOp> = Vec::new();
    if had_clear {
        new_ops.push(EnvOp::Clear);
    }
    if let Auth::Askpass(p) = &auth {
        new_ops.push(EnvOp::Set(OsString::from("SUDO_ASKPASS"), p.as_os_str().to_os_string()));
    }

    cmd.set_input_argv(argv);
    cmd.set_env_ops(new_ops);
    Ok(PosixRewrite {
        report: Some(ElevationReport {
            via: ElevatedVia::Wrapped(backend),
            stripped_env: stripped,
            stdio: ElevatedStdio::Passthrough,
        }),
    })
}
```

Note: `use super::{Auth, Backend};` at the top of `posix.rs` already imports `Auth`/`Backend`; the new block references `Backend::Run0` etc. via that import.

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
git commit -m "feat: POSIX elevation rewrite (pure host-injectable) + Child::elevation report"
```

---

### Task 12: Windows detection + integrity + deps + identity-from-handle helper

**Files:**
- Modify: `Cargo.toml`, `src/elevation.rs`, `src/identity.rs`
- Create: `src/elevation/windows.rs`, `src/elevation/windows_tests.rs`

**Interfaces:**
- Produces: `#[cfg(windows)] pub(super) fn detect() -> Host`; `#[cfg(windows)] pub(super) fn is_elevated() -> bool`; `#[cfg(windows)] pub(super) fn integrity_level() -> Option<u32>` (the integrity RID; USED by `detect` for a debug log AND asserted below-High in tests, so never dead code); `#[cfg(windows)] pub(crate) fn crate::identity::windows_identity_from_handle(handle, pid) -> Option<ProcessId>`.

**Two correctness fixes baked in:**
- `TOKEN_MANDATORY_LABEL` is read from an 8-byte-ALIGNED buffer (`Vec<u64>`), and the `Sid` pointer field is read via `addr_of!` + `read_unaligned` — never forming a misaligned reference (the aarch64-windows CI leg would UB on a `Vec<u8>` align-1 buffer).
- `integrity_level` is wired into `detect` (debug log) so it is not dead code under `-D warnings`.

Windows dep features: ADD `Win32_System_SystemServices` (integrity RID constants), `Win32_System_Com` (CoInitializeEx — Task 14), `Win32_UI_Shell` + `Win32_UI_WindowsAndMessaging` (ShellExecuteEx — Task 14). Keep the existing 7.

- [ ] **Step 1: Write the failing test** — create `src/elevation/windows_tests.rs`:

```rust
#[test]
fn unprivileged_process_is_not_elevated() {
    if std::env::var_os("SUBPROCESS_TEST_ELEVATION").is_some() {
        return; // a live elevated runner may be admin.
    }
    assert!(!super::is_elevated());
}

#[test]
fn detect_reports_windows_os() {
    let h = super::plan::Host::detect();
    assert_eq!(h.os, super::plan::Os::Windows);
}

#[test]
fn unprivileged_integrity_is_below_high() {
    if std::env::var_os("SUBPROCESS_TEST_ELEVATION").is_some() {
        return;
    }
    use windows::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
    if let Some(rid) = super::integrity_level() {
        assert!(rid < SECURITY_MANDATORY_HIGH_RID as u32, "unprivileged process integrity RID {rid} >= High");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (Windows runner): `cargo test --lib elevation::windows`
Expected: FAIL — module `windows` not found.

- [ ] **Step 3: Write minimal implementation**

In `Cargo.toml`, extend the windows feature list (add four features to the existing seven):

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
        ok && e.TokenIsElevated != 0
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
            return None;
        }
        let words = (ret as usize).div_ceil(8);
        let mut buf = vec![0u64; words];
        let cap = (words * 8) as u32;
        GetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            cap,
            &mut ret,
        )
        .ok()?;
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

In `src/identity.rs`, add the crate helper (deriving identity from an ALREADY-OPEN handle — no second `OpenProcess` that could fail):

```rust
/// Build a `ProcessId` from an already-open Windows process handle and its pid,
/// reusing the backend creation-token read. Avoids a second `OpenProcess` (which
/// can fail and would otherwise force dropping a live elevated child).
#[cfg(windows)]
pub(crate) fn windows_identity_from_handle(
    handle: windows::Win32::Foundation::HANDLE,
    pid: RawPid,
) -> Option<ProcessId> {
    let start = backend::creation_token(handle)?;
    Some(ProcessId { pid, start })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run (Windows): `cargo test --lib elevation::windows`
Expected: PASS (3 tests). Also `cargo clippy --all-targets --locked -- -D warnings` clean (integrity_level is used by detect).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/elevation.rs src/elevation/windows.rs src/elevation/windows_tests.rs src/identity.rs
git commit -m "feat: Windows elevation detection (aligned integrity read) + identity-from-handle helper"
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
    c.stdio(3, Stdio::pipe_out()).unwrap();
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

> Adjust `stdio(3, ...)` / `merge` / `stdio` to the crate's actual descriptor-setter names if they differ; the crate exposes `.stdio(fd, Stdio)` and `Stdio::merge`/`pipe_out` per `src/stdio.rs`.

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

### Task 14: Windows `launch_runas` + `spawn_elevated`

**Files:**
- Modify: `src/elevation/windows.rs`, `src/elevation/windows_tests.rs`

**Interfaces:**
- Produces:
  - `#[cfg(windows)] pub(crate) enum RunasOutcome { AlreadyElevated, Launched { proc: OwnedHandle, pid: u32, id: ProcessId, report: ElevationReport } }`.
  - `#[cfg(windows)] pub(crate) fn launch_runas(cmd: &mut Command) -> Result<RunasOutcome, Error>` — the shared prelude used by BOTH the sync `spawn_elevated` and the async path (Task 16), so async child construction can live inside `crate::tokio`.
  - `#[cfg(windows)] pub(crate) fn spawn_elevated(cmd: &mut Command, kill_on_drop: bool) -> Result<crate::child::Child, Error>`.

**Findings woven in:**
- **Plan FIRST, then gate.** `launch_runas` plans before touching the capability gate; `RunAsIs` returns `AlreadyElevated` with NO ShellExecuteEx restrictions. `reject_unsupported_config` runs only on the actual-elevate arm.
- **COM init.** `CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)` before `ShellExecuteExW` (per the ShellExecuteEx docs, which require COM initialized and note shell extensions may need STA). Tolerate `S_FALSE` (already inited, same mode) and `RPC_E_CHANGED_MODE` (already inited MTA); pair `CoUninitialize` only when WE initialized (`S_OK`).
- **`nShow` type.** `SW_SHOWNORMAL.0` is `u32` (`SHOW_WINDOW_CMD`) but `SHELLEXECUTEINFOW::nShow` is `i32` in windows 0.62 → cast `as i32`.
- **`lpDirectory`** is set from `cmd.cwd()` (else the elevated child runs in System32).
- **argv[0]** distinct from a set `executable()` → `Unsupported` (runas cannot set an independent argv[0]).
- **Identity from the OWNED handle.** `GetProcessId(handle)` + `crate::identity::windows_identity_from_handle` — no second `OpenProcess`. If identity is still unobtainable, the child is TERMINATED (auth SUCCEEDED, so not leaked) and the error is `Untracked`, not `AuthFailed`.
- **RunAsIs report.** The already-elevated arm attaches `via: AlreadyElevated` so a genuinely-elevated child is reported, not `None`.
- **`ERROR_CANCELLED`** (UAC declined) → `AuthDeclined`.

- [ ] **Step 1: Write the failing test** — append to `src/elevation/windows_tests.rs` (live launch is gated to Task 17; here assert the gate runs before UAC):

```rust
#[test]
fn spawn_elevated_rejects_bad_config_before_any_prompt() {
    // Must fail with Unsupported and never prompt — the gate runs before ShellExecuteEx.
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(Stdio::pipe()).unwrap();
    assert!(is_unsupported(super::spawn_elevated(&mut c, true)));
}

#[test]
fn commandline_elevated_is_unsupported_on_windows() {
    let mut c = Command::new();
    c.commandline("whoami").elevate();
    assert!(is_unsupported(super::spawn_elevated(&mut c, true)));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (Windows): `cargo test --lib elevation::windows::windows_tests::spawn_elevated`
Expected: FAIL — `spawn_elevated` not found.

- [ ] **Step 3: Write minimal implementation** — append to `src/elevation/windows.rs`:

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
use crate::child::spawn::windows_raw::proc::RawChild;
use crate::command::{Command, CommandInput};
use crate::containment::{Attached, Containment};
use crate::elevation::plan::{Host, Transition};
use crate::elevation::{ElevatedStdio, ElevatedVia, ElevationReport, Privilege};
use crate::error::{ElevationErrorKind, Error};
use crate::identity::ProcessId;

/// `ERROR_CANCELLED` (1223) as an HRESULT (0x800704C7) — the UAC-declined code.
const ERROR_CANCELLED_HRESULT: windows::core::HRESULT = windows::core::HRESULT(0x800704C7_u32 as i32);

fn wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// The outcome of a runas launch. `Launched` carries the owned handle, pid, stable
/// identity, and the report — the async path (Task 16) builds its own `Child` from
/// these, so async child construction stays inside `crate::tokio`.
pub(crate) enum RunasOutcome {
    AlreadyElevated,
    Launched { proc: OwnedHandle, pid: u32, id: ProcessId, report: ElevationReport },
}

/// Balances a `CoInitializeEx` with `CoUninitialize` only when WE initialized.
struct ComInit {
    uninit: bool,
}
impl ComInit {
    fn init() -> Result<ComInit, Error> {
        // SAFETY: COM apartment init on the calling thread; balanced in Drop.
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        if hr == S_OK {
            Ok(ComInit { uninit: true })
        } else if hr == S_FALSE || hr == RPC_E_CHANGED_MODE {
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
            // SAFETY: balances our successful CoInitializeEx on this thread.
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
    // Plan FIRST — the capability gate applies only when we actually elevate.
    let req = cmd.elevation_request();
    let host = Host::detect();
    match host.plan(Privilege::Elevated, req.backend, req.auth.clone()) {
        Transition::RunAsIs => return Ok(RunasOutcome::AlreadyElevated),
        Transition::Reject { error } => return Err(error),
        Transition::ElevatePosix { .. } => {
            return Err(Error::Elevation {
                kind: ElevationErrorKind::BackendUnavailable,
                detail: "internal: POSIX transition on a Windows host".into(),
            })
        }
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
    let id = if pid != 0 { crate::identity::windows_identity_from_handle(handle, pid) } else { None };
    let Some(id) = id else {
        // Auth SUCCEEDED but we cannot track the child — terminate it, don't leak it.
        // SAFETY: `handle` is live; terminating our own launched child.
        unsafe { let _ = TerminateProcess(handle, 1); }
        return Err(Error::Elevation {
            kind: ElevationErrorKind::Untracked,
            detail: "the elevated child launched but its identity could not be resolved; it was terminated".into(),
        });
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
            let mut child = crate::child::Child::from_parts(
                ProcHandle::Raw(RawChild::new(proc, pid)),
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

> Implementation seams to confirm at code time (the pattern is proven in `src/child/spawn/windows_raw/proc.rs`): the exact module path of `RawChild` (`crate::child::spawn::windows_raw::proc::RawChild` — adjust if the raw backend re-exports it one level up) and the `HANDLE(*mut c_void)` shape (`HANDLE(proc.as_raw_handle())`). `Child::from_parts` is `pub(crate)` (verified in `src/child.rs`), so it is callable here.

- [ ] **Step 4: Run test to verify it passes**

Run (Windows): `cargo test --lib elevation::windows`
Expected: PASS. Also `cargo build --target x86_64-pc-windows-msvc` and `cargo clippy --all-targets --locked -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add src/elevation/windows.rs src/elevation/windows_tests.rs
git commit -m "feat: Windows ShellExecuteEx runas launch (plan-first, COM init, identity-from-handle)"
```

---

### Task 15: `spawn()` elevation branch (fd-take reorder)

**Files:**
- Modify: `src/child/spawn.rs`
- Test: `src/child/spawn_tests.rs`

**Interfaces:**
- Produces: `spawn()` now runs the elevation branch BEFORE `spawn_unelevated`'s `std::mem::take(cmd.fds_mut())`, so the effect layers see and mutate `cmd.fds()` while it is still populated. Both effect fns (`posix::rewrite`, Task 11; `windows::spawn_elevated`, Task 14) already exist — no forward reference.

**Why the reorder matters (S2):** if the branch ran after `mem::take`, the Windows reject gate would iterate an EMPTY `cmd.fds()` and pass vacuously (a silent lie — `.elevate().stdout(pipe())` would discard output), and the POSIX `Auth::Stdin` pipe injection would write into a map nobody reads. Running before `mem::take` fixes both.

- [ ] **Step 1: Write the failing test** — append to `src/child/spawn_tests.rs`:

```rust
#[cfg(windows)]
#[test]
fn elevated_pipe_is_unsupported_through_spawn() {
    // Integration through the real spawn entrypoint (not the effect fn directly):
    // the reject gate must see the piped slot, proving the branch runs before mem::take.
    let mut c = crate::command::Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(crate::stdio::Stdio::pipe()).unwrap();
    assert!(matches!(super::spawn(&mut c), Err(crate::error::Error::Unsupported { .. })));
}
```

(The POSIX "fds[STDIN] is a pipe after the branch" assertion is covered by `stdin_auth_injects_a_stdin_pipe_and_consumes_fd0` in Task 11, which exercises the same `rewrite` the branch calls.)

- [ ] **Step 2: Run test to verify it fails**

Run (Windows): `cargo test --lib spawn_tests::elevated_pipe_is_unsupported_through_spawn`
Expected: FAIL — `spawn` does not yet route elevated commands (it spawns `whoami` piped instead of rejecting).

- [ ] **Step 3: Write minimal implementation** — change `spawn()` in `src/child/spawn.rs` (post-Task-10 two-line wrapper) to:

```rust
pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let kill_on_drop = cmd.kill_on_drop_flag();
    // Elevation runs BEFORE spawn_unelevated's std::mem::take(cmd.fds_mut()), so the
    // effect layers see/modify cmd.fds() while it is still populated (the honest
    // Windows reject gate and the POSIX Auth::Stdin pipe injection both depend on it).
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            return crate::elevation::windows::spawn_elevated(cmd, kill_on_drop);
        }
        #[cfg(unix)]
        {
            let report = crate::elevation::posix::rewrite(cmd)?.report;
            let mut child = spawn_unelevated(cmd, kill_on_drop)?;
            child.set_elevation(report);
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
git commit -m "feat: spawn() elevation branch before fd-take (honest Windows gate + Stdin injection)"
```

---

### Task 16: Async (tokio) parity

**Files:**
- Modify: `src/tokio/command.rs`, `src/tokio/child.rs`, `src/tokio/spawn.rs`
- Test: `src/tokio/command_tests.rs`

**Interfaces:**
- Produces on `tokio::Command`: `.elevate()`, `.elevation_backend(Backend)`, `.elevation_auth(Auth)`, `.sanitize_env(EnvSanitizer)` — forwarding to the inner sync `Command`.
- Produces on `tokio::Child`: `elevation: Option<ElevationReport>` field, `set_elevation`, `pub fn elevation(&self) -> Option<ElevationReport>`.
- Produces: async spawn branch mirroring sync — POSIX reuses `posix::rewrite` (the `Auth::Stdin` password is delivered by a BLOCKING write inside `rewrite`, so there is NO `.await` in the sync `spawn` fn); Windows uses `windows::launch_runas`, and the async `Child` is constructed INSIDE `crate::tokio::spawn` (so it can call the `pub(super)` `tokio::child::Child::from_parts`).

**Findings woven in:**
- `ffad4627` (no `.await` in the sync `spawn`): the password is written by `posix::rewrite`'s blocking pipe write before spawn — no async delivery needed. `d84c0808` (log write errors) and `ef880aab` (consume fd0 / error on caller fd0) are already handled in `rewrite`.
- `60eb2f86`: `tokio::child::Child::from_parts` is `pub(super)`, so the async elevated `Child` is built in `src/tokio/spawn.rs`, not in `src/elevation/windows.rs`. `FdPipes::new()` exists (a `BTreeMap` alias, used at `src/tokio/spawn.rs`).
- `8d18c6d8`: the forwarding test asserts against the inner `Command::elevation_request()`.

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

In `src/tokio/spawn.rs`, after the runtime-availability check and BEFORE `let mut fds = std::mem::take(cmd.fds_mut());`, add the elevation branch, and change the final `Ok(Child::from_parts(...))` to attach the report:

```rust
    // Elevation runs before fds are taken, mirroring the sync path. On Windows the
    // async Child is built HERE (tokio::child::Child::from_parts is pub(super)).
    let mut elevation_report: Option<crate::elevation::ElevationReport> = None;
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            use crate::elevation::windows::{launch_runas, RunasOutcome};
            match launch_runas(cmd)? {
                RunasOutcome::Launched { proc, pid, id, report } => {
                    let raw = windows_raw::RawAsyncChild::new(proc, pid);
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
                    // fall through to the normal async spawn
                }
            }
        }
        #[cfg(unix)]
        {
            elevation_report = crate::elevation::posix::rewrite(cmd)?.report;
        }
    }
```

Then the tail:

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

`ProcSource` is already imported in `src/tokio/spawn.rs` via `use super::child::{reap_now, Child, ProcSource};`. `windows_raw::RawAsyncChild::new(proc: OwnedHandle, pid: u32)` is verified. `elevation_report`'s `mut` is used on both platforms (unix arm assigns it; the windows AlreadyElevated arm assigns it), so no `unused_mut`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --features tokio --lib tokio::command`
Then: `cargo build --features tokio` on Unix and Windows; `cargo clippy --all-targets --features tokio --locked -- -D warnings`.
Expected: PASS, clean.

- [ ] **Step 5: Commit**

```bash
git add src/tokio/command.rs src/tokio/child.rs src/tokio/spawn.rs
git commit -m "feat: async elevation parity (tokio builder, Child::elevation, in-tokio Windows child build)"
```

---

### Task 17: Live gated integration tests + testbin subcommands

**Files:**
- Create: `tests/elevation.rs`
- Modify: `testbin/main.rs`

**Interfaces:**
- Consumes: the full public surface (`Command::elevate`, `Child::elevation`, `elevation::is_elevated`, `posix::controlling_terminal_present`), sync + async.
- Produces: `testbin` subcommands `is-elevated-report` (prints `1`/`0`), `controlling-terminal` (prints `controlling_terminal_present()` as `1`/`0`), `write-marker <path>` (writes a byte, exit 0). Live privilege-gain tests gated behind `SUBPROCESS_TEST_ELEVATION`; the `setsid` controlling-terminal test is UNGATED (deterministic on Linux).

**Findings woven in:**
- `f3f0608c`: `posix_child_self_detects_elevation` sets `.executable(&exe)` AND passes `exe` as argv[0], so no distinct-argv0 rejection.
- Decision #2: the `setsid` negative case is cross-process tested via the `controlling-terminal` subcommand and the `#[doc(hidden)]` probe.
- Decision #3 / S5: a gated run0 kill-propagation live test; the `env --` corner case is confirmed empirically here.

- [ ] **Step 1: Write the failing test** — create `tests/elevation.rs`:

```rust
//! Live elevation tier — gated behind SUBPROCESS_TEST_ELEVATION (cgroup precedent):
//! a TRUE no-op when the var is absent, and FAILS LOUDLY when set but elevation is
//! unavailable. The pure tiers (planner/sanitizer/argv/rejections/detection) cover all
//! logic unconditionally; only the privilege-gain is gated.

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

// GATED (S5): run0 client -> unit kill propagation. Explicit Backend::Run0, long-lived child.
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
    // The client is gone; assert the elevated unit did not survive as our descendant.
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

Run: `cargo test --test elevation` (ungated: privilege tests no-op, but the `setsid` test runs on Linux)
Expected on Linux: FAIL — `controlling_terminal_probe_is_false_after_setsid` (testbin has no `controlling-terminal` subcommand → non-`0` output).

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
Expected: PASS (privilege tests no-op; Linux `setsid` test green).
Run (gated, Linux w/ passwordless sudo): `SUBPROCESS_TEST_ELEVATION=1 cargo test --test elevation`
Expected: PASS (root uid `0`, self-detect `1`). Confirm empirically that the `env --` corner case in Task 7 holds (the `id -u` under sudo still runs).

- [ ] **Step 5: Commit**

```bash
git add tests/elevation.rs testbin/main.rs
git commit -m "test: gated live elevation tier + ungated setsid controlling-terminal probe"
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
  --body "Implements the elevation design spec (.tmp/claude/superpowers/specs/2026-07-25-elevation-design.md): pure Host::plan planner as the single validation choke point, EnvSanitizer boundary, POSIX sudo/run0/doas/pkexec rewrite, Windows ShellExecuteEx(runas) reduced child, queryable Child::elevation(), full sync+async parity. Live tier gated behind SUBPROCESS_TEST_ELEVATION. Closes #6."
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
| `is_elevated()` free fn | 9 (unix), 12 (windows) |
| Flat builder: `.elevate/.elevation_backend/.elevation_auth/.sanitize_env` | 8 (sync), 16 (async) |
| `Backend`/`Auth`/`ElevatedStdio`/`ElevatedVia`/`Privilege`/`Secret` spellings | 2, 3 |
| `EnvSanitizer` consent gradient (default/keep/filter/allowlist/none); keep additive-within-policy | 6 |
| Two-layer env (clean default + denylist over explicit set) | 6 (denylist) + 11 (`explicit_env` is the only forwarded set; `.env_clear()` intent preserved) |
| `ElevationReport { via, stripped_env, stdio }` + `Child::elevation()` = Some iff requested | 11 (sync), 14 (windows RunAsIs/UAC), 16 (async) |
| Pure `Host::plan` → `Transition`; single validation choke point BEFORE elevated short-circuit | 4, 5 |
| Auto = sudo>doas (run0 excluded); pkexec explicit; Gui explicit | 4, 5 |
| Auth default Interactive; no controlling terminal → NoTty (`/dev/tty` probe) | 5 (planner), 9 (probe) |
| Auth × backend × platform matrix (POSIX + Windows) | 5 |
| Error split: `Unsupported` (structural) vs `Elevation` (runtime, incl. `Untracked`) | 1, 5, 13 |
| POSIX argv threading (`env K=V` + `--` terminator; run0 `--pipe`/`--setenv`; abs argv[0]; no `--preserve-env`) | 7 |
| POSIX command rewrite reuses existing spawn; `spawn_unelevated` core | 10, 11, 15 |
| Windows `ShellExecuteEx(runas)` reduced child; plan-first; COM init; lpDirectory; identity-from-handle; ERROR_CANCELLED→AuthDeclined | 14 |
| Windows capability matrix (all non-inherit slots + fd>=3 + env + contain → Unsupported; `OwnConsole` reported) | 13, 14 |
| run0 process model (explicit-only, `--pipe`, contain-reject, client kill/id, gated propagation test) | 4, 5, 7, 11, 17 |
| Detection tests (unelevated false; Windows integrity below High) | 9, 12 |
| Live gated tier (uid 0, self-detect, Windows marker, run0 kill) sync+async + ungated setsid probe | 17 |
| Async parity (builder, report, POSIX rewrite reuse, in-tokio Windows child build, no `.await` for Stdin) | 16 |
| CI provisioning TODO | 18 |
| Branch/PR/CI workflow | 19 |
| zeroize dep; windows feature adds (SystemServices/Com/Shell/WindowsAndMessaging) | 2, 12 |

No spec section is unmapped.

**2. Placeholder scan:** No "TBD / similar to Task N / add error handling later" remain; every code step shows complete code. Two implementation seams are explicitly flagged (not hidden), both proven patterns in `src/child/spawn/windows_raw/proc.rs`: the exact `RawChild` import path and the `HANDLE(*mut c_void)` cast shape (Task 14). The `Auth::Stdin` password is fully delivered (blocking pipe write in `rewrite`), not deferred.

**3. Type consistency (matches code + tests everywhere):**
- `Backend` (Auto/Run0/Sudo/Doas/Pkexec)
- `Auth` (Interactive/NonInteractive/Askpass/Stdin/Gui)
- `ElevatedStdio` (**Passthrough/OwnConsole** — `#[non_exhaustive]`; the old 4-variant list is gone from the Interfaces blocks and this table)
- `ElevatedVia` (Wrapped(Backend)/WindowsUac/AlreadyElevated)
- `ElevationReport { via, stripped_env, stdio }` (NOT `backend`)
- `ElevationErrorKind` (BackendUnavailable/AuthFailed/AuthDeclined/NoTty/Untracked)
- `Privilege` (Unprivileged/Elevated)
- `Host { elevated, has_tty, available, os }`; `BackendSet { run0, sudo, doas, pkexec }` each `Option<PathBuf>`
- `Transition` (RunAsIs / ElevatePosix { backend, path, auth } / ElevateWindows { auth } / Reject { error })
- `ElevationRequest { enabled, backend, auth, sanitizer }`
- `build_argv(backend, backend_path, auth, program, args, env)`
- `PosixRewrite { report }`; `rewrite` / `rewrite_with_host`
- `RunasOutcome { AlreadyElevated, Launched { proc, pid, id, report } }`; `launch_runas`; `spawn_elevated`
- `spawn_unelevated(cmd, kill_on_drop)`
- `Child::elevation` / `set_elevation` (sync + async)
- `controlling_terminal_present`; `integrity_level`; `windows_identity_from_handle`

All names are identical everywhere they appear.

**4. No forward references:** Windows detection (12), reject gate (13), and `spawn_elevated`/`launch_runas` (14) all land before the `spawn()` branch (15) that calls them. `spawn_unelevated` (10) and POSIX `rewrite` (11) land before the same branch. The async branch (16) references only symbols from 11/14. Every task compiles on its target platform(s) at commit time.
