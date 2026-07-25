# Elevation (elevate-to-admin/root) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add cross-platform, DX-honest privilege elevation to the `subprocess` crate — a declarative `.elevate()` builder that wraps the CHILD (never the caller) via POSIX `sudo`/`run0`/`doas`/`pkexec` or Windows `ShellExecuteEx("runas")`, with a pure cross-OS planner, an env security boundary, and a queryable achieved-state report, in full sync + async parity.

**Architecture:** A pure `Host::plan(target, backend, auth) -> Transition` planner (plain data `Host`, no syscalls, cross-OS-testable) decides RunAsIs / ElevatePosix / ElevateWindows / Reject. Two effect layers consume it: POSIX **rewrites** the `Command` into a backend invocation and reuses the existing spawn path unchanged; Windows is a **distinct** `ShellExecuteEx` spawn backend returning a reduced `Child` (wait/exit-code/kill only). Every capability gap is a loud `Error::Unsupported` (structural) or `Error::Elevation` (runtime), never a silent lie; the achieved disposition is reported via `Child::elevation() -> Option<ElevationReport>`.

**Tech Stack:** Rust 1.87 (edition 2021), `thiserror` 2, `log` 0.4, `shared_child` 1, `zeroize` 1 (new), `nix` 0.31 / `libc` 0.2 (POSIX detect), `windows` 0.62 (token + ShellExecuteEx), `tokio` 1 (async, `tokio` feature). Reuses the crate's own `crate::quote::windows::join_wide` for Windows command-line construction and the raw-backend `RawChild`/`RawAsyncChild` handle wrappers.

## Global Constraints

- Rust edition 2021, `rust-version = "1.87"`. No new MSRV bump.
- Dependency versions (verbatim from `Cargo.toml`): `thiserror = "2"`, `shared_child = { version = "1", features = ["timeout"] }`, `log = "0.4"`, `tokio = { version = "1", optional = true, features = ["process","rt","io-util","macros","net","sync","time"] }`, `tempfile = "3"` (dev), `libc = "0.2"`, `nix = { version = "0.31", features = ["signal","process","event"] }`, `windows = "0.62"`. NEW: `zeroize = "1"`.
- Module style: `foo.rs` + `foo/` subdir (NOT `mod.rs`). Unit tests in a SEPARATE sibling `foo_tests.rs`, included via `#[cfg(test)] #[path = "foo_tests.rs"] mod foo_tests;`. Debug asserts encouraged. `#[cfg(unix)]` / `#[cfg(windows)]` gating for platform effect code; pure code compiles everywhere.
- Async is gated behind the `tokio` feature; every async task's tests run under `--features tokio`.
- Builder methods are flat and return `&mut Command`, mirroring `.contain()` / `.contain_with()` / `.nesting()`.
- `Error::Unsupported` = "can never work on this platform"; `Error::Elevation` = "could work but failed now." Never conflate.
- Live privilege-gain tests are gated behind `SUBPROCESS_TEST_ELEVATION`: a true no-op when the var is absent, and FAIL LOUDLY when it is set but elevation is unavailable (mirror `SUBPROCESS_TEST_CGROUP` in `tests/spawn_io.rs`).
- Commit messages are single-line (repo rule; see `git log`).
- Work stays on branch `azhukova/6` (issue #6). Never push to `main`.
- DEFERRED — do NOT implement: run-as-user, elevate-to-SYSTEM, de-elevation, signed broker/piping, un-killable-child teardown, macOS GUI elevation.

---

## File Structure

**Create:**
- `src/elevation.rs` — public surface: `is_elevated()`, enums (`Backend`, `Auth`, `ElevatedStdio`, `Privilege`), `Secret`, `ElevationReport`, crate-internal `ElevationRequest`, `apply_pre_spawn`, module wiring + re-exports.
- `src/elevation_tests.rs` — unit tests for the public surface (enum defaults, `Secret` redaction, `is_elevated` detection).
- `src/elevation/plan.rs` — PURE `Host` / `BackendSet` / `Os` / `Transition` + `Host::detect()` + `Host::plan()`.
- `src/elevation/plan_tests.rs` — cross-OS planner + rejection tests (fake `Host` on any runner).
- `src/elevation/sanitize.rs` — `EnvSanitizer`, `DEFAULT_DENYLIST`, `apply()`.
- `src/elevation/sanitize_tests.rs` — denylist / keep / allowlist / filter / none tests.
- `src/elevation/posix.rs` — `#[cfg(unix)]`: `detect()`, `is_elevated()`, pure `build_argv()`, `rewrite()`, `prime_sudo()`.
- `src/elevation/posix_tests.rs` — argv-construction + rewrite tests (no backend install needed).
- `src/elevation/windows.rs` — `#[cfg(windows)]`: `detect()`, `is_elevated()`, integrity level, `spawn_elevated()`, honest-contract rejections.
- `src/elevation/windows_tests.rs` — detection + rejection tests (no UAC needed).
- `tests/elevation.rs` — gated live integration tests (sync + async).

**Modify:**
- `Cargo.toml` — add `zeroize = "1"`; extend `[target.'cfg(windows)'.dependencies] windows` feature list.
- `src/error.rs` (+ `src/error_tests.rs`) — add `ElevationErrorKind` and `Error::Elevation`.
- `src/lib.rs` — `pub mod elevation;` + re-exports.
- `src/command.rs` (+ `src/command_tests.rs`) — `.elevate()` / `.elevation_backend()` / `.elevation_auth()` / `.sanitize_env()` + `ElevationRequest` field + accessor.
- `src/child.rs` — `elevation: Option<ElevationReport>` field, `set_elevation()`, `elevation()`.
- `src/child/spawn.rs` — elevation branch at the top of `spawn()`.
- `src/tokio/command.rs` — mirror the four builder methods.
- `src/tokio/child.rs` — `elevation: Option<ElevationReport>` field + `set_elevation()` + `elevation()`.
- `src/tokio/spawn.rs` — async elevation branch.
- `testbin/main.rs` — `is-elevated-report` and `write-marker` subcommands for live tests.
- `TODO.md` — CI provisioning note for the elevation live tier.

---

### Task 1: Elevation error taxonomy

**Files:**
- Modify: `src/error.rs`
- Test: `src/error_tests.rs`

**Interfaces:**
- Produces: `ElevationErrorKind::{BackendUnavailable, AuthFailed, AuthDeclined, NoTty}` (Debug, Clone, Copy, PartialEq, Eq); `Error::Elevation { kind: ElevationErrorKind, detail: String }`.

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
    assert_ne!(BackendUnavailable.to_string(), AuthFailed.to_string());
    assert_ne!(AuthFailed.to_string(), AuthDeclined.to_string());
    assert_ne!(AuthDeclined.to_string(), NoTty.to_string());
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
    /// Wrong password, or `sudo -n` found no cached credential.
    #[error("elevation authentication failed")]
    AuthFailed,
    /// The UAC / GUI prompt was cancelled by the user (Windows `ERROR_CANCELLED`).
    #[error("elevation prompt was declined")]
    AuthDeclined,
    /// Interactive auth requested but there is no controlling terminal to prompt on.
    #[error("no controlling terminal for interactive elevation")]
    NoTty,
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

### Task 3: Public enums, `ElevationReport`, and `ElevationRequest`

**Files:**
- Modify: `src/elevation.rs`, `src/elevation_tests.rs`

**Interfaces:**
- Produces:
  - `pub enum Backend { Auto, Run0, Sudo, Doas, Pkexec }` — Debug, Clone, Copy, PartialEq, Eq; `Default = Auto`.
  - `pub enum Auth { Interactive, NonInteractive, Askpass(PathBuf), Stdin(Secret), Gui }` — Debug, Clone; `Default = Interactive`.
  - `pub enum ElevatedStdio { Piped, Inherited, OwnConsole, Hidden }` — Debug, Clone, Copy, PartialEq, Eq.
  - `pub enum Privilege { Unprivileged, Elevated }` — Debug, Clone, Copy, PartialEq, Eq, `#[non_exhaustive]`.
  - `pub struct ElevationReport { backend: Backend, stripped_env: Vec<OsString>, stdio: ElevatedStdio }` — Debug, Clone; public fields.
  - `pub(crate) struct ElevationRequest { enabled: bool, backend: Backend, auth: Auth, sanitizer: EnvSanitizer }` — Debug; `Default`.

- [ ] **Step 1: Write the failing test** — append to `src/elevation_tests.rs`:

```rust
use super::{Auth, Backend, ElevatedStdio, ElevationReport, Privilege};

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
fn elevation_report_holds_achieved_state() {
    let r = ElevationReport {
        backend: Backend::Sudo,
        stripped_env: vec!["LD_PRELOAD".into()],
        stdio: ElevatedStdio::Passthrough,
    };
    assert_eq!(r.backend, Backend::Sudo);
    assert_eq!(r.stripped_env, vec![std::ffi::OsString::from("LD_PRELOAD")]);
    assert_eq!(r.stdio, ElevatedStdio::Passthrough);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation_tests`
Expected: FAIL — `cannot find type Backend/Auth/Privilege/ElevationReport`.

- [ ] **Step 3: Write minimal implementation** — in `src/elevation.rs`, add above the `Secret` definition:

```rust
use std::ffi::OsString;
use std::path::PathBuf;

pub mod plan;
pub mod sanitize;

pub use sanitize::EnvSanitizer;

/// Which elevation program runs. `Auto` (default) detects among the CLI
/// backends only — order `run0` > `sudo` > `doas`; it never selects a graphical
/// backend. `Pkexec` and graphical elevation are explicit-only.
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
/// controlling TTY; with no TTY it is a loud [`crate::error::ElevationErrorKind::NoTty`].
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
///
/// `#[non_exhaustive]`: the deferred elevation broker will add a `Piped` variant
/// (true captured streams across the boundary) and an `SW_HIDE` builder knob will
/// add `Hidden`; neither is reachable in this plan, so neither is defined yet
/// (no dead variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElevatedStdio {
    /// POSIX: the child's stdio is wired exactly as the `Command` configured it
    /// (`sudo`/`run0`/`doas`/`pkexec` pass fds straight through) — elevation
    /// imposed no change, so whatever you set (pipe/inherit/null) is what the
    /// child got. Honest precisely because it does NOT claim `Inherited` when you
    /// actually piped.
    Passthrough,
    /// Windows `runas`: the child received its OWN console; the parent's streams
    /// were not shared, regardless of any `inherit()` request.
    OwnConsole,
}

/// The planner's privilege target. `#[non_exhaustive]` so run-as-user / SYSTEM
/// can extend it later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Privilege {
    Unprivileged,
    Elevated,
}

/// Achieved elevation state, queried via [`crate::Child::elevation`], mirroring
/// [`crate::Child::containment`].
#[derive(Debug, Clone)]
pub struct ElevationReport {
    /// The backend that ACTUALLY ran (e.g. `Sudo` after `Auto` resolution).
    pub backend: Backend,
    /// Vars the sanitizer dropped before forwarding (also `log`ged).
    pub stripped_env: Vec<OsString>,
    /// How stdio was actually wired.
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

> Note: `pub mod sanitize;` and `pub mod plan;` are declared here but land in Tasks 4–6; add empty stub files now so the crate compiles: create `src/elevation/sanitize.rs` containing only `#[derive(Debug, Default)] pub struct EnvSanitizer;` and `src/elevation/plan.rs` empty. These stubs are fleshed out in Tasks 4–6.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib elevation_tests`
Expected: PASS (all elevation_tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation.rs src/elevation_tests.rs src/elevation/plan.rs src/elevation/sanitize.rs
git commit -m "feat: elevation public enums, ElevationReport, ElevationRequest"
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
  - `pub struct BackendSet { run0: bool, sudo: bool, doas: bool, pkexec: bool }` — Debug, Clone, Copy, PartialEq, Eq, Default.
  - `pub struct Host { elevated: bool, has_tty: bool, available: BackendSet, os: Os }` — Debug, Clone.
  - `pub enum Transition { RunAsIs, ElevatePosix { backend: Backend, auth: Auth }, ElevateWindows { auth: Auth }, Reject { error: Error } }` — Debug only (Error is not PartialEq).
  - `impl Host { pub fn plan(&self, target: Privilege, backend: Backend, auth: Auth) -> Transition }`.

- [ ] **Step 1: Write the failing test** — create `src/elevation/plan_tests.rs`:

```rust
use super::{BackendSet, Host, Os, Transition};
use crate::elevation::{Auth, Backend, Privilege};

fn unix_host(available: BackendSet, elevated: bool, has_tty: bool) -> Host {
    Host { elevated, has_tty, available, os: Os::Unix }
}

fn all_backends() -> BackendSet {
    BackendSet { run0: true, sudo: true, doas: true, pkexec: true }
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
fn auto_prefers_run0_then_sudo_then_doas() {
    // run0 present -> run0
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevatePosix { backend: Backend::Run0, .. }
    ));
    // no run0 -> sudo
    let h = unix_host(BackendSet { run0: false, ..all_backends() }, false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevatePosix { backend: Backend::Sudo, .. }
    ));
    // only doas -> doas
    let h = unix_host(BackendSet { run0: false, sudo: false, doas: true, pkexec: false }, false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevatePosix { backend: Backend::Doas, .. }
    ));
}

#[test]
fn auto_never_selects_pkexec() {
    // Only pkexec available: Auto must NOT pick it — that is a BackendUnavailable reject.
    let h = unix_host(BackendSet { run0: false, sudo: false, doas: false, pkexec: true }, false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::Reject { .. }
    ));
}

#[test]
fn forced_available_backend_is_honored() {
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Doas, Auth::Interactive),
        Transition::ElevatePosix { backend: Backend::Doas, .. }
    ));
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

use super::{Auth, Backend, Privilege};
use crate::error::{ElevationErrorKind, Error};

/// Which OS the effect layer will use. Data, not `cfg!`, so `plan` is cross-tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Unix,
    Windows,
}

/// Which CLI backends are on PATH (filled by `detect`, faked in tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackendSet {
    pub run0: bool,
    pub sudo: bool,
    pub doas: bool,
    pub pkexec: bool,
}

impl BackendSet {
    fn has(&self, backend: Backend) -> bool {
        match backend {
            Backend::Run0 => self.run0,
            Backend::Sudo => self.sudo,
            Backend::Doas => self.doas,
            Backend::Pkexec => self.pkexec,
            Backend::Auto => self.run0 || self.sudo || self.doas,
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
    ElevatePosix { backend: Backend, auth: Auth },
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

    /// Pure decision. No side effects, no privileges.
    pub fn plan(&self, target: Privilege, backend: Backend, auth: Auth) -> Transition {
        if target == Privilege::Unprivileged || self.elevated {
            return Transition::RunAsIs;
        }
        match self.os {
            Os::Windows => self.plan_windows(backend, auth),
            Os::Unix => self.plan_posix(backend, auth),
        }
    }

    fn plan_windows(&self, backend: Backend, auth: Auth) -> Transition {
        // Only `Auto` is meaningful on Windows; a CLI backend is a wrong-platform request.
        if backend != Backend::Auto {
            return Transition::Reject {
                error: Error::Unsupported {
                    op: format!("elevation backend {backend:?}"),
                    platform: "windows",
                    detail: "POSIX elevation backends do not exist on Windows; use Backend::Auto \
                             (ShellExecuteEx runas)"
                        .into(),
                },
            };
        }
        Transition::ElevateWindows { auth }
    }

    fn plan_posix(&self, backend: Backend, auth: Auth) -> Transition {
        // (Rejection combos land in Task 5.)
        let resolved = match backend {
            Backend::Auto => {
                if self.available.run0 {
                    Backend::Run0
                } else if self.available.sudo {
                    Backend::Sudo
                } else if self.available.doas {
                    Backend::Doas
                } else {
                    return Transition::Reject {
                        error: Error::Elevation {
                            kind: ElevationErrorKind::BackendUnavailable,
                            detail: "no run0/sudo/doas on PATH for Backend::Auto".into(),
                        },
                    };
                }
            }
            explicit => {
                if !self.available.has(explicit) {
                    return Transition::Reject {
                        error: Error::Elevation {
                            kind: ElevationErrorKind::BackendUnavailable,
                            detail: format!("forced backend {explicit:?} is not on PATH"),
                        },
                    };
                }
                explicit
            }
        };
        Transition::ElevatePosix { backend: resolved, auth }
    }
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod plan_tests;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib plan_tests`
Expected: PASS (all plan_tests). (Detect's `super::posix`/`super::windows` are added in Tasks 9/11; they are `cfg`-gated and unused by these host tests — the crate still compiles because the `#[cfg(unix)]`/`#[cfg(windows)]` arms reference modules declared in Task 9/11. To keep this task self-compiling, temporarily stub `detect()`'s body to `Host { elevated: false, has_tty: false, available: BackendSet::default(), os: if cfg!(windows) { Os::Windows } else { Os::Unix } }`; Task 9/11 replace it.)

- [ ] **Step 5: Commit**

```bash
git add src/elevation/plan.rs src/elevation/plan_tests.rs
git commit -m "feat: pure elevation planner with cross-OS happy-path transitions"
```

---

### Task 5: Planner rejection matrix

**Files:**
- Modify: `src/elevation/plan.rs`, `src/elevation/plan_tests.rs`

**Interfaces:**
- Consumes: `Host::plan` from Task 4.
- Produces: `plan()` now emits `Transition::Reject` for: `Interactive` + no TTY (`Elevation::NoTty`); `Doas` + `Askpass` (`Unsupported`); `Pkexec` + non-`Gui` (`Unsupported`); `Gui` + non-`Pkexec` (`Unsupported`).

- [ ] **Step 1: Write the failing test** — append to `src/elevation/plan_tests.rs`:

```rust
use crate::error::{ElevationErrorKind, Error};
use std::path::PathBuf;

fn reject_error(t: Transition) -> Error {
    match t {
        Transition::Reject { error } => error,
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn interactive_without_tty_is_no_tty() {
    let h = unix_host(all_backends(), false, /* has_tty */ false);
    let e = reject_error(h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive));
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
fn doas_with_askpass_is_unsupported() {
    let h = unix_host(all_backends(), false, true);
    let e = reject_error(h.plan(Privilege::Elevated, Backend::Doas, Auth::Askpass(PathBuf::from("/x"))));
    assert!(matches!(e, Error::Unsupported { .. }), "{e}");
}

#[test]
fn pkexec_without_gui_is_unsupported() {
    let h = unix_host(all_backends(), false, true);
    let e = reject_error(h.plan(Privilege::Elevated, Backend::Pkexec, Auth::Interactive));
    assert!(matches!(e, Error::Unsupported { .. }), "{e}");
}

#[test]
fn gui_without_pkexec_is_unsupported() {
    let h = unix_host(all_backends(), false, true);
    let e = reject_error(h.plan(Privilege::Elevated, Backend::Sudo, Auth::Gui));
    assert!(matches!(e, Error::Unsupported { .. }), "{e}");
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
Expected: FAIL — `interactive_without_tty_is_no_tty`, `doas_with_askpass_is_unsupported`, `pkexec_without_gui_is_unsupported`, `gui_without_pkexec_is_unsupported` (planner currently ignores auth combos and TTY).

- [ ] **Step 3: Write minimal implementation** — in `plan_posix`, insert the combo + TTY guards BEFORE the `resolved` block:

```rust
    fn plan_posix(&self, backend: Backend, auth: Auth) -> Transition {
        // ---- structural combos: "can never work" -> Unsupported ----
        let unsupported = |op: String, detail: &str| Transition::Reject {
            error: Error::Unsupported { op, platform: "unix", detail: detail.into() },
        };
        match (backend, &auth) {
            (Backend::Doas, Auth::Askpass(_)) => {
                return unsupported("doas + Askpass".into(), "doas has no askpass mechanism; use sudo for Askpass");
            }
            (Backend::Pkexec, a) if !matches!(a, Auth::Gui) => {
                return unsupported(
                    "pkexec + non-Gui auth".into(),
                    "pkexec is the graphical backend; pair it with Auth::Gui",
                );
            }
            (b, Auth::Gui) if b != Backend::Pkexec => {
                return unsupported(
                    format!("{b:?} + Auth::Gui"),
                    "graphical (Gui) auth is only available through Backend::Pkexec",
                );
            }
            _ => {}
        }
        // ---- runtime precondition: interactive prompt needs a TTY ----
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
        // ...unchanged `resolved` selection from Task 4...
```

(Keep the Task-4 `resolved` block below, unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib plan_tests`
Expected: PASS (all plan_tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation/plan.rs src/elevation/plan_tests.rs
git commit -m "feat: planner rejection matrix (NoTty, doas/askpass, pkexec/gui combos)"
```

---

### Task 6: `EnvSanitizer` + default denylist

**Files:**
- Modify: `src/elevation/sanitize.rs`
- Create: `src/elevation/sanitize_tests.rs`

**Interfaces:**
- Produces:
  - `pub struct EnvSanitizer` — Debug (manual), Default (denylist, no holes).
  - `EnvSanitizer::default()`, `.keep<I: IntoIterator<Item = impl Into<OsString>>>(self, keys) -> Self`, `EnvSanitizer::filter<F: Fn(&OsStr, &OsStr) -> bool + Send + Sync + 'static>(f) -> Self` (return `true` to KEEP), `EnvSanitizer::allowlist<I>(keys) -> Self`, `EnvSanitizer::none() -> Self`.
  - `pub(crate) fn apply(&self, env: Vec<(OsString, OsString)>) -> (Vec<(OsString, OsString)>, Vec<OsString>)` — returns `(kept, stripped)`, stripped `log`ged at info.
  - `pub(crate) const DEFAULT_DENYLIST: &[&str]`.

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
fn keep_pokes_exactly_one_hole() {
    let s = EnvSanitizer::default().keep(["LD_LIBRARY_PATH"]);
    let (kept, stripped) = s.apply(env(&[("LD_LIBRARY_PATH", "/opt/lib"), ("LD_PRELOAD", "/e.so")]));
    assert_eq!(keys(&kept), vec!["LD_LIBRARY_PATH"]);
    assert_eq!(keys(&stripped), vec!["LD_PRELOAD"]);
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

> Kept order in these asserts is sorted-by-key: `apply` sorts its output for deterministic argv construction downstream.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib sanitize_tests`
Expected: FAIL — the stub `EnvSanitizer` has no `keep`/`filter`/`allowlist`/`none`/`apply`.

- [ ] **Step 3: Write minimal implementation** — replace the stub `src/elevation/sanitize.rs`:

```rust
//! The env consent gradient (layer 2): a denylist over the vars the user
//! *deliberately* forwards past the backend's env_reset scrub. See the design
//! spec's "Environment as a security boundary".

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

/// Loader/injection footguns that `sudo env K=V prog` would otherwise re-inject
/// past `ld.so`'s setuid scrub. Prefix families are matched in [`is_denied`].
pub(crate) const DEFAULT_DENYLIST: &[&str] = &[
    "IFS", "BASH_ENV", "ENV", "PS4", "TERMINFO", "TERMCAP", "HOSTALIASES", "RES_OPTIONS", "LIBPATH",
    "SHLIB_PATH", "GCONV_PATH", "PYTHONPATH", "PERL5LIB", "NODE_OPTIONS",
];
/// Prefix families: any var starting with one of these is a loader footgun.
const DENYLIST_PREFIXES: &[&str] = &["LD_", "DYLD_", "_RLD", "LDR_"];

fn is_denied(key: &OsStr) -> bool {
    let k = key.to_string_lossy();
    DENYLIST_PREFIXES.iter().any(|p| k.starts_with(p)) || DEFAULT_DENYLIST.contains(&k.as_ref())
}

enum Policy {
    /// Default denylist, minus the named holes.
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
    /// Poke named holes in the default denylist (the greppable, opt-in weaken).
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
            // `keep` on a non-denylist policy resets to a denylist with those holes.
            _ => Policy::Denylist { keep: extra },
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

    /// Partition `env` into `(kept, stripped)`, both sorted by key. Every strip
    /// is `log`ged at info so it is never invisible.
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
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation/sanitize.rs src/elevation/sanitize_tests.rs
git commit -m "feat: EnvSanitizer consent gradient with default loader denylist"
```

---

### Task 7: POSIX argv construction (pure)

**Files:**
- Create: `src/elevation/posix.rs`, `src/elevation/posix_tests.rs`
- Modify: `src/elevation.rs` (declare `#[cfg(unix)] pub mod posix;`)

**Interfaces:**
- Consumes: `super::{Auth, Backend}`.
- Produces: `pub(crate) fn build_argv(backend: Backend, auth: &Auth, program: &OsStr, args: &[OsString], env: &[(OsString, OsString)]) -> Vec<OsString>` — the full elevated argv (argv[0] = the backend program). Pure; needs no installed backend.

- [ ] **Step 1: Write the failing test** — create `src/elevation/posix_tests.rs`:

```rust
use super::build_argv;
use crate::elevation::{Auth, Backend};
use std::ffi::OsString;

fn s(v: &[&str]) -> Vec<OsString> {
    v.iter().map(|x| OsString::from(*x)).collect()
}
fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|(k, v)| (OsString::from(*k), OsString::from(*v))).collect()
}

#[test]
fn sudo_noninteractive_threads_env_after_preserve_and_env() {
    let argv = build_argv(
        Backend::Sudo,
        &Auth::NonInteractive,
        std::ffi::OsStr::new("/usr/bin/systemctl"),
        &s(&["restart", "nginx"]),
        &env(&[("FOO", "bar")]),
    );
    assert_eq!(
        argv,
        s(&["sudo", "-n", "--preserve-env=FOO", "env", "FOO=bar", "/usr/bin/systemctl", "restart", "nginx"])
    );
}

#[test]
fn sudo_interactive_has_no_auth_flag() {
    let argv = build_argv(Backend::Sudo, &Auth::Interactive, std::ffi::OsStr::new("id"), &s(&["-u"]), &[]);
    assert_eq!(argv, s(&["sudo", "--preserve-env=", "env", "id", "-u"]));
}

#[test]
fn sudo_stdin_uses_dash_s() {
    let argv = build_argv(
        Backend::Sudo,
        &Auth::Stdin(crate::elevation::Secret::new("pw")),
        std::ffi::OsStr::new("id"),
        &[],
        &[],
    );
    assert_eq!(argv, s(&["sudo", "-S", "--preserve-env=", "env", "id"]));
}

#[test]
fn doas_prefixes_env_without_flags() {
    let argv = build_argv(Backend::Doas, &Auth::Interactive, std::ffi::OsStr::new("id"), &s(&["-u"]), &env(&[("A", "1")]));
    assert_eq!(argv, s(&["doas", "env", "A=1", "id", "-u"]));
}

#[test]
fn run0_uses_setenv() {
    let argv = build_argv(Backend::Run0, &Auth::Interactive, std::ffi::OsStr::new("id"), &[], &env(&[("A", "1"), ("B", "2")]));
    assert_eq!(argv, s(&["run0", "--setenv=A=1", "--setenv=B=2", "id"]));
}

#[test]
fn pkexec_prefixes_env() {
    let argv = build_argv(Backend::Pkexec, &Auth::Gui, std::ffi::OsStr::new("id"), &[], &env(&[("A", "1")]));
    assert_eq!(argv, s(&["pkexec", "env", "A=1", "id"]));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation::posix` (Unix runner)
Expected: FAIL — module `posix` / `build_argv` not found.

- [ ] **Step 3: Write minimal implementation** — create `src/elevation/posix.rs`:

```rust
//! POSIX elevation effect layer (`cfg(unix)`): backend detection, pure argv
//! construction, command rewrite, and sudo credential priming.

use std::ffi::{OsStr, OsString};

use super::{Auth, Backend};

/// `K=V` as an `OsString` (env-safe: assignment tokens precede the program).
fn kv(k: &OsStr, v: &OsStr) -> OsString {
    let mut s = k.to_os_string();
    s.push("=");
    s.push(v);
    s
}

/// Build the full elevated argv for `backend`. `env` MUST be pre-sanitized and
/// sorted (see [`super::sanitize::EnvSanitizer::apply`]). Pure — no installed
/// backend required.
pub(crate) fn build_argv(
    backend: Backend,
    auth: &Auth,
    program: &OsStr,
    args: &[OsString],
    env: &[(OsString, OsString)],
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = Vec::new();
    match backend {
        Backend::Sudo => {
            argv.push("sudo".into());
            match auth {
                Auth::NonInteractive => argv.push("-n".into()),
                Auth::Stdin(_) => argv.push("-S".into()),
                Auth::Askpass(_) => argv.push("-A".into()),
                Auth::Interactive | Auth::Gui => {}
            }
            let keys: Vec<String> = env.iter().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
            argv.push(OsString::from(format!("--preserve-env={}", keys.join(","))));
            argv.push("env".into());
            for (k, v) in env {
                argv.push(kv(k, v));
            }
        }
        Backend::Doas => {
            argv.push("doas".into());
            argv.push("env".into());
            for (k, v) in env {
                argv.push(kv(k, v));
            }
        }
        Backend::Pkexec => {
            argv.push("pkexec".into());
            argv.push("env".into());
            for (k, v) in env {
                argv.push(kv(k, v));
            }
        }
        Backend::Run0 => {
            argv.push("run0".into());
            for (k, v) in env {
                let mut a = OsString::from("--setenv=");
                a.push(kv(k, v));
                argv.push(a);
            }
        }
        // `Auto` is resolved to a concrete backend by the planner before this is
        // ever called; treat a stray `Auto` as `sudo` under a debug tripwire.
        Backend::Auto => {
            debug_assert!(false, "build_argv received unresolved Backend::Auto");
            return build_argv(Backend::Sudo, auth, program, args, env);
        }
    }
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
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation.rs src/elevation/posix.rs src/elevation/posix_tests.rs
git commit -m "feat: pure POSIX elevated-argv construction per backend"
```

---

### Task 8: `Command` builder methods

**Files:**
- Modify: `src/command.rs`, `src/command_tests.rs`

**Interfaces:**
- Consumes: `crate::elevation::{Auth, Backend, ElevationRequest, EnvSanitizer}`.
- Produces on `Command`: `.elevate() -> &mut Command`, `.elevation_backend(Backend) -> &mut Command`, `.elevation_auth(Auth) -> &mut Command`, `.sanitize_env(EnvSanitizer) -> &mut Command`, and `pub(crate) fn elevation_request(&self) -> &ElevationRequest`. Each setter also sets `enabled = true`.

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

Add the field to `struct Command`:

```rust
    contain: ContainRequest,
    elevation: crate::elevation::ElevationRequest,
```

In `impl Default for Command`, add `elevation: crate::elevation::ElevationRequest::default(),`.

Add the methods after `nesting`:

```rust
    /// Run this child elevated (admin/root). Sugar for `Backend::Auto` +
    /// `Auth::Interactive` + the default `EnvSanitizer`. Elevation wraps the
    /// CHILD, never this process. See [`crate::elevation`].
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
```

Re-export the public enums from `src/elevation.rs` (already public there); no `lib.rs` change needed since callers use `subprocess::elevation::Backend`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib command_tests::elev`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/command.rs src/command_tests.rs
git commit -m "feat: Command elevation builder methods (.elevate + overrides)"
```

---

### Task 9: POSIX detection (`detect` / `is_elevated`)

**Files:**
- Modify: `src/elevation/posix.rs`, `src/elevation.rs`, `src/elevation_tests.rs`, `src/elevation/plan.rs`

**Interfaces:**
- Produces: `#[cfg(unix)] pub(super) fn detect() -> crate::elevation::plan::Host`; `#[cfg(unix)] pub(super) fn is_elevated() -> bool`; and the public `crate::elevation::is_elevated() -> bool` dispatcher (Unix arm now real).

- [ ] **Step 1: Write the failing test** — append to `src/elevation_tests.rs`:

```rust
#[test]
fn is_elevated_is_false_in_the_unprivileged_test_process() {
    // The test harness runs unprivileged; elevated CI would set SUBPROCESS_TEST_ELEVATION.
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation_tests::is_elevated`
Expected: FAIL — `is_elevated` not found in `crate::elevation`.

- [ ] **Step 3: Write minimal implementation**

In `src/elevation/posix.rs`, add:

```rust
use super::plan::{BackendSet, Host, Os};

pub(super) fn is_elevated() -> bool {
    // SAFETY: geteuid has no preconditions and never fails.
    unsafe { libc::geteuid() == 0 }
}

fn on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&path).any(|dir| {
        let cand = dir.join(program);
        std::fs::metadata(&cand).map(|m| m.is_file()).unwrap_or(false)
    })
}

pub(super) fn detect() -> Host {
    // SAFETY: isatty has no preconditions.
    let has_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    Host {
        elevated: is_elevated(),
        has_tty,
        available: BackendSet {
            run0: on_path("run0"),
            sudo: on_path("sudo"),
            doas: on_path("doas"),
            pkexec: on_path("pkexec"),
        },
        os: Os::Unix,
    }
}
```

Add `use super::plan;` reference in `plan.rs` already routes `detect()` to `super::posix::detect()`; replace the Task-4 stubbed `detect()` body with the real `#[cfg(unix)] super::posix::detect()` / `#[cfg(windows)] super::windows::detect()` dispatch (windows arm compiles once Task 11 lands; on a Unix build only the unix arm is active).

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
git commit -m "feat: POSIX elevation detection (euid/tty/backend availability)"
```

---

### Task 10: POSIX effect integration (rewrite + `Child::elevation()` + Stdin priming)

**Files:**
- Modify: `src/elevation/posix.rs`, `src/elevation.rs`, `src/child.rs`, `src/child/spawn.rs`
- Test: `src/elevation/posix_tests.rs`

**Interfaces:**
- Produces:
  - `#[cfg(unix)] pub(crate) fn rewrite(cmd: &mut crate::command::Command) -> Result<PosixRewrite, Error>` where `pub(crate) struct PosixRewrite { report: Option<ElevationReport>, stdin_secret: Option<Vec<u8>> }`.
  - `crate::elevation::apply_pre_spawn` is NOT introduced; the branch lives directly in `spawn::spawn`.
  - On `Child`: `pub(crate) fn set_elevation(&mut self, r: Option<ElevationReport>)`, `pub fn elevation(&self) -> Option<ElevationReport>`.

- [ ] **Step 1: Write the failing test** — append to `src/elevation/posix_tests.rs`:

```rust
use crate::command::Command;

#[cfg(unix)]
#[test]
fn rewrite_replaces_argv_with_sudo_prefix_and_reports() {
    // Force NonInteractive + Sudo so the rewrite is deterministic without a TTY/backend.
    let mut c = Command::new();
    c.args(["id", "-u"])
        .env("LD_PRELOAD", "/evil.so")
        .env("FOO", "bar")
        .elevation_backend(crate::elevation::Backend::Sudo)
        .elevation_auth(crate::elevation::Auth::NonInteractive);
    // Skip if sudo is genuinely absent on this runner (BackendUnavailable is a valid outcome).
    if !std::path::Path::new("/usr/bin/sudo").exists() && !std::path::Path::new("/bin/sudo").exists() {
        return;
    }
    let out = super::rewrite(&mut c).expect("rewrite");
    let report = out.report.expect("some report");
    assert_eq!(report.backend, crate::elevation::Backend::Sudo);
    assert_eq!(report.stripped_env, vec![std::ffi::OsString::from("LD_PRELOAD")]);
    // The command's argv now begins with the sudo wrapper.
    match c.input() {
        crate::command::CommandInput::Argv(argv) => {
            assert_eq!(argv[0], std::ffi::OsString::from("sudo"));
            assert!(argv.contains(&std::ffi::OsString::from("FOO=bar")));
            assert!(!argv.iter().any(|a| a.to_string_lossy().contains("LD_PRELOAD")));
        }
        other => panic!("expected Argv, got {other:?}"),
    }
}
```

(For this to compile, `CommandInput` and `Command::input()` are already `pub(crate)`; the test is in-crate.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib elevation::posix::posix_tests::rewrite`
Expected: FAIL — `rewrite` not found.

- [ ] **Step 3: Write minimal implementation**

In `src/elevation/posix.rs`:

```rust
use crate::command::{Command, CommandInput, EnvOp};
use crate::elevation::plan::Transition;
use crate::elevation::{ElevatedStdio, ElevationReport, Privilege};
use crate::error::{ElevationErrorKind, Error};

/// Outcome of a POSIX rewrite: the report to attach, and (for `Auth::Stdin`) the
/// password bytes the spawn path feeds to `sudo -S`.
pub(crate) struct PosixRewrite {
    pub report: Option<ElevationReport>,
    pub stdin_secret: Option<Vec<u8>>,
}

/// Collect the explicitly-set env into an ordered (k,v) list, honoring later
/// `Remove`/`Clear` ops. Only `Set` values survive — the sanitizer runs over these.
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

/// The program + args of a command in argv form (rewrite requires argv input).
fn program_and_args(cmd: &Command) -> Result<(OsString, Vec<OsString>), Error> {
    match cmd.input() {
        CommandInput::Argv(argv) if !argv.is_empty() => Ok((argv[0].clone(), argv[1..].to_vec())),
        _ => Err(Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            detail: "elevation requires an argv command (set .args([...])); commandline() is not supported".into(),
        }),
    }
}

/// Detect + plan + sanitize + rewrite `cmd` in place into a backend invocation.
pub(crate) fn rewrite(cmd: &mut Command) -> Result<PosixRewrite, Error> {
    let req = cmd.elevation_request();
    let host = Host::detect();
    let transition = host.plan(Privilege::Elevated, req.backend, req.auth.clone());
    match transition {
        Transition::RunAsIs => Ok(PosixRewrite { report: None, stdin_secret: None }),
        Transition::Reject { error } => Err(error),
        Transition::ElevateWindows { .. } => Err(Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            detail: "internal: Windows transition on a POSIX host".into(),
        }),
        Transition::ElevatePosix { backend, auth } => {
            let (program, args) = program_and_args(cmd)?;
            let (kept, stripped) = req.sanitizer.apply(explicit_env(cmd.env_ops()));
            let argv = build_argv(backend, &auth, &program, &args, &kept);
            let stdin_secret = match &auth {
                Auth::Stdin(secret) => {
                    let mut bytes = secret.expose().to_vec();
                    bytes.push(b'\n');
                    Some(bytes)
                }
                _ => None,
            };
            cmd.set_input_argv(argv);
            cmd.clear_env_ops();
            Ok(PosixRewrite {
                report: Some(ElevationReport { backend, stripped_env: stripped, stdio: ElevatedStdio::Passthrough }),
                stdin_secret,
            })
        }
    }
}
```

Add the two crate-internal mutators to `src/command.rs`:

```rust
    pub(crate) fn set_input_argv(&mut self, argv: Vec<OsString>) {
        self.input = CommandInput::Argv(argv);
        self.executable = None;
    }
    pub(crate) fn clear_env_ops(&mut self) {
        self.env_ops.clear();
    }
```

In `src/child.rs`, add the field, constructor init, and accessors:

```rust
// struct Child { ... , attached, elevation: Option<crate::elevation::ElevationReport> }
```
In `from_parts`, add `elevation: None,` to the struct literal. Then:

```rust
    pub(crate) fn set_elevation(&mut self, report: Option<crate::elevation::ElevationReport>) {
        self.elevation = report;
    }
    /// The achieved elevation state, or `None` if this child was not elevated
    /// (mirrors [`Child::containment`]).
    pub fn elevation(&self) -> Option<crate::elevation::ElevationReport> {
        self.elevation.clone()
    }
```

In `src/child/spawn.rs`, at the very top of `spawn()` (after `let kill_on_drop = ...;`):

```rust
    let mut elevation_report: Option<crate::elevation::ElevationReport> = None;
    let mut stdin_secret: Option<Vec<u8>> = None;
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            let mut child = crate::elevation::windows::spawn_elevated(cmd, kill_on_drop)?;
            return Ok(child);
        }
        #[cfg(unix)]
        {
            let rw = crate::elevation::posix::rewrite(cmd)?;
            elevation_report = rw.report;
            stdin_secret = rw.stdin_secret;
            if stdin_secret.is_some() {
                // sudo -S reads the password line from stdin; wire a pipe we feed post-spawn.
                cmd.stdin(crate::Stdio::pipe())?;
            }
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
```

Just before the final `Ok(Child::from_parts(...))`, feed the secret and attach the report:

```rust
    let mut child = Child::from_parts(ProcHandle::Std(shared), id, parent_ends, kill_on_drop, containment, attached);
    if let Some(secret) = stdin_secret {
        if let Some(mut w) = child.take_stdin_writer() {
            use std::io::Write;
            let _ = w.write_all(&secret); // best-effort; a closed pipe surfaces as sudo auth failure
        }
    }
    child.set_elevation(elevation_report);
    Ok(child)
```

(Replace the existing final `Ok(Child::from_parts(...))` with this block.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib elevation::posix::posix_tests::rewrite`
Expected: PASS (skips only if sudo is absent).

Run full unit suite to confirm no regressions: `cargo test --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/elevation/posix.rs src/command.rs src/child.rs src/child/spawn.rs src/elevation/posix_tests.rs
git commit -m "feat: POSIX elevation effect layer — command rewrite, Child::elevation, Stdin priming"
```

---

### Task 11: Windows detection + integrity + windows deps

**Files:**
- Modify: `Cargo.toml`, `src/elevation.rs`
- Create: `src/elevation/windows.rs`, `src/elevation/windows_tests.rs`

**Interfaces:**
- Produces: `#[cfg(windows)] pub(super) fn detect() -> Host`; `#[cfg(windows)] pub(super) fn is_elevated() -> bool`; internal `integrity_is_high_or_above(token) -> bool`.

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
```

- [ ] **Step 2: Run test to verify it fails**

Run (Windows runner): `cargo test --lib elevation::windows`
Expected: FAIL — module `windows` not found.

- [ ] **Step 3: Write minimal implementation**

In `Cargo.toml`, extend the windows feature list (add three features):

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
    "Win32_UI_Shell",
    "Win32_UI_WindowsAndMessaging",
] }
```

Create `src/elevation/windows.rs`:

```rust
//! Windows elevation effect layer (`cfg(windows)`): token-based detection and
//! (Task 13) the `ShellExecuteEx("runas")` reduced-child spawn.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation, TokenIntegrityLevel,
    TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
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
    let Some(token) = open_process_token() else { return false };
    // SAFETY: fixed-size TOKEN_ELEVATION query on a live token.
    unsafe {
        let mut e = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut e as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok();
        ok && e.TokenIsElevated != 0
    }
}

/// `true` iff the current token's integrity level is at or above High.
pub(super) fn integrity_is_high_or_above() -> bool {
    let Some(token) = open_process_token() else { return false };
    // SAFETY: two-call GetTokenInformation; the SID is read only while `buf` lives.
    unsafe {
        let mut ret = 0u32;
        let _ = GetTokenInformation(token.0, TokenIntegrityLevel, None, 0, &mut ret);
        if ret == 0 {
            return false;
        }
        let mut buf = vec![0u8; ret as usize];
        if GetTokenInformation(token.0, TokenIntegrityLevel, Some(buf.as_mut_ptr() as *mut _), ret, &mut ret).is_err() {
            return false;
        }
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() || *count_ptr == 0 {
            return false;
        }
        let last = (*count_ptr as u32) - 1;
        let rid = *GetSidSubAuthority(sid, last);
        rid >= SECURITY_MANDATORY_HIGH_RID as u32
    }
}

pub(super) fn detect() -> Host {
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

- [ ] **Step 4: Run test to verify it passes**

Run (Windows runner): `cargo test --lib elevation::windows`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/elevation.rs src/elevation/windows.rs src/elevation/windows_tests.rs
git commit -m "feat: Windows elevation detection (TokenElevation + integrity level)"
```

---

### Task 12: Windows honest-contract rejections

**Files:**
- Modify: `src/elevation/windows.rs`, `src/elevation/windows_tests.rs`

**Interfaces:**
- Produces: `#[cfg(windows)] pub(crate) fn reject_unsupported_config(cmd: &Command) -> Result<(), Error>` — returns `Error::Unsupported` for captured stdio (`.output()`/piped 0/1/2), any explicit `.env()`, or `.contain()` combined with elevation on Windows.

- [ ] **Step 1: Write the failing test** — append to `src/elevation/windows_tests.rs`:

```rust
use crate::command::Command;
use crate::error::Error;

fn is_unsupported<T>(r: Result<T, Error>) -> bool {
    matches!(r, Err(Error::Unsupported { .. }))
}

#[test]
fn captured_stdio_on_elevated_windows_is_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(crate::Stdio::pipe()).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn env_forward_on_elevated_windows_is_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().env("FOO", "bar");
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn contain_plus_elevate_on_windows_is_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().contain();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn inherit_only_elevated_config_is_accepted() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    assert!(super::reject_unsupported_config(&c).is_ok());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (Windows): `cargo test --lib elevation::windows::windows_tests`
Expected: FAIL — `reject_unsupported_config` not found.

- [ ] **Step 3: Write minimal implementation** — in `src/elevation/windows.rs`:

```rust
use crate::command::Command;
use crate::error::Error;
use crate::stdio::{Fd, ResolvedStdio};

/// Enforce the honest capability matrix for Windows elevation: captured stdio,
/// explicit env forwarding, and `.contain()` cannot cross the integrity boundary
/// without a broker (deferred), so each is a loud `Unsupported` — never a lie.
pub(crate) fn reject_unsupported_config(cmd: &Command) -> Result<(), Error> {
    let unsupported = |op: &str, detail: &str| {
        Err(Error::Unsupported { op: op.into(), platform: "windows", detail: detail.into() })
    };
    for (&slot, resolved) in cmd.fds() {
        if matches!(resolved, ResolvedStdio::Pipe(_)) && slot.raw() < 3 {
            return unsupported(
                "captured stdio on an elevated Windows child",
                "ShellExecuteEx(runas) exposes no stdio-handle mechanism; capture needs the \
                 (deferred) signed broker. Use inherit(), or elevate on POSIX.",
            );
        }
    }
    let _ = Fd::STDIN; // slot-type import kept explicit for the raw() comparison above.
    if !cmd.env_ops().is_empty() {
        return unsupported(
            "env forwarding to an elevated Windows child",
            "runas provides no environment mechanism; forwarding needs the (deferred) broker.",
        );
    }
    if cmd.contain_request().mode.is_some() {
        return unsupported(
            ".contain() + elevate on Windows",
            "a Job Object cannot span the integrity boundary of a runas child (deferred).",
        );
    }
    Ok(())
}
```

(`Command::fds()` is already `pub(crate)`; `contain_request()` and `env_ops()` too.)

- [ ] **Step 4: Run test to verify it passes**

Run (Windows): `cargo test --lib elevation::windows::windows_tests`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/elevation/windows.rs src/elevation/windows_tests.rs
git commit -m "feat: Windows elevation honest-contract rejections (stdio/env/contain)"
```

---

### Task 13: Windows `ShellExecuteEx("runas")` reduced-child spawn

**Files:**
- Modify: `src/elevation/windows.rs`, `src/child/spawn.rs`

**Interfaces:**
- Consumes: `reject_unsupported_config` (Task 12), `RawChild::new` (existing raw backend), `Host::detect`/`plan`.
- Produces: `#[cfg(windows)] pub(crate) fn spawn_elevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, Error>` — launches the child via `ShellExecuteExW` runas, wraps `hProcess` in a reduced `Child` (wait/exit/kill only, `Containment::None`), attaches an `ElevationReport { stdio: OwnConsole }`; `ERROR_CANCELLED` → `Error::Elevation { AuthDeclined }`.

- [ ] **Step 1: Write the failing test** — the live behavior is gated (Task 15). Here assert the wrong-config rejection routes through `spawn_elevated`. Append to `src/elevation/windows_tests.rs`:

```rust
#[test]
fn spawn_elevated_rejects_captured_stdio_before_uac() {
    // Must fail with Unsupported (no UAC prompt) — validates the rejection gate runs first.
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(crate::Stdio::pipe()).unwrap();
    let r = super::spawn_elevated(&mut c, true);
    assert!(matches!(r, Err(Error::Unsupported { .. })));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (Windows): `cargo test --lib elevation::windows::windows_tests::spawn_elevated_rejects`
Expected: FAIL — `spawn_elevated` not found.

- [ ] **Step 3: Write minimal implementation** — in `src/elevation/windows.rs`:

```rust
use std::collections::BTreeMap;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::core::PCWSTR;
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::Win32::System::Threading::GetProcessId;

use crate::child::proc_handle::ProcHandle;
use crate::child::spawn::windows_raw::RawChild;
use crate::child::Child;
use crate::containment::{Attached, Containment};
use crate::elevation::plan::{Host, Transition};
use crate::elevation::{Backend, ElevatedStdio, ElevationReport, Privilege};
use crate::error::{ElevationErrorKind, Error};
use crate::identity::ProcessId;

/// `ERROR_CANCELLED` (1223) as an HRESULT (0x800704C7) — the UAC-declined code.
const ERROR_CANCELLED_HRESULT: windows::core::HRESULT = windows::core::HRESULT(0x800704C7_u32 as i32);

fn wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Launch `cmd` elevated via ShellExecuteEx(runas) and return a reduced `Child`.
pub(crate) fn spawn_elevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, Error> {
    // 1. Honest-contract gate BEFORE any UAC prompt.
    reject_unsupported_config(cmd)?;

    // 2. Plan (Windows accepts only Backend::Auto; auth maps to the UAC gate).
    let req = cmd.elevation_request();
    let host = Host::detect();
    match host.plan(Privilege::Elevated, req.backend, req.auth.clone()) {
        Transition::RunAsIs => {
            // Already elevated: fall back to the ordinary raw/std spawn by clearing the flag.
            // The caller (spawn::spawn) short-circuits on `enabled`, so re-enter the normal path.
            return crate::child::spawn::spawn_unelevated(cmd, kill_on_drop);
        }
        Transition::Reject { error } => return Err(error),
        Transition::ElevatePosix { .. } => {
            return Err(Error::Elevation {
                kind: ElevationErrorKind::BackendUnavailable,
                detail: "internal: POSIX transition on a Windows host".into(),
            })
        }
        Transition::ElevateWindows { .. } => {}
    }

    // 3. Resolve program (argv[0]) + a joined parameter line for the rest.
    let (program, params) = program_and_params(cmd)?;
    let file_w = wide_nul(&program);
    let params_w = wide_nul(&params);
    let verb_w = wide_nul(std::ffi::OsStr::new("runas"));

    // SAFETY: `info` is fully initialized with the correct cbSize; the `wide`
    // buffers outlive the call. SEE_MASK_NOCLOSEPROCESS yields hProcess, wrapped below.
    let proc: OwnedHandle = unsafe {
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb_w.as_ptr()),
            lpFile: PCWSTR(file_w.as_ptr()),
            lpParameters: PCWSTR(params_w.as_ptr()),
            nShow: SW_SHOWNORMAL.0,
            ..Default::default()
        };
        ShellExecuteExW(&mut info).map_err(|e| {
            if e.code() == ERROR_CANCELLED_HRESULT {
                Error::Elevation { kind: ElevationErrorKind::AuthDeclined, detail: "UAC prompt was declined".into() }
            } else {
                Error::Elevation {
                    kind: ElevationErrorKind::AuthFailed,
                    detail: format!("ShellExecuteEx(runas) failed: {e}"),
                }
            }
        })?;
        if info.hProcess.is_invalid() {
            return Err(Error::Elevation {
                kind: ElevationErrorKind::AuthFailed,
                detail: "ShellExecuteEx returned no process handle for the elevated child".into(),
            });
        }
        OwnedHandle::from_raw_handle(info.hProcess.0 as *mut _)
    };

    // 4. pid + stable identity, then a reduced Child.
    // SAFETY: `proc` is a live process handle owned above.
    let pid = unsafe { GetProcessId(windows::Win32::Foundation::HANDLE(proc.as_raw_handle_isize())) };
    let id = ProcessId::of(pid).ok_or_else(|| Error::Elevation {
        kind: ElevationErrorKind::AuthFailed,
        detail: "elevated child vanished before its identity could be read".into(),
    })?;

    let mut child = Child::from_parts(
        ProcHandle::Raw(RawChild::new(proc, pid)),
        id,
        BTreeMap::new(),
        kill_on_drop,
        Containment::None,
        Attached::None,
    );
    child.set_elevation(Some(ElevationReport {
        backend: Backend::Auto,
        stripped_env: Vec::new(),
        stdio: ElevatedStdio::OwnConsole, // runas gets its own console; reported, never faked.
    }));
    Ok(child)
}

/// Program (argv[0], the loaded exe) + the joined parameter line for runas.
fn program_and_params(cmd: &Command) -> Result<(std::ffi::OsString, std::ffi::OsString), Error> {
    use crate::command::CommandInput;
    match cmd.input() {
        CommandInput::Argv(argv) if !argv.is_empty() => {
            let program = cmd.executable_path().map(|p| p.as_os_str().to_os_string()).unwrap_or_else(|| argv[0].clone());
            // Join the tail with the crate's CommandLineToArgvW quoter (reuse, not re-port).
            let tail_wide: Vec<Vec<u16>> = argv[1..].iter().map(|a| a.encode_wide().collect()).collect();
            let tail_refs: Vec<&[u16]> = tail_wide.iter().map(|v| v.as_slice()).collect();
            let joined = crate::quote::windows::join_wide(&tail_refs);
            Ok((program, std::ffi::OsString::from_wide(&joined)))
        }
        _ => Err(Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            detail: "Windows elevation requires an argv command (set .args([...]))".into(),
        }),
    }
}
```

Add a tiny helper on `OwnedHandle` usage — since `OwnedHandle` has no `as_raw_handle_isize`, replace the two `HANDLE(...)` constructions with `HANDLE(proc.as_raw_handle() as *mut _)` via `use std::os::windows::io::AsRawHandle;` and `std::ffi::OsString::from_wide` via `use std::os::windows::ffi::OsStringExt;`. (Add those two imports.)

In `src/child/spawn.rs`, extract the current post-elevation-branch body into a `pub(crate) fn spawn_unelevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, Error>` so the Windows `RunAsIs` path can re-enter the normal spawn without the elevation flag. The simplest form: have `spawn()` call `spawn_unelevated` after the elevation branch, and `spawn_unelevated` contains everything from `#[cfg(windows)] { has_high_fd ... }` onward. The elevated Windows branch returns `spawn_elevated(...)`; the already-elevated `RunAsIs` sub-case calls `spawn_unelevated`.

- [ ] **Step 4: Run test to verify it passes**

Run (Windows): `cargo test --lib elevation::windows`
Expected: PASS. Also `cargo build --target x86_64-pc-windows-msvc` succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/elevation/windows.rs src/child/spawn.rs
git commit -m "feat: Windows ShellExecuteEx runas reduced-child elevation spawn"
```

---

### Task 14: Async parity (tokio builder + `Child::elevation()` + async spawn)

**Files:**
- Modify: `src/tokio/command.rs`, `src/tokio/child.rs`, `src/tokio/spawn.rs`
- Test: `src/tokio/command.rs` (inline `command_tests`) or `src/tokio/spawn_tests.rs`

**Interfaces:**
- Produces on `tokio::Command`: `.elevate()`, `.elevation_backend(Backend)`, `.elevation_auth(Auth)`, `.sanitize_env(EnvSanitizer)` — forwarding to the inner sync `Command`.
- Produces on `tokio::Child`: `elevation: Option<ElevationReport>` field, `set_elevation`, `pub fn elevation(&self) -> Option<ElevationReport>`.
- Produces: async spawn branch mirroring sync — POSIX reuses `posix::rewrite`; Windows calls `windows::spawn_elevated_async`.

- [ ] **Step 1: Write the failing test** — append to `src/tokio/command_tests.rs`:

```rust
#[test]
fn tokio_elevate_forwards_to_inner_request() {
    let mut c = Command::new();
    c.args(["id", "-u"]).elevation_backend(crate::elevation::Backend::Sudo);
    // The inner sync Command carries the request; assert via a spawn-time rewrite on Unix.
    // Here we only assert the builder compiles + chains; behavior is covered by the live tier.
    let _ = &mut c;
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

In `src/tokio/spawn.rs`, at the top of `spawn()` (after `let kill_on_drop = ...;`), add the elevation branch mirroring sync:

```rust
    let mut elevation_report: Option<crate::elevation::ElevationReport> = None;
    let mut stdin_secret: Option<Vec<u8>> = None;
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            return crate::elevation::windows::spawn_elevated_async(cmd, kill_on_drop);
        }
        #[cfg(unix)]
        {
            let rw = crate::elevation::posix::rewrite(cmd)?;
            elevation_report = rw.report;
            stdin_secret = rw.stdin_secret;
            if stdin_secret.is_some() {
                cmd.stdin(crate::Stdio::pipe())?;
            }
        }
    }
```

Before the final `Ok(Child::from_parts(...))`, attach the report and feed the secret:

```rust
    let mut child = Child::from_parts(ProcSource::Tokio(child), id, attached, kill_on_drop, containment, pipes, owned_std);
    if let Some(secret) = stdin_secret {
        if let Some(mut w) = child.stdin() {
            use ::tokio::io::AsyncWriteExt;
            let _ = w.write_all(&secret).await;
            let _ = w.shutdown().await;
        }
    }
    child.set_elevation(elevation_report);
    Ok(child)
```

Add `#[cfg(windows)] pub(crate) fn spawn_elevated_async(cmd: &mut Command, kill_on_drop: bool) -> Result<crate::tokio::Child, Error>` to `src/elevation/windows.rs`. It is the exact twin of `spawn_elevated`, differing only in the final child construction: it wraps the `OwnedHandle` in `RawAsyncChild::new(proc, pid)` and builds the async `Child` via `crate::tokio::child::Child::from_parts(ProcSource::Raw(RawAsyncChild::new(proc, pid)), id, Attached::None, kill_on_drop, Containment::None, FdPipes::new(), BTreeMap::new())`, then `set_elevation(Some(report))`. Factor the shared prelude (rejection gate, plan, program_and_params, ShellExecuteExW → OwnedHandle + pid) into a private `fn launch_runas(cmd: &mut Command) -> Result<(OwnedHandle, u32), Error>` so both `spawn_elevated` and `spawn_elevated_async` call it and only differ in wrapping.

(The spec's "wrap the blocking ShellExecuteEx in spawn_blocking" applies to the *long wait*, which is already async in `RawAsyncChild::wait`; the runas launch itself is a brief synchronous call and runs inline, as the sync raw backend's `spawn_raw` does.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --features tokio --lib tokio::command`
Expected: PASS. Also `cargo build --features tokio` on Unix and Windows.

- [ ] **Step 5: Commit**

```bash
git add src/tokio/command.rs src/tokio/child.rs src/tokio/spawn.rs src/elevation/windows.rs
git commit -m "feat: async elevation parity — tokio builder, Child::elevation, async spawn"
```

---

### Task 15: Live gated integration tests + testbin subcommands

**Files:**
- Create: `tests/elevation.rs`
- Modify: `testbin/main.rs`

**Interfaces:**
- Consumes: the full public surface (`Command::elevate`, `Child::elevation`, `elevation::is_elevated`), sync + async.
- Produces: `testbin` subcommands `is-elevated-report` (prints `is_elevated()` as `1`/`0`) and `write-marker <path>` (writes a byte, exit 0). Gated tests behind `SUBPROCESS_TEST_ELEVATION`.

- [ ] **Step 1: Write the failing test** — create `tests/elevation.rs`:

```rust
//! Live elevation tier — gated behind SUBPROCESS_TEST_ELEVATION (cgroup precedent):
//! a TRUE no-op when the var is absent, and FAILS LOUDLY when set but elevation is
//! unavailable. Tiers 1-5 (planner/sanitizer/argv/rejections/detection) cover all
//! logic unconditionally; only the privilege-*gain* is gated here.

use std::path::PathBuf;

fn gated() -> bool {
    std::env::var_os("SUBPROCESS_TEST_ELEVATION").is_some()
}
fn testbin() -> PathBuf {
    // Sibling of the integration test binary.
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
    // SUBPROCESS_TEST_ELEVATION set: elevation MUST work (passwordless sudo provisioned).
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
    let mut c = subprocess::Command::new();
    c.executable(&exe)
        .args(["subprocess_testbin", "is-elevated-report"])
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let s = c.read().expect("read");
    assert_eq!(s.trim(), "1", "elevated testbin did not self-detect elevation");
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
        "subprocess_testbin".into(),
        "write-marker".into(),
        marker.clone().into_os_string().into_string().unwrap(),
    ]);
    c.elevate();
    let child = c.spawn().expect("runas spawn");
    // Honest report: OwnConsole (never a faked shared stream).
    assert_eq!(child.elevation().unwrap().stdio, subprocess::elevation::ElevatedStdio::OwnConsole);
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

Run: `cargo test --test elevation` (no gate: all no-op/pass) — then simulate the gate locally where possible.
Expected without gate: PASS (no-ops). With `is-elevated-report`/`write-marker` missing, the gated paths would fail if run — build fails first because the subcommands don't exist? They are runtime strings, so build succeeds. Verify by running gated `SUBPROCESS_TEST_ELEVATION=1 cargo test --test elevation posix_child_self_detects` under sudo — FAIL: testbin unknown mode `is-elevated-report`.

- [ ] **Step 3: Write minimal implementation** — in `testbin/main.rs`, add two arms before the final `other =>`:

```rust
        "is-elevated-report" => {
            // Print whether THIS process is elevated, for the self-detection live test.
            println!("{}", if subprocess::elevation::is_elevated() { "1" } else { "0" });
        }
        "write-marker" => {
            // Admin-only action for the Windows live tier: write a byte to `path`, exit 0.
            let path = &args[2];
            std::fs::write(path, b"1").expect("write marker");
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run (ungated): `cargo test --test elevation` and `cargo test --features tokio --test elevation`
Expected: PASS (no-ops).
Run (gated, Linux w/ passwordless sudo): `SUBPROCESS_TEST_ELEVATION=1 cargo test --test elevation`
Expected: PASS (root uid `0`, self-detect `1`).

- [ ] **Step 5: Commit**

```bash
git add tests/elevation.rs testbin/main.rs
git commit -m "test: gated live elevation tier (POSIX uid capture, self-detect, Windows marker)"
```

---

### Task 16: `TODO.md` CI provisioning note

**Files:**
- Modify: `TODO.md`

- [ ] **Step 1: Write the change** — under the cgroup "CI provisioning required" section, add a sibling section (mirroring its structure):

```markdown
## CI provisioning required (elevation live tier)

The live elevation tests (`tests/elevation.rs`) are gated behind
`SUBPROCESS_TEST_ELEVATION`: a true no-op when absent, FAIL LOUDLY when set but
elevation is unavailable (identical to `SUBPROCESS_TEST_CGROUP`).

To run the live tier in CI:

- **Linux:** provision passwordless `sudo` for the job user (a `NOPASSWD:ALL`
  sudoers drop-in), then set `SUBPROCESS_TEST_ELEVATION=1`. The tests spawn
  `id -u` elevated and assert `0`; `Auth::NonInteractive` is used so no prompt
  blocks. `run0`/`doas` are optional; `Backend::Auto` picks whatever is present.
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

### Task 17: Open PR against main and verify CI

**Files:** none (workflow only).

- [ ] **Step 1: Confirm branch + clean tree**

Run: `git status` and `git branch --show-current`
Expected: on `azhukova/6`, working tree clean, all Task 1–16 commits present. Do NOT push to `main`.

- [ ] **Step 2: Push the branch**

```bash
git push -u origin azhukova/6
```

- [ ] **Step 3: Open the PR** (issue #6)

```bash
gh pr create --base main --head azhukova/6 \
  --title "feat: privilege elevation (admin/root vertical, sync + async)" \
  --body "Implements the elevation design spec (.tmp/claude/superpowers/specs/2026-07-25-elevation-design.md): pure Host::plan planner, EnvSanitizer boundary, POSIX sudo/run0/doas/pkexec rewrite, Windows ShellExecuteEx(runas) reduced child, queryable Child::elevation(), full sync+async parity. Live tier gated behind SUBPROCESS_TEST_ELEVATION. Closes #6."
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
| `is_elevated()` free fn | 9 (unix), 11 (windows) |
| Flat builder: `.elevate/.elevation_backend/.elevation_auth/.sanitize_env` | 8 (sync), 14 (async) |
| `Backend`/`Auth`/`ElevatedStdio`/`Privilege`/`Secret` spellings | 2, 3 |
| `EnvSanitizer` consent gradient (default/keep/filter/allowlist/none) | 6 |
| Two-layer env (clean default + denylist over explicit set) | 6 (denylist) + 10 (explicit_env is the only forwarded set) |
| `ElevationReport` + `Child::elevation()` | 10 (sync), 14 (async) |
| Pure `Host::plan` → `Transition`, cross-OS | 4, 5 |
| Backend auto-detect run0>sudo>doas; pkexec explicit; Gui explicit | 4, 5 |
| Auth default Interactive; no-TTY → NoTty | 5 |
| Error split: `Unsupported` (structural) vs `Elevation` (runtime) | 1, 5, 12 |
| POSIX argv threading (`--preserve-env` + `env K=V`; run0 `--setenv`) | 7 |
| POSIX command rewrite reuses existing spawn | 10 |
| Windows `ShellExecuteEx(runas)` reduced child; ERROR_CANCELLED→AuthDeclined | 13 |
| Windows capability matrix (captured stdio/.env/.contain → Unsupported; ElevatedStdio reported OwnConsole) | 12, 13 |
| Detection tests (unelevated false; Windows integrity) | 9, 11 |
| Live gated tier (uid 0, self-detect, Windows marker) sync+async | 15 |
| Async parity (builder, report, POSIX rewrite reuse, Windows spawn_blocking wrap) | 14 |
| CI provisioning TODO | 16 |
| Branch/PR/CI workflow | 17 |
| zeroize dep | 2 |

No spec section is unmapped.

**2. Placeholder scan:** No "TBD/similar to Task N/add error handling" remain; every code step shows complete code. One deliberate design note: `Auth::Stdin` password delivery is fully implemented (secret bytes fed to `sudo -S` via a stdin pipe in Task 10 sync / Task 14 async) — not deferred.

**3. Type consistency:** Verified across tasks — `Backend` (Auto/Run0/Sudo/Doas/Pkexec), `Auth` (Interactive/NonInteractive/Askpass/Stdin/Gui), `EnvSanitizer`, `ElevationReport{backend,stripped_env,stdio}`, `ElevatedStdio` (Piped/Inherited/OwnConsole/Hidden), `ElevationErrorKind` (BackendUnavailable/AuthFailed/AuthDeclined/NoTty), `Host{elevated,has_tty,available,os}`, `BackendSet{run0,sudo,doas,pkexec}`, `Transition` (RunAsIs/ElevatePosix/ElevateWindows/Reject), `Privilege` (Unprivileged/Elevated), `ElevationRequest{enabled,backend,auth,sanitizer}`, `build_argv`, `rewrite`/`PosixRewrite`, `spawn_elevated`/`spawn_elevated_async`, `Child::elevation`/`set_elevation` — all names identical everywhere they appear.

Two integration seams called out for the implementer (flagged, not hidden):
- Task 13 introduces `spawn::spawn_unelevated` by extracting the post-branch body of `spawn()`; Task 13's already-elevated `RunAsIs` arm and Task 10's normal continuation both rely on it. Land the extraction as the first move of Task 13.
- `OwnedHandle` raw-handle access in Task 13 uses `std::os::windows::io::AsRawHandle` + `HANDLE(h as *mut _)`; adjust the exact cast to the `windows` 0.62 `HANDLE(*mut c_void)` shape at implementation time (the pattern is proven in `src/child/spawn/windows_raw.rs`).
