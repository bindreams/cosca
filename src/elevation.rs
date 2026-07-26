//! Cross-platform privilege elevation. Elevation wraps the CHILD (a
//! `sudo`/`run0`/`doas`/`pkexec` prefix on POSIX; `ShellExecuteEx("runas")` on
//! Windows), never the calling process. See the pure planner in [`plan`].

use std::ffi::OsString;
use std::path::PathBuf;

use zeroize::Zeroize;

pub mod plan;
#[cfg(unix)]
#[path = "elevation/posix.rs"]
pub mod posix;
pub mod sanitize;
#[cfg(windows)]
#[path = "elevation/windows.rs"]
pub mod windows;

pub use sanitize::EnvSanitizer;

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
    /// POSIX [`Auth::Stdin`]: fd0 is the elevation password channel (EOF after
    /// the password), not the caller's stdin.
    StdinConsumed,
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
    /// Vars the crate's own sanitizer dropped before forwarding (also `log`ged). The
    /// vars that DO survive are forwarded to the backend but remain subject to the
    /// site's own policy — sudo's `env_check`/`env_delete` and `secure_path` may still
    /// filter or override a forwarded var, which the crate cannot observe.
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

/// The single source of the "already elevated, no wrapper needed" report. Every
/// sync/async spawn arm that short-circuits on ambient privilege calls this, so the
/// literal is never hand-copied.
// The Windows `RunAsIs` arm (Task 14) consumes this; the POSIX spawn arms that
// short-circuit on ambient privilege land in a later task, so it stays dead there.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn already_elevated_report(stdio: ElevatedStdio) -> ElevationReport {
    ElevationReport {
        via: ElevatedVia::AlreadyElevated,
        stripped_env: Vec::new(),
        stdio,
    }
}

/// Map a raw kill/terminate `io::Error` on an ELEVATED wrapper child to the typed
/// `Unkillable` error. EPERM (POSIX) and ACCESS_DENIED (Windows) both surface as
/// `io::ErrorKind::PermissionDenied`; anything else, or a non-elevated child, stays `Io`.
pub(crate) fn map_elevated_kill_error(err: std::io::Error, elevated_wrapper: bool) -> crate::error::Error {
    use crate::error::{ElevationErrorKind, Error};
    if elevated_wrapper && err.kind() == std::io::ErrorKind::PermissionDenied {
        Error::Elevation {
            kind: ElevationErrorKind::Unkillable,
            detail: format!("could not signal the elevated child: {err}"),
        }
    } else {
        Error::Io(err)
    }
}

/// Whether `backend_path` is unusable as an elevation backend: missing, or (unix
/// only) present but lacking the executable bit (cleared exec bit, `noexec` mount,
/// SELinux denial). Non-unix has no portable executable-bit concept, so existence
/// is the only check.
// Reached from `remap_derived_spawn_error` on the unix sync spawn arm.
#[cfg(unix)]
fn backend_unusable(backend_path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let Ok(cpath) = std::ffi::CString::new(backend_path.as_os_str().as_bytes()) else {
        return true; // a NUL byte in the path can never name a real file
    };
    // SAFETY: `cpath` is a valid, NUL-terminated C string for the lifetime of the call.
    unsafe { libc::faccessat(libc::AT_FDCWD, cpath.as_ptr(), libc::X_OK, libc::AT_EACCESS) != 0 }
}

// Dead on non-unix: `remap_derived_spawn_error` has no non-unix production caller.
#[allow(dead_code)]
#[cfg(not(unix))]
fn backend_unusable(backend_path: &std::path::Path) -> bool {
    !backend_path.exists()
}

/// Remap a DERIVED-backend spawn error honestly. The derived command's program IS the
/// elevation backend, but it also carries the caller's `current_dir()` — a bad cwd
/// yields the same `NotFound`/`PermissionDenied` kinds. So only remap to
/// `BackendUnavailable` when the backend path itself is unusable (missing, or on unix
/// present-but-not-executable); otherwise the original `Io` survives. Either way the
/// underlying `io::Error` and the backend path are embedded so the cause is never lost.
// Consumed by the unix sync spawn arm (`crate::child::spawn::spawn`); dead on non-unix,
// where the Windows arm delegates straight to `windows::spawn_elevated`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn remap_derived_spawn_error(
    err: crate::error::Error,
    backend_path: &std::path::Path,
) -> crate::error::Error {
    use crate::error::{ElevationErrorKind, Error};
    match err {
        Error::Io(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) && backend_unusable(backend_path) =>
        {
            Error::Elevation {
                kind: ElevationErrorKind::BackendUnavailable,
                detail: format!(
                    "elevation backend {} could not be executed: {e}",
                    backend_path.display()
                ),
            }
        }
        other => other,
    }
}

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
