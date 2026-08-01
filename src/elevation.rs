//! Cross-platform privilege elevation. Elevation wraps the CHILD (a
//! `sudo`/`run0`/`doas`/`pkexec` prefix on POSIX; `ShellExecuteEx("runas")` on
//! Windows), never the calling process.

use std::ffi::OsString;
use std::path::PathBuf;

use zeroize::Zeroize;

// Effect-layer submodules are crate-internal (matching the `containment` convention); only the
// public types below are exported. The one exception is `controlling_terminal_present`, a
// `#[doc(hidden)]` probe the separate `testbin` binary (an external consumer) needs — re-exported
// at this module's root so `posix` itself stays `pub(crate)`.
// Pure and cross-tested, so it is compiled everywhere — but its only in-crate
// caller is `posix.rs`, which is `cfg(unix)`. Off-unix every item is therefore
// test-only, exactly like the `command.rs` accessors it calls.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) mod macos;
pub(crate) mod plan;
#[cfg(unix)]
#[path = "elevation/posix.rs"]
pub(crate) mod posix;
pub(crate) mod sanitize;
#[cfg(windows)]
#[path = "elevation/windows.rs"]
pub(crate) mod windows;

#[cfg(unix)]
#[doc(hidden)]
pub use posix::controlling_terminal_present;
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
/// explicit-only (`run0` spawns a PID-1-parented unit, not a descendant of the caller; a
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
///
/// `Gui` is the system graphical authentication dialog — the one form of elevation
/// that works in a windowed application, which has no controlling terminal to
/// prompt on:
///
/// | Platform | `Auth::Gui` | Backend |
/// |---|---|---|
/// | Windows | the UAC consent gate | `Backend::Auto` |
/// | macOS | Authorization Services, via `osascript` | `Backend::Auto` |
/// | Linux | polkit, via `pkexec` | `Backend::Pkexec` |
///
/// The three are not interchangeable in what they can carry. Read
/// [`ElevatedVia::MacosOsascript`] before using `Auth::Gui` on macOS: the elevated
/// program leaves this process's tree, so stdio, exit-status fidelity, `kill()` and
/// `.contain()` all behave differently there.
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
    /// macOS [`Auth::Gui`]: the caller's stdio was NOT given to the elevated
    /// program. The stdout/stderr you configure are **osascript's**, and what flows
    /// through them is a relay, not the program's own streams:
    ///
    /// - the program's stdout is captured in full by `osascript` and written to
    ///   osascript's stdout once the program exits — **buffered**, never streamed;
    /// - that stdout round-trips through UTF-8 text and loses its final line
    ///   ending, so byte-exact binary output does not survive;
    /// - the program's **stderr is not relayed at all**. osascript's stderr carries
    ///   AppleScript's own error text (which quotes the program's stderr when it
    ///   exits non-zero), not the program's stream;
    /// - the program's stdin comes from Authorization Services, not the caller.
    ///   Configuring a pipe or file on fd0 is rejected, because nothing would ever
    ///   read it;
    /// - the relay is written only when the program exits, so killing or dropping
    ///   the child early yields an empty or truncated capture with no signal that
    ///   the program is still running. See [`ElevatedVia::MacosOsascript`];
    /// - **on a non-zero exit there is no relay at all.** `do shell script` raises
    ///   an AppleScript error instead of returning a result, so the program's
    ///   stdout is discarded entirely and only osascript's error text reaches
    ///   stderr. A caller that needs output on the failure path must have the
    ///   program write it somewhere the caller reads, not rely on the relay.
    OsascriptRelay,
}

/// How elevation was achieved. Distinct from [`Backend`]: `WindowsUac` is the
/// dedicated Windows runas disposition (NOT `Backend::Auto`, a POSIX concept).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElevatedVia {
    /// A POSIX backend wrapped the child (the resolved backend that ran).
    Wrapped(Backend),
    /// Windows `ShellExecuteEx("runas")` elevated the child through UAC.
    WindowsUac,
    /// macOS `osascript … with administrator privileges` asked Authorization
    /// Services to run the command as root.
    ///
    /// The elevated program is **not in this process's tree**. macOS runs it under
    /// `com.apple.security.authtrampoline`, parented to `launchd`, so the tracked
    /// [`crate::Child`] is the `osascript` front-end, not the program:
    ///
    /// - **Left alone, osascript outlives the program**: it blocks until the program
    ///   exits, so [`crate::Child::wait`] returning means the elevated work is
    ///   finished.
    /// - **Killed or dropped early, it does not.** [`crate::Child::kill`] — and the
    ///   drop-kill that [`crate::Command::kill_on_drop`] performs, which is **on by
    ///   default** — reaches only osascript. The root program keeps running, nothing
    ///   unprivileged can stop it, and once the front-end is gone its completion and
    ///   its exit status are unobservable. If you need the program's outcome, do not
    ///   kill the child and do not drop it before [`crate::Child::wait`] returns. (An
    ///   explicit `.kill_on_drop(true)` cannot currently be told apart from the
    ///   builder default, so this is documented rather than refused.)
    /// - `wait` reports **osascript's** exit status. It is zero if and only if the
    ///   elevated program exited zero; a non-zero code is osascript's, not the
    ///   program's — and on that path the program's stdout is discarded rather than
    ///   relayed (see [`ElevatedStdio::OsascriptRelay`]).
    /// - A **cancelled** authentication dialog is one such non-zero exit, not a
    ///   spawn-time [`crate::error::ElevationErrorKind::AuthDeclined`].
    /// - Process containment cannot span the boundary, so `.contain()` is rejected
    ///   up front.
    /// - A `current_dir()` the caller can traverse but root cannot (NFS
    ///   `root_squash`) fails the `cd` on the far side of the trampoline: the program
    ///   never runs and the failure surfaces as a bare non-zero exit, because the
    ///   explaining stderr is not relayed.
    ///
    /// The command text is visible to anyone able to inspect the running processes —
    /// a real difference from `sudo` and from UAC. Do not put a secret in the argv of
    /// an elevated macOS command.
    ///
    /// See [`ElevatedStdio::OsascriptRelay`] for what happens to stdio.
    MacosOsascript,
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
// Consumed by the Windows `RunAsIs` arms only (the POSIX rewrite reports
// `AlreadyElevated` through `PosixRewrite`), hence the gated allow.
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
