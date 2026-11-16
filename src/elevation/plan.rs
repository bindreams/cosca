//! The PURE elevation planner: plain-data [`Host`] + a syscall-free
//! [`Host::plan`]. A Linux test constructs a Windows-shaped `Host` and asserts
//! the Windows decision — the `Containment` host-testing pattern.

use std::path::PathBuf;

use super::{Auth, Backend, Privilege};
use crate::error::{ElevationErrorKind, Error};

/// Which OS the effect layer will use. Data, not `cfg!`, so `plan` is cross-tested.
// The planner models EVERY platform's decision on ANY host (that is the whole point — a
// Windows-shaped `Host` is planned on Linux and vice versa), so in a non-test single-platform
// build the other platform's variant is never constructed. That is by design, not dead logic.
#[allow(
    dead_code,
    reason = "the other platform's Os variant is never constructed in a single-platform non-test build"
)]
// The enum is named `Os` and `MacOs` names an OS, so the variant unavoidably ends
// with the enum's name. Renaming either to satisfy the lint would make both worse.
#[allow(
    clippy::enum_variant_names,
    reason = "MacOs necessarily ends with the enum's own name Os; renaming either would make both worse"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Every POSIX host except macOS and Linux — the BSDs, illumos. Planned as Linux is, except
    /// for what needs Linux itself.
    Unix,
    /// Linux: a Unix whose `/proc` cosca launches pkexec through ([`Backend::Pkexec`]).
    Linux,
    MacOs,
    Windows,
}

/// Is this request the macOS graphical path? Deliberately privilege-free: it is a
/// property of the REQUEST, so the same answer holds for a root and a non-root
/// caller. Every site that needs "is this osascript?" calls THIS — the structural
/// matrix, [`Host::plan`]'s resolution arm, and the effect layer's gate selection.
/// Deriving it inline in three places is how they drift apart.
pub(crate) fn is_macos_gui_auto(os: Os, backend: Backend, auth: &Auth) -> bool {
    os == Os::MacOs && matches!(auth, Auth::Gui) && backend == Backend::Auto
}

/// What the search for one elevation front found: its absolute path, nothing, or an entry it could
/// not examine.
#[derive(Debug, Clone, Default)]
pub enum FrontState {
    /// Not there: the search ended without a candidate.
    #[default]
    Absent,
    /// The file the search found. Carrying the ABSOLUTE path is what closes the CWD-hijack hole:
    /// the validated path is exactly the one argv[0] emits.
    Found(PathBuf),
    /// The search stopped on an entry it could not examine (`error`), so whether the front is there
    /// is unknown. The planner reports it, as the cause of `BackendUnavailable`, only if it needs
    /// the front.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only the POSIX detection finds a front it cannot examine")
    )]
    Unexamined(std::sync::Arc<Error>),
}

/// What the search for each elevation front found, filled by `detect` (the one POSIX program lookup,
/// [`crate::resolve::posix::lookup`]) and faked in tests.
#[derive(Debug, Clone, Default)]
pub struct BackendSet {
    pub sudo: FrontState,
    pub doas: FrontState,
    pub pkexec: FrontState,
    /// macOS only: `/usr/bin/osascript`, the graphical elevation front-end. Not a [`Backend`]: it
    /// does not wrap the child, it asks Authorization Services to run the command as root.
    pub osascript: FrontState,
}

impl BackendSet {
    /// The front `backend` runs: the backend itself, its program name and its state. `Backend::Auto`
    /// runs the first of `sudo`, `doas` not absent (an unexamined `sudo` is taken, so `doas` never
    /// replaces it), and `None` when neither is on `PATH`.
    pub(crate) fn resolve(&self, backend: Backend) -> Option<(Backend, &'static str, &FrontState)> {
        match backend {
            Backend::Sudo => Some((Backend::Sudo, "sudo", &self.sudo)),
            Backend::Doas => Some((Backend::Doas, "doas", &self.doas)),
            Backend::Pkexec => Some((Backend::Pkexec, "pkexec", &self.pkexec)),
            Backend::Auto => [Backend::Sudo, Backend::Doas]
                .into_iter()
                .filter_map(|front| self.resolve(front))
                .find(|(_, _, state)| !matches!(state, FrontState::Absent)),
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
    /// `sysctl kern.argmax` — the exec argument budget, read at detect time
    /// because it has changed across macOS releases and must never be guessed.
    /// `None` when the query failed or the platform has no equivalent; the macOS
    /// length guard is then skipped rather than run against an invented number.
    /// Only the macOS graphical path reads it; it lives here because the planner
    /// is plain data.
    pub arg_max: Option<usize>,
    /// What [`BackendSet::pkexec`]'s `--version` said; asked only for a request that launches pkexec
    /// — `Backend::Pkexec` with `Auth::Gui`, from a non-root caller, on Linux.
    // Read only by the POSIX rewrite.
    #[cfg_attr(not(unix), allow(dead_code, reason = "read only by the POSIX rewrite"))]
    pub pkexec_version: super::pkexec::PkexecVersion,
    /// [`BackendSet::pkexec`], opened by detection: the version probe and the launch both exec this
    /// descriptor's file (`/proc/self/fd/N`), so a file renamed over the path between them is
    /// never run. `Some` exactly for a request that launches pkexec, when its file was opened.
    // Read only by the POSIX rewrite.
    #[cfg_attr(not(unix), allow(dead_code, reason = "read only by the POSIX rewrite"))]
    pub pkexec_pin: Option<std::sync::Arc<std::fs::File>>,
}

/// The planner's decision. Not `PartialEq` — `Reject` wraps a non-comparable
/// [`Error`]; tests use `matches!` and inspect fields.
// Cross-platform like [`Os`]: the effect arm for the other platform (and its fields) is never
// constructed in a single-platform non-test build, but is exercised by the cross-OS planner tests.
#[allow(
    dead_code,
    reason = "the other platform's effect arm is never constructed in a single-platform non-test build"
)]
#[derive(Debug)]
pub enum Transition {
    RunAsIs,
    ElevatePosix {
        backend: Backend,
        path: PathBuf,
        auth: Auth,
    },
    ElevateWindows {
        auth: Auth,
    },
    ElevateMacosGui {
        /// The absolute path of `/usr/bin/osascript`, carried for the same reason
        /// the POSIX backends carry theirs: the validated path is exactly the one
        /// argv[0] emits, so nothing on PATH can be substituted for it.
        osascript: PathBuf,
        /// The detected `kern.argmax`, carried so the effect layer stays pure.
        arg_max: Option<usize>,
    },
    Reject {
        error: Error,
    },
}

impl Host {
    /// The facts for a request naming `backend` and `auth`, which decide whether `pkexec` is asked
    /// its version. `elevated` is the caller's privilege. Unix looks for `sudo`, `doas` and `pkexec`
    /// on `path_var` (`None` finds none); macOS also finds the fixed `/usr/bin/osascript`. Windows
    /// ignores `path_var`.
    pub fn detect(backend: Backend, auth: &Auth, path_var: Option<&std::ffi::OsStr>, elevated: bool) -> Host {
        #[cfg(unix)]
        {
            super::posix::detect_with(
                path_var,
                super::posix::host_os(),
                elevated,
                backend,
                auth,
                |p| std::fs::canonicalize(p),
                super::posix::run_version_probe,
            )
        }
        #[cfg(windows)]
        {
            let _ = (backend, auth, path_var);
            super::windows::detect(elevated)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (backend, auth, path_var);
            Host {
                elevated,
                has_tty: false,
                available: BackendSet::default(),
                os: Os::Unix,
                arg_max: None,
                pkexec_version: crate::elevation::pkexec::PkexecVersion::NotProbed,
                pkexec_pin: None,
            }
        }
    }

    pub fn plan(&self, target: Privilege, backend: Backend, auth: Auth) -> Transition {
        if target != Privilege::Elevated {
            return Transition::RunAsIs;
        }
        // Structural matrix — privilege-independent, BEFORE the already-elevated
        // short-circuit, so an impossible combo never passes under root.
        let structural = match self.os {
            Os::Windows => structural_windows(backend, &auth),
            os => structural_posix(os, backend, &auth, self),
        };
        if let Some(error) = structural {
            return Transition::Reject { error };
        }
        if self.elevated {
            return Transition::RunAsIs;
        }
        match self.os {
            Os::Windows => Transition::ElevateWindows { auth },
            Os::MacOs if is_macos_gui_auto(self.os, backend, &auth) => {
                match &self.available.osascript {
                    FrontState::Found(p) => Transition::ElevateMacosGui {
                        osascript: p.to_path_buf(),
                        arg_max: self.arg_max,
                    },
                    FrontState::Unexamined(error) => Transition::Reject {
                        error: unexamined("/usr/bin/osascript", error),
                    },
                    // /usr/bin/osascript can genuinely be missing.
                    FrontState::Absent => reject_backend_unavailable(
                        "/usr/bin/osascript is missing; macOS graphical elevation needs it",
                        None,
                    ),
                }
            }
            Os::MacOs | Os::Unix | Os::Linux => self.resolve_posix(backend, auth),
        }
    }

    fn resolve_posix(&self, backend: Backend, auth: Auth) -> Transition {
        let Some((resolved, program, state)) = self.available.resolve(backend) else {
            return reject_backend_unavailable("no sudo/doas on PATH for Backend::Auto", None);
        };
        let path = match state {
            FrontState::Found(p) => p.to_path_buf(),
            FrontState::Unexamined(error) => {
                return Transition::Reject {
                    error: unexamined(program, error),
                }
            }
            FrontState::Absent => {
                return reject_backend_unavailable(&format!("forced backend {resolved:?} is not on PATH"), None)
            }
        };
        // Environmental, not structural: whether a TTY is attached is a fact about
        // this run, not the (backend, auth) config, so it stays here rather than in
        // `structural_posix` — it legitimately differs by invocation.
        if matches!(auth, Auth::Interactive) && !self.has_tty {
            return Transition::Reject {
                error: Error::Elevation {
                    kind: ElevationErrorKind::NoTty,
                    detail: "Auth::Interactive requires a controlling terminal; use \
                             Auth::NonInteractive / Askpass / Stdin, or run from a TTY"
                        .into(),
                    source: None,
                },
            };
        }
        Transition::ElevatePosix {
            backend: resolved,
            path,
            auth,
        }
    }
}

/// Whether a request launches pkexec: whether [`Host::plan`], on `os` with a pkexec on `PATH`,
/// yields `ElevatePosix` for it. Detection opens and probes pkexec only then, and asks the planner
/// itself rather than restating its rules.
// Only the POSIX detection calls it.
#[cfg_attr(not(unix), allow(dead_code, reason = "only the POSIX detection calls it"))]
pub(crate) fn launches_pkexec(os: Os, backend: Backend, auth: &Auth, elevated: bool) -> bool {
    let host = Host {
        elevated,
        has_tty: true,
        available: BackendSet {
            pkexec: FrontState::Found(PathBuf::from("pkexec")),
            ..BackendSet::default()
        },
        os,
        arg_max: None,
        pkexec_version: super::pkexec::PkexecVersion::NotProbed,
        pkexec_pin: None,
    };
    matches!(
        host.plan(Privilege::Elevated, backend, auth.clone()),
        Transition::ElevatePosix {
            backend: Backend::Pkexec,
            ..
        }
    )
}

/// `BackendUnavailable` for the front `program`, which could not be examined (a `PATH` entry, or the
/// real file of the one found): `error` is the cause, and says which file and what failed.
fn unexamined(program: &str, error: &std::sync::Arc<Error>) -> Error {
    backend_unavailable(
        &format!("{program} could not be found or opened"),
        Some(std::sync::Arc::clone(error)),
    )
}

fn backend_unavailable(detail: &str, source: Option<std::sync::Arc<Error>>) -> Error {
    Error::Elevation {
        kind: ElevationErrorKind::BackendUnavailable,
        detail: detail.into(),
        source,
    }
}

fn reject_backend_unavailable(detail: &str, source: Option<std::sync::Arc<Error>>) -> Transition {
    Transition::Reject {
        error: backend_unavailable(detail, source),
    }
}

/// The full POSIX (backend, auth) matrix, privilege-independent: called BEFORE the
/// already-elevated short-circuit so an impossible combo never passes under root.
///
/// The Askpass/Stdin-needs-sudo check is evaluated against the backend `Auto` WOULD
/// resolve to (via `host`), not against ambient privilege — otherwise
/// `Backend::Auto` + `Auth::Stdin` on a doas-only host would return `Unsupported`
/// unprivileged but `RunAsIs` once already root, a verdict that flips on ambient
/// privilege instead of staying a property of the request.
fn structural_posix(os: Os, backend: Backend, auth: &Auth, host: &Host) -> Option<Error> {
    let platform = if os == Os::MacOs { "macos" } else { "unix" };
    let unsupported = |op: String, detail: &str| {
        Some(Error::Unsupported {
            op,
            platform,
            detail: detail.into(),
            source: None,
        })
    };
    // polkit is a Linux stack. Saying "not on PATH" on macOS reads as a
    // fixable environment problem on a platform where it will never exist.
    // sudo and doas are NOT in this list: both are portable and do run on macOS.
    if os == Os::MacOs {
        let impossible = match backend {
            Backend::Pkexec => Some(
                "pkexec is a polkit (Linux) program and does not exist on macOS; \
                 use Backend::Auto with Auth::Gui for the macOS authentication dialog",
            ),
            _ => None,
        };
        if let Some(detail) = impossible {
            return unsupported(format!("Backend::{backend:?}"), detail);
        }
    }
    if os == Os::Unix && backend == Backend::Pkexec {
        return unsupported(
            "Backend::Pkexec".into(),
            "cosca launches pkexec through Linux's /proc/self/fd, so that the pkexec it checked is the one \
             it runs; pkexec elevation needs Linux, so use sudo or doas here",
        );
    }
    if matches!(auth, Auth::Gui) {
        if os == Os::MacOs {
            if !is_macos_gui_auto(os, backend, auth) {
                return unsupported(
                    format!("{backend:?} + Auth::Gui"),
                    "macOS graphical elevation goes through Authorization Services, not a \
                     CLI wrapper; pair Auth::Gui with Backend::Auto",
                );
            }
        } else if backend != Backend::Pkexec {
            return unsupported(
                format!("{backend:?} + Auth::Gui"),
                "graphical (Gui) auth is only available through Backend::Pkexec",
            );
        }
    }
    if backend == Backend::Pkexec && !matches!(auth, Auth::Gui) {
        return unsupported(
            "pkexec + non-Gui auth".into(),
            "pkexec is the graphical backend; pair it with Auth::Gui",
        );
    }
    if matches!(auth, Auth::Askpass(_) | Auth::Stdin(_)) {
        // `Auto` with neither sudo nor doas on PATH is left to resolution's `BackendUnavailable`,
        // not reported as a config mismatch here. One whose search could not be completed is that
        // same `BackendUnavailable` here, so the verdict does not depend on the caller's privilege.
        let effective = host.available.resolve(backend);
        if let (Backend::Auto, Some((_, program, FrontState::Unexamined(error)))) = (backend, effective) {
            return Some(unexamined(program, error));
        }
        if let Some(eff) = effective.map(|(eff, ..)| eff).filter(|eff| *eff != Backend::Sudo) {
            let (kind, detail) = if matches!(auth, Auth::Askpass(_)) {
                (
                    "Askpass",
                    "askpass auth is sudo-only; doas/pkexec have no askpass mechanism",
                )
            } else {
                (
                    "Stdin",
                    "Stdin (sudo -S) auth is sudo-only; doas has no -S and non-sudo targets would leak the password",
                )
            };
            let op = if backend == Backend::Auto {
                format!("Auto (resolves to {eff:?}) + {kind}")
            } else {
                format!("{backend:?} + {kind}")
            };
            return unsupported(op, detail);
        }
    }
    None
}

/// The full Windows (backend, auth) matrix, privilege-independent for the same reason
/// as [`structural_posix`].
fn structural_windows(backend: Backend, auth: &Auth) -> Option<Error> {
    if backend != Backend::Auto {
        return Some(Error::Unsupported {
            op: format!("elevation backend {backend:?}"),
            platform: "windows",
            detail: "POSIX elevation backends do not exist on Windows; use Backend::Auto (ShellExecuteEx runas)".into(),
            source: None,
        });
    }
    if matches!(auth, Auth::NonInteractive | Auth::Askpass(_) | Auth::Stdin(_)) {
        return Some(Error::Unsupported {
            op: "runas + non-interactive/askpass/stdin auth".into(),
            platform: "windows",
            detail: "ShellExecuteEx(runas) has no non-interactive, askpass, or stdin-credential mechanism; \
                     use Auth::Interactive or Auth::Gui (both map to the UAC consent gate)"
                .into(),
            source: None,
        });
    }
    None
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod plan_tests;
