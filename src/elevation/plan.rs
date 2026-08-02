//! The PURE elevation planner: plain-data [`Host`] + a syscall-free
//! [`Host::plan`]. A Linux test constructs a Windows-shaped `Host` and asserts
//! the Windows decision — the `Containment` host-testing pattern.

use std::path::{Path, PathBuf};

use super::{Auth, Backend, Privilege};
use crate::error::{ElevationErrorKind, Error};

/// Which OS the effect layer will use. Data, not `cfg!`, so `plan` is cross-tested.
// The planner models EVERY platform's decision on ANY host (that is the whole point — a
// Windows-shaped `Host` is planned on Linux and vice versa), so in a non-test single-platform
// build the other platform's variant is never constructed. That is by design, not dead logic.
#[allow(dead_code)]
// The enum is named `Os` and `MacOs` names an OS, so the variant unavoidably ends
// with the enum's name. Renaming either to satisfy the lint would make both worse.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Every POSIX host EXCEPT macOS — Linux, the BSDs, illumos. Deliberately not
    /// named `Linux`: nothing keyed off it is Linux-specific, and a Linux-shaped
    /// name would invite gating genuinely Linux-only behavior on it.
    Unix,
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
    /// macOS only: the absolute path of `/usr/bin/osascript`, the graphical
    /// elevation front-end. Not a [`Backend`]: it does not wrap the child, it asks
    /// Authorization Services to run the command as root.
    pub osascript: Option<PathBuf>,
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
    /// `sysctl kern.argmax` — the exec argument budget, read at detect time
    /// because it has changed across macOS releases and must never be guessed.
    /// `None` when the query failed or the platform has no equivalent; the macOS
    /// length guard is then skipped rather than run against an invented number.
    /// Only the macOS graphical path reads it; it lives here because the planner
    /// is plain data.
    pub arg_max: Option<usize>,
}

/// The planner's decision. Not `PartialEq` — `Reject` wraps a non-comparable
/// [`Error`]; tests use `matches!` and inspect fields.
// Cross-platform like [`Os`]: the effect arm for the other platform (and its fields) is never
// constructed in a single-platform non-test build, but is exercised by the cross-OS planner tests.
#[allow(dead_code)]
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
            Host {
                elevated: false,
                has_tty: false,
                available: BackendSet::default(),
                os: Os::Unix,
                arg_max: None,
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
            os => structural_posix(os, backend, &auth, &self.available),
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
                match self.available.osascript.as_deref() {
                    Some(p) => Transition::ElevateMacosGui {
                        osascript: p.to_path_buf(),
                        arg_max: self.arg_max,
                    },
                    // Honest here, unlike the pkexec verdict: /usr/bin/osascript
                    // can genuinely be missing or non-executable.
                    None => reject_backend_unavailable(
                        "/usr/bin/osascript is missing or not executable; \
                         macOS graphical elevation needs it",
                    ),
                }
            }
            Os::MacOs | Os::Unix => self.resolve_posix(backend, auth),
        }
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

fn reject_backend_unavailable(detail: &str) -> Transition {
    Transition::Reject {
        error: Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            detail: detail.into(),
        },
    }
}

/// The full POSIX (backend, auth) matrix, privilege-independent: called BEFORE the
/// already-elevated short-circuit so an impossible combo never passes under root.
///
/// The Askpass/Stdin-needs-sudo check is evaluated against the backend `Auto` WOULD
/// resolve to (via `available`), not against ambient privilege — otherwise
/// `Backend::Auto` + `Auth::Stdin` on a doas-only host would return `Unsupported`
/// unprivileged but `RunAsIs` once already root, a verdict that flips on ambient
/// privilege instead of staying a property of the request.
fn structural_posix(os: Os, backend: Backend, auth: &Auth, available: &BackendSet) -> Option<Error> {
    let platform = if os == Os::MacOs { "macos" } else { "unix" };
    let unsupported = |op: String, detail: &str| {
        Some(Error::Unsupported {
            op,
            platform,
            detail: detail.into(),
        })
    };
    // polkit and systemd are Linux stacks. Saying "not on PATH" on macOS reads as a
    // fixable environment problem on a platform where neither will ever exist.
    // sudo and doas are NOT in this list: both are portable and do run on macOS.
    if os == Os::MacOs {
        let impossible = match backend {
            Backend::Pkexec => Some(
                "pkexec is a polkit (Linux) program and does not exist on macOS; \
                 use Backend::Auto with Auth::Gui for the macOS authentication dialog",
            ),
            Backend::Run0 => Some(
                "run0 ships with systemd and does not exist on macOS; \
                 use Backend::Auto (sudo), or Auth::Gui for the macOS authentication dialog",
            ),
            _ => None,
        };
        if let Some(detail) = impossible {
            return unsupported(format!("Backend::{backend:?}"), detail);
        }
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
        // `Auto` with neither sudo nor doas on PATH is left to resolution's
        // `BackendUnavailable`, not reported as a config mismatch here.
        let effective = match backend {
            Backend::Auto => {
                if available.sudo.is_some() {
                    Some(Backend::Sudo)
                } else if available.doas.is_some() {
                    Some(Backend::Doas)
                } else {
                    None
                }
            }
            explicit => Some(explicit),
        };
        if let Some(eff) = effective.filter(|eff| *eff != Backend::Sudo) {
            let (kind, detail) = if matches!(auth, Auth::Askpass(_)) {
                (
                    "Askpass",
                    "askpass auth is sudo-only; run0/doas/pkexec have no askpass mechanism",
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
        });
    }
    if matches!(auth, Auth::NonInteractive | Auth::Askpass(_) | Auth::Stdin(_)) {
        return Some(Error::Unsupported {
            op: "runas + non-interactive/askpass/stdin auth".into(),
            platform: "windows",
            detail: "ShellExecuteEx(runas) has no non-interactive, askpass, or stdin-credential mechanism; \
                     use Auth::Interactive or Auth::Gui (both map to the UAC consent gate)"
                .into(),
        });
    }
    None
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod plan_tests;
