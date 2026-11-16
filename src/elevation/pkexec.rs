//! The installed `pkexec`'s polkit version, and whether cosca may launch it.
//!
//! Every `pkexec` launch passes `--keep-cwd`, so the child runs in the caller's directory as it
//! does under `sudo` and `doas`. polkit added the option in [`KEEP_CWD_SINCE`]. An older pkexec
//! takes it for the program name: measured on 0.105 and 0.117, it exits 127 with `Cannot run
//! program --keep-cwd: No such file or directory`, and runs, as root, a file named `--keep-cwd`
//! that it finds on the caller's `PATH`. So `pkexec --version` is read first, and a pkexec not
//! shown to be [`KEEP_CWD_SINCE`] or later is refused, including an older one with the option
//! backported.

use crate::error::Error;
use std::path::Path;
use std::sync::Arc;

/// The first polkit release whose pkexec has `--keep-cwd`: polkit NEWS lists "add option
/// (--keep-cwd) for pkexec" under polkit 121. Measured: 121 (Fedora 37) honours it.
pub(crate) const KEEP_CWD_SINCE: u32 = 121;

/// What `pkexec --version` said.
#[derive(Debug, Clone)]
pub enum PkexecVersion {
    /// Not asked, because the request cannot launch pkexec: it names another backend, pairs
    /// `Backend::Pkexec` with an auth other than `Auth::Gui`, comes from a caller already root, or
    /// runs off Linux; or because no pkexec was found.
    /// See [`crate::elevation::plan::Host::pkexec_version`].
    NotProbed,
    /// The pkexec could not be started to run `--version`.
    SpawnFailed(Arc<std::io::Error>),
    /// It started, but waiting for it or reading its output failed.
    RunFailed(Arc<std::io::Error>),
    /// It exited unsuccessfully; both streams are kept, lossily decoded.
    Failed {
        status: String,
        stdout: String,
        stderr: String,
    },
    /// Its stdout was not UTF-8; kept lossily decoded.
    NonUtf8(String),
    /// UTF-8, but not exactly `pkexec version <V>\n`.
    Unparsed(String),
    /// `pkexec version <V>\n`. `release` is `V` in polkit's current scheme (`121`, `122`, …), and
    /// `None` in the old `0.1xx` one, every release of which predates [`KEEP_CWD_SINCE`].
    Parsed { version: String, release: Option<u32> },
}

/// Read `pkexec --version`'s stdout: exactly `pkexec version <V>\n`, where `V` is `0.` and digits
/// (polkit 0.120 and earlier) or an integer without a leading zero (121 and later).
pub(crate) fn parse(stdout: &[u8]) -> PkexecVersion {
    let Ok(text) = std::str::from_utf8(stdout) else {
        return PkexecVersion::NonUtf8(String::from_utf8_lossy(stdout).into_owned());
    };
    let unparsed = || PkexecVersion::Unparsed(text.to_owned());
    let Some(version) = text.strip_prefix("pkexec version ").and_then(|t| t.strip_suffix('\n')) else {
        return unparsed();
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let release = match version.strip_prefix("0.") {
        Some(minor) if digits(minor) => None,
        Some(_) => return unparsed(),
        None if digits(version) && !version.starts_with('0') => match version.parse() {
            Ok(n) => Some(n),
            Err(_) => return unparsed(),
        },
        None => return unparsed(),
    };
    PkexecVersion::Parsed {
        version: version.to_owned(),
        release,
    }
}

impl PkexecVersion {
    /// `None` if this pkexec has `--keep-cwd`, else the error to launch it with: `Unsupported` for a
    /// pkexec not shown to be 121 or later. One that could not be started, or whose run failed, is
    /// no polkit verdict: its error is what a launch of `pkexec` (the file launched, at `path`)
    /// gives, as [`crate::elevation::remap_derived_spawn_error`] has it.
    pub(crate) fn refusal(&self, path: &Path) -> Option<Error> {
        let why = match self {
            PkexecVersion::Parsed { release: Some(n), .. } if *n >= KEEP_CWD_SINCE => return None,
            PkexecVersion::Parsed { version, .. } => format!("pkexec reports version {version}"),
            PkexecVersion::NotProbed => "the pkexec version was not checked".into(),
            PkexecVersion::SpawnFailed(error) => {
                return Some(super::remap_derived_spawn_error(
                    Error::Io(crate::error::shared_io(error)),
                    path,
                ))
            }
            PkexecVersion::RunFailed(error) => return Some(Error::Io(crate::error::shared_io(error))),
            PkexecVersion::Failed { status, stdout, stderr } => {
                format!("`pkexec --version` exited with {status}, printing {stdout:?} and, to stderr, {stderr:?}")
            }
            PkexecVersion::NonUtf8(lossy) => format!("`pkexec --version` printed non-UTF-8 output {lossy:?}"),
            PkexecVersion::Unparsed(text) => {
                format!("`pkexec --version` printed {text:?}, not `pkexec version <N>`")
            }
        };
        Some(Error::Unsupported {
            op: "elevation through a pkexec not shown to be polkit 121 or later".into(),
            platform: "unix",
            detail: format!(
                "{why}; cosca passes pkexec --keep-cwd, which polkit {KEEP_CWD_SINCE} added, and an older pkexec takes it for the program and searches PATH for it. Use sudo/doas, or polkit {KEEP_CWD_SINCE} or later"
            ),
            source: None,
        })
    }
}

#[cfg(test)]
#[path = "pkexec_tests.rs"]
mod pkexec_tests;
