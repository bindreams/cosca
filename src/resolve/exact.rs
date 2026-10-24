//! `raw_executable()` on POSIX: making an `Exact` program unsearchable, which is the opposite of
//! searching for it. The spawn anchors it to the cwd the child inherits ([`anchor_posix`]).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::Error;

/// The unelevated spawn's form of an `Exact` program: one no `exec` will search, resolved by the
/// child against the working directory it inherits at `fork` — **without reading this process's
/// cwd, searching, appending anything, or touching the filesystem**.
///
/// An absolute program is left as is, and `child_cwd` goes to std as given. A relative one is
/// prefixed with `./` unless it already contains a `/` (`execvp` searches only a name without
/// one), and [`Anchored::enter`] is set: the sink must `chdir` to `child_cwd` in the child
/// itself, just before the exec, rather than hand it to std, whose handling of a relative program
/// with a `current_dir` its docs call "platform specific and unstable". The child then reads the
/// name against the directory it is about to run in, both relative to the cwd it inherited, so
/// the file loaded and the directory run in cannot come from two readings — and a cwd with no
/// usable path (an unsearchable ancestor, an unlinked directory, one outside a chroot) works,
/// as it does for `./tool` under std.
///
/// Refused with `InvalidInput` before anything else: an interior NUL, which no exec argument can
/// carry, and a name that [names no file](super::names_no_file) — empty, `/`-terminated, or a
/// final `.`/`..`. POSIX grammar, byte-level, on every host.
// Off unix the std spawn never has an `Exact` program: it routes to the raw backend.
#[cfg_attr(
    not(unix),
    allow(
        dead_code,
        reason = "off-unix the std spawn never has an Exact program - it routes to the raw backend"
    )
)]
pub(crate) fn anchor_posix(program: &OsStr, child_cwd: Option<&Path>) -> Result<Anchored, Error> {
    refuse_unnameable(program)?;
    let cwd = child_cwd.map(Path::to_path_buf);
    if is_absolute(program) {
        return Ok(Anchored {
            program: PathBuf::from(program),
            cwd,
            enter: false,
        });
    }
    let program = if program.as_encoded_bytes().contains(&b'/') {
        PathBuf::from(program)
    } else {
        // Bytes, not `Path::join`: off unix that would insert the host's separator.
        let mut anchored = OsString::from("./");
        anchored.push(program);
        PathBuf::from(anchored)
    };
    Ok(Anchored {
        program,
        cwd,
        enter: true,
    })
}

/// [`anchor_posix`]'s answer.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(
    not(unix),
    allow(
        dead_code,
        reason = "off-unix the std spawn never has an Exact program - it routes to the raw backend"
    )
)]
pub(crate) struct Anchored {
    pub(crate) program: PathBuf,
    /// `current_dir()` as given.
    pub(crate) cwd: Option<PathBuf>,
    /// Whether the child must `chdir` to `cwd` itself, right before the exec, instead of std.
    pub(crate) enter: bool,
}

/// [`anchor_posix`]'s refusals: an interior NUL, which no exec argument can carry, and a name that
/// [names no file](super::names_no_file).
pub(crate) fn refuse_unnameable(program: &OsStr) -> Result<(), Error> {
    if program.as_encoded_bytes().contains(&0) {
        // A literal: interpolating the token would put a raw U+0000 into logs and terminals.
        return Err(invalid_input(
            "raw_executable() was given a path containing an embedded NUL, so it names no file".into(),
        ));
    }
    if super::names_no_file(program, false) {
        return Err(invalid_input(format!(
            "raw_executable() was given a path that names no file: {program:?}"
        )));
    }
    Ok(())
}

fn is_absolute(p: &OsStr) -> bool {
    p.as_encoded_bytes().first() == Some(&b'/')
}

fn invalid_input(msg: String) -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

#[cfg(test)]
#[path = "exact_tests.rs"]
mod exact_tests;
