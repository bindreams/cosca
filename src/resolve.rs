//! Which file a `Command` loads — on the spawn paths that currently consult it.
//!
//! **Coverage: every unix spawn, on the POSIX grammar (`posix::lookup`), and the Windows raw
//! `CreateProcessW` backend (sync and its tokio mirror), on the Windows grammar — in both, only for a
//! `Search` program**, i.e. one recorded by `Command::executable()`, or the argv[0]/first-token
//! fallback when neither setter was called. The Windows backend is reached when
//! `Command::executable_path()` is set or an fd >= 3 is mapped.
//!
//! An `Exact` program, from `Command::raw_executable()`, deliberately does NOT come through
//! [`resolve`]: "load exactly this file" is the absence of this module's SEARCH policy, not an
//! application of it. Where a sink would search a relative name, it is put in a form no sink
//! searches: on the POSIX spawn a `./`-anchored name ([`exact::anchor_posix`]), and on the Windows
//! raw backend an absolute path (`windows_raw::resolve::absolutise_exact_on`). An elevated spawn
//! refuses both setters, so neither reaches an elevation backend.
//!
//! It does, however, share this module's naming CLASSIFIERS: every `Exact` arm refuses a program
//! that names no file via [`names_no_file`], so the two axes cannot drift apart on what counts as
//! a filename. Classifying is not searching.
//!
//! The Windows elevated (`ShellExecuteEx`) path passes argv[0] to `ShellExecuteEx` unresolved, and
//! `executable()` is refused under elevation. Producing an ABSOLUTE path is what lets a backend skip
//! its own search: the unix spawns hand the child (Linux) or std (macOS) a path with a `/`, which
//! `execve` and `execvp` do not search for, and `ShellExecuteEx` skips its directory search for an
//! absolute `lpFile` (though not `PATHEXT`; see [`reject_unloadable_image`]) — that wiring has not
//! happened yet for it.
//!
//! Classification is byte-level and parameterised by [`ResolveInput::windows`] rather than using
//! `std::path`, whose parsing is host-specific — `Path::new("C:tool").prefix()` is `None` off
//! Windows, so a `Path`-based rule could not be exercised from a POSIX host at all.
//!
//! A bare name is resolved from [`ResolveInput::system_dirs`] (Windows only) and then `PATH` —
//! **never** the current directory, in either sense of that phrase: bare-name resolution never
//! reads [`ResolveInput::cwd`] (the CHILD's working directory) at all, a structural guarantee of
//! this module, and never reaches THIS PROCESS's own cwd either, because [`accepted`] rejects any
//! joined candidate that is not fully qualified, so a relative `PATH` element (which would resolve
//! against this process's cwd if followed) never produces a match. And, in practice, never the app
//! directory (the directory this process's own image loaded from) either: `system_dirs` is an
//! arbitrary caller-supplied closure, so this module CAN be handed the app directory (the test
//! suite does exactly that as a positive control), but the one production caller,
//! `windows_raw::resolve::windows_system_dirs`, never includes it. `system_dirs` is likewise taken
//! as a parameter rather than queried from the OS here, for the
//! same host-independence reason; see its doc for what it contains and why it precedes `PATH`.
//!
//! # Which error kind
//!
//! The two kinds [`resolve`] returns answer different questions, and the split is part of the
//! public contract (see [`crate::Command::executable`]):
//!
//! - [`std::io::ErrorKind::InvalidInput`] — the string was NOT ACCEPTED. It was refused on its
//!   shape; no search ran, and no filesystem result is being reported.
//! - [`std::io::ErrorKind::NotFound`] — the string was acceptable, the search ran to this
//!   module's policy, and nothing matched.
//!
//! The operational test for a new rule is **could a different filesystem make this input
//! succeed?** No — the refusal is a property of the string, not of the disk — means
//! `InvalidInput`. Yes means `NotFound`. So `C:\` (a directory, whatever is on the disk) is a
//! refusal, while a missing `tool` or `C:\abs\missing.exe` is a miss. A refusal must be stated
//! explicitly and early, never left to fall out of candidate filtering: that reports the right
//! kind by accident and changes it silently when the filtering does.
//!
//! A drive-relative name (`C:tool`) is completed onto a directory by [`drive_relative::drive_base`]
//! and is from there exactly a relative located name: its candidates, error kinds and normalisation
//! are that name's.

use crate::error::Error;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

pub(crate) mod drive_relative;
pub(crate) mod exact;
pub(crate) mod join;
#[cfg(unix)]
pub(crate) mod posix;

/// Everything the policy reads. Taken as parameters so the rules are testable without touching
/// the ambient environment.
pub(crate) struct ResolveInput<'a> {
    /// The program as the caller wrote it.
    pub program: &'a Path,
    /// The directory the CHILD will run in, the base a relative located name is read against.
    ///
    /// On the Windows grammar it must be fully qualified: the caller completes it as Win32 does
    /// (`windows_raw::resolve::complete_on`), since that needs this process's cwd, which this module
    /// does not read. On the POSIX grammar a relative base is probed as given and `None` is the
    /// inherited directory: see `posix::lookup`.
    ///
    /// On the Windows grammar `None` is allowed only for a name [`needs_base`] says needs none,
    /// which then reads nothing; for any other name it is a contract violation and panics.
    pub cwd: Option<&'a Path>,
    /// Directories searched for a bare name BEFORE `PATH`, in order, queried lazily: called at
    /// most once, and only from the `Shape::BareName` arm of [`resolve`] — after every shape
    /// refusal above it has already passed. A `Located` or absolute name never calls it at all, so
    /// a query that can fail (the production caller reaches the OS; see
    /// `windows_raw::resolve::windows_system_dirs`) cannot break resolution of a name that was
    /// never going to consult it. Ignored entirely when `windows` is `false` — POSIX has no
    /// analogous search order to preserve.
    ///
    /// On Windows, the production caller (`windows_raw::resolve::windows_system_dirs`) passes the
    /// System32 directory, then the Windows directory — this field itself enforces no particular
    /// order or content, only that whatever it holds is searched before `PATH`.
    /// `CreateProcessW`'s own documented NULL-`lpApplicationName` search order has six steps: app
    /// directory, current directory, System32, the 16-bit system directory, the Windows directory,
    /// then `PATH`. This policy keeps `System32`, the Windows directory, and `PATH` itself
    /// (searched after both, never dropped), and excludes the other three:
    ///
    /// - The 16-bit system directory is left out because Win32 exposes no function to obtain its
    ///   path directly. This crate could in principle reconstruct it from the Windows directory
    ///   plus the name `System` Microsoft gives it, but does not (see
    ///   `windows_raw::resolve::windows_system_dirs`'s doc for Microsoft's own wording and why
    ///   not).
    /// - The current directory and the app directory (the directory this process's own image
    ///   loaded from) ARE queryable, and excluding both is a deliberate choice: each is a
    ///   binary-planting vector, since where a process's current directory points, or where its own
    ///   image sits (a per-user install, a portable zip-extracted copy, a build/test output
    ///   directory), is not a fixed, vetted location the way `System32`/the Windows directory are —
    ///   `CreateProcessW` searches both regardless; `std::process::Command` searches the app
    ///   directory too, but — like this crate — not the current directory (a Rust-side hardening,
    ///   not a Win32 default).
    ///
    /// Both exclusions narrow the search along a TRUST ordering this crate treats as a default,
    /// not a proof that holds for every possible install: `System32` and the Windows directory are
    /// treated as at least as trustworthy as an arbitrary current directory or app directory,
    /// because on an ordinary install planting a file into either system directory takes
    /// privileges an attacker confined to a process's own app directory or its current
    /// directory does not have. `PATH` gets no such blanket trust — an early `PATH` entry can
    /// itself be user-writable, exactly the risk the WIDENING paragraph below spells out — but this
    /// policy still searches it, at the position `CreateProcessW` gives it, rather than dropping it
    /// too. That default can be wrong in a specific, unusually locked-down install: a name present
    /// in BOTH the current directory (or the app directory) and an early `PATH` entry, but absent
    /// from `System32` and the Windows directory, resolves through the current/app directory under
    /// `CreateProcessW`'s own order; under this policy it resolves via whatever `PATH` supplies
    /// instead, which could in principle be a LESS trustworthy file than the current/app-directory
    /// copy would have been in that specific install. What holds in every install, given the
    /// production caller's `system_dirs`, is that this policy never lets an unvetted current or
    /// app directory pre-empt `PATH`.
    ///
    /// `System32` and the Windows directory keep their precedence over `PATH` regardless: a caller
    /// supplying a `system_dirs` closure that returns no directories — dropping them too — would be
    /// a straightforward WIDENING, not a narrowing, letting a user-writable directory placed early
    /// on `PATH` (a dev toolchain install, an `%LOCALAPPDATA%\...\WindowsApps` shim) shadow e.g.
    /// `System32\find.exe`, a way to load the wrong binary that `CreateProcessW`'s own order
    /// (`System32` ahead of `PATH`) prevents. The caller supplies this closure (rather than this
    /// module calling `GetSystemDirectoryW`/`GetSystemWindowsDirectoryW` itself) so the rule stays
    /// testable from a POSIX host, exactly like `windows` below.
    pub system_dirs: &'a dyn Fn() -> Result<Vec<PathBuf>, Error>,
    /// The `PATH` the CHILD will see, after `env()`/`env_clear()`.
    pub path_var: Option<&'a OsStr>,
    /// Apply Windows rules: `;` separated `PATH`, `\` a separator, drive prefixes, the `.exe` rule.
    pub windows: bool,
    /// Keep only candidates ending in `.exe`/`.com`, for a caller that hands the result to a sink
    /// that extends a name, as `ShellExecuteEx` does: see [`reject_unloadable_image`]. Windows
    /// only.
    ///
    /// A FILTER, so a non-loadable candidate is skipped rather than chosen and then refused: with
    /// both `bin/tool` and `bin/tool.exe` present, `bin/tool` resolves to `bin/tool.exe`. Refusing
    /// after the choice would report `InvalidInput` for a string a file on disk satisfies, and let
    /// whoever can write an extensionless `tool` into `bin/` block the spawn. `false` leaves
    /// resolution exactly as an ordinary spawn sees it.
    ///
    /// It also makes the search fail closed on a candidate whose existence cannot be determined,
    /// where an ordinary Windows search skips it with a warning (a POSIX search never does: it stops
    /// with an error that names the entry): see [`resolve`].
    pub loadable_only: bool,
    /// How Win32 completes a located name that is verbatim (`\\?\`) only because the cwd base is:
    /// `GetFullPathNameW`, which the raw backend passes. Win32 normalises a name it completes
    /// against a verbatim cwd (`sub.\tool.exe` on `\\?\C:\d` is `\\?\C:\d\sub\tool.exe`), and
    /// the candidate is probed and returned as that. Nothing else reaches it: a name written
    /// verbatim, one joined onto a non-verbatim cwd, and every candidate of a `PATH` or system
    /// directory search, whose directories are written verbatim by whoever set them. Windows only.
    pub normalise: &'a dyn Fn(&Path) -> std::io::Result<PathBuf>,
    /// The CHILD's own current directory on a drive, by the drive's prefix (`E:`): the directory
    /// `E:tool` is completed onto when `E:` is not the drive of [`cwd`](Self::cwd). `None` for none,
    /// which completes onto the drive's root. The caller decides what counts as one (on Windows,
    /// `windows_raw::resolve::DriveDirs`); an answer is fully qualified. Called lazily, at most
    /// once, and only for a drive-relative name that names a file. Ignored on the POSIX grammar.
    pub child_drive_dir: &'a dyn Fn(&OsStr) -> Option<OsString>,
    /// Whether two drive prefixes (`C:`, any one unit and `:`) name one drive. The OS-bound caller
    /// states the OS's comparison (on Windows, as `RtlGetFullPathName_U` upcases both units, the
    /// table of an environment key: `é:` and `É:` are one).
    /// Ignored on the POSIX grammar.
    pub same_drive: &'a dyn Fn(&OsStr, &OsStr) -> bool,
}

#[cfg(test)]
pub(crate) fn no_drive_dir(_: &OsStr) -> Option<OsString> {
    None
}

/// [`ResolveInput::same_drive`] for a test that compares drives by ASCII case alone.
#[cfg(test)]
pub(crate) fn ascii_same_drive(a: &OsStr, b: &OsStr) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// [`ResolveInput::normalise`] for a test that probes every candidate as joined.
#[cfg(test)]
pub(crate) fn as_written(path: &Path) -> std::io::Result<PathBuf> {
    Ok(path.to_path_buf())
}

/// [`ResolveInput::system_dirs`] for a test with no system directories to search — `PATH` only.
#[cfg(test)]
pub(crate) fn no_system_dirs() -> Result<Vec<PathBuf>, Error> {
    Ok(Vec::new())
}

/// How the program names its file, which decides whether `PATH` (and, on Windows,
/// `system_dirs`) is consulted at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// No separator and no drive prefix: the only shape that searches `system_dirs` and `PATH`.
    BareName,
    /// Contains a separator, or carries a drive prefix (`C:tool` means "relative to drive C's
    /// current directory", so a `PATH` search for it would be a lie).
    Located,
}

/// How Win32 reads a path, decided as `RtlDetermineDosPathNameType_U` decides it: separators
/// first, then a drive. Every Windows-grammar classifier here, and the raw backend's completion
/// of a `raw_executable()` token or `current_dir`, reads a path through this one function, so no
/// two of them can disagree on the same string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathType {
    /// Two leading separators, either kind: UNC, `\\?\`, `\\.\`.
    Unc,
    /// A drive and a separator: `C:\x`.
    DriveAbsolute,
    /// A drive with no separator after it: `C:x`, relative to that drive's own current directory.
    DriveRelative,
    /// One leading separator: `\x`, on the current drive or share.
    Rooted,
    /// Anything else, relative to the current directory.
    Relative,
}

/// `program`'s Win32 path type. See [`PathType`].
pub(crate) fn path_type(program: &OsStr) -> PathType {
    let bytes = program.as_encoded_bytes();
    let sep_at = |i: usize| bytes.get(i).is_some_and(|&b| is_sep(b, true));
    if sep_at(0) {
        return if sep_at(1) { PathType::Unc } else { PathType::Rooted };
    }
    match drive_len(bytes) {
        Some(len) if sep_at(len) => PathType::DriveAbsolute,
        Some(_) => PathType::DriveRelative,
        None => PathType::Relative,
    }
}

/// The byte length of a drive prefix — any ONE UTF-16 unit, then `:` — or `None`. Win32 takes any
/// unit there, not only a letter (`RtlDetermineDosPathNameType_U` tests `path[1] == ':'`), so
/// `1:tool` names drive `1`. Byte-level over the WTF-8 encoding: a lead byte of up to three bytes
/// is one unit, a four-byte one (a supplementary character) is two.
///
/// Not the whole story on its own: [`path_type`] checks separators first, so `\:x` is rooted.
pub(crate) fn drive_len(bytes: &[u8]) -> Option<usize> {
    let unit = match *bytes.first()? {
        b if b < 0x80 => 1,
        b if b >= 0xF0 => return None,
        b if b >= 0xE0 => 3,
        b if b >= 0xC0 => 2,
        _ => return None,
    };
    (bytes.get(unit) == Some(&b':')).then_some(unit + 1)
}

/// `program` split after its drive (`C:`, any one unit and `:`), for a drive-absolute or
/// drive-relative path; `None` for any other type.
pub(crate) fn split_drive(program: &OsStr) -> Option<(&OsStr, &OsStr)> {
    if !matches!(path_type(program), PathType::DriveAbsolute | PathType::DriveRelative) {
        return None;
    }
    let bytes = program.as_encoded_bytes();
    let len = drive_len(bytes)?;
    // SAFETY: `len` ends just after an ASCII `:`, so both halves are whole WTF-8 substrings.
    Some(unsafe {
        (
            OsStr::from_encoded_bytes_unchecked(&bytes[..len]),
            OsStr::from_encoded_bytes_unchecked(&bytes[len..]),
        )
    })
}

pub(crate) fn classify(program: &OsStr, windows: bool) -> Shape {
    let bytes = program.as_encoded_bytes();
    if bytes.iter().any(|&b| is_sep(b, windows)) {
        return Shape::Located;
    }
    // `C:tool` names a file relative to drive C's own current directory. It has no separator, so
    // a naive rule calls it bare and searches `PATH` — but joining a directory onto it collapses
    // straight back to `C:tool` (`PathBuf::push` clears for any prefixed path), so the search is
    // a lie that lands in a current directory.
    if windows && drive_len(bytes).is_some() {
        return Shape::Located;
    }
    Shape::BareName
}

/// Whether [`resolve`] reads [`ResolveInput::cwd`] for `program`: exactly for a relative located
/// name, and a drive-relative one. A bare name is searched, an absolute one is its own location,
/// and a share-less UNC-shaped one is refused before any base is read. A caller that supplies the
/// base itself asks this to know whether it must.
pub(crate) fn needs_base(program: &OsStr, windows: bool) -> bool {
    if windows {
        return classify(program, true) == Shape::Located
            && matches!(
                path_type(program),
                PathType::Rooted | PathType::Relative | PathType::DriveRelative
            );
    }
    classify(program, false) == Shape::Located && !is_absolute_name(program, false)
}

/// Whether Win32 reads `program` as UNC — it starts with two separators, either kind — while no
/// UNC prefix parses from it, because the share is missing or empty (`\\tool.exe`, `//tool.exe`,
/// `\\srv\\x.exe`). Windows only.
fn is_unc_without_share(program: &OsStr, windows: bool) -> bool {
    windows && path_type(program) == PathType::Unc && windows_prefix_len(program.as_encoded_bytes()) == 0
}

/// Whether `program` is ABSOLUTE in the simulated platform's grammar: on POSIX a leading `/`; on
/// Windows a drive and a root (`C:\`), or a UNC, verbatim or device prefix (`\\server\share`,
/// `\\?\`, `\\.\`). A rooted `\tool` and a drive-relative `C:tool` are not: each still
/// needs a current directory.
pub(crate) fn is_absolute_name(program: &OsStr, windows: bool) -> bool {
    let bytes = program.as_encoded_bytes();
    if !windows {
        return bytes.first() == Some(&b'/');
    }
    match path_type(program) {
        PathType::DriveAbsolute => true,
        PathType::Unc => windows_prefix_len(bytes) > 0 && !is_verbatim_unc_without_share(bytes),
        PathType::DriveRelative | PathType::Rooted | PathType::Relative => false,
    }
}

/// Whether `bytes` is a verbatim UNC prefix (`\\?\UNC\`) missing its server or share, which
/// names no share as the plain `\\srv` does. [`windows_prefix_len`] counts such a prefix whole,
/// since nothing may be appended to it either way.
///
/// Split on `\` alone, as [`join`] parses a verbatim prefix and NT reads one, so the path this
/// admits is the one the join completes: `\\?\UNC\srv/shr` is server `srv/shr` with no share,
/// and `\\?\UNC/srv` is no UNC path at all but the namespace `UNC/srv`. std's `parse_prefix`
/// reads the latter as a share-less UNC path, since it rewrites `/` to `\` in the first eight bytes.
fn is_verbatim_unc_without_share(bytes: &[u8]) -> bool {
    let is_verbatim_unc =
        bytes.len() >= 8 && bytes[..4] == *br"\\?\" && bytes[4..7].eq_ignore_ascii_case(b"UNC") && bytes[7] == b'\\';
    if !is_verbatim_unc {
        return false;
    }
    let mut parts = bytes[8..].split(|&b| b == b'\\');
    let server = parts.next().unwrap_or_default();
    let share = parts.next().unwrap_or_default();
    server.is_empty() || share.is_empty()
}

fn is_sep(b: u8, windows: bool) -> bool {
    b == b'/' || (windows && b == b'\\')
}

/// An ASCII-letter drive, for the one place Win32 does not parse the path at all: after a `\\?\`
/// marker, where `std` and `PureWindowsPath` recognise only a letter. Everywhere else a drive is
/// [`drive_len`]'s.
fn has_ascii_drive(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

/// Whether `program` is DRIVE-RELATIVE: a drive prefix not followed by a separator, as in
/// `C:tool` or `D:sub\x`; see the module doc.
fn is_drive_relative(program: &OsStr, windows: bool) -> bool {
    windows && path_type(program) == PathType::DriveRelative
}

/// The length of the Windows PREFIX — the leading run naming a volume, share, device or verbatim
/// namespace rather than anything inside it: `C:`, `\\server\share`, `\\?\C:`,
/// `\\?\UNC\server\share`, `\\?\namespace`, `\\.\device`. `0` when there is none.
///
/// A prefix's own components are not filenames, so nothing may be appended to one: `\\server\share`
/// is a share root exactly as `C:\` is a volume root. `Path::file_name` agrees — it is `None` for
/// every prefix-only path — but only on a Windows HOST, which is why this is parsed byte-wise here.
///
/// `/` and `\` separate components here exactly as they do in [`final_component`], so the whole
/// string is read under ONE separator rule. `std` is deliberately not followed on this point:
/// `parse_next_component(.., verbatim: true)` splits the components of a verbatim prefix on `\`
/// alone, which would let the prefix swallow `srv/shr\a` in `\\?\UNC\srv/shr\a` and leave an empty
/// final component — refusing a path that names the file `a`. `PureWindowsPath` is the reference
/// (see [`names_no_file`]) and it normalises `/` to `\` everywhere.
///
/// Two `std` rules ARE followed, because they decide whether a prefix is present rather than how
/// its components are split: the `\\?\` marker must be spelt with literal backslashes (a `/` among
/// those four bytes means no verbatim prefix), and `\\server` with no share is no prefix at all.
///
/// The `UNC` marker is NT's, not `std`'s: it marks a UNC path only before `\`, since NT does not
/// read `/` as a separator after `\\?\`. So `\\?\UNC/srv\tool.exe` is the namespace `\\?\UNC`
/// holding `srv\tool.exe`, not a share. `std` rewrites `/` to `\` in the first eight bytes and would
/// read a share there. The share-less gate and [`join`] read the marker the same way.
fn windows_prefix_len(bytes: &[u8]) -> usize {
    if !(bytes.len() >= 2 && is_sep(bytes[0], true) && is_sep(bytes[1], true)) {
        // A separator in slot 0 is never a drive: `\:x` is rooted.
        if bytes.first().is_some_and(|&b| is_sep(b, true)) {
            return 0;
        }
        return drive_len(bytes).unwrap_or(0);
    }
    // End offset of the component starting at `at`, exclusive of its separator.
    let component = |at: usize| {
        bytes[at..]
            .iter()
            .position(|&b| is_sep(b, true))
            .map_or(bytes.len(), |i| at + i)
    };
    if bytes.len() >= 4 && bytes[2] == b'?' && is_sep(bytes[3], true) && !bytes[..4].contains(&b'/') {
        // `\\?\UNC\server\share`: server and share belong to the prefix, as they do without it.
        if bytes.len() >= 8 && bytes[4..7].eq_ignore_ascii_case(b"UNC") && bytes[7] == b'\\' {
            let server = component(8);
            if server >= bytes.len() {
                return bytes.len();
            }
            return component(server + 1);
        }
        // `\\?\C:` — a drive is recognised only EXACTLY here: `\\?\C:x` is the verbatim namespace
        // `C:x`, not drive C. `PureWindowsPath` agrees (`\\?\C:a` names nothing), as does `std`.
        if has_ascii_drive(&bytes[4..]) && bytes.get(6).is_none_or(|&b| is_sep(b, true)) {
            return 6;
        }
        return component(4);
    }
    if bytes.len() >= 4 && bytes[2] == b'.' && is_sep(bytes[3], true) {
        return component(4); // `\\.\device`
    }
    // `\\server\share`. Missing either half is no prefix at all (`std` parses none), leaving the
    // ordinary final-component rule to answer — which refuses `\\` and `\\server\` anyway.
    let server = component(2);
    if server == 2 || server >= bytes.len() {
        return 0;
    }
    let share = component(server + 1);
    if share == server + 1 {
        0
    } else {
        share
    }
}

/// Whether `program` names a DIRECTORY rather than a file, so no search could make it executable.
///
/// True when the final component — taken after the Windows prefix, if any — is empty (a
/// separator-terminated name, a root, a bare prefix such as `\\server\share`, or the empty
/// string) or is `.`/`..`. NOTHING ELSE, on either platform.
///
/// On what counts as a NAME, `PureWindowsPath` agrees: `C:\dir\...` is named `...`, `C:\dir\tool.`
/// is named `tool.`, a lone space is a name. Win32's trimming of trailing dots and spaces is not
/// modelled, because it describes what an API does to a path STRING on its way in and not what may
/// exist on disk — Microsoft's own rule concedes a trailing-space name can be created, so trimming
/// here would refuse names that name real files.
///
/// It is not the authority on what is REFUSED, because it normalises the string first, and each of
/// the three shapes has inputs where that shows: it collapses `C:\dir\y\` to `y`, it drops the `.`
/// in `C:\dir\.` to give `dir`, and it reports `..` as an ordinary name. This module reads the RAW
/// string, where each of those final components survives, and refuses all three. (On the commonest
/// spellings it does agree — a lone `.`, a root, a bare prefix and `""` are all nameless there
/// too; it is the longer forms that diverge.)
///
/// `Path::file_name` answers the same question, but host-specifically: off Windows it sees neither
/// `\` nor any prefix, so a `Path`-based rule could not be exercised from a POSIX host at all.
/// Byte-level and parameterised, like every other classifier here — see the module doc.
///
/// `pub(crate)` for `windows_raw::resolve::reject_unnameable_program`: the `Exact` arms refuse the
/// same shapes, and sharing the predicate is what stops the two axes drifting apart on what counts
/// as a filename.
pub(crate) fn names_no_file(program: &OsStr, windows: bool) -> bool {
    matches!(final_component(program, windows), b"" | b"." | b"..")
}

/// The run after the last separator, with any Windows prefix taken off first. Shared so that
/// "which component does the rule read" has ONE answer: `names_no_file` classifies on it and
/// [`takes_the_exe_fallback`] tests its extension, and a separator set or prefix rule that changed
/// in only one of them would leave the two judging different bytes.
///
/// BOTH halves are gated on `windows`, not just the prefix: off Windows `\` is an ordinary
/// filename character, so `final_component(r"C:\dir\tool", false)` is the whole string. Byte-level
/// and parameterised, like every other classifier here — see the module doc.
fn final_component(program: &OsStr, windows: bool) -> &[u8] {
    let bytes = program.as_encoded_bytes();
    let rest = if windows {
        &bytes[windows_prefix_len(bytes)..]
    } else {
        bytes
    };
    let start = rest.iter().rposition(|&b| is_sep(b, windows)).map_or(0, |i| i + 1);
    &rest[start..]
}

/// The filenames tried in each candidate directory, in order.
///
/// **`.exe` is a property of names that get SEARCHED, not of files that get LOADED.** That split
/// is what the two shapes encode, and it is the platform's own, not this crate's invention:
///
/// - The PE/COFF format makes no extension normative — an image is identified by `MZ`, the `PE\0\0`
///   signature at the offset in `0x3c`, and header flags such as `IMAGE_FILE_DLL`. A valid PE
///   named `myapp` or `payload.tmp` is a valid PE.
/// - `CreateProcessW` documents, for the `lpApplicationName` this resolver actually feeds: "This
///   parameter must include the file name extension; **no default extension is assumed**." Its
///   command-line mode agrees the moment a path is involved: ".exe is appended" only "if the file
///   name does not contain a directory path".
/// - `PATHEXT` is a `cmd.exe` feature, and it cannot express "no extension" — there is no entry
///   meaning "try the bare name". That, not the loader, is why an extensionless image is
///   unreachable by bare name.
/// - Microsoft's current app model draws the same line: `uap5:ExecutionAlias`/`uap8:ExecutionAlias`
///   require the `Alias` — the name a user TYPES — to end in `.exe`, while the manifest's
///   `Executable=` path, which names the file, carries no such constraint.
///
/// # The rule
///
/// - POSIX (`windows` is `false`): `name` unchanged, always, either shape. POSIX has no
///   loader-level notion of an "executable extension" for this crate to reproduce.
/// - Windows, final path component already ending in `.exe`/`.com` (compared CASE-INSENSITIVELY,
///   so `TOOL.EXE` is never doubled into `TOOL.EXE.exe`): `name` unchanged, either shape. There is
///   nothing to append that would not name a file the caller did not write.
/// - Windows, [`Shape::BareName`]: `name` + `.exe`, and ONLY that, appended to the name AS
///   WRITTEN. `tool.` yields `tool..exe` and `...` yields `....exe` — odd-looking, but the one
///   rule unbranched, and appending to anything but what the caller wrote would search for a file
///   they did not name. See the monotonicity note, which counts this as a widening.
/// - Windows, [`Shape::Located`]: `name` first, always. `name` + `.exe` follows ONLY when the
///   name carries no extension at all AND names a file — see [`takes_the_exe_fallback`], which is
///   what keeps this axis from widening against `main`.
///
/// # Why `Located` tries the exact name first
///
/// A located name visits exactly one directory: the one the caller named. There is no search to
/// bias, so the ordering answers only "did the caller mean this file?" — and they wrote it, so yes.
/// Refusing it would make `executable()` unable to name a perfectly loadable image (a staged
/// `payload.tmp`, a content-addressed cache entry, a `.scr`, anything named by hash), a restriction
/// neither the format, the loader, nor the app model imposes.
///
/// The `.exe` fallback stays because it is the reason the rule exists at all: someone writing
/// `executable("bin/my-program")` for code that builds on both platforms must not be forced to
/// append `.exe` conditionally themselves.
///
/// One consequence, stated plainly: where both `bin/tool` and `bin/tool.exe` exist, the
/// extensionless one wins. A writer who can create files in that directory but not overwrite a
/// locked, running `tool.exe` can therefore decide the outcome. This is the ordering `main`
/// shipped, kept deliberately — the alternative loses the ability to name an exact file, which is
/// the whole point of the located axis.
///
/// # Why `.exe` *and* `.com`
///
/// `.exe` and `.com` are exactly the two extensions `CreateProcessW` loads directly as a PE image.
/// A `.com` file on a modern Windows install (`more.com`, `chcp.com`, `tree.com`, all shipped in
/// `System32`) is an ordinary PE whose extension is cosmetic; leaving `.com` off the allowlist
/// would turn `args(["more.com"])` into a search for the nonexistent `more.com.exe`, breaking
/// resolution of a name the system-directory search makes work today.
///
/// Script extensions (`.bat`/`.cmd`) are deliberately NOT in the allowlist — but NOT because this
/// crate treats a script as an illegitimate target. Resolving a bare name to a script is a
/// SEPARATE, CURRENTLY UNIMPLEMENTED feature: batch support needs its own `cmd.exe`
/// metacharacter quoter (alongside the existing MSVCRT one) plus PATHEXT-based resolution, and is
/// planned as its own follow-up PR. This is unrelated to — and does not weaken — this crate's
/// existing, separate batch-path rejection (see `reject_batch_path`'s own message: "cmd.exe batch
/// escaping is not implemented (CVE-2024-24576)").
///
/// # Monotonicity of the BARE-name rule — stated honestly, in both directions
///
/// This section justifies the single candidate for [`Shape::BareName`] ONLY. It is measured on the
/// surfaces that resolve a bare name, and deliberately does not reach the located axis above.
///
/// Measured on real Windows CI (amd64 and arm64 alike): `CreateProcessW` with a NULL
/// `lpApplicationName`, and `cmd.exe`, `pwsh` 7, and Windows PowerShell 5.1 alike, all refuse to
/// run an extensionless PE by bare name — a directory holding only `tool` (no extension) yields
/// `ERROR_FILE_NOT_FOUND`/"not recognized" from every one of them. So this NARROWS for a bare
/// extensionless name: the old rule tried `tool.exe` then `tool`, and that second candidate never
/// actually ran on any of those four surfaces — dropping it removes a candidate nothing on the
/// platform could launch anyway, and removes the hazard of an ambient extensionless file winning
/// in some directory the search visits.
///
/// Those same three shells (unlike `CreateProcessW` itself) resolve a bare DOTTED name via
/// PATHEXT — typing `foo.bar` runs `foo.bar.exe` when that file exists — while the OLD has-a-dot
/// heuristic here refused to append `.exe` to anything already containing a `.`, so `python3.11`
/// could never resolve even though every one of those shells finds `python3.11.exe`. So this rule
/// also WIDENS for a dotted bare name: it now appends `.exe` where it used to leave the name alone.
/// That widening is deliberate and matches the three shells, measured — it does NOT match
/// `CreateProcessW`'s own NULL-`lpApplicationName` behaviour, and is not meant to: that parity is
/// already given up on for `.bat`/`.cmd`, above.
///
/// Membership in that widening set is `Path::extension().is_some()` and nothing else — never a
/// judgement about where the dot sits. `tool.`, `...`, `.. ` and `tool. ` are all in it, and are
/// worth calling out because they are the plantable ones: `main` searched only for the literal
/// `tool.`, which Win32 opens as `tool`, whereas this rule searches for `tool..exe`, a name `main`
/// never looked for and a writer of any searched directory can create. Kept anyway, because
/// trimming is worse: it searches for `tool.exe`, a name the caller did not write EITHER, and buys
/// the refusal of `...` — which names a file, so refusing it reports `InvalidInput` for an input
/// some filesystem satisfies, breaking this module's own kind rule. The shells' PATHEXT behaviour
/// was measured on `foo.bar` and on none of these; that they fall under the same rule is an
/// argument from uniformity, not a measurement.
///
/// # Not a permanent rule
///
/// The one-candidate rule for a BARE name is expected to be superseded by proper PATHEXT-based
/// resolution once batch support lands (see the `.bat`/`.cmd` note above) — a future reader should
/// not assume it is permanent. The `Located` behaviour is expected to survive that change
/// unchanged, because PATHEXT is a search mechanism and the located axis does not search.
fn filename_candidates(name: &OsStr, windows: bool, shape: Shape) -> Vec<std::ffi::OsString> {
    if !windows || has_loadable_extension(name) {
        return vec![name.to_os_string()];
    }
    match shape {
        // Nothing to append to: `.exe` would become the whole name (`.` -> `..exe`), a plant under
        // a name the caller never wrote. `resolve` refuses this shape before reaching here, so the
        // guard is defence in depth for a future caller that bypasses it — the located axis asks
        // the same question, through [`takes_the_exe_fallback`].
        Shape::BareName if names_no_file(name, windows) => vec![name.to_os_string()],
        Shape::BareName => vec![push_exe(name.as_encoded_bytes())],
        // A located name with SOME extension gets exactly one candidate, the name as written.
        // `main` keyed its `.exe` fallback on `Path::extension().is_none()`, so appending to a
        // dotted name here would be a WIDENING on the located axis: `executable(r"C:\t\thing.bin")`
        // would newly resolve to `thing.bin.exe` when `thing.bin` is absent, loading a file a
        // writer of that directory could plant where `main` returned `NotFound`. The monotonicity
        // argument below is measured on the SEARCHED axis and does not license that.
        Shape::Located if takes_the_exe_fallback(name, windows) => {
            vec![name.to_os_string(), push_exe(name.as_encoded_bytes())]
        }
        Shape::Located => vec![name.to_os_string()],
    }
}

fn push_exe(bytes: &[u8]) -> std::ffi::OsString {
    // SAFETY: both callers pass a whole `as_encoded_bytes` slice, unsliced, which round-trips by
    // definition.
    let mut out = unsafe { OsStr::from_encoded_bytes_unchecked(bytes) }.to_os_string();
    out.push(".exe");
    out
}

/// Whether a LOCATED name gets the second, `.exe` candidate.
///
/// Distinct from [`has_loadable_extension`], which asks the narrower "is it already `.exe`/`.com`".
/// This decides the fallback, and it exists to keep the located axis from WIDENING against `main`,
/// which keyed on `Path::extension().is_none()` and appended via `Path::with_extension`.
///
/// Two ways to get that wrong, both of which this rules out: a name whose final component already
/// carries an extension must not gain `name.exe` (`main` refused it), and a name that names no
/// file must not gain one either — there `.exe` becomes the whole final component, naming a
/// dotfile INSIDE the directory (`C:\tools\dir\` -> `C:\tools\dir\.exe`) or a sibling of it
/// (`C:\t\.` -> `C:\t\..exe`), either of which a writer of that directory can plant and which
/// `main` — whose `Path::with_extension` is a no-op on a path with no file name — never looked
/// for. That second question is [`names_no_file`]'s, and is asked by calling it rather than by
/// re-deriving it here, because the bare axis asks the same question and two spellings of one rule
/// drift apart.
///
/// [`resolve`] refuses such a name before reaching here, so this is defence in depth for any
/// future caller of this function that does not go through it.
fn takes_the_exe_fallback(name: &OsStr, windows: bool) -> bool {
    if names_no_file(name, windows) {
        return false;
    }
    // Otherwise: only when there is no extension, matching `Path::extension()`'s rule that a
    // LEADING dot is part of the stem (`.bashrc` has none) — which is what `main` keyed on.
    let rposition = final_component(name, windows).iter().rposition(|&b| b == b'.');
    matches!(rposition, Some(0) | None)
}

/// Whether `name` already ends in `.exe` or `.com`, compared case-insensitively — `TOOL.EXE` must
/// not become `TOOL.EXE.exe`. These are the two extensions `CreateProcessW` loads directly as a PE
/// image; see `filename_candidates`'s doc for why exactly these two and no others.
///
/// Unlike its sibling classifiers this does NOT split off the final component first, and so takes
/// no `windows` flag. Neither suffix contains a separator, so for every input that REACHES here
/// the two readings coincide: both callers ([`resolve`] and [`reject_unloadable_image`]) refuse a
/// [`names_no_file`] name first, and only such a name can have its final component swallowed by a
/// prefix (`\\server\share.exe` ends in `.exe` while its final component is empty). A future
/// caller bypassing that refusal would get the whole-string answer; compare
/// `final_component(name, windows)` instead if it needs the other.
fn has_loadable_extension(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    ends_with_ignore_ascii_case(bytes, b".exe") || ends_with_ignore_ascii_case(bytes, b".com")
}

/// Refuse an image whose name does not end in `.exe`/`.com` — the ELEVATED path's allowlist.
///
/// `ShellExecuteEx` does not open `lpFile`, it RESOLVES it, and it applies `PATHEXT` even when
/// `lpFile` is absolute. Measured on both CI architectures and on a real desktop: `PATHEXT`
/// OUTRANKS AN EXISTING FILE, so an absolute `C:\dir\tool` with a planted `C:\dir\tool.bat`
/// beside it runs the batch file even when `tool` is a real PE. From an unelevated caller that
/// child runs at High integrity, and the consent dialog reads "Windows Command Processor",
/// Microsoft Corporation (verified) — the batch resolves to its signed handler, so the bypass
/// launders the one thing the user is being asked to judge.
///
/// Existence therefore cannot be the test; only the NAME can be. An ALLOWLIST rather than a
/// denylist of script extensions, because `ShellExecuteEx` resolves any registered association:
/// `.lnk`, `.vbs`, `.ps1`, `.js`, `.hta` and `.msi` are all refused here by construction, where
/// a denylist would have to enumerate a registry the caller's machine controls. `.lnk` is the
/// sharp case — a shortcut's target can be `cmd.exe /c ...`, elevating a program never named.
///
/// Those measurements are of a launch without a class. cosca launches as `exefile`
/// (`SEE_MASK_CLASSNAME`), and whether that launch applies `PATHEXT` on the consent route an
/// unelevated caller takes is unmeasured.
///
/// The allowlist closes the extensionless case only, whatever that answer is. Whether
/// `ShellExecuteEx` applies `PATHEXT` to an `lpFile` that already ends in `.exe` — a real
/// `tool.exe` beside a planted `tool.exe.bat` — is unmeasured on every route, and this rule makes
/// no claim about it.
///
/// # Deliberately stricter than an unelevated spawn
///
/// `CreateProcessW` does NOT extend `lpApplicationName` ("no default extension is assumed"), so
/// it loads an extensionless PE by absolute path quite safely; `ShellExecuteEx` does extend, so
/// the same name is plantable there. The asymmetry is the platform's, and this rule follows it
/// rather than papering over it: `.elevate()` refuses names an ordinary spawn accepts.
/// `args([r"C:\t\tool"]).elevate()` wants `C:\t\tool.exe`.
///
/// Over-rejection is the safe direction and is taken where the two disagree: `tool.exe.` (trailing
/// dot) resolves to `tool.exe` on Windows but is refused here, because a trailing dot does NOT
/// suppress `PATHEXT` (measured) and reasoning about which spellings Windows silently trims is
/// how the plantability bug got in.
pub(crate) fn reject_unloadable_image(program: &Path, windows: bool) -> Result<(), Error> {
    // `names_no_file` first: it is what makes `has_loadable_extension`'s whole-string reading the
    // final component's (see its doc).
    if !names_no_file(program.as_os_str(), windows) && has_loadable_extension(program.as_os_str()) {
        return Ok(());
    }
    Err(unloadable_image(program))
}

fn unloadable_image(program: &Path) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "elevation requires an image named .exe or .com, because ShellExecuteEx may apply \
             PATHEXT to any other name and a planted script would then outrank it: {program:?}"
        ),
    ))
}

fn ends_with_ignore_ascii_case(bytes: &[u8], suffix: &[u8]) -> bool {
    bytes.len() >= suffix.len() && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Split a `PATH` value on the simulated platform's separator.
///
/// On Windows a `"` toggles quoting, so a `;` inside quotes does not split — letting a directory
/// that contains a literal `;` (or leading/trailing space) survive as ONE element rather than
/// being torn in half by a naive byte-level `;` split. `"C:\a;b"` is one element, `C:\a;b`; a
/// plain, unquoted `C:\bin` passes through unchanged.
///
/// Every `"` is consumed as a delimiter wherever it appears, not only a wrapping pair: an
/// interior `C:\Pro"gram Files"\bin` yields `C:\Program Files\bin`, with the quotes removed and
/// the remainder concatenated. That matches `std::env::split_paths`'s own Windows parser, which
/// this replaced, so the behaviour is deliberate — but it does mean a `"` is never preserved as
/// a literal path character on Windows.
///
/// Stripping is what keeps a quoted entry alive at all: leaving the quotes IN would fail the
/// `is_absolute()` filter the caller applies afterwards (a leading `"` is not a recognised drive
/// prefix), so the entry would be SILENTLY DROPPED rather than erroring.
///
/// On POSIX, `"` is an ordinary filename character and `;` is not a separator: quoting is
/// deliberately NOT applied there — only `:` splits, and any quote characters in an element are
/// preserved literally, matching every POSIX shell's own (quote-free) `PATH` handling.
fn split_path_var(var: Option<&OsStr>, windows: bool) -> Vec<PathBuf> {
    let Some(var) = var else { return Vec::new() };
    let bytes = var.as_encoded_bytes();
    if windows {
        split_path_var_windows(bytes)
    } else {
        split_path_var_posix(bytes)
    }
}

fn split_path_var_posix(bytes: &[u8]) -> Vec<PathBuf> {
    bytes
        .split(|&b| b == b':')
        // SAFETY: the bytes came from `as_encoded_bytes` and are split on an ASCII byte, which
        // is the documented-safe way to slice an `OsStr`'s encoded form.
        .map(|part| PathBuf::from(unsafe { OsStr::from_encoded_bytes_unchecked(part) }))
        .collect()
}

/// Windows `PATH` splitting with quote handling — see [`split_path_var`]'s doc for the rule.
fn split_path_var_windows(bytes: &[u8]) -> Vec<PathBuf> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut in_quotes = false;
    for &b in bytes {
        match b {
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => parts.push(std::mem::take(&mut current)),
            _ => current.push(b),
        }
    }
    parts.push(current);
    parts
        .into_iter()
        // SAFETY: the bytes came from `as_encoded_bytes`; dropping quote bytes and splitting on
        // an ASCII byte are both the documented-safe way to slice an `OsStr`'s encoded form.
        .map(|part| PathBuf::from(unsafe { OsStr::from_encoded_bytes_unchecked(&part) }))
        .collect()
}

/// Whether a candidate exists as a file, on either grammar.
///
/// Existence is the whole test, on both platforms: the execute bit, and every other reason the
/// file cannot be started, is the launch's own error (`EACCES`, `ENOEXEC`), reported as that and
/// not as a miss, and no later candidate is tried in its place. A directory is not a file, so a
/// directory of the program's name does not end a search. `named`: the caller wrote this path, so
/// whatever is there is the match (a directory or a device too, which a launch refuses with its own
/// error); a miss would say the program is not there when it is.
///
/// `Err` when the filesystem could not say whether `path` exists (a permission, I/O or network
/// failure), as distinct from saying it does not: see [`resolve`] for what each caller does with
/// that. Only a missing file or directory, a non-directory in the path, and a name no filesystem
/// accepts are a definite "not here".
pub(crate) fn is_file(path: &Path, named: bool) -> std::io::Result<bool> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(named || meta.is_file()),
        Err(e) if is_absence(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Whether a metadata error says definitely "no such file": nothing at the path, a non-directory
/// in it, a name no filesystem accepts, or (Windows) no such drive.
///
/// Decided on the raw OS code, not [`std::io::ErrorKind`]: std maps `ERROR_BAD_NETPATH` and
/// `ERROR_BAD_NET_NAME` to `NotFound` too, and an unreachable share may only be unreachable for now.
fn is_absence(e: &std::io::Error) -> bool {
    let Some(code) = e.raw_os_error() else {
        return e.kind() == std::io::ErrorKind::NotFound;
    };
    #[cfg(windows)]
    {
        // FILE_NOT_FOUND, PATH_NOT_FOUND, INVALID_DRIVE, INVALID_NAME, BAD_PATHNAME, DIRECTORY.
        matches!(code, 2 | 3 | 15 | 123 | 161 | 267)
    }
    #[cfg(unix)]
    {
        matches!(code, libc::ENOENT | libc::ENOTDIR)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = code;
        e.kind() == std::io::ErrorKind::NotFound
    }
}

/// `candidate` under `dir`: on the Windows grammar by [`join::join`], the one Windows join, with
/// the host's separator since the result is probed on this host; otherwise `PathBuf::join`. An empty
/// `dir` is an absolute name's own location. With `as_units` (a completed drive-relative name) the
/// candidate is [`join::append`]ed as units, whatever it parses to.
fn join_candidate(dir: &Path, candidate: &OsStr, windows: bool, as_units: bool) -> PathBuf {
    if !windows {
        return dir.join(candidate);
    }
    if dir.as_os_str().is_empty() {
        return PathBuf::from(candidate);
    }
    let sep = std::path::MAIN_SEPARATOR_STR;
    if as_units {
        return PathBuf::from(join::append(dir.as_os_str(), candidate, sep));
    }
    PathBuf::from(join::join(dir.as_os_str(), candidate, sep))
}

/// Whether a joined candidate is fully qualified, so no current directory, the process's or a
/// drive's, decides which file it names. Either reading counts: `std`'s knows the host's grammar
/// (and on Windows only letter drives), [`is_absolute_name`] the simulated one.
fn accepted(joined: &Path, windows: bool) -> bool {
    joined.is_absolute() || is_absolute_name(joined.as_os_str(), windows)
}

/// Whether `name` is rooted (`\x`) and `base` verbatim: a name Win32 completes off the base's
/// volume, which [`resolve`] and the raw backend's completion both refuse.
pub(crate) fn is_rooted_on_verbatim(name: &OsStr, base: Option<&OsStr>) -> bool {
    path_type(name) == PathType::Rooted && base.is_some_and(|b| join::is_verbatim(b.as_encoded_bytes()))
}

/// The refusal for [`is_rooted_on_verbatim`].
pub(crate) fn rooted_on_verbatim(name: &Path) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{name:?} is rooted, and Win32 completes a rooted name against a verbatim (\\\\?\\) \
             directory to a path off that directory's volume; spell it in full"
        ),
    ))
}

/// The refusal of a program for which [`names_no_file`] holds.
fn names_no_file_refusal(program: &Path) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("program does not name a file: {program:?}"),
    ))
}

#[cfg_attr(
    not(any(windows, test)),
    allow(
        dead_code,
        reason = "a unix spawn calls `search`; the Windows backend and the tests call this"
    )
)]
pub(crate) fn resolve(input: ResolveInput<'_>) -> Result<PathBuf, Error> {
    search(input).map(|(found, _)| found.path)
}

/// A file a search names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) path: PathBuf,
    /// The `PATH` element, as written, the path was joined to. `None` for a located name and for any name on
    /// the Windows grammar: only the POSIX grammar has an element to name (a Windows match can be in a
    /// system directory, which is no `PATH` element).
    pub(crate) entry: Option<PathBuf>,
}

/// What a search says when it stops at `candidate`, which it cannot examine: in `dir`, the entry the
/// candidate was joined to, when it has one (a bare name; a located one has none). The one text of the
/// stop, for the parent's search and for the child's walk of the later candidates, which both stop there.
/// With no `candidate` (the child's report did not name it) it says only that a later one cannot be told.
pub(crate) fn unexamined_context(candidate: Option<&Path>, dir: Option<&Path>) -> String {
    match (candidate, dir) {
        (Some(candidate), Some(dir)) => {
            format!("could not tell whether {candidate:?} exists in {dir:?}, so the search stops")
        }
        (Some(candidate), None) => format!("could not tell whether {candidate:?} exists, so the search stops"),
        (None, _) => "could not tell whether a later candidate exists, so the search stops".into(),
    }
}

/// [`resolve`], and with the match the candidates after it: for a POSIX bare name, the `PATH`
/// elements after the one the match is in, joined to the name, in order and fully qualified only
/// (not probed), each with its element; empty for any other name and for the Windows grammar. The
/// match carries the element it was found in when the name is bare, on the POSIX grammar.
pub(crate) fn search(input: ResolveInput<'_>) -> Result<(Candidate, Vec<Candidate>), Error> {
    let name = input.program.as_os_str();
    // The base contract, reported at the call boundary rather than where the base is first used.
    debug_assert!(
        input.cwd.is_some() || !input.windows || !needs_base(name, input.windows),
        "{name:?} needs a base, and none was given"
    );
    debug_assert!(
        !input.windows || input.cwd.is_none_or(|cwd| accepted(cwd, true)),
        "a Windows base must be fully qualified: {:?}",
        input.cwd
    );
    // A name with no stem does not merely fail to resolve, it INVENTS one: the `.exe` rule turned
    // `""` into the candidate `.exe`, `.` into `..exe`, and `C:\t\.` into `C:\t\..exe` — each a
    // file that a writer of the searched directory can plant under a name the caller never wrote.
    // Guarding one candidate rule at a time leaves the next spelling open, so the shape is refused
    // outright. `InvalidInput`, not `NotFound`: nothing was looked for.
    if names_no_file(name, input.windows) {
        return Err(names_no_file_refusal(input.program));
    }
    // `PathBuf::join` would read such a name as rooted and keep the base's own drive, loading a
    // local file where Win32 reads a UNC path the caller named.
    if is_unc_without_share(name, input.windows) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "program starts with two separators, which Win32 reads as a UNC path, but names no \
                 share: {:?}",
                input.program
            ),
        )));
    }
    // Win32 completes a rooted name against a verbatim directory off that directory's volume
    // (`\\t.exe` on `\\?\UNC\srv\shr\d`, measured), so no file there could be the one it names.
    if input.windows && is_rooted_on_verbatim(name, input.cwd.map(Path::as_os_str)) {
        return Err(rooted_on_verbatim(input.program));
    }
    // From here on a drive-relative name is the located name it completes to, based on
    // `drive_base`'s directory.
    let drive_based = if is_drive_relative(name, input.windows) {
        let cwd = input
            .cwd
            .unwrap_or_else(|| unreachable!("{name:?} needs a base, and none was given"));
        Some(drive_relative::drive_base(name, cwd, input.same_drive, |drive| {
            Ok((input.child_drive_dir)(drive))
        })?)
    } else {
        None
    };
    let (name, base) = match &drive_based {
        Some((base, rest)) => (*rest, Some(base.path())),
        None => (name, input.cwd),
    };
    // Classify FIRST: the candidate filenames depend on the shape (a located name also tries the
    // exact name the caller wrote, a searched one does not — see `filename_candidates`).
    let shape = if drive_based.is_some() {
        Shape::Located
    } else {
        classify(name, input.windows)
    };
    let mut candidates = filename_candidates(name, input.windows, shape);
    debug_assert!(
        input.windows || !input.loadable_only,
        "loadable_only is a Windows rule: {:?}",
        input.program
    );
    if input.loadable_only {
        candidates.retain(|c| has_loadable_extension(c));
        // Candidates depend on the string alone, so none surviving is a refusal on shape
        // (`bin/tool.bat`), stated here rather than left to the loop's `NotFound`.
        if candidates.is_empty() {
            return Err(unloadable_image(input.program));
        }
    }

    let dirs: Vec<PathBuf> = match shape {
        // An absolute name is its own location: joining it onto any directory yields it again, so
        // no cwd is read for it.
        Shape::Located if drive_based.is_none() && !needs_base(name, input.windows) => vec![PathBuf::new()],
        Shape::Located => vec![match base {
            // Either reading counts: `std` knows only the host's grammar (and on Windows, only
            // letter drives), this module's classifier only the simulated one.
            Some(cwd) if accepted(cwd, input.windows) => cwd.to_path_buf(),
            // POSIX: probed as given. The OS reads a relative base against the directory this
            // process inherited, with no path of it, which is the directory the child reads the
            // name against (it `chdir`s into `cwd` itself, so the name is not joined to `cwd`
            // again: the caller keeps the name, see `posix::lookup`).
            Some(cwd) if !input.windows => cwd.to_path_buf(),
            Some(cwd) => unreachable!("a Windows base must be fully qualified: {cwd:?}"),
            None if !input.windows => PathBuf::new(),
            // A caller that supplies its own base passes `None` only for a name that
            // `needs_base` says needs none. Reading the process cwd here instead would be a second
            // read that caller cannot see.
            None => unreachable!("{:?} needs a base, and none was given", input.program),
        }],
        // `system_dirs` precedes `PATH`, and is called HERE — the one place in `resolve` that
        // invokes it — so a query that can fail is only ever reached once every shape refusal above
        // has already passed and the name is confirmed bare; a `Located` or absolute name returns
        // through one of the arms above without calling it at all. The cwd is never read on this
        // arm at all — a structural guarantee, not a property of `system_dirs`. The app directory is
        // absent only because the production caller (`windows_system_dirs`) omits it from what it
        // returns; this arm searches whatever the closure returns, as the app-directory
        // positive-control test demonstrates. See `ResolveInput::system_dirs`'s doc for the full
        // trust-ordering argument. Ignored outright off Windows: `system_dirs` is never called there
        // in practice, but the `input.windows` guard makes that a hard rule rather than a convention
        // a future POSIX caller could violate by accident.
        Shape::BareName => {
            let mut dirs = if input.windows {
                (input.system_dirs)()?
            } else {
                Vec::new()
            };
            dirs.extend(split_path_var(input.path_var, input.windows));
            dirs
        }
    };

    for (at, dir) in dirs.iter().enumerate() {
        for candidate in &candidates {
            let made_verbatim = input.windows
                && shape == Shape::Located
                && join::is_verbatim(dir.as_os_str().as_encoded_bytes())
                && !join::is_verbatim(candidate.as_encoded_bytes());
            // Only the cwd base is a directory the caller did not spell verbatim. A `PATH` or
            // system directory is written verbatim by whoever set it, and is taken as written.
            // A made-verbatim name is joined as written, for `normalise` to collapse as Win32 does.
            let joined = if made_verbatim {
                PathBuf::from(join::concat(dir.as_os_str(), candidate, "\\"))
            } else {
                // A drive-relative name is appended as units: `D:\x` after `C:` is a file in the
                // directory, not drive D's root, which a join would make it.
                join_candidate(dir, candidate, input.windows, drive_based.is_some())
            };
            // Only a fully qualified `joined` is accepted — this is what actually keeps a relative
            // or empty `PATH` element from resolving through the current directory (an empty
            // element means "the current directory", and a relative one such as `.`/`tools`
            // resolves against it just as surely). A drive-relative element (`C:` or `C:tools`)
            // joins to a drive-relative path, which would resolve through a drive's own current
            // directory. This single check is also what keeps the contract every backend relies on:
            // the answer is always absolute, except a POSIX located name, which is read against the
            // inherited directory and is no search.
            if !accepted(&joined, input.windows) && (input.windows || shape != Shape::Located) {
                continue;
            }
            let probed = if made_verbatim {
                match (input.normalise)(&joined) {
                    // Win32's floor lets `..` climb past a verbatim share, to a share root or a
                    // path on no share (measured). No disk could put a file there.
                    Ok(path) if names_no_file(path.as_os_str(), true) => {
                        return Err(Error::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "{:?} completes against {dir:?} to {path:?}, which names no file",
                                input.program
                            ),
                        )))
                    }
                    other => other,
                }
            } else {
                Ok(joined.clone())
            }
            .and_then(|path| Ok(is_file(&path, !input.windows && shape == Shape::Located)?.then_some(path)));
            match probed {
                Ok(Some(path)) => {
                    // A POSIX search also answers the candidates after the match, for a launch that finds
                    // the match gone: see `posix::lookup`.
                    let later = if !input.windows && shape == Shape::BareName {
                        dirs[at + 1..]
                            .iter()
                            .flat_map(|dir| {
                                candidates
                                    .iter()
                                    .map(move |c| (dir, join_candidate(dir, c, false, false)))
                            })
                            .filter(|(_, joined)| accepted(joined, false))
                            .map(|(dir, path)| Candidate {
                                path,
                                entry: Some(dir.clone()),
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                    let entry = (!input.windows && shape == Shape::BareName).then(|| dir.clone());
                    return Ok((Candidate { path, entry }, later));
                }
                Ok(None) => {}
                // A `loadable_only` search fails closed: skipping a candidate it could not check
                // would let a later directory, perhaps one on `PATH` an attacker can write, supply
                // the image. So does every POSIX search: an entry that cannot be examined means the
                // search cannot be carried out as written. The error names the candidate and the
                // entry; the OS code is down its `source()` chain, as the `Error` docs say.
                //
                // A POSIX located name is no search: its error is the OS's own, bare, for a spawn's
                // caller to branch on.
                Err(e) if !input.windows && shape == Shape::Located => return Err(Error::Io(e)),
                Err(e) if !input.windows || input.loadable_only => {
                    let context =
                        unexamined_context(Some(&joined), (shape == Shape::BareName).then_some(dir.as_path()));
                    return Err(Error::Io(crate::error::io_context(context, e)));
                }
                // An ordinary Windows spawn goes on, so one unreadable `PATH` directory does not
                // break every search, as `CreateProcessW`'s own does not.
                Err(e) => log::warn!(
                    "skipping {joined:?}, whose existence could not be determined: {report}",
                    report = crate::error::Report(&e)
                ),
            }
        }
    }
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("could not resolve executable: {}", input.program.display()),
    )))
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
pub(crate) mod resolve_tests;

#[cfg(test)]
#[path = "resolve_loadable_tests.rs"]
mod resolve_loadable_tests;

#[cfg(test)]
#[path = "resolve_base_tests.rs"]
mod resolve_base_tests;

#[cfg(all(test, windows))]
#[path = "resolve_windows_tests.rs"]
mod resolve_windows_tests;
