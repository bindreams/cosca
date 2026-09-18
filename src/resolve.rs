//! Which file a `Command` loads — on the spawn paths that currently consult it.
//!
//! **Coverage today: only the Windows raw `CreateProcessW` backend (sync and its tokio mirror),
//! reached when `Command::executable_path()` is set or an fd >= 3 is mapped.** Every other spawn
//! path resolves the program name itself, ignorant of this module entirely: POSIX spawning still
//! calls `execvp`/`posix_spawn`'s own PATH search directly, and the Windows elevated
//! (`ShellExecuteEx`) path still passes its `lpFile` through unresolved. `src/lib.rs`'s
//! `#[cfg_attr(not(windows), allow(dead_code))]` on this module tracks exactly that: the `allow`
//! goes away once the POSIX and default spawn paths route through it too.
//! Producing an ABSOLUTE path is what would let a backend skip its own search once it is wired
//! up — `execvp` does not search a name containing a separator, and `ShellExecuteEx` does not
//! search an absolute `lpFile` — but that wiring has not happened yet for either.
//!
//! Classification is byte-level and parameterised by [`ResolveInput::windows`] rather than using
//! `std::path`, whose parsing is host-specific — `Path::new("C:tool").prefix()` is `None` off
//! Windows, so a `Path`-based rule could not be exercised from a POSIX host at all.
//!
//! A bare name is resolved from [`ResolveInput::system_dirs`] (Windows only) and then `PATH` —
//! **never** the current directory. `system_dirs` is likewise taken as a parameter rather than
//! queried from the OS here, for the same host-independence reason; see its doc for what it
//! contains and why it precedes `PATH`.

use crate::error::Error;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Everything the policy reads. Taken as parameters so the rules are testable without touching
/// the ambient environment.
pub(crate) struct ResolveInput<'a> {
    /// The program as the caller wrote it.
    pub program: &'a Path,
    /// The directory the CHILD will run in: `Command::cwd()` when set, else the parent's.
    pub cwd: &'a Path,
    /// Directories searched for a bare name BEFORE `PATH`, in order. Ignored entirely when
    /// `windows` is `false` — POSIX has no analogous search order to preserve.
    ///
    /// On Windows this reproduces `CreateProcessW`'s documented NULL-`lpApplicationName` search
    /// order — app directory, then the System32 directory, then the Windows directory — MINUS the
    /// parent's current directory, which this crate refuses to search at all (see `cwd`'s own
    /// doc and the module doc above). That framing is what makes prepending these directories
    /// provably monotonic rather than just "probably fine": the old, unpatched order was app dir
    /// -> cwd -> System32 -> Windows dir -> `PATH`; removing the cwd step is a strict narrowing,
    /// but if this crate ALSO silently dropped the system-directory precedence over `PATH` — which
    /// is exactly what happens if `system_dirs` is left empty for a route that has no
    /// `executable()` set — that would be a strict WIDENING on that route: a user-writable
    /// directory placed early on `PATH` (a dev toolchain install, an `%LOCALAPPDATA%\...\WindowsApps`
    /// shim) would then shadow e.g. `System32\find.exe`, a new way to load the wrong binary that
    /// the pre-patch code never had. The caller passes these in (rather than this module calling
    /// `GetSystemDirectoryW`/`GetWindowsDirectoryW`/`current_exe` itself) so the rule stays
    /// testable from a POSIX host, exactly like `windows` below.
    pub system_dirs: &'a [PathBuf],
    /// The `PATH` the CHILD will see, after `env()`/`env_clear()`.
    pub path_var: Option<&'a OsStr>,
    /// Apply Windows rules: `;` separated `PATH`, `\` a separator, drive prefixes, the `.exe` rule.
    pub windows: bool,
}

/// How the program names its file, which decides whether `PATH` (and, on Windows,
/// `system_dirs`) is consulted at all.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    /// No separator and no drive prefix: the only shape that searches `system_dirs` and `PATH`.
    BareName,
    /// Contains a separator, or carries a drive prefix (`C:tool` means "relative to drive C's
    /// current directory", so a `PATH` search for it would be a lie).
    Located,
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
    if windows && has_drive_prefix(bytes) {
        return Shape::Located;
    }
    Shape::BareName
}

fn is_sep(b: u8, windows: bool) -> bool {
    b == b'/' || (windows && b == b'\\')
}

fn has_drive_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

/// The single filename tried in each candidate directory — ONE candidate, not a fallback pair.
/// Applies identically to a [`Shape::BareName`] and a [`Shape::Located`] program: extension
/// handling and the PATH/`system_dirs` search are INDEPENDENT axes (see `resolve`'s use of this
/// function, called once before the shape match). `executable()` is the smart setter on both axes,
/// not just the search one — someone writing `executable("bin/my-program")` for code that builds
/// on both platforms must not be forced to conditionally append `.exe` themselves; anyone with a
/// genuinely extensionless image at a known path can bypass this rule entirely by resolving it
/// externally and handing `executable()` the exact, already-correct file name.
///
/// # The rule
///
/// - POSIX (`windows` is `false`): `name` unchanged, always. POSIX has no loader-level notion of
///   an "executable extension" for this crate to reproduce.
/// - Windows: if the FINAL PATH COMPONENT of `name` already ends in `.exe` or `.com` — compared
///   CASE-INSENSITIVELY, so `TOOL.EXE` is left as `TOOL.EXE`, never doubled into `TOOL.EXE.exe` —
///   use `name` unchanged. Otherwise use `name` with `.exe` appended.
///
/// # Why `.exe` *and* `.com`, and why this is NOT a statement about scripts
///
/// `.exe` and `.com` are exactly the two extensions `CreateProcessW` loads directly as a PE image.
/// A `.com` file on a modern Windows install (`more.com`, `chcp.com`, `tree.com`, all shipped in
/// `System32`) is an ordinary PE whose extension is cosmetic; leaving `.com` off the allowlist
/// would turn `args(["more.com"])` into a search for the nonexistent `more.com.exe`, breaking
/// resolution of a name that the system-directory search (added earlier in this same PR) makes
/// work today.
///
/// Script extensions (`.bat`/`.cmd`) are deliberately NOT in the allowlist — but NOT because this
/// crate treats a script as an illegitimate target. Resolving a bare name to a script is a
/// SEPARATE, CURRENTLY UNIMPLEMENTED feature: batch support needs its own `cmd.exe`
/// metacharacter quoter (alongside the existing MSVCRT one) plus PATHEXT-based resolution, and is
/// planned as its own follow-up PR. Until it lands, `tool.bat` resolves as `tool.bat.exe` (a miss),
/// same as any other non-`.exe`/`.com` dotted name. This is unrelated to — and does not weaken —
/// this crate's existing, separate batch-path rejection (see `reject_batch_path`'s own message:
/// "cmd.exe batch escaping is not implemented (CVE-2024-24576)").
///
/// # Monotonicity — stated honestly, in both directions
///
/// Measured on real Windows CI (amd64 and arm64 alike): `CreateProcessW` with a NULL
/// `lpApplicationName`, and `cmd.exe`, `pwsh` 7, and Windows PowerShell 5.1 alike, all refuse to
/// run an extensionless PE by bare name — a directory holding only `tool` (no extension) yields
/// `ERROR_FILE_NOT_FOUND`/"not recognized" from every one of them. So this rule NARROWS for a bare
/// extensionless name: the old rule tried `tool.exe` then `tool`, and that second candidate never
/// actually ran on any of those four surfaces — dropping it removes a candidate nothing on the
/// platform could launch anyway.
///
/// Those same three shells (unlike `CreateProcessW` itself) resolve a bare DOTTED name via
/// PATHEXT — typing `foo.bar` runs `foo.bar.exe` when that file exists — while the OLD has-a-dot
/// heuristic here refused to append `.exe` to anything already containing a `.`, so `python3.11`
/// could never resolve even though every one of those shells finds `python3.11.exe`. So this rule
/// also WIDENS for a dotted name: it now appends `.exe` where it used to leave the name alone. That
/// widening is deliberate and matches the three shells, measured — it does NOT match
/// `CreateProcessW`'s own NULL-`lpApplicationName` behaviour, and is not meant to: that parity is
/// already given up on for `.bat`/`.cmd`, above.
///
/// # Not a permanent rule
///
/// This one-candidate rule for a BARE name is expected to be superseded by proper PATHEXT-based
/// resolution once batch support lands (see the `.bat`/`.cmd` note above) — a future reader should
/// not assume it is permanent. The `Located` behaviour (extension decided purely from the name, no
/// search) is expected to survive that change unchanged.
fn filename_candidates(name: &OsStr, windows: bool) -> Vec<std::ffi::OsString> {
    if !windows || has_loadable_extension(name, windows) {
        return vec![name.to_os_string()];
    }
    let mut with_exe = name.to_os_string();
    with_exe.push(".exe");
    vec![with_exe]
}

/// Whether `name`'s final path component already ends in `.exe` or `.com`, compared
/// case-insensitively — `TOOL.EXE` must not become `TOOL.EXE.exe`. These are the two extensions
/// `CreateProcessW` loads directly as a PE image; see `filename_candidates`'s doc for why exactly
/// these two and no others.
fn has_loadable_extension(name: &OsStr, windows: bool) -> bool {
    let bytes = name.as_encoded_bytes();
    let start = bytes.iter().rposition(|&b| is_sep(b, windows)).map_or(0, |i| i + 1);
    let final_component = &bytes[start..];
    ends_with_ignore_ascii_case(final_component, b".exe") || ends_with_ignore_ascii_case(final_component, b".com")
}

fn ends_with_ignore_ascii_case(bytes: &[u8], suffix: &[u8]) -> bool {
    bytes.len() >= suffix.len() && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Split a `PATH` value on the simulated platform's separator.
///
/// On Windows a `PATH` element may be wrapped in a pair of `"` quotes, letting a directory that
/// contains a literal `;` (or leading/trailing space) survive as ONE element rather than being
/// torn in half by a naive byte-level `;` split. The quotes are consumed as delimiters, not
/// content: `"C:\a;b"` is one element, `C:\a;b`; a plain, unquoted `C:\bin` passes through
/// unchanged. Leaving the quotes IN the element would fail the `is_absolute()` filter the caller
/// applies afterwards (a leading `"` is not a recognised drive prefix), so a quoted entry would
/// be SILENTLY DROPPED rather than erroring — stripping them here is what keeps it alive.
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

/// Whether a candidate is a file this platform could actually exec.
///
/// On POSIX the execute bit is part of the answer: `execvp` skips a readable-but-non-executable
/// match and keeps searching (measured), so keying on existence alone stops at a file that would
/// have been passed over and hands it to exec, turning a working command into `EACCES`.
/// `faccessat(AT_EACCESS)` asks for the ids that will actually exec, unlike `access`.
fn is_execable(path: &Path, windows: bool) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    if !windows {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: a read-only permission query on a valid NUL-terminated path.
        return unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 };
    }
    let _ = windows;
    true
}

pub(crate) fn resolve(input: ResolveInput<'_>) -> Result<PathBuf, Error> {
    let name = input.program.as_os_str();
    let candidates = filename_candidates(name, input.windows);

    // The cwd is absolutised BEFORE joining. A relative one would otherwise be applied twice:
    // the resolver joins it, and std chdirs the child into it as well, so `./tool` with
    // `current_dir("sub")` would exec `sub/sub/tool` (measured).
    let cwd_owned;
    let cwd: &Path = if input.cwd.is_absolute() {
        input.cwd
    } else {
        cwd_owned = std::env::current_dir().map_err(Error::Io)?.join(input.cwd);
        &cwd_owned
    };

    let dirs: Vec<PathBuf> = match classify(name, input.windows) {
        Shape::Located => vec![cwd.to_path_buf()],
        // System directories precede `PATH` — never the cwd, which is deliberately absent from
        // this list; see `ResolveInput::system_dirs`'s doc for why that ordering is what keeps
        // this change a strict narrowing of the pre-patch `CreateProcessW` search rather than
        // trading one hazard for another. Ignored outright off Windows: `system_dirs` is always
        // empty there in practice, but the `input.windows` guard makes that a hard rule rather
        // than a convention a future POSIX caller could violate by accident.
        Shape::BareName => {
            let mut dirs = if input.windows {
                input.system_dirs.to_vec()
            } else {
                Vec::new()
            };
            dirs.extend(split_path_var(input.path_var, input.windows));
            dirs
        }
    };

    for dir in dirs {
        for candidate in &candidates {
            let joined = dir.join(candidate);
            // Only an absolute `joined` is accepted — this is what actually keeps a relative or
            // empty `PATH` element from resolving through the current directory (an empty element
            // means "the current directory", and a relative one such as `.`/`tools` resolves
            // against it just as surely). A drive-relative name (`C:tool`) survives the join
            // unchanged too, because `PathBuf::push` clears for any prefixed path — so it would
            // otherwise resolve through drive C's own current directory, which cosca does not
            // track. This single check is also what keeps the contract every backend relies on:
            // the answer is always absolute.
            if joined.is_absolute() && is_execable(&joined, input.windows) {
                return Ok(joined);
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
mod resolve_tests;
