//! Program resolution + Windows environment-block construction for the raw
//! `CreateProcessW` backend.
//!
//! [`resolve_executable`] delegates to [`crate::resolve`] (a bare name is looked up in the
//! system directories — app dir, System32, the Windows directory — and then `PATH`, never the
//! current directory, resolving through `name.exe` alone; a name containing a separator is not
//! searched at all and is tried as written first, falling back to `name.exe` only when it carries
//! no extension) rather than full `CreateProcessW` search parity — this keeps
//! `.bat`/`.cmd` out of resolution so batch-program rejection stays a separate concern. The
//! system-directory step exists to reproduce
//! `CreateProcessW`'s own NULL-`lpApplicationName` search order minus the current directory: see
//! [`crate::resolve::ResolveInput::system_dirs`] for why dropping only the cwd (and not also the
//! system directories' precedence over `PATH`) is what keeps this a strict narrowing of that
//! order rather than trading one hazard for another. [`ChildEnv`] is the child's environment,
//! captured once per spawn from an [`EnvSnapshot`] and a recorded [`EnvOp`] sequence; resolution
//! reads its `PATH` and [`ChildEnv::into_block`] gives `CreateProcessW` its block.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::GetFullPathNameW;
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

use super::env_key::EnvKey;
use super::env_snapshot::EnvSnapshot;
use crate::command::EnvOp;
use crate::error::Error;

// Program resolution =====

/// Resolve `exe` for the raw backend against `base`, the CHILD's directory, and the CHILD's `PATH`.
///
/// `base` is fully qualified, or `None` for a name [`crate::resolve::needs_base`] says needs none.
/// The raw backend passes its [`effective_cwd`], the same value it gives `CreateProcessW` as
/// `lpCurrentDirectory`, so the file resolved and the directory run in come from one read of this
/// process's state.
///
/// `path` is the child's `PATH`, [`ChildEnv::path`] of the same [`ChildEnv`] whose
/// [`ChildEnv::into_block`] the child is spawned with, so the directories searched here are the
/// ones the CHILD will actually have — as [`crate::resolve::ResolveInput::path_var`]'s doc
/// promises — and no second read of this process's environment can disagree with the block.
pub(crate) fn resolve_executable(exe: &Path, base: Option<&Path>, path: Option<&OsStr>) -> Result<PathBuf, Error> {
    resolve_executable_in(exe, base, &windows_system_dirs(), path, false)
}

/// A raw spawn's effective working directory: filled once per spawn, and the one value every later
/// step uses — the base a program is resolved or completed against, and `lpCurrentDirectory`.
///
/// - A `current_dir` is checked ([`check_current_dir`]), then completed as Win32 completes it
///   ([`complete_on`]), with a drive's own directory (`=Q:`) read from `snapshot`, the spawn's one
///   environment read. It must then be fully qualified, so `current_dir(r"\\server")` is refused.
/// - With none, it is this process's cwd.
///
/// `process_cwd` is called at most once. Leaving `lpCurrentDirectory` null instead would have
/// `CreateProcessW` read the cwd again, so a `set_current_dir` in between could load one
/// directory's file and run the child in another.
pub(crate) fn effective_cwd(
    cmd_cwd: Option<&Path>,
    snapshot: &super::env_snapshot::EnvSnapshot,
    process_cwd: impl FnOnce() -> Result<PathBuf, Error>,
) -> Result<PathBuf, Error> {
    match cmd_cwd {
        Some(dir) => {
            check_current_dir(dir)?;
            let done = complete_on(dir, process_cwd, |drive| Ok(snapshot.var(&drive_cwd_var(drive))))?;
            reject_not_fully_qualified("working directory", &done.path)?;
            Ok(done.path)
        }
        None => process_cwd(),
    }
}

/// The checks every Windows spawn makes on a `current_dir` as written, before anything reads or
/// completes it: no interior NUL, which Win32 would truncate at, and not empty. `""` names no
/// directory, and completing it would silently yield this process's cwd; it is `NotFound`, as the
/// POSIX spawn's `chdir("")` reports.
pub(crate) fn check_current_dir(dir: &Path) -> Result<(), Error> {
    ensure_no_nul_wide("working directory", dir.as_os_str())?;
    if dir.as_os_str().is_empty() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "current_dir(\"\") names no directory",
        )));
    }
    Ok(())
}

/// Refuse a completed field that is still not fully qualified: Win32 reads a path starting with two
/// separators as UNC, and one naming no share (`\\tool.exe`) completes to itself, a path neither
/// on a drive nor on a share. Judged by the resolver's classifier, not `Path::is_absolute`, which
/// knows only letter drives.
pub(crate) fn reject_not_fully_qualified(what: &str, path: &Path) -> Result<(), Error> {
    if crate::resolve::is_absolute_name(path.as_os_str(), true) {
        return Ok(());
    }
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("the {what} names no drive or share once completed: {path:?}"),
    )))
}

/// The real system directories, in `CreateProcessW`'s NULL-`lpApplicationName` search order minus
/// the current directory — see [`crate::resolve::ResolveInput::system_dirs`] for why that
/// ordering matters. Queried here, at the one caller that has ambient OS access, rather than
/// inside `crate::resolve` itself, which is deliberately parameterised so its rules stay
/// exercisable from a POSIX host.
///
/// A step this process cannot determine is left out rather than failing the whole resolution:
/// `resolve_executable`'s caller still falls through to `PATH`, exactly the outcome an empty
/// `system_dirs` produces deliberately in tests, so a transient failure here degrades to
/// (at worst) today's already-shipped behaviour rather than an unrelated spawn error.
fn windows_system_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(3);
    dirs.extend(app_dir());
    dirs.extend(get_system_directory());
    dirs.extend(get_windows_directory());
    dirs
}

/// The directory the running process's own image was loaded from — step 1 of `CreateProcessW`'s
/// search order.
fn app_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(Path::to_path_buf)
}

/// The 32-bit Windows system directory (`System32`) — step 3 of `CreateProcessW`'s search order
/// (step 2, the parent's current directory, is the one this crate deliberately never searches).
fn get_system_directory() -> Option<PathBuf> {
    // SAFETY: `GetSystemDirectoryW` writes into the given buffer, or reports the required length
    // via its return value when the buffer is too small; both are honoured by `wide_dir_buffer`.
    wide_dir_buffer(|buf| unsafe { GetSystemDirectoryW(buf) })
}

/// The Windows directory — step 5 of `CreateProcessW`'s search order (step 4, the 16-bit system
/// directory, does not exist on any Windows version this crate targets).
fn get_windows_directory() -> Option<PathBuf> {
    // SAFETY: see `get_system_directory` — `GetWindowsDirectoryW` has the identical contract.
    wide_dir_buffer(|buf| unsafe { GetWindowsDirectoryW(buf) })
}

/// Call a `GetXDirectoryW`-shaped Win32 function, growing the buffer until the directory fits.
///
/// These functions return the copied length (excluding the NUL) when the buffer was big enough,
/// or the required length (including the NUL) when it was not, and `0` on failure — so `0` is the
/// only outcome that means "give up", never "empty path".
fn wide_dir_buffer(f: impl Fn(Option<&mut [u16]>) -> u32) -> Option<PathBuf> {
    // A system directory this process cannot determine is skipped, not fatal — see this
    // function's doc. Callers that DO need the reason use `grow_wide_buffer` directly.
    grow_wide_buffer(f).ok()
}

/// The shared buffer-growth loop, preserving the Win32 failure reason.
///
/// Same convention for every `GetXW`-shaped path API used here — `GetSystemDirectoryW`,
/// `GetWindowsDirectoryW` and `GetFullPathNameW` alike: the copied length EXCLUDING the NUL on
/// success, the required length INCLUDING it when the buffer was too small, and `0` on failure.
fn grow_wide_buffer(f: impl Fn(Option<&mut [u16]>) -> u32) -> Result<PathBuf, std::io::Error> {
    let mut buf = vec![0u16; 260];
    loop {
        let len = f(Some(&mut buf)) as usize;
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len < buf.len() {
            buf.truncate(len);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        // The documented convention leaves `len == buf.len()` unreachable: success returns the
        // copied length EXCLUDING the NUL (so strictly less than the buffer), and a too-small
        // buffer returns the required length INCLUDING it (so strictly greater). Loud in debug if
        // that is ever violated.
        debug_assert!(
            len > buf.len(),
            "GetXDirectoryW returned {len} for a {}-element buffer: the documented convention makes \
             equality unreachable, and treating it as 'too small' would not grow the buffer",
            buf.len()
        );
        // `.max(buf.len() + 1)` is load-bearing in RELEASE, where the assert is compiled out: a
        // bare `resize(len, 0)` with `len == buf.len()` is a NO-OP, so `f` would be re-called with
        // an identical buffer and this loop would spin forever — a hang on every raw-backend
        // spawn, not a wrong answer. Growing by at least one guarantees progress on every
        // iteration, which is what makes the loop terminate without an arbitrary iteration cap.
        buf.resize(len.max(buf.len() + 1), 0);
    }
}

/// Refuse a program name that names no file — empty, separator-terminated, a root, or a final
/// component of `.`/`..`.
///
/// `raw_executable("")` is the sharpest case: as `lpApplicationName` an empty string becomes a
/// pointer to a lone NUL rather than the NULL pointer, and whether `CreateProcessW` treats those
/// identically is undocumented — if it does, the image search this crate exists to prevent is
/// back, including the current directory. The wider rule covers the rest of the shape:
/// `raw_executable(r"C:\t\dir\")` promises "load exactly this file" while naming a directory, a
/// promise no completion can keep.
///
/// The predicate is [`crate::resolve::names_no_file`] rather than a local copy, so the `Exact` and
/// `Search` arms cannot drift apart on what counts as a filename — and so the rule stays covered
/// by tests that run on any host, not only the Windows runner.
///
/// `Search` reaches the same verdict through [`crate::resolve::resolve`], which refuses these
/// before it searches; this is the `Exact` arms' equivalent.
pub(crate) fn reject_unnameable_program(program: &Path) -> Result<(), Error> {
    if crate::resolve::names_no_file(program.as_os_str(), true) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("raw_executable() was given a path that names no file: {program:?}"),
        )));
    }
    Ok(())
}

/// Complete a possibly-relative program name into an absolute path the way the Win32 loader
/// itself would — **without searching, appending an extension, or touching the filesystem**.
///
/// This is the `Exact` (`raw_executable()`) counterpart to [`resolve_executable`], and both Win32
/// sinks get a completed name:
///
/// - `CreateProcessW` would complete a partial `lpApplicationName` itself ("the function uses the
///   current drive and current directory to complete the specification. The function will not
///   use the search path"), but from its own, second read of the cwd. The raw backend completes it
///   through [`absolutise_exact_on`] instead, from the one read its working directory comes from.
/// - `ShellExecuteEx` SEARCHES a path-less `lpFile`, which is how the elevated path reached the
///   `.bat`/`.cmd` vector; completing the name here stops that search. The consent path also gates
///   the completed name against `.exe`/`.com` — see [`crate::resolve::reject_unloadable_image`]
///   for why existence-checking is not enough.
///
/// `GetFullPathNameW` is the right primitive rather than a hand-rolled join, on three counts
/// documented by Win32 itself:
///
/// - It uses the same base the loader does — it "merges the name of the current drive and
///   directory with a specified file name", matching `lpApplicationName`'s own wording.
/// - It "does not verify that the resulting path and file name are valid, or that they see an
///   existing file", so `raw_executable()`'s "no existence check" clause survives intact.
/// - It resolves a DRIVE-RELATIVE name (`C:tool`) through that drive's own current directory —
///   state Win32 tracks and cosca does not, which is why `executable()`'s search path fails such
///   names closed instead. Here the platform answers it correctly.
///
/// A verbatim (`\\?\`) name is taken as written, never normalised.
///
/// The current directory is process-global and can change between calls, so the elevated path
/// consumes the relative name exactly once and everything downstream uses the absolute result —
/// which is precisely what `GetFullPathNameW`'s own doc advises for shared library code.
pub(crate) fn absolutise_exact(program: &Path) -> Result<PathBuf, Error> {
    complete_exact(program, || Ok(program.to_path_buf()))
}

/// A path Win32 has completed, and whether this process's cwd went into it.
pub(crate) struct Completed {
    pub(crate) path: PathBuf,
    /// Whether the cwd read was USED to build `path`, not merely fetched: a drive-relative path on
    /// another drive fetches it to learn the current drive, then takes nothing from it.
    pub(crate) used_cwd: bool,
}

/// Complete `path` as `GetFullPathNameW` would, with this process's cwd read through
/// `process_cwd` (at most once) and another drive's own current directory through `drive_cwd`,
/// instead of by `GetFullPathNameW` itself. `GetFullPathNameW` then only normalises a path that is
/// already fully qualified, which reads neither; a verbatim (`\\?\`) path is not normalised at all.
///
/// The path's type is [`crate::resolve::path_type`]'s, the one classifier the resolver uses too:
///
/// - [`Unc`](crate::resolve::PathType::Unc) or
///   [`DriveAbsolute`](crate::resolve::PathType::DriveAbsolute): as written. Nothing is read.
/// - [`DriveRelative`](crate::resolve::PathType::DriveRelative) (`C:x`): the cwd is read to learn
///   the current drive. On that drive the rest is appended to the cwd. On another, it is appended
///   to that drive's own directory, the `=Q:` variable when it is fully qualified, else the drive's
///   root (Wine `ntdll/path.c`, `RtlPathTypeDriveRelative`), and the cwd is not used.
/// - [`Rooted`](crate::resolve::PathType::Rooted) (`\x`): appended to the cwd's drive or share.
/// - [`Relative`](crate::resolve::PathType::Relative): appended to the cwd.
///
/// Appended as units, never `Path::join`ed: `join` replaces its base when the rest parses a prefix
/// of its own, so `C:D:\x` would become `D:\x` where Win32 reads `C:\cwd\D:\x`.
pub(crate) fn complete_on(
    path: &Path,
    process_cwd: impl FnOnce() -> Result<PathBuf, Error>,
    drive_cwd: impl FnOnce(&OsStr) -> Result<Option<OsString>, Error>,
) -> Result<Completed, Error> {
    let anchored = anchor(path, process_cwd, drive_cwd)?;
    // A verbatim path is taken as written, as `std::path::absolute` takes one: Win32 passes it to
    // the filesystem unparsed, so it names what it spells (`a.`, `a `, a literal `..`).
    if is_verbatim(&anchored.path) {
        return Ok(anchored);
    }
    Ok(Completed {
        path: full_path_name(&anchored.path)?,
        used_cwd: anchored.used_cwd,
    })
}

/// [`complete_on`] without the final normalisation.
fn anchor(
    path: &Path,
    process_cwd: impl FnOnce() -> Result<PathBuf, Error>,
    drive_cwd: impl FnOnce(&OsStr) -> Result<Option<OsString>, Error>,
) -> Result<Completed, Error> {
    use crate::resolve::{path_type, PathType};
    let name = path.as_os_str();
    let done = match path_type(name) {
        PathType::Unc | PathType::DriveAbsolute => Completed {
            path: path.to_path_buf(),
            used_cwd: false,
        },
        PathType::DriveRelative => {
            let (drive, rest) = crate::resolve::split_drive(name).expect("a drive-relative path has a drive");
            let cwd = process_cwd()?;
            // Case-insensitive by the OS's own table, as `RtlGetFullPathName_U` upcases both units,
            // not by ASCII alone: a drive may be any unit.
            let on_cwd_drive = crate::resolve::split_drive(cwd.as_os_str())
                .is_some_and(|(d, _)| super::env_key::EnvKey::new(d) == super::env_key::EnvKey::new(drive));
            if on_cwd_drive {
                Completed {
                    path: append(cwd.as_os_str(), rest),
                    used_cwd: true,
                }
            } else {
                let base = drive_cwd(drive)?
                    .filter(|dir| crate::resolve::is_absolute_name(dir, true))
                    .unwrap_or_else(|| {
                        let mut root = drive.to_os_string();
                        root.push("\\");
                        root
                    });
                Completed {
                    path: append(&base, rest),
                    used_cwd: false,
                }
            }
        }
        PathType::Rooted | PathType::Relative => Completed {
            path: PathBuf::from(crate::resolve::join::join(process_cwd()?.as_os_str(), name, "\\")),
            used_cwd: true,
        },
    };
    // `GetFullPathNameW` completes these two types without reading any process state.
    debug_assert!(
        matches!(
            path_type(done.path.as_os_str()),
            PathType::Unc | PathType::DriveAbsolute
        ),
        "{path:?} must anchor to a fully qualified path, got {:?}",
        done.path
    );
    Ok(done)
}

/// `rest` after the directory `base`, by [`crate::resolve::join::append`].
fn append(base: &OsStr, rest: &OsStr) -> PathBuf {
    PathBuf::from(crate::resolve::join::append(base, rest, "\\"))
}

/// The name of the variable holding `drive`'s own current directory: `=Q:` for `Q:`.
pub(crate) fn drive_cwd_var(drive: &OsStr) -> OsString {
    let mut name = OsString::from("=");
    name.push(drive);
    name
}

/// [`absolutise_exact`], completed by [`complete_on`] against the spawn's effective cwd
/// ([`effective_cwd`]) instead of by `GetFullPathNameW` reading this process's cwd itself, so the
/// file loaded and the directory the child runs in come from the same value.
pub(crate) fn absolutise_exact_on(
    program: &Path,
    process_cwd: impl FnOnce() -> Result<PathBuf, Error>,
    drive_cwd: impl FnOnce(&OsStr) -> Result<Option<OsString>, Error>,
) -> Result<Completed, Error> {
    let mut used_cwd = false;
    let path = complete_exact(program, || {
        let anchored = anchor(program, process_cwd, drive_cwd)?;
        used_cwd = anchored.used_cwd;
        Ok(anchored.path)
    })?;
    Ok(Completed { path, used_cwd })
}

/// Whether `path` is verbatim (`\\?\`), which Win32 passes to the filesystem unparsed.
fn is_verbatim(path: &Path) -> bool {
    path.as_os_str().as_encoded_bytes().starts_with(br"\\?\")
}

/// `GetFullPathNameW` on `path`.
fn full_path_name(path: &Path) -> Result<PathBuf, Error> {
    // `to_wide_nul` would truncate at an interior NUL, so `GetFullPathNameW` would complete a path
    // the caller never named. Every caller NUL-checks, naming its field, first.
    debug_assert_no_nul_wide("path to complete", path.as_os_str());
    let wide = super::to_wide_nul(path.as_os_str());
    grow_wide_buffer(|buf| unsafe {
        // SAFETY: `wide` is NUL-terminated; `GetFullPathNameW` writes into the given buffer or
        // reports the required length, both honoured by `wide_dir_buffer`. The `lpFilePart`
        // out-param is optional and unused here.
        GetFullPathNameW(PCWSTR(wide.as_ptr()), buf, None)
    })
    // The Win32 reason is preserved rather than flattened: unlike the system-directory queries,
    // `GetFullPathNameW`'s failures are INPUT-dependent (`ERROR_INVALID_NAME`,
    // `ERROR_FILENAME_EXCED_RANGE`), so the code is what tells a caller which path was bad.
    .map_err(Error::Io)
}

/// [`absolutise_exact`]'s checks around `GetFullPathNameW`, applied to whatever `anchored` makes
/// of `program` once the first checks pass.
fn complete_exact(program: &Path, anchored: impl FnOnce() -> Result<PathBuf, Error>) -> Result<PathBuf, Error> {
    // FIRST, ahead of the shape check, so the refusal names the NUL, not a trailing separator Win32
    // would never see (`x` + NUL + `\`). `to_wide_nul` appends a terminator, and `PCWSTR` stops at
    // the FIRST NUL — so an interior NUL silently truncates the path Win32 sees.
    // `raw_executable("C:\\a\\b.exe\0x")` would become `lpFile = C:\a\b.exe`, loading a file the
    // caller did not name, elevated. The raw backend already fails such a path closed (`spawn_raw`
    // NUL-checks the image); without this the same `Command` would error unelevated and silently
    // load a different file elevated.
    ensure_no_nul_wide("program path", program.as_os_str())?;
    // The shape is checked TWICE, on purpose, because the two checks catch different things.
    //
    // BEFORE: normalisation can also REMOVE the shape. `C:\t\.` normalises to `C:\t`, whose final
    // component `t` names a file, so only the spelling shows that the caller named a directory.
    reject_unnameable_program(program)?;
    let anchored = anchored()?;
    // A verbatim path is taken as written, as `std::path::absolute` takes one: the loader hands it
    // to the filesystem unparsed, so `\\?\C:\t\tool.exe.` names that file, which normalising would
    // turn into its sibling `tool.exe`.
    if is_verbatim(&anchored) {
        return Ok(anchored);
    }
    let full = full_path_name(&anchored)?;
    // AFTER: normalisation STRIPS trailing dots and spaces from the final component, so it can
    // CREATE the shape the pre-check refuses. `C:\t\...` passes as written — `...` is neither
    // empty nor `.`/`..` — and normalises to `C:\t\`, a directory, which would then be handed to
    // `ShellExecuteEx` as `lpFile` under `runas`. Checking only the spelling refuses the spelling
    // and not the shape.
    reject_unnameable_program(&full)?;
    Ok(full)
}

/// Resolve `exe` against an explicit `base_cwd`, system directories, and `PATH` string.
///
/// A name containing a path separator resolves against `base_cwd` with no search at
/// all. Only a true bare name is searched, and that search visits `system_dirs` and then the
/// `PATH` directories — **never `base_cwd`**. A final component already ending in `.exe`/`.com`
/// (case-insensitively) is used unchanged; otherwise a SEARCHED name is tried as `exe.exe` only,
/// while a PATHED one is tried as `exe` first and — only when it carries no extension at all —
/// `exe.exe` second. See [`crate::resolve`]'s `filename_candidates` doc for why the extension
/// rule belongs to the searched axis and not the located one. `PATH` elements that are empty or
/// relative are skipped, and the result is always absolute. A miss is
/// [`std::io::ErrorKind::NotFound`]; a name refused on its shape is
/// [`std::io::ErrorKind::InvalidInput`], per [`crate::resolve`]'s error-kind rule.
///
/// `system_dirs` visits BEFORE `PATH` — the app directory, `System32`, then the Windows
/// directory, i.e. `CreateProcessW`'s own NULL-`lpApplicationName` search order minus `base_cwd`.
/// This is what makes cutting `base_cwd` out of the search a strict narrowing of that order
/// rather than an unrelated behaviour change: see [`crate::resolve::ResolveInput::system_dirs`]
/// for the full monotonicity argument. Pass an empty slice to search `PATH` only.
///
/// `loadable_only` is [`crate::resolve::ResolveInput::loadable_only`].
///
/// A drive-relative name such as `C:tool` is refused outright — `InvalidInput`, before any
/// search — and is never loaded from `base_cwd`: resolving it would need drive C's own current
/// directory, which cosca does not track. A name that names no file (`C:\`, `tools\dir\`,
/// `...`, a bare `\\server\share`) is refused the same way.
///
/// Visiting `base_cwd` first is a binary-planting hazard: `executable("helper")` would load a
/// `helper.exe` dropped in whatever directory the process happened to sit in. Reach it explicitly
/// with `./helper`, which contains a separator.
///
/// Existence is tested through `crate::resolve`'s `is_execable`, which asks `std::fs::metadata`
/// for a file, not just for something: a directory is never a runnable program, so a same-named
/// directory must not shadow the executable (which would end the search early and hand
/// `CreateProcessW` an unlaunchable path with no fallback).
pub(crate) fn resolve_executable_in(
    exe: &Path,
    base_cwd: Option<&Path>,
    system_dirs: &[PathBuf],
    path: Option<&OsStr>,
    loadable_only: bool,
) -> Result<PathBuf, Error> {
    crate::resolve::resolve(crate::resolve::ResolveInput {
        program: exe,
        cwd: base_cwd,
        system_dirs,
        path_var: path,
        windows: true,
        loadable_only,
    })
}

// Environment block =====

/// A child's environment: a snapshot of this process's, with ops applied.
pub(crate) enum ChildEnv {
    /// The snapshot's block verbatim, duplicates and order included, as std's NULL block hands a
    /// child this process's own. `path` is what `GetEnvironmentVariableW` reads from it.
    Inherited { block: Vec<u16>, path: Option<OsString> },
    /// Rebuilt from the snapshot's variables, as std's `CommandEnv::capture` rebuilds from
    /// `vars_os`.
    Captured(BTreeMap<EnvKey, OsString>),
}

impl ChildEnv {
    /// The environment of a child that inherits `snapshot` unchanged.
    pub(crate) fn inherit(snapshot: &EnvSnapshot) -> Self {
        Self::Inherited {
            block: snapshot.block().to_vec(),
            path: snapshot.var(OsStr::new("PATH")),
        }
    }

    /// Capture the environment `ops` give a child that inherits `snapshot`, rebuilt even when
    /// `ops` is empty.
    ///
    /// With ops, keys collide when [`EnvKey`] says they are equal and the last write wins.
    ///
    /// The ops are recorded by std's own `Command` (via `apply_env`, exactly as the std
    /// backend records them), so the emitted name is the one std's
    /// `CommandEnv::{set, remove, clear, capture}` produces:
    /// - With no `Clear` in `ops`, a variable in `base` keeps its first name there,
    ///   whatever ops removed or re-set it; any other variable takes the name of the
    ///   first op that named it, a `Remove` included.
    /// - With a `Clear`, `base` and every op before the last `Clear` are dropped, and
    ///   a `Remove` deletes the variable's entry, so the name is that of the first
    ///   `Set` after both the last `Clear` and the variable's last `Remove`.
    pub(crate) fn capture(snapshot: &EnvSnapshot, ops: &[EnvOp]) -> Self {
        // std records the ops; `get_envs` yields its first-name keys and pending values.
        // What std does not expose is `capture`, the merge with `base`, replayed here.
        let mut changes = std::process::Command::new("");
        crate::child::spawn::apply_env(&mut changes, ops);
        let mut vars: BTreeMap<EnvKey, OsString> = BTreeMap::new();
        // std's `clear` flag is only ever set, never reset, so any `Clear` drops `base`.
        if !ops.iter().any(|op| matches!(op, EnvOp::Clear)) {
            for (key, val) in snapshot.vars() {
                // `BTreeMap::insert` keeps an existing equal key: the first name sticks.
                vars.insert(EnvKey::new(&key), val);
            }
        }
        for (key, change) in changes.get_envs() {
            match change {
                Some(val) => {
                    vars.insert(EnvKey::new(key), val.to_os_string());
                }
                None => {
                    vars.remove(&EnvKey::new(key));
                }
            }
        }
        Self::Captured(vars)
    }

    /// The variables of a captured environment, in block order; `None` for an inherited one.
    pub(crate) fn captured_vars(&self) -> Option<impl Iterator<Item = (&OsStr, &OsStr)>> {
        match self {
            Self::Inherited { .. } => None,
            Self::Captured(vars) => Some(vars.iter().map(|(key, val)| (key.name(), val.as_os_str()))),
        }
    }

    /// The child's `PATH`, as it will read it.
    pub(crate) fn path(&self) -> Option<&OsStr> {
        match self {
            Self::Inherited { path, .. } => path.as_deref(),
            Self::Captured(vars) => vars.get(&EnvKey::new(OsStr::new("PATH"))).map(OsString::as_os_str),
        }
    }

    /// The `CreateProcessW` block, always passed explicitly, never as NULL, so the child gets
    /// exactly this environment. A captured one is `KEY=VAL\0` entries in [`EnvKey`] order, closed
    /// by a trailing `\0` (a double-NUL terminator); an embedded NUL in any key or value is
    /// [`std::io::ErrorKind::InvalidInput`].
    pub(crate) fn into_block(self) -> Result<Vec<u16>, Error> {
        let vars = match self {
            Self::Inherited { block, .. } => return Ok(block),
            Self::Captured(vars) => vars,
        };
        let mut block: Vec<u16> = Vec::new();
        // An empty-but-present environment is signalled by a leading NUL, so the
        // block is never a lone terminator that `CreateProcessW` reads as "inherit".
        if vars.is_empty() {
            block.push(0);
        }
        for (key, val) in &vars {
            let key = key.name();
            ensure_no_nul_wide("environment key", key)?;
            ensure_no_nul_wide("environment value", val)?;
            block.extend(key.encode_wide());
            block.push(u16::from(b'='));
            block.extend(val.encode_wide());
            block.push(0);
        }
        block.push(0);
        Ok(block)
    }
}

/// Reject a string carrying an embedded NUL, which Win32 would silently truncate at.
///
/// Serves every wide string built out of CALLER INPUT on either Windows launch path: the raw
/// backend's environment block, program token, working directory, argv tokens and command line,
/// and the elevated `SHELLEXECUTEINFOW`'s fields (via `elevation::windows::wide_nul`). `what`
/// names the offending field, so the refusal does not blame one caller's field for another's
/// defect. Shared rather than restated per path — the predicate and the sentence are the same, and
/// two copies of them drifted apart once already.
///
/// The raw backend's program image is the one wide string checked by assertion instead, because
/// it is already refused upstream by the time it is built; see [`debug_assert_no_nul_wide`].
pub(crate) fn ensure_no_nul_wide(what: &str, s: &OsStr) -> Result<(), Error> {
    if s.encode_wide().any(|unit| unit == 0) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the {what} contains an embedded NUL, which Win32 would silently truncate"),
        )));
    }
    Ok(())
}

/// Assert the same property of a wide string that is ALREADY REFUSED upstream, rather than one
/// received unchecked here.
///
/// The one caller is `spawn_raw`'s image, and neither of the two ways that image is produced can
/// carry a NUL by the time it arrives:
///
/// - Resolved by [`resolve_executable`] — every one of its returns is gated on `fs::metadata`
///   (through `crate::resolve`'s `is_execable`), which fails for any path Win32 cannot encode, so
///   such a path is never returned.
/// - Passed through verbatim by `raw_executable()`'s `Exact` arm of `windows_raw::target_with` —
///   caller input, but `reject_batch_program` runs FIRST in both raw backends and
///   [`ensure_no_nul_wide`]s that same token as the "program token".
///
/// So a NUL here would be a broken contract upstream, not a caller defect — and refusing it at
/// runtime advertises a caller-facing vector that does not exist, sending a reader to audit an
/// input they do not control. Asserted instead, so it still fails loudly in every debug build the
/// moment either of those two guarantees is dropped.
pub(crate) fn debug_assert_no_nul_wide(what: &str, s: &OsStr) {
    debug_assert!(
        !s.encode_wide().any(|unit| unit == 0),
        "the {what} contains an embedded NUL, which Win32 would silently truncate"
    );
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod resolve_tests;

#[cfg(test)]
#[path = "absolutise_on_tests.rs"]
mod absolutise_on_tests;
