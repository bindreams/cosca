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
//! order rather than trading one hazard for another. [`build_env_block`] produces the sorted,
//! wide, double-NUL block `CreateProcessW` expects from a recorded [`EnvOp`] sequence.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

use crate::command::EnvOp;
use crate::error::Error;

// Program resolution =====

/// Resolve `exe` against the CHILD's cwd and the CHILD's `PATH`.
///
/// `cmd_cwd` is `Command::cwd()` — the directory the child will actually run in. When it is
/// `None` (no override was set), the child inherits the parent's cwd, so
/// [`std::env::current_dir`] is the correct fallback. Seeding resolution from the parent's cwd
/// UNCONDITIONALLY (ignoring a `Command::cwd()` override) would resolve `./helper` against the
/// wrong directory: the doc on [`crate::resolve::ResolveInput::cwd`] promises the CHILD's
/// directory, and that promise is also the documented escape hatch for reaching "the current
/// directory explicitly" — reaching the parent's instead defeats it.
///
/// `env_ops` is `Command::env_ops()` — the same recorded `env()`/`env_remove()`/`env_clear()`
/// sequence [`build_env_block`] turns into the child's actual environment block. `PATH` is looked
/// up through [`effective_path_var`], which replays those ops over the ambient `PATH` the same
/// way [`build_env_block_from`] replays them over the ambient environment, so the directories
/// searched here are the ones the CHILD will actually have — not silently the parent's, which
/// [`crate::resolve::ResolveInput::path_var`]'s own doc already promises.
///
/// Convenience wrapper over [`resolve_executable_in`] seeded from `cmd_cwd` (or
/// [`std::env::current_dir`]), the real system directories, and the child's effective `PATH`.
pub(crate) fn resolve_executable(exe: &Path, cmd_cwd: Option<&Path>, env_ops: &[EnvOp]) -> Result<PathBuf, Error> {
    let base_cwd;
    let base_cwd: &Path = match cmd_cwd {
        Some(dir) => dir,
        None => {
            base_cwd = std::env::current_dir()?;
            &base_cwd
        }
    };
    let path = effective_path_var(env_ops);
    let system_dirs = windows_system_dirs();
    resolve_executable_in(exe, base_cwd, &system_dirs, path.as_deref())
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
    let mut buf = vec![0u16; 260];
    loop {
        let len = f(Some(&mut buf)) as usize;
        if len == 0 {
            return None;
        }
        if len < buf.len() {
            buf.truncate(len);
            return Some(PathBuf::from(OsString::from_wide(&buf)));
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

/// The `PATH` value the child will actually see, replaying `env_ops` over the ambient `PATH` —
/// `Set`/`Remove` match the key case-insensitively (Windows env var names are), and `Clear` wipes
/// it outright, mirroring [`build_env_block_from`]'s own base-then-ops replay exactly so the two
/// never disagree about what the child's `PATH` ends up being.
fn effective_path_var(env_ops: &[EnvOp]) -> Option<OsString> {
    let path_key = fold_key(OsStr::new("PATH"));
    let mut path = std::env::var_os("PATH");
    for op in env_ops {
        match op {
            EnvOp::Set(key, val) if fold_key(key) == path_key => path = Some(val.clone()),
            EnvOp::Remove(key) if fold_key(key) == path_key => path = None,
            EnvOp::Clear => path = None,
            _ => {}
        }
    }
    path
}

/// Resolve `exe` against an explicit `base_cwd`, system directories, and `PATH` string.
///
/// A name containing a path separator resolves against `base_cwd` with no search at
/// all. Only a true bare name is searched, and that search visits `system_dirs` and then the
/// `PATH` directories — **never `base_cwd`**. A final component already ending in `.exe`/`.com`
/// (case-insensitively) is used unchanged; otherwise a SEARCHED name is tried as `exe.exe` only,
/// while a PATHED one is tried as `exe` first and `exe.exe` second — see [`crate::resolve`]'s
/// `filename_candidates` doc for why the extension rule belongs to the searched axis and not the
/// located one. `PATH` elements that are empty or relative are skipped, and the result is always
/// absolute. A miss is [`std::io::ErrorKind::NotFound`].
///
/// `system_dirs` visits BEFORE `PATH` — the app directory, `System32`, then the Windows
/// directory, i.e. `CreateProcessW`'s own NULL-`lpApplicationName` search order minus `base_cwd`.
/// This is what makes cutting `base_cwd` out of the search a strict narrowing of that order
/// rather than an unrelated behaviour change: see [`crate::resolve::ResolveInput::system_dirs`]
/// for the full monotonicity argument. Pass an empty slice to search `PATH` only.
///
/// A drive-relative name such as `C:tool` always fails closed with `NotFound`, and is
/// never loaded from `base_cwd`: joining a directory onto it collapses straight back
/// to `C:tool` (`PathBuf::push` clears for any prefixed path), so resolving it would
/// need drive C's own current directory, which cosca does not track.
///
/// Visiting `base_cwd` first was the previous behaviour, and it was a
/// binary-planting hazard: `executable("helper")` loaded a `helper.exe` dropped in
/// whatever directory the process happened to sit in. Reach it explicitly with
/// `./helper`, which contains a separator.
///
/// Existence is tested with [`Path::is_file`], not [`Path::exists`]: a directory
/// is never a runnable program, so a same-named directory must not shadow the
/// executable (which would end the search early and hand `CreateProcessW` an
/// unlaunchable path with no fallback).
pub(crate) fn resolve_executable_in(
    exe: &Path,
    base_cwd: &Path,
    system_dirs: &[PathBuf],
    path: Option<&OsStr>,
) -> Result<PathBuf, Error> {
    crate::resolve::resolve(crate::resolve::ResolveInput {
        program: exe,
        cwd: base_cwd,
        system_dirs,
        path_var: path,
        windows: true,
    })
}

// Environment block =====

/// Build the `CreateProcessW` environment block for `ops`, inheriting the parent
/// environment as the base.
pub(crate) fn build_env_block(ops: &[EnvOp]) -> Result<Option<Vec<u16>>, Error> {
    let base: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    build_env_block_from(&base, ops)
}

/// Build the `CreateProcessW` environment block from an explicit `base` plus
/// `ops`.
///
/// Returns `Ok(None)` when `ops` is empty — the child inherits the parent
/// environment. Otherwise the block is a UTF-16 sequence of `KEY=VAL\0` entries
/// sorted by their case-folded key and closed by a trailing `\0` (a
/// double-NUL terminator). Keys collide case-insensitively (Windows env
/// semantics), last write wins, and the last writer's key casing is emitted. An
/// embedded NUL in any key or value is [`std::io::ErrorKind::InvalidInput`].
pub(crate) fn build_env_block_from(base: &[(OsString, OsString)], ops: &[EnvOp]) -> Result<Option<Vec<u16>>, Error> {
    if ops.is_empty() {
        return Ok(None);
    }

    // Keyed by the case-folded key; the value keeps the original-case key so the
    // emitted block preserves the caller's casing.
    let mut vars: BTreeMap<Vec<u16>, (OsString, OsString)> = BTreeMap::new();
    for (key, val) in base {
        vars.insert(fold_key(key), (key.clone(), val.clone()));
    }
    for op in ops {
        match op {
            EnvOp::Set(key, val) => {
                vars.insert(fold_key(key), (key.clone(), val.clone()));
            }
            EnvOp::Remove(key) => {
                vars.remove(&fold_key(key));
            }
            EnvOp::Clear => vars.clear(),
        }
    }

    let mut block: Vec<u16> = Vec::new();
    // An empty-but-present environment is signalled by a leading NUL, so the
    // block is never a lone terminator that `CreateProcessW` reads as "inherit".
    if vars.is_empty() {
        block.push(0);
    }
    for (key, val) in vars.values() {
        ensure_no_nul_wide(key)?;
        ensure_no_nul_wide(val)?;
        block.extend(key.encode_wide());
        block.push(u16::from(b'='));
        block.extend(val.encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(Some(block))
}

/// Reject a key or value carrying an embedded NUL, which would truncate the
/// wide, NUL-delimited environment block.
pub(crate) fn ensure_no_nul_wide(s: &OsStr) -> Result<(), Error> {
    if s.encode_wide().any(|unit| unit == 0) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "environment key or value contains an embedded NUL",
        )));
    }
    Ok(())
}

/// Case-fold an environment key for case-insensitive comparison and sorting.
///
/// Uppercases each Unicode scalar of the UTF-16 encoding; unpaired surrogates
/// (which have no case) pass through unchanged so distinct keys never collide.
fn fold_key(key: &OsStr) -> Vec<u16> {
    let mut folded = Vec::new();
    for unit in char::decode_utf16(key.encode_wide()) {
        match unit {
            Ok(c) => {
                let mut buf = [0u16; 2];
                for upper in c.to_uppercase() {
                    folded.extend_from_slice(upper.encode_utf16(&mut buf));
                }
            }
            Err(e) => folded.push(e.unpaired_surrogate()),
        }
    }
    folded
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod resolve_tests;
