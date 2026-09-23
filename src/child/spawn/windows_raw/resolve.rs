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
//! captured once per spawn from an [`env_snapshot`] and a recorded [`EnvOp`] sequence; resolution
//! reads its `PATH` and [`ChildEnv::block`] serializes it for `CreateProcessW`.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

use super::env_key::EnvKey;
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
/// `env` is the child's environment, the same [`ChildEnv`] whose [`ChildEnv::block`] the child
/// is spawned with. `PATH` is read from it, so the directories searched here are the ones the
/// CHILD will actually have — as [`crate::resolve::ResolveInput::path_var`]'s doc promises — and
/// no second read of this process's environment can disagree with the block.
///
/// Convenience wrapper over [`resolve_executable_in`] seeded from `cmd_cwd` (or
/// [`std::env::current_dir`]), the real system directories, and the child's `PATH`.
pub(crate) fn resolve_executable(exe: &Path, cmd_cwd: Option<&Path>, env: &ChildEnv) -> Result<PathBuf, Error> {
    let base_cwd;
    let base_cwd: &Path = match cmd_cwd {
        Some(dir) => dir,
        None => {
            base_cwd = std::env::current_dir()?;
            &base_cwd
        }
    };
    let system_dirs = windows_system_dirs();
    resolve_executable_in(exe, base_cwd, &system_dirs, env.path())
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
/// A drive-relative name such as `C:tool` is refused outright — `InvalidInput`, before any
/// search — and is never loaded from `base_cwd`: resolving it would need drive C's own current
/// directory, which cosca does not track. A name that names no file (`C:\`, `tools\dir\`,
/// `...`, a bare `\\server\share`) is refused the same way.
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

/// This process's environment, read once per spawn. Every environment-dependent step of a raw
/// spawn derives from this one read, so none can see a different environment than the child gets.
pub(crate) fn env_snapshot() -> Vec<(OsString, OsString)> {
    std::env::vars_os().collect()
}

/// Whether `base` has a variable named `name`, matched as [`EnvKey`] matches.
pub(crate) fn snapshot_has(base: &[(OsString, OsString)], name: &str) -> bool {
    let name = EnvKey::new(OsStr::new(name));
    base.iter().any(|(key, _)| EnvKey::new(key) == name)
}

/// A child's environment: `base` with `ops` applied.
pub(crate) struct ChildEnv(BTreeMap<EnvKey, OsString>);

impl ChildEnv {
    /// Capture the environment `ops` give a child that inherits `base`.
    /// Keys collide when [`EnvKey`] says they are equal and the last write wins.
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
    pub(crate) fn capture(base: &[(OsString, OsString)], ops: &[EnvOp]) -> Self {
        // std records the ops; `get_envs` yields its first-name keys and pending values.
        // What std does not expose is `capture`, the merge with `base`, replayed here.
        let mut changes = std::process::Command::new("");
        crate::child::spawn::apply_env(&mut changes, ops);
        let mut vars: BTreeMap<EnvKey, OsString> = BTreeMap::new();
        // std's `clear` flag is only ever set, never reset, so any `Clear` drops `base`.
        if !ops.iter().any(|op| matches!(op, EnvOp::Clear)) {
            for (key, val) in base {
                // `BTreeMap::insert` keeps an existing equal key: the first name sticks.
                vars.insert(EnvKey::new(key), val.clone());
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
        Self(vars)
    }

    /// The child's `PATH`.
    pub(crate) fn path(&self) -> Option<&OsStr> {
        self.0.get(&EnvKey::new(OsStr::new("PATH"))).map(OsString::as_os_str)
    }

    /// The `CreateProcessW` block: `KEY=VAL\0` entries in [`EnvKey`] order, closed by a trailing
    /// `\0` (a double-NUL terminator). Always passed explicitly, never as NULL, so the child gets
    /// exactly this environment. An embedded NUL in any key or value is
    /// [`std::io::ErrorKind::InvalidInput`].
    pub(crate) fn block(&self) -> Result<Vec<u16>, Error> {
        let mut block: Vec<u16> = Vec::new();
        // An empty-but-present environment is signalled by a leading NUL, so the
        // block is never a lone terminator that `CreateProcessW` reads as "inherit".
        if self.0.is_empty() {
            block.push(0);
        }
        for (key, val) in &self.0 {
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
/// The one wide string that is not caller input is the resolved program image; see
/// [`debug_assert_no_nul_wide`].
pub(crate) fn ensure_no_nul_wide(what: &str, s: &OsStr) -> Result<(), Error> {
    if s.encode_wide().any(|unit| unit == 0) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the {what} contains an embedded NUL, which Win32 would silently truncate"),
        )));
    }
    Ok(())
}

/// Assert the same property of a wide string the crate PRODUCED rather than received.
///
/// [`resolve_executable`] is the only such producer, and it cannot yield a NUL: every one of its
/// returns is gated on [`Path::is_file`], which goes through `fs::metadata` and so is false for
/// any path Win32 cannot encode. A NUL here would therefore be a broken contract in resolution,
/// not a caller defect — and refusing it at runtime advertises a caller-facing vector that does
/// not exist, sending a reader to audit an input they do not control. Asserted instead, so it
/// still fails loudly in every debug build the moment resolution grows a return that is not
/// `is_file`-gated.
pub(crate) fn debug_assert_no_nul_wide(what: &str, s: &OsStr) {
    debug_assert!(
        !s.encode_wide().any(|unit| unit == 0),
        "the {what} contains an embedded NUL, which Win32 would silently truncate"
    );
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod resolve_tests;
