//! Program resolution + Windows environment-block construction for the raw
//! `CreateProcessW` backend.
//!
//! [`resolve_executable`] applies a deliberate cwd+`PATH`+`.exe` rule (base cwd
//! first, then `PATH` directories; append `.exe` only when the program has no
//! extension) rather than full `CreateProcessW` search parity — this keeps
//! `.bat`/`.cmd` out of resolution so batch-program rejection stays a separate
//! concern. [`build_env_block`] produces the sorted, wide, double-NUL block
//! `CreateProcessW` expects from a recorded [`EnvOp`] sequence.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::command::EnvOp;
use crate::error::Error;

// Program resolution =====

/// Resolve `exe` against the current process's cwd and `PATH`.
///
/// Convenience wrapper over [`resolve_executable_in`] seeded from
/// [`std::env::current_dir`] and the `PATH` variable.
pub(crate) fn resolve_executable(exe: &Path) -> Result<PathBuf, Error> {
    let base_cwd = std::env::current_dir()?;
    let path = std::env::var_os("PATH");
    resolve_executable_in(exe, &base_cwd, path.as_deref())
}

/// Resolve `exe` against an explicit `base_cwd` and `PATH` string.
///
/// An absolute `exe` that is an existing file is returned unchanged. Otherwise
/// the search visits `base_cwd` first, then each `PATH` directory, testing
/// `dir/exe` and — only when `exe` carries no extension — `dir/exe.exe`; the
/// first existing file wins. A miss is [`std::io::ErrorKind::NotFound`].
///
/// Existence is tested with [`Path::is_file`], not [`Path::exists`]: a directory
/// is never a runnable program, so a same-named directory must not shadow the
/// executable (which would end the search early and hand `CreateProcessW` an
/// unlaunchable path with no fallback).
pub(crate) fn resolve_executable_in(exe: &Path, base_cwd: &Path, path: Option<&OsStr>) -> Result<PathBuf, Error> {
    if exe.is_absolute() && exe.is_file() {
        return Ok(exe.to_path_buf());
    }

    let append_exe = exe.extension().is_none();
    let path_dirs = path.into_iter().flat_map(std::env::split_paths);
    let dirs = std::iter::once(base_cwd.to_path_buf()).chain(path_dirs);

    for dir in dirs {
        let candidate = dir.join(exe);
        if candidate.is_file() {
            return Ok(candidate);
        }
        if append_exe {
            let with_exe = candidate.with_extension("exe");
            if with_exe.is_file() {
                return Ok(with_exe);
            }
        }
    }

    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("could not resolve executable: {}", exe.display()),
    )))
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
