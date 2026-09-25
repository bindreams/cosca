//! [`ResolveInput::loadable_only`]: the `.exe`/`.com` requirement,
//! applied as a candidate filter.
//!
//! `windows: true` on a POSIX host is safe here for the reason `resolve_tests`' `HOST_WINDOWS`
//! doc gives: tempdir paths hold no `;` and no drive prefix, and `is_execable` reduces to
//! `is_file()`.

use super::*;
use std::path::PathBuf;

fn touch(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, b"x").unwrap();
    p
}

fn go(program: &str, cwd: &Path, path_var: Option<&OsStr>, loadable_only: bool) -> Result<PathBuf, Error> {
    resolve(ResolveInput {
        program: Path::new(program),
        cwd: Some(cwd),
        system_dirs: &no_system_dirs,
        path_var,
        windows: true,
        loadable_only,
        normalise: &as_written,
    })
}

fn kind(got: Result<PathBuf, Error>) -> std::io::ErrorKind {
    match got {
        Err(Error::Io(e)) => e.kind(),
        other => panic!("expected an io error, got {other:?}"),
    }
}

/// A `bin/` beneath a fresh tempdir holding `files`, and that tempdir as the cwd.
fn bin_with(files: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let cwd = tempfile::tempdir().unwrap();
    let bin = cwd.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    for f in files {
        touch(&bin, f);
    }
    (cwd, bin)
}

#[test]
fn an_extensionless_sibling_does_not_block_the_exe() {
    // The located axis prefers the exact name, so choosing first and refusing after would return
    // `InvalidInput` here — although `bin/tool.exe` exists, and although anyone able to write an
    // extensionless `tool` into `bin/` could thereby block the spawn.
    let (cwd, bin) = bin_with(&["tool", "tool.exe"]);
    assert_eq!(go("bin/tool", cwd.path(), None, true).unwrap(), bin.join("tool.exe"));
}

#[test]
fn only_an_extensionless_file_is_not_found() {
    // `NotFound`, not `InvalidInput`: `bin/tool.exe` would satisfy this very string.
    let (cwd, _bin) = bin_with(&["tool"]);
    assert_eq!(
        kind(go("bin/tool", cwd.path(), None, true)),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn only_the_exe_resolves_to_it() {
    let (cwd, bin) = bin_with(&["tool.exe"]);
    assert_eq!(go("bin/tool", cwd.path(), None, true).unwrap(), bin.join("tool.exe"));
}

#[test]
fn a_loadable_name_written_by_the_caller_is_kept() {
    // Case-insensitive, like `has_loadable_extension`, and `.com` counts.
    let (cwd, bin) = bin_with(&["TOOL.EXE", "more.com"]);
    assert_eq!(
        go("bin/TOOL.EXE", cwd.path(), None, true).unwrap(),
        bin.join("TOOL.EXE")
    );
    assert_eq!(
        go("bin/more.com", cwd.path(), None, true).unwrap(),
        bin.join("more.com")
    );
}

#[test]
fn a_located_name_with_no_loadable_candidate_is_refused_on_shape() {
    // `bin/tool.bat` gets one candidate, itself, and the filter removes it: no filesystem can make
    // this string succeed, so `InvalidInput` whether or not the file exists.
    for present in [true, false] {
        let (cwd, _bin) = bin_with(if present {
            &["tool.bat", "tool.", "tool.bin"]
        } else {
            &[]
        });
        for name in ["bin/tool.bat", "bin/tool.", "bin/tool.bin"] {
            let got = go(name, cwd.path(), None, true);
            assert_eq!(
                kind(got),
                std::io::ErrorKind::InvalidInput,
                "{name:?} (present: {present})"
            );
        }
    }
}

#[test]
fn a_bare_name_resolves_as_it_does_unelevated() {
    // A bare name's only candidate already ends in `.exe`, so the filter removes nothing.
    let cwd = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    touch(dir.path(), "tool");
    let want = touch(dir.path(), "tool.exe");
    let path = dir.path().as_os_str();
    assert_eq!(go("tool", cwd.path(), Some(path), true).unwrap(), want);
    assert_eq!(go("tool", cwd.path(), Some(path), false).unwrap(), want);
}

#[test]
fn unelevated_resolution_is_unchanged() {
    // `loadable_only: false` is the ordinary spawn: the exact name still wins, and a file with no
    // loadable name still resolves.
    let (cwd, bin) = bin_with(&["tool", "tool.exe", "tool.bat"]);
    assert_eq!(go("bin/tool", cwd.path(), None, false).unwrap(), bin.join("tool"));
    assert_eq!(
        go("bin/tool.bat", cwd.path(), None, false).unwrap(),
        bin.join("tool.bat")
    );
    let (cwd, bin) = bin_with(&["tool"]);
    assert_eq!(go("bin/tool", cwd.path(), None, false).unwrap(), bin.join("tool"));
}
