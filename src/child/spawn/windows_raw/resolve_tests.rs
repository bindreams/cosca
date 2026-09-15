use super::*;
use crate::command::EnvOp;
use std::ffi::OsString;

#[test]
fn resolve_absolute_existing_is_returned_as_is() {
    let me = std::env::current_exe().unwrap();
    assert_eq!(resolve_executable(&me).unwrap(), me);
}
#[test]
fn resolve_bare_name_is_not_taken_from_base_cwd() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), dir.path().join("sp_shadow.exe")).unwrap();
    // INVERTED deliberately: a bare name searches PATH only. Resolving it from the current
    // directory is the binary-planting hazard this resolver exists to avoid, so a matching file
    // there with nothing on PATH must NOT resolve.
    // Explicit base dir — no process-global SetCurrentDirectory, so parallel tests can't race.
    let got = resolve_executable_in(std::path::Path::new("sp_shadow"), dir.path(), None);
    assert!(got.is_err(), "{got:?}");
}
#[test]
fn resolve_bare_name_appends_exe_from_path() {
    let p = resolve_executable(std::path::Path::new("cmd")).unwrap();
    assert!(
        p.is_absolute() && p.exists() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")),
        "{p:?}"
    );
}
#[test]
fn empty_ops_inherit() {
    assert!(build_env_block(&[]).unwrap().is_none());
}
#[test]
fn set_sorts_ci_and_double_nul() {
    let b = build_env_block_from(
        &[],
        &[
            EnvOp::Set("Zeta".into(), "1".into()),
            EnvOp::Set("alpha".into(), "2".into()),
        ],
    )
    .unwrap()
    .unwrap();
    assert_eq!(&b[b.len() - 2..], &[0u16, 0u16]);
    let s = String::from_utf16(&b).unwrap();
    assert!(s.find("alpha=").unwrap() < s.find("Zeta=").unwrap(), "{s:?}");
}
#[test]
fn remove_is_case_insensitive() {
    let b = build_env_block_from(
        &[(OsString::from("SP_R"), OsString::from("x"))],
        &[EnvOp::Remove("sp_r".into())],
    )
    .unwrap()
    .unwrap();
    assert!(!String::from_utf16(&b).unwrap().to_uppercase().contains("SP_R="));
}
#[test]
fn clear_then_set_yields_only_the_set_var() {
    let b = build_env_block_from(
        &[(OsString::from("PATH"), OsString::from("x"))],
        &[EnvOp::Clear, EnvOp::Set("ONLYME".into(), "1".into())],
    )
    .unwrap()
    .unwrap();
    let s = String::from_utf16(&b).unwrap();
    assert!(s.contains("ONLYME=1") && !s.to_uppercase().contains("PATH="));
}
#[test]
fn embedded_nul_is_rejected() {
    let e = build_env_block_from(&[], &[EnvOp::Set("K".into(), OsString::from("a\u{0}b"))]).unwrap_err();
    assert!(matches!(e, crate::error::Error::Io(_)));
}
#[test]
fn resolve_skips_directory_shadow_and_finds_path_exe() {
    let base = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    // A directory in base_cwd whose name matches the bare program must not
    // shadow the real executable found later on PATH — a directory can never run.
    // The shadow directory lives on PATH, AHEAD of the real executable: base_cwd is no longer
    // searched, so planting it there would no longer exercise the `is_file` guard at all.
    let shadow_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(shadow_dir.path().join("sp_dirtool")).unwrap();
    let path_copy = other.path().join("sp_dirtool.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &path_copy).unwrap();
    let joined = std::env::join_paths([shadow_dir.path(), other.path()]).unwrap();
    let got = resolve_executable_in(
        std::path::Path::new("sp_dirtool"),
        base.path(),
        Some(joined.as_os_str()),
    )
    .unwrap();
    assert_eq!(got.canonicalize().unwrap(), path_copy.canonicalize().unwrap());
}
#[test]
fn resolve_absolute_directory_is_not_returned() {
    let dir = tempfile::tempdir().unwrap();
    // An absolute path naming an existing *directory* is not a runnable program.
    let got = resolve_executable_in(dir.path(), std::path::Path::new("."), None);
    assert!(got.is_err(), "{got:?}");
}
#[test]
fn path_wins_over_base_cwd_when_both_have_exe() {
    let base = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let me = std::env::current_exe().unwrap();
    let base_copy = base.path().join("sp_pref.exe");
    std::fs::copy(&me, &base_copy).unwrap();
    std::fs::copy(&me, other.path().join("sp_pref.exe")).unwrap();
    // INVERTED deliberately: base_cwd is no longer searched for a bare name, so the PATH copy
    // wins even though an identically named file sits in the current directory.
    let got = resolve_executable_in(
        std::path::Path::new("sp_pref"),
        base.path(),
        Some(other.path().as_os_str()),
    )
    .unwrap();
    let want = other.path().join("sp_pref.exe");
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
    assert_ne!(got.canonicalize().unwrap(), base_copy.canonicalize().unwrap());
}
#[test]
fn clear_only_yields_empty_double_nul_block() {
    // An empty-but-present environment is a bare double-NUL, distinct from the
    // `None` "inherit" signal — pins the leading-NUL push.
    let b = build_env_block_from(&[(OsString::from("A"), OsString::from("1"))], &[EnvOp::Clear])
        .unwrap()
        .unwrap();
    assert_eq!(b, vec![0u16, 0u16]);
}
#[test]
fn embedded_nul_in_key_is_rejected_as_invalid_input() {
    let e = build_env_block_from(&[], &[EnvOp::Set(OsString::from("a\u{0}b"), "1".into())]).unwrap_err();
    assert!(
        matches!(e, crate::error::Error::Io(ref io) if io.kind() == std::io::ErrorKind::InvalidInput),
        "{e:?}"
    );
}
