use super::*;
use crate::command::EnvOp;
use std::ffi::OsString;

#[test]
fn resolve_absolute_existing_is_returned_as_is() {
    let me = std::env::current_exe().unwrap();
    assert_eq!(resolve_executable(&me, None, &[]).unwrap(), me);
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
    let p = resolve_executable(std::path::Path::new("cmd"), None, &[]).unwrap();
    assert!(
        p.is_absolute() && p.exists() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")),
        "{p:?}"
    );
}
// Item 4: `resolve_executable` must honor the CHILD's PATH, not the ambient one ────────
//
// `path_var`'s own doc (`crate::resolve::ResolveInput::path_var`) promises "the PATH the CHILD
// will see, after env()/env_clear()" — but `resolve_executable` used to read
// `std::env::var_os("PATH")` unconditionally, ignoring `Command::env_ops()` entirely. cosca's own
// std backend already threads `env_ops` onto the child correctly (`apply_env` in
// `child::spawn.rs`); the raw backend must match it, not silently search the PARENT's PATH while
// the child would see a different one.
#[test]
fn resolve_executable_honors_an_env_set_path_override() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), dir.path().join("sp_env_path.exe")).unwrap();
    let want = dir.path().join("sp_env_path.exe");
    // Positive control: with no env ops, the fabricated name is not on the ambient PATH at all, so
    // a pass below cannot be an accident of the ambient PATH already containing it.
    assert!(resolve_executable(std::path::Path::new("sp_env_path"), None, &[]).is_err());

    let ops = [EnvOp::Set(
        OsString::from("PATH"),
        dir.path().as_os_str().to_os_string(),
    )];
    let got = resolve_executable(std::path::Path::new("sp_env_path"), None, &ops);
    assert_eq!(got.unwrap().canonicalize().unwrap(), want.canonicalize().unwrap());
}
#[test]
fn resolve_executable_path_key_match_is_case_insensitive() {
    // Windows env var names are case-insensitive; `Command::env("Path", ...)` must override the
    // same `PATH` the resolver consults, not silently coexist as a distinct key.
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), dir.path().join("sp_env_path_ci.exe")).unwrap();
    let want = dir.path().join("sp_env_path_ci.exe");
    let ops = [EnvOp::Set(
        OsString::from("Path"),
        dir.path().as_os_str().to_os_string(),
    )];
    let got = resolve_executable(std::path::Path::new("sp_env_path_ci"), None, &ops);
    assert_eq!(got.unwrap().canonicalize().unwrap(), want.canonicalize().unwrap());
}
#[test]
fn resolve_executable_env_clear_defeats_ambient_path() {
    // Positive control: with no env ops, "cmd" resolves via the ambient PATH.
    assert!(resolve_executable(std::path::Path::new("cmd"), None, &[]).is_ok());
    // `Command::env_clear()` means the child sees NO environment at all, PATH included — the
    // resolver must not silently fall back to searching the PARENT's PATH once the child's own is
    // cleared.
    let got = resolve_executable(std::path::Path::new("cmd"), None, &[EnvOp::Clear]);
    assert!(got.is_err(), "{got:?}");
}
#[test]
fn resolve_executable_env_remove_path_defeats_ambient_path() {
    assert!(resolve_executable(std::path::Path::new("cmd"), None, &[]).is_ok());
    let got = resolve_executable(
        std::path::Path::new("cmd"),
        None,
        &[EnvOp::Remove(OsString::from("path"))],
    );
    assert!(got.is_err(), "{got:?}");
}
// B1: `resolve_executable`'s `cmd_cwd` parameter ─────────────────────────────────────
//
// The resolver was designed for the CHILD's cwd (`Command::cwd()` when set, else the parent's —
// see `crate::resolve::ResolveInput::cwd`'s doc), but `resolve_executable` used to seed
// `base_cwd` purely from `std::env::current_dir()`, silently ignoring a `Command::cwd()`
// override. That broke the documented escape hatch: "write `./helper` to reach the current
// directory explicitly" landed on the PARENT's ambient directory instead of the child's, which is
// the exact directory this crate exists to stop trusting.
#[test]
fn resolve_executable_uses_the_given_cwd_not_the_process_cwd() {
    // No process-global `set_current_dir` here, deliberately: `resolve_executable`'s `Some(dir)`
    // arm never reads `std::env::current_dir()` at all (see its match on `cmd_cwd`), so an
    // explicit `cmd_cwd` needs no process-cwd mutation to prove it is honoured — mutating it
    // anyway would only add this test to the process-global cwd race other tests in this binary
    // must serialize against, for zero extra regression-catching power. The decoy below still
    // proves the given cwd wins over the process's REAL (unmutated) cwd, which is a weaker but
    // sufficient claim: it is wherever `cargo test` started this binary, almost certainly not
    // `cmd_dir`.
    let cmd_dir = tempfile::tempdir().unwrap();
    let want = std::fs::copy(
        std::env::current_exe().unwrap(),
        cmd_dir.path().join("sp_b1_helper.exe"),
    )
    .map(|_| cmd_dir.path().join("sp_b1_helper.exe"))
    .unwrap();

    // Located name (contains a separator) — resolves against the given cwd with no PATH search.
    let got = resolve_executable(std::path::Path::new("./sp_b1_helper.exe"), Some(cmd_dir.path()), &[]);

    assert_eq!(got.unwrap().canonicalize().unwrap(), want.canonicalize().unwrap());
}
#[test]
fn resolve_executable_falls_back_to_the_process_cwd_when_no_cwd_is_given() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), dir.path().join("sp_b1_fallback.exe")).unwrap();
    let want = dir.path().join("sp_b1_fallback.exe");

    // `cmd_cwd: None` mirrors an unset `Command::cwd()` — the doc says that means "the parent's",
    // i.e. the real process cwd, so the `None` fallback must still reach it rather than resolving
    // nothing. Exercising that fallback needs an actual process-cwd mutation, which is
    // process-global: serialize against `spawn_lock()` (see `crate::test_child::RestoreCwd`'s doc
    // for exactly what that lock does and does not buy) and restore via `RestoreCwd`'s `Drop`,
    // declared AFTER the lock guard so it runs — and un-does the mutation — BEFORE the lock
    // releases, even if an assertion below panics.
    let _guard = crate::child::spawn::spawn_lock();
    let _restore = crate::test_child::RestoreCwd::capture();
    std::env::set_current_dir(dir.path()).unwrap();
    let got = resolve_executable(std::path::Path::new("./sp_b1_fallback.exe"), None, &[]);

    assert_eq!(got.unwrap().canonicalize().unwrap(), want.canonicalize().unwrap());
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
