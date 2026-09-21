use super::*;
use crate::command::EnvOp;
use std::ffi::OsString;

/// The name was accepted and searched, and nothing matched — `NotFound`, never a shape refusal.
/// A bare `is_err()` cannot tell the two apart, which is how the kind drifted unnoticed before;
/// see `crate::resolve`'s module doc for the rule.
fn assert_not_found(got: Result<PathBuf, Error>) {
    match got {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        other => panic!("a search miss must be Io(NotFound), got {other:?}"),
    }
}

/// Renamed from `resolve_absolute_existing_is_returned_as_is`, which named a property the code no
/// longer has: there is no "absolute and exists -> return unchanged" shortcut any more (that was
/// `main`'s `exe.is_absolute() && exe.is_file()` early return, deleted with the rewrite). An
/// absolute path now goes through the ordinary located path — one directory, the exact name
/// tried first — which lands on the same answer by a different route.
///
/// The old name also passed for the wrong reason: `current_exe()` ends in `.exe` on Windows, so
/// it took the already-has-a-loadable-extension branch and could never have caught the located
/// `.exe`-appending regression. The extensionless and unrelated-extension cases are gated in
/// `crate::resolve`'s own tests, which force `windows: true` and so run on every host.
#[test]
fn resolve_an_absolute_path_to_an_existing_image_yields_that_path() {
    let me = std::env::current_exe().unwrap();
    assert_eq!(resolve_executable(&me, None, &[]).unwrap(), me);
}
#[test]
fn resolve_bare_name_is_not_taken_from_base_cwd() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), dir.path().join("sp_shadow.exe")).unwrap();
    // INVERTED deliberately: a bare name searches system directories and then PATH, never the
    // current directory. Resolving it from the current directory is the binary-planting hazard
    // this resolver exists to avoid, so a matching file there with nothing in system_dirs or on
    // PATH must NOT resolve. `system_dirs` is empty here — this test is about base_cwd, not
    // system-directory precedence, which has its own tests in `crate::resolve_tests`.
    // Explicit base dir — no process-global SetCurrentDirectory, so parallel tests can't race.
    assert_not_found(resolve_executable_in(
        std::path::Path::new("sp_shadow"),
        dir.path(),
        &[],
        None,
    ));
}
#[test]
fn resolve_bare_extensionless_name_appends_exe() {
    // Renamed from `..._from_path`: since the merge-blocker fix added system-directory search
    // (`crate::resolve::ResolveInput::system_dirs`), "cmd" now resolves via `System32` — it lives
    // there — rather than necessarily via the ambient `PATH`. That is fine for what this test
    // actually pins (the `.exe`-append rule fires regardless of which searched directory supplies
    // the match); the old name just asserted a stronger claim about the source directory than the
    // test body ever checked.
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
    assert_not_found(resolve_executable(std::path::Path::new("sp_env_path"), None, &[]));

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
// A fabricated name, never "cmd" or another well-known system binary, is required by both tests
// below now that `resolve_executable` also searches Windows system directories ahead of PATH (the
// maintainer's merge-blocker fix — see `crate::resolve::ResolveInput::system_dirs`'s doc). `cmd`
// genuinely lives in `System32`, so it keeps resolving there even with PATH fully cleared or
// removed, which would silently mask exactly the PATH-defeat regression these two tests exist to
// catch: measured directly — before this rename, both tests failed on real Windows CI with
// `Ok("C:\\Windows\\system32\\cmd.exe")`, proving PATH-independent resolution is real, not
// theoretical. A name that lives ONLY in a tempdir set as `PATH` removes that ambiguity.
#[test]
fn resolve_executable_env_clear_defeats_ambient_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), dir.path().join("sp_env_clear.exe")).unwrap();
    let set = [EnvOp::Set(
        OsString::from("PATH"),
        dir.path().as_os_str().to_os_string(),
    )];
    // Positive control: with PATH pointed at the fabricated name's directory, it resolves — so a
    // failure below is really about env_clear, not merely that this name can never resolve.
    assert!(resolve_executable(std::path::Path::new("sp_env_clear"), None, &set).is_ok());
    // `Command::env_clear()` means the child sees NO environment at all, PATH included — the
    // resolver must not silently fall back to searching the PARENT's PATH once the child's own is
    // cleared.
    //
    // `[Set(PATH, dir), Clear]`, not bare `[Clear]`: with `EnvOp::Clear => path = None` deleted from
    // `effective_path_var` (silently absorbed by its `_ => {}` arm), a bare `[Clear]` leaves the
    // AMBIENT `PATH` in force, which never happens to contain this fabricated tempdir — so `is_err()`
    // held for the wrong reason. Setting PATH to a directory that WOULD resolve, then clearing it,
    // means Clear must actually discard a PATH that works, mirroring the sibling
    // `..._env_remove_path_defeats_ambient_path` test's shape below.
    let got = resolve_executable(
        std::path::Path::new("sp_env_clear"),
        None,
        &[
            EnvOp::Set(OsString::from("PATH"), dir.path().as_os_str().to_os_string()),
            EnvOp::Clear,
        ],
    );
    assert_not_found(got);
}
#[test]
fn resolve_executable_env_remove_path_defeats_ambient_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), dir.path().join("sp_env_remove.exe")).unwrap();
    let set = [EnvOp::Set(
        OsString::from("PATH"),
        dir.path().as_os_str().to_os_string(),
    )];
    // Positive control, same reasoning as the env_clear test above.
    assert!(resolve_executable(std::path::Path::new("sp_env_remove"), None, &set).is_ok());
    // `EnvOp::Remove` on the just-`Set` key (case-folded, per `Command::env_remove`'s contract)
    // must take the child's PATH away again — the resolver must not keep searching a directory the
    // env ops explicitly removed.
    let got = resolve_executable(
        std::path::Path::new("sp_env_remove"),
        None,
        &[
            EnvOp::Set(OsString::from("PATH"), dir.path().as_os_str().to_os_string()),
            EnvOp::Remove(OsString::from("path")),
        ],
    );
    assert_not_found(got);
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
    //
    // Named `sp_dirtool.exe`, not extensionless `sp_dirtool`: the bare-name candidate rule (see
    // `crate::resolve`'s `filename_candidates` doc) means the only filename ever tried for a bare
    // `sp_dirtool` is `sp_dirtool.exe`. An extensionless shadow directory is never even looked at,
    // which would make `is_file()` -> `exists()` a silently green one-line mutation here — the
    // shadow has to be named exactly what the search will actually stat.
    let shadow_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(shadow_dir.path().join("sp_dirtool.exe")).unwrap();
    let path_copy = other.path().join("sp_dirtool.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &path_copy).unwrap();
    let joined = std::env::join_paths([shadow_dir.path(), other.path()]).unwrap();
    let got = resolve_executable_in(
        std::path::Path::new("sp_dirtool"),
        base.path(),
        &[],
        Some(joined.as_os_str()),
    )
    .unwrap();
    assert_eq!(got.canonicalize().unwrap(), path_copy.canonicalize().unwrap());
}
#[test]
fn resolve_absolute_directory_is_not_returned() {
    let dir = tempfile::tempdir().unwrap();
    // An absolute path naming an existing *directory* is not a runnable program.
    //
    // The directory itself is named `...exe` so `filename_candidates` leaves the name unchanged
    // (its final component already ends in `.exe`) and the joined candidate is exactly this
    // existing directory. Passing `dir.path()` bare would instead produce a candidate of
    // `<tempdir-name>.exe`, which exists under NEITHER `is_file()` NOR `exists()` — making
    // `is_file()` -> `exists()` a silently green one-line mutation, since nothing was ever there to
    // tell the two checks apart.
    let sub = dir.path().join("sp_dir_shadow.exe");
    std::fs::create_dir(&sub).unwrap();
    assert_not_found(resolve_executable_in(&sub, std::path::Path::new("."), &[], None));
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
    // wins even though an identically named file sits in the current directory. `system_dirs` is
    // empty here — this test is about base_cwd vs PATH, not system-directory precedence.
    let got = resolve_executable_in(
        std::path::Path::new("sp_pref"),
        base.path(),
        &[],
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
// ── FIX: real Windows system directories, end to end (merge blocker) ────────────────
//
// The core ordering policy is pinned host-independently in `crate::resolve_tests` (it takes
// `system_dirs` as fabricated `PathBuf`s, by design, so it can run without Windows at all). These
// two tests instead exercise the REAL `GetSystemDirectoryW`/`GetWindowsDirectoryW`/`current_exe`
// wiring in `windows_system_dirs` — the one part of this fix a cross-compile cannot validate,
// because `cargo xwin check`/`clippy` only prove the code TYPE-CHECKS for Windows, never that it
// runs correctly there. What a real runner catches here is a wrong Win32 return-value convention
// and `System32` not being where this crate assumes it is.
//
// NOT `wide_dir_buffer`'s grow loop: `System32` and the Windows directory fit the initial
// 260-element buffer on every install, so the loop never runs and no test on any host reaches it.
// Its own `debug_assert!` and the `.max(buf.len() + 1)` that keeps it from spinning are what
// stand in for coverage there.
#[test]
fn windows_system_dirs_are_real_existing_directories() {
    let dirs = windows_system_dirs();
    for dir in &dirs {
        assert!(dir.is_dir(), "{dir:?} is not a real, existing directory");
    }

    // Exercise all THREE individual sources by calling each private accessor directly, not just
    // the aggregate: a bound like `dirs.len() >= 2` (the old assertion here) survives deleting
    // EITHER the `app_dir()` or the `get_windows_directory()` line from `windows_system_dirs`,
    // even though this test's own preamble claims to cover all three. All three should resolve
    // under `cargo test` on a real Windows runner, so each is asserted present outright rather than
    // loosely.
    let app = app_dir();
    let sys32 = get_system_directory();
    let win = get_windows_directory();
    assert!(app.is_some(), "current_exe()'s parent should resolve under cargo test");
    assert!(sys32.is_some(), "GetSystemDirectoryW should succeed under cargo test");
    assert!(win.is_some(), "GetWindowsDirectoryW should succeed under cargo test");
    let (app, sys32, win) = (app.unwrap(), sys32.unwrap(), win.unwrap());
    assert!(dirs.contains(&app), "app dir {app:?} missing from {dirs:?}");
    assert!(dirs.contains(&sys32), "System32 {sys32:?} missing from {dirs:?}");
    assert!(dirs.contains(&win), "Windows dir {win:?} missing from {dirs:?}");

    // Pin the ORDER too: app dir -> System32 -> Windows dir is the policy both
    // `crate::resolve::ResolveInput::system_dirs` and the public `executable()` doc state — all
    // three being merely PRESENT, in any order, would still let a widening regression (system-dir
    // precedence over PATH silently reshuffled) through undetected.
    let pos = |d: &PathBuf| dirs.iter().position(|x| x == d).unwrap();
    let (app_pos, sys32_pos, win_pos) = (pos(&app), pos(&sys32), pos(&win));
    assert!(
        app_pos < sys32_pos && sys32_pos < win_pos,
        "expected app dir < System32 < Windows dir, got positions {app_pos}, {sys32_pos}, {win_pos} in {dirs:?}"
    );
}

#[test]
fn resolve_finds_a_real_system32_binary_through_system_dirs() {
    // `notepad.exe` ships in `System32` on every supported Windows version and is not normally on
    // a dev machine's `PATH`, so successfully resolving the BARE name "notepad" with an empty
    // `PATH` can only have come from `system_dirs` — proving the real wiring end to end, not just
    // that `windows_system_dirs()` returns plausible-looking paths.
    let dirs = windows_system_dirs();
    let cwd = tempfile::tempdir().unwrap();
    let got = resolve_executable_in(std::path::Path::new("notepad"), cwd.path(), &dirs, None).unwrap();
    assert!(got.to_string_lossy().to_lowercase().contains("system32"), "{got:?}");
}

#[test]
fn embedded_nul_in_key_is_rejected_as_invalid_input() {
    let e = build_env_block_from(&[], &[EnvOp::Set(OsString::from("a\u{0}b"), "1".into())]).unwrap_err();
    assert!(
        matches!(e, crate::error::Error::Io(ref io) if io.kind() == std::io::ErrorKind::InvalidInput),
        "{e:?}"
    );
}
