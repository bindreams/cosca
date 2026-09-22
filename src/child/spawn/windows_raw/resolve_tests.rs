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

/// There is no "absolute and exists -> return unchanged" shortcut: an absolute path goes through
/// the ordinary located path — one directory, the exact name tried first — and lands on the same
/// answer by a different route.
///
/// This cannot gate the located `.exe`-appending rule: `current_exe()` ends in `.exe` on Windows,
/// so it takes the already-has-a-loadable-extension branch. The extensionless and
/// unrelated-extension cases are gated in `crate::resolve`'s own tests, which force
/// `windows: true` and so run on every host.
#[test]
fn resolve_an_absolute_path_to_an_existing_image_yields_that_path() {
    let me = std::env::current_exe().unwrap();
    assert_eq!(resolve_executable(&me, None, &[]).unwrap(), me);
}
#[test]
fn resolve_bare_name_is_not_taken_from_base_cwd() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), dir.path().join("sp_shadow.exe")).unwrap();
    // A bare name searches system directories and then PATH, never the current directory.
    // Resolving it from the current directory is the binary-planting hazard this resolver exists
    // to avoid, so a matching file there with nothing in system_dirs or on PATH must NOT resolve.
    // `system_dirs` is empty here — this test is about base_cwd, not system-directory precedence,
    // which has its own tests in `crate::resolve_tests`.
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
    // Pins the `.exe`-append rule only, not which directory supplies the match: `cmd` lives in
    // `System32`, so system-directory search (`crate::resolve::ResolveInput::system_dirs`) may
    // satisfy it before the ambient `PATH` is ever consulted.
    let p = resolve_executable(std::path::Path::new("cmd"), None, &[]).unwrap();
    assert!(
        p.is_absolute() && p.exists() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")),
        "{p:?}"
    );
}
// ── `resolve_executable` honors the CHILD's PATH, not the ambient one ──────────────────
//
// `path_var`'s own doc (`crate::resolve::ResolveInput::path_var`) promises "the PATH the CHILD
// will see, after env()/env_clear()", so `resolve_executable` must apply `Command::env_ops()`
// rather than reading `std::env::var_os("PATH")`. cosca's std backend already threads `env_ops`
// onto the child correctly (`apply_env` in `child::spawn.rs`); the raw backend must match it, not
// silently search the PARENT's PATH while the child would see a different one.
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
// below, because `resolve_executable` searches Windows system directories ahead of PATH (see
// `crate::resolve::ResolveInput::system_dirs`'s doc). `cmd` genuinely lives in `System32`, so it
// keeps resolving there even with PATH fully cleared or removed, silently masking exactly the
// PATH-defeat regression these two tests exist to catch — measured on real Windows CI, where a
// `cmd`-based version of both tests returned `Ok("C:\\Windows\\system32\\cmd.exe")`. A name that
// lives ONLY in a tempdir set as `PATH` removes that ambiguity.
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
// ── `resolve_executable`'s `cmd_cwd` parameter ────────────────────────────────────────
//
// The resolver reads the CHILD's cwd (`Command::cwd()` when set, else the parent's — see
// `crate::resolve::ResolveInput::cwd`'s doc), so `base_cwd` must honour a `Command::cwd()`
// override rather than being seeded from `std::env::current_dir()`. Otherwise the documented
// escape hatch breaks: "write `./helper` to reach the current directory explicitly" would land on
// the PARENT's ambient directory, the exact directory this crate exists to stop trusting.
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

    // `cmd_cwd: None` mirrors an unset `Command::cwd()` — the doc says that means "the parent's",
    // i.e. the real process cwd, so the `None` fallback must still reach it rather than resolving
    // nothing. See `crate::resolve::resolve_tests::empty_path_elements_are_skipped`'s doc for why
    // exercising that needs a re-exec'd child.
    crate::test_child::run_fixture_with_cwd(
        crate::test_child::fixture_path!(fixture_resolve_executable_falls_back_to_process_cwd),
        dir.path(),
        FIXTURE_RESOLVE_FALLBACK_MARKER,
    );
}

const FIXTURE_RESOLVE_FALLBACK_MARKER: &str = "COSCA_FIXTURE_RESOLVE_FALLBACK";

/// The child half of [`resolve_executable_falls_back_to_the_process_cwd_when_no_cwd_is_given`].
/// Reconstructs `want` from its own (already-`dir.path()`) cwd rather than receiving it from the
/// parent, since the two are guaranteed equal by construction. Mirrors
/// `crate::resolve::resolve_tests::fixture_empty_path_elements_are_skipped`'s shape.
#[test]
fn fixture_resolve_executable_falls_back_to_process_cwd() {
    let Some(cwd) = crate::test_child::expected_cwd(FIXTURE_RESOLVE_FALLBACK_MARKER) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    let want = cwd.join("sp_b1_fallback.exe");
    assert!(
        want.is_file(),
        "the parent must have planted `sp_b1_fallback.exe` here: {want:?}"
    );
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
    // base_cwd is not searched for a bare name, so the PATH copy wins even though an identically
    // named file sits in the current directory. `system_dirs` is empty here — this test is about
    // base_cwd vs PATH, not system-directory precedence.
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
// ── real Windows system directories, end to end ─────────────────────────────────────
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
    // the aggregate: a bound like `dirs.len() >= 2` survives deleting EITHER the `app_dir()` or
    // the `get_windows_directory()` line from `windows_system_dirs`, even though this test's own
    // preamble claims to cover all three. All three should resolve
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

/// The NUL refusal must name WHICH field carried it. One checker serves the environment block, the
/// program token, the working directory and every argv token, so a message fixed to "environment
/// key or value" reports a NUL in a PROGRAM PATH as a broken environment.
#[test]
fn a_nul_refusal_names_the_field_that_carried_it() {
    let key = build_env_block_from(&[], &[EnvOp::Set(OsString::from("a\u{0}b"), "1".into())]).unwrap_err();
    assert!(key.to_string().contains("environment key"), "{key}");

    let val = build_env_block_from(&[], &[EnvOp::Set("K".into(), OsString::from("a\u{0}b"))]).unwrap_err();
    assert!(val.to_string().contains("environment value"), "{val}");

    // The `what` really is the caller's, not a constant the two legs above happen to share.
    let other = ensure_no_nul_wide("program token", OsStr::new("a\u{0}b")).unwrap_err();
    assert!(other.to_string().contains("program token"), "{other}");
    assert!(
        !other.to_string().contains("environment"),
        "a program token is not the environment: {other}"
    );
}

/// [`debug_assert_no_nul_wide`] promises to fail LOUDLY the moment resolution grows a return that
/// is not `is_file`-gated. An assert nobody fires is indistinguishable from an assert whose
/// condition was inverted or dropped, so the promise is worth a probe of its own.
///
/// `debug_assertions`-only: the assert is compiled out of a release build by design, so in CI's
/// `--release --lib` leg the expected panic would never arrive and a working crate would go red.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "program image contains an embedded NUL")]
fn debug_assert_no_nul_wide_panics_on_an_embedded_nul() {
    debug_assert_no_nul_wide("program image", OsStr::new("a\u{0}b"));
}

// Environment key identity =====

fn wide(units: &[u16]) -> OsString {
    OsString::from_wide(units)
}

/// Split a block into `(key, value)` entries. Splits at the LAST `=`, so a key that is itself `=`
/// parses as long as values carry none.
fn block_entries(block: &[u16]) -> Vec<(OsString, OsString)> {
    block[..block.len() - 1]
        .split(|&u| u == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let eq = entry.iter().rposition(|&u| u == u16::from(b'=')).unwrap();
            (wide(&entry[..eq]), wide(&entry[eq + 1..]))
        })
        .collect()
}

/// Whether setting `b` over an inherited `a` replaces it (the same variable) or adds a second one.
fn same_var(a: &OsStr, b: &OsStr) -> bool {
    let block = build_env_block_from(&[(a.into(), "base".into())], &[EnvOp::Set(b.into(), "op".into())])
        .unwrap()
        .unwrap();
    match block_entries(&block).len() {
        1 => true,
        2 => false,
        n => panic!("{a:?} over {b:?} produced {n} entries"),
    }
}

/// Windows folds one UTF-16 code unit to one, so a character whose full uppercase is longer, or
/// lives in a surrogate pair, never names the same variable as that uppercase.
#[test]
fn full_case_mapping_does_not_merge_env_keys() {
    for (a, b) in [("SS", "ß"), ("FI", "ﬁ"), ("I", "ı"), ("\u{10400}", "\u{10428}")] {
        assert!(
            !same_var(OsStr::new(a), OsStr::new(b)),
            "{a:?} and {b:?} are distinct on Windows"
        );
    }
}

#[test]
fn simple_case_pairs_are_the_same_env_key() {
    for (a, b) in [("PATH", "path"), ("É", "é")] {
        assert!(
            same_var(OsStr::new(a), OsStr::new(b)),
            "{a:?} and {b:?} are one variable"
        );
    }
}

/// An unpaired surrogate is its own code unit: it matches only itself, and does not stop the rest
/// of the key from folding.
#[test]
fn unpaired_surrogates_in_env_keys_compare_by_code_unit() {
    let hi = 0xD800;
    let a = u16::from(b'a');
    let upper_a = u16::from(b'A');
    assert!(same_var(&wide(&[hi]), &wide(&[hi])));
    assert!(!same_var(&wide(&[hi]), &wide(&[0xDC00])));
    assert!(same_var(&wide(&[hi, a]), &wide(&[hi, upper_a])));
}

#[test]
fn setting_eszett_keeps_an_inherited_ss() {
    let block = build_env_block_from(
        &[(OsString::from("SS"), OsString::from("inherited"))],
        &[EnvOp::Set(OsString::from("ß"), OsString::from("set"))],
    )
    .unwrap()
    .unwrap();
    let mut got = block_entries(&block);
    got.sort();
    assert_eq!(got, [("SS".into(), "inherited".into()), ("ß".into(), "set".into())]);
}

type Entries = Vec<(OsString, OsString)>;

/// The raw block for `ops` over an empty base, next to what std's `Command` holds after the same
/// ops. With nothing inherited, std's block is exactly `get_envs`' set entries: same keys (with
/// std's casing), same values, and `get_envs` iterates std's own `EnvKey` order, which is the
/// order std writes its block in.
fn block_vs_std(ops: &[EnvOp]) -> (Entries, Entries) {
    let mut std_cmd = std::process::Command::new("unused");
    crate::child::spawn::apply_env(&mut std_cmd, ops);
    let ours = block_entries(&build_env_block_from(&[], ops).unwrap().unwrap());
    let std = std_cmd
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_os_string(), v?.to_os_string())))
        .collect();
    (ours, std)
}

/// A cleared env followed by one `Set` per key, valued by its index.
fn set_each(keys: &[OsString]) -> Vec<EnvOp> {
    std::iter::once(EnvOp::Clear)
        .chain(
            keys.iter()
                .enumerate()
                .map(|(i, key)| EnvOp::Set(key.clone(), i.to_string().into())),
        )
        .collect()
}

/// `CreateProcessW` expects the block sorted case-insensitively by ordinal, locale-free; std sorts
/// by `CompareStringOrdinal`, so the raw backend must produce the same order and the same merges.
#[test]
fn env_block_order_and_merges_match_std() {
    let keys: Vec<OsString> = [
        "T",
        "ß",
        "SS",
        "sa",
        "st",
        "_x",
        "a",
        "Z",
        "é",
        "É",
        "ﬁ",
        "FI",
        "ı",
        "I",
        "\u{10428}",
        "\u{10400}",
        "\u{FFFF}",
    ]
    .iter()
    .map(OsString::from)
    .chain([wide(&[0xD800]), wide(&[0xDC00, u16::from(b'a')])])
    .collect();
    let (ours, std) = block_vs_std(&set_each(&keys));
    assert_eq!(ours, std);
}

/// Every non-NUL code unit as a one-unit key: the raw backend and std agree on every merge, every
/// emitted key and the whole order.
#[test]
fn env_block_matches_std_over_every_code_unit() {
    let keys: Vec<OsString> = (1..=u16::MAX).map(|u| wide(&[u])).collect();
    let (ours, std) = block_vs_std(&set_each(&keys));
    assert_eq!(ours.len(), std.len());
    assert!(
        ours == std,
        "first divergence at {:?}",
        ours.iter().zip(&std).position(|(a, b)| a != b)
    );
}

/// When keys collide, std keeps the casing of the first op that named the variable since the last
/// `Clear` (a `Remove` counts), and the raw backend must emit the same name.
#[test]
fn colliding_keys_keep_std_casing() {
    let set = |k: &str, v: &str| EnvOp::Set(k.into(), v.into());
    let remove = |k: &str| EnvOp::Remove(k.into());
    for ops in [
        vec![set("Path", "1"), set("PATH", "2")],
        vec![remove("path"), set("PATH", "1")],
        vec![EnvOp::Clear, remove("path"), set("PATH", "1")],
        vec![set("a", "1"), EnvOp::Clear, set("A", "2")],
    ] {
        let (ours, std) = block_vs_std(&ops);
        assert_eq!(ours, std, "{ops:?}");
    }
}

/// An inherited variable keeps its inherited name when an op overrides it, as std's capture does.
#[test]
fn an_inherited_key_keeps_its_casing() {
    let base = [(OsString::from("Path"), OsString::from("inherited"))];
    for ops in [
        vec![EnvOp::Set("PATH".into(), "x".into())],
        vec![EnvOp::Remove("PATH".into()), EnvOp::Set("pAth".into(), "x".into())],
    ] {
        let block = build_env_block_from(&base, &ops).unwrap().unwrap();
        assert_eq!(block_entries(&block), [("Path".into(), "x".into())], "{ops:?}");
    }
}
