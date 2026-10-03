//! [`ResolveInput::cwd`]: which names need a base, and that `None` resolves those that do not.

use super::*;

#[skuld::test]
fn absolute_names_by_grammar() {
    for (name, windows, want) in [
        (r"C:\t\tool", true, true),
        ("C:/t/tool", true, true),
        (r"\\srv\shr\tool", true, true),
        (r"\\?\C:\t\tool", true, true),
        (r"\\.\dev\tool", true, true),
        (r"\\?\UNC\srv\shr\tool", true, true),
        (r"\\?\UNC\srv\shr", true, true),
        // A verbatim UNC path with no share names no share, as the plain `\\srv` does.
        (r"\\?\UNC\srv", true, false),
        // The marker is matched case-insensitively, as NT matches it.
        (r"\\?\Unc\srv", true, false),
        (r"\\?\unc\srv\shr\tool", true, true),
        (r"\\?\UNC\srv\", true, false),
        (r"\\?\UNC\", true, false),
        (r"\\?\UNC\\shr", true, false),
        // After the verbatim marker only `\` separates, as the join reads it: `srv/shr` is the
        // server, and there is no share.
        (r"\\?\UNC\srv/shr", true, false),
        // Nor is `/` the `UNC` marker's separator: NT reads `\\?\UNC/srv` as the verbatim namespace
        // `UNC/srv`, which is fully qualified. std's `parse_prefix` rewrites `/` to `\` in the first
        // eight bytes and so reads a share-less UNC there; cosca follows NT, which is what opens the
        // path, and its own join, which reads the namespace.
        (r"\\?\UNC/srv", true, true),
        (r"\\?\UNC/srv\tool.exe", true, true),
        (r"\\srv", true, false),
        (r"\t\tool", true, false),
        ("C:tool", true, false),
        (r"t\tool", true, false),
        ("tool", true, false),
        ("/t/tool", false, true),
        ("t/tool", false, false),
        (r"C:\t\tool", false, false),
    ] {
        assert_eq!(
            is_absolute_name(OsStr::new(name), windows),
            want,
            "{name:?} (windows: {windows})"
        );
    }
}

/// An absolute name resolves with no base at all: joining it onto any directory yields it again.
#[skuld::test]
fn an_absolute_name_needs_no_base() {
    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("tool");
    std::fs::write(&tool, b"x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let got = resolve(ResolveInput {
        program: &tool,
        cwd: None,
        system_dirs: &no_system_dirs,
        path_var: None,
        windows: cfg!(windows),
        loadable_only: false,
        normalise: &as_written,
    });
    assert_eq!(got.unwrap(), tool);
}

/// A bare name is searched on `PATH` alone, so it needs no base either.
#[skuld::test]
fn a_bare_name_needs_no_base() {
    let dir = tempfile::tempdir().unwrap();
    let name = if cfg!(windows) { "tool.exe" } else { "tool" };
    let tool = dir.path().join(name);
    std::fs::write(&tool, b"x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let got = resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: None,
        system_dirs: &no_system_dirs,
        path_var: Some(dir.path().as_os_str()),
        windows: cfg!(windows),
        loadable_only: false,
        normalise: &as_written,
    });
    assert_eq!(got.unwrap(), tool);
}

/// Win32 reads a name starting with two separators as UNC. One that parses no share names no
/// local file, so it is refused rather than joined onto a base, which would load a file on the
/// base's own drive (`\\tool.exe` onto `C:\d` is `C:\tool.exe`).
#[skuld::test]
fn a_unc_shaped_name_with_no_share_is_refused() {
    for name in [
        r"\\tool.exe",
        "//tool.exe",
        r"\/tool.exe",
        r"/\tool.exe",
        r"\\srv\\x.exe",
    ] {
        let got = resolve(ResolveInput {
            program: Path::new(name),
            cwd: None,
            system_dirs: &no_system_dirs,
            path_var: None,
            windows: true,
            loadable_only: false,
            normalise: &as_written,
        });
        match got {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{name:?}: {e}"),
            other => panic!("{name:?} must be refused, got {other:?}"),
        }
    }
}

/// Exactly the names the resolver reads a base for: a relative located name. A bare name, an
/// absolute one, and the two refused shapes do not.
#[skuld::test]
fn which_names_need_a_base() {
    for (name, want) in [
        (r"sub\tool.exe", true),
        (r".\tool.exe", true),
        (r"\tool.exe", true),
        ("tool.exe", false),
        (r"C:\t\tool.exe", false),
        (r"\\srv\shr\tool.exe", false),
        ("C:tool.exe", false),
        (r"\\tool.exe", false),
    ] {
        assert_eq!(needs_base(OsStr::new(name), true), want, "{name:?}");
    }
    assert!(needs_base(OsStr::new("sub/tool"), false));
    assert!(!needs_base(OsStr::new("/t/tool"), false));
}

/// Win32's path type (`RtlDetermineDosPathNameType_U`): separators first, then a drive of any one
/// UTF-16 unit before `:`.
#[skuld::test]
fn path_types_as_win32_reads_them() {
    use PathType::*;
    for (name, want) in [
        (r"\\srv\shr\x", Unc),
        ("//x", Unc),
        (r"\/x", Unc),
        (r"\\?\C:\x", Unc),
        (r"C:\x", DriveAbsolute),
        ("C:/x", DriveAbsolute),
        ("C:x", DriveRelative),
        ("1:tool.exe", DriveRelative),
        ("\u{e9}:x", DriveRelative),
        (r"C:D:\x", DriveRelative),
        ("::x", DriveRelative),
        (r"\x", Rooted),
        (r"\:x.exe", Rooted),
        ("/:x.exe", Rooted),
        (r"\:\x.exe", Rooted),
        ("x", Relative),
        (r"sub\x", Relative),
        // A supplementary character is two UTF-16 units, so the `:` is not in slot 1.
        ("\u{1f600}:x", Relative),
    ] {
        assert_eq!(path_type(OsStr::new(name)), want, "{name:?}");
    }
}

/// A lone surrogate is one UTF-16 unit, three WTF-8 bytes, so it is a drive like any other unit.
#[skuld::test]
fn a_lone_surrogate_is_a_drive() {
    for (rest, want) in [
        (&b":x"[..], PathType::DriveRelative),
        (br":\x", PathType::DriveAbsolute),
    ] {
        // U+D800 in WTF-8, the encoding `OsStr` uses on Windows.
        let bytes = [&[0xED, 0xA0, 0x80][..], rest].concat();
        assert_eq!(drive_len(&bytes), Some(4), "{bytes:?}");
        // SAFETY: WTF-8 bytes of an unpaired surrogate followed by ASCII, which is a valid `OsStr`
        // encoding on Windows; any bytes are one elsewhere.
        let name = unsafe { OsStr::from_encoded_bytes_unchecked(&bytes) };
        assert_eq!(path_type(name), want, "{bytes:?}");
    }
}

/// Every classifier agrees with the path type: `1:tool.exe` is drive-relative to all of them, so
/// the resolver refuses it rather than searching `PATH` for `1:tool.exe.exe`.
#[skuld::test]
fn a_digit_drive_is_drive_relative_everywhere() {
    let name = OsStr::new("1:tool.exe");
    assert_eq!(classify(name, true), Shape::Located);
    assert!(is_drive_relative(name, true));
    assert!(!is_absolute_name(name, true));
    assert!(!needs_base(name, true));
    let got = resolve(ResolveInput {
        program: Path::new(name),
        cwd: None,
        system_dirs: &no_system_dirs,
        path_var: None,
        windows: true,
        loadable_only: false,
        normalise: &as_written,
    });
    match got {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}"),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

/// A separator in slot 0 is never a drive, so `\:x` has no prefix.
#[skuld::test]
fn a_leading_separator_is_never_a_drive_prefix() {
    assert_eq!(windows_prefix_len(br"\:x"), 0);
    assert_eq!(windows_prefix_len(b"1:x"), 2);
    assert_eq!(windows_prefix_len("\u{e9}:x".as_bytes()), 3);
}

/// A name that needs a base resolved without one is a caller's contract violation, never a
/// second, untracked read of this process's cwd.
#[skuld::test]
#[should_panic(expected = "needs a base")]
fn a_located_name_without_a_base_is_a_contract_violation() {
    _ = resolve(ResolveInput {
        program: Path::new("sub/tool"),
        cwd: None,
        system_dirs: &no_system_dirs,
        path_var: None,
        windows: false,
        loadable_only: false,
        normalise: &as_written,
    });
}

/// A candidate is joined by the one classifier, never by `PathBuf::join`, which parses the base
/// with std's letter-only drive rule: a Rooted name on a digit-drive base keeps that drive.
#[skuld::test]
fn candidates_join_by_the_one_classifier() {
    let sep = std::path::MAIN_SEPARATOR_STR;
    for (dir, candidate, want) in [
        (r"1:\work", r"\tool.exe", r"1:\tool.exe".to_owned()),
        (r"1:\work", "tool.exe", format!(r"1:\work{sep}tool.exe")),
        (r"1:\work\", "tool.exe", r"1:\work\tool.exe".to_owned()),
        (r"\\srv\shr\d", r"\t.exe", r"\\srv\shr\t.exe".to_owned()),
        // A bare drive is that drive's current directory, so the result stays drive-relative.
        ("C:", "tool.exe", "C:tool.exe".to_owned()),
        ("", r"C:\t.exe", r"C:\t.exe".to_owned()),
        // A verbatim base is normalised as std normalises one, whatever the host separator.
        (r"\\?\C:\work", "./t.exe", r"\\?\C:\work\t.exe".to_owned()),
        (r"\\?\C:\work", "sub/../t.exe", r"\\?\C:\work\t.exe".to_owned()),
        (r"\\?\C:\work", "/t.exe", r"\\?\C:\t.exe".to_owned()),
    ] {
        assert_eq!(
            join_candidate(Path::new(dir), OsStr::new(candidate), true),
            PathBuf::from(&want),
            "{dir:?} + {candidate:?}"
        );
    }
}

/// Acceptance asks the one classifier too: `1:\tool.exe` is fully qualified to Win32 though std
/// knows no drive `1`.
#[skuld::test]
fn a_candidate_is_accepted_when_fully_qualified() {
    for (joined, want) in [
        (r"1:\tool.exe", true),
        (r"C:\tool.exe", true),
        (r"\\srv\shr\tool.exe", true),
        ("C:tool.exe", false),
        (r"\tool.exe", false),
        ("tool.exe", false),
    ] {
        assert_eq!(accepted(Path::new(joined), true), want, "{joined:?}");
    }
}

/// The raw OS error [`crate::error::io_context`] wrapped: it keeps the original error as `source()`
/// so the code survives, and several codes share one [`std::io::ErrorKind`].
#[cfg(unix)]
fn wrapped_raw_os_error(e: &std::io::Error) -> Option<i32> {
    std::error::Error::source(e)
        .and_then(|s| s.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
}

/// Joins two directories into the `PATH` value [`search_tool`]'s `windows: true` parses. Not
/// `std::env::join_paths`, which uses the host's `:`. Each entry is quoted, which
/// [`split_path_var_windows`] copies through literally, so a `;` in an ambient `TMPDIR` cannot split
/// an entry.
///
/// Panics on a `"` in either path: the grammar has no escape for one, and NTFS forbids it in a name.
#[cfg(unix)]
fn windows_path_var(first: &Path, second: &Path) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStrExt;
    for dir in [first, second] {
        assert!(
            !dir.as_os_str().as_bytes().contains(&b'"'),
            "precondition: {dir:?} must not contain a `\"` — NTFS forbids it, and the Windows \
             PATH grammar cannot express one"
        );
    }
    let mut path = std::ffi::OsString::from("\"");
    path.push(first);
    path.push("\";\"");
    path.push(second);
    path.push("\"");
    path
}

#[cfg(unix)]
#[skuld::test]
fn windows_path_var_resolves_two_ordinary_directories() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    std::fs::write(second.path().join("tool.exe"), b"x").unwrap();
    let path = windows_path_var(first.path(), second.path());
    assert_eq!(search_tool(&path, false).unwrap(), second.path().join("tool.exe"));
}

/// An ambient `TMPDIR` containing the `PATH` separator must not merge two entries into one.
#[cfg(unix)]
#[skuld::test]
fn windows_path_var_resolves_a_directory_whose_name_contains_the_separator() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::Builder::new().prefix("has;semicolon").tempdir().unwrap();
    std::fs::write(second.path().join("tool.exe"), b"x").unwrap();
    let path = windows_path_var(first.path(), second.path());
    assert_eq!(search_tool(&path, false).unwrap(), second.path().join("tool.exe"));
}

#[cfg(unix)]
#[skuld::test]
#[should_panic(expected = "must not contain a `\"`")]
fn windows_path_var_refuses_a_component_holding_a_quote() {
    windows_path_var(Path::new("/tmp/has\"quote"), Path::new("/tmp/b"));
}

/// A `PATH` entry whose candidate cannot be checked, followed by one that holds the name.
///
/// The first entry is a symlink to itself, so `<loop>/tool.exe` is `ELOOP` for every uid: the
/// kernel's loop limit is not a DAC (discretionary access control) decision, which no capability
/// overrides. The precondition, a candidate `is_absence` cannot call absent, is asserted.
#[cfg(unix)]
fn loop_then_open() -> (tempfile::TempDir, PathBuf, std::ffi::OsString) {
    let root = tempfile::tempdir().unwrap();
    let looping = root.path().join("loop");
    std::os::unix::fs::symlink("loop", &looping).unwrap();
    let open = root.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::write(open.join("tool.exe"), b"x").unwrap();
    let candidate = looping.join("tool.exe");
    let e = std::fs::metadata(&candidate).unwrap_err();
    assert!(
        !is_absence(&e),
        "precondition: {candidate:?} must be undeterminable, not a definite absence: {e}"
    );
    let path = windows_path_var(&looping, &open);
    (root, open, path)
}

/// A `chmod 0o000` directory, and the guard that unlocks it on drop.
#[cfg(unix)]
struct Locked(PathBuf, crate::test_child::RestoreMode);

#[cfg(unix)]
impl Locked {
    fn new(dir: PathBuf) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let restore = crate::test_child::RestoreMode::new(&dir, 0o755);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        Locked(dir, restore)
    }
}

/// A `PATH` entry whose candidate is refused with `EACCES`, followed by one that holds the name:
/// the one failure whose kind is `PermissionDenied`.
///
/// Only a caller without DAC bypass gets `EACCES`: root's, or either DAC capability, would see an
/// empty directory. Callers therefore run in a fixture [`crate::test_child::run_fixture`] started
/// without it, and the precondition is asserted.
#[cfg(unix)]
fn locked_then_open() -> (tempfile::TempDir, Locked, PathBuf, std::ffi::OsString) {
    let root = crate::test_child::fixture_scratch_tempdir();
    let locked = root.path().join("locked");
    let open = root.path().join("open");
    std::fs::create_dir(&locked).unwrap();
    std::fs::create_dir(&open).unwrap();
    std::fs::write(open.join("tool.exe"), b"x").unwrap();
    let locked = Locked::new(locked);
    let candidate = locked.0.join("tool.exe");
    let e = std::fs::metadata(&candidate).unwrap_err();
    assert_eq!(
        e.raw_os_error(),
        Some(libc::EACCES),
        "precondition: {candidate:?} must be denied to this caller, not {e} — did the caller \
         forget run_fixture?"
    );
    let path = windows_path_var(&locked.0, &open);
    (root, locked, open, path)
}

#[cfg(unix)]
fn search_tool(path_var: &OsStr, loadable_only: bool) -> Result<PathBuf, Error> {
    resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: None,
        system_dirs: &no_system_dirs,
        path_var: Some(path_var),
        windows: true,
        loadable_only,
        normalise: &as_written,
    })
}

/// The env var [`stat_errno_via_grandchild`] sets `fixture_stat_errno_probe`'s target to.
#[cfg(unix)]
const FIXTURE_STAT_TARGET_ENV: &str = "COSCA_FIXTURE_STAT_TARGET";

/// Prefix of the line the probe writes to its real stderr: `stat`'s raw errno, `0` on success.
#[cfg(unix)]
const STAT_ERRNO_PREFIX: &str = "COSCA_FIXTURE_STAT_ERRNO=";

/// Inert in an ordinary suite run. `stat`s [`FIXTURE_STAT_TARGET_ENV`] and reports the raw errno on
/// its real stderr as `STAT_ERRNO_PREFIX<n>`. A number carries no locale, unlike `strerror()` text,
/// and unlike the exit status it cannot be confused with libtest's own codes.
#[cfg(unix)]
#[skuld::test]
fn fixture_stat_errno_probe() {
    use std::io::Write as _;
    let Some(target) = std::env::var_os(FIXTURE_STAT_TARGET_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    let errno = std::fs::metadata(&target)
        .err()
        .map_or(0, |e| e.raw_os_error().unwrap_or(-1));
    writeln!(std::io::stderr(), "{STAT_ERRNO_PREFIX}{errno}").expect("report the errno");
}

/// Re-execs [`fixture_stat_errno_probe`] against `target` in a fresh child, a real `execve` rather
/// than this thread's own `stat`, and returns the errno it saw (`None` on success). Panics unless
/// the probe passed its gate and reported.
#[cfg(unix)]
fn stat_errno_via_grandchild(target: &Path) -> Option<i32> {
    let child = crate::test_spawn::spawn(
        crate::test_child::fixture_command(crate::test_child::fixture_path!(fixture_stat_errno_probe))
            .env(FIXTURE_STAT_TARGET_ENV, target),
    )
    .expect("spawn the stat probe");
    let output = child.wait_with_output().expect("wait for the stat probe");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stderr.contains(crate::test_child::FIXTURE_GATE_PASSED_LINE),
        "the stat probe did not run: {output:?}"
    );
    let errno: i32 = stderr
        .lines()
        .find_map(|l| l.strip_prefix(STAT_ERRNO_PREFIX))
        .unwrap_or_else(|| panic!("the stat probe reported no errno: {stderr}"))
        .parse()
        .expect("the reported errno is a number");
    (errno != 0).then_some(errno)
}

/// Under `loadable_only`, a candidate whose existence cannot be determined fails the search closed:
/// the entry after it must not win because a check errored. Uid-independent: passes as root and as
/// any other caller alike.
#[cfg(unix)]
#[skuld::test]
fn an_undeterminable_candidate_fails_a_loadable_only_search_closed() {
    let (_root, _open, path) = loop_then_open();
    match search_tool(&path, true) {
        Err(Error::Io(e)) => assert_eq!(wrapped_raw_os_error(&e), Some(libc::ELOOP), "{e}"),
        other => panic!("a loadable_only search must not skip an undeterminable candidate: {other:?}"),
    }
}

/// The `EACCES` twin of [`an_undeterminable_candidate_fails_a_loadable_only_search_closed`]: the
/// production case (`resolve.rs`'s `Err(e) if input.loadable_only` arm). Runs in a re-exec.
#[cfg(unix)]
#[skuld::test]
fn a_denied_candidate_fails_a_loadable_only_search_closed() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(
        fixture_a_denied_candidate_fails_a_loadable_only_search_closed
    ));
}

/// The child half of [`a_denied_candidate_fails_a_loadable_only_search_closed`]; inert unless
/// [`crate::test_child::run_fixture`] started it.
#[cfg(unix)]
#[skuld::test]
fn fixture_a_denied_candidate_fails_a_loadable_only_search_closed() {
    if !crate::test_child::is_fixture_reexec() {
        return; // picked up by an ordinary suite run — deliberately inert
    }
    let (_root, _locked, _open, path) = locked_then_open();
    match search_tool(&path, true) {
        Err(Error::Io(e)) => assert_eq!(wrapped_raw_os_error(&e), Some(libc::EACCES), "{e}"),
        other => panic!("a loadable_only search must not skip an undeterminable candidate: {other:?}"),
    }
}

/// An ordinary spawn skips it and goes on, as before, so one `PATH` entry whose candidate cannot be
/// checked does not break every unelevated spawn.
#[cfg(unix)]
#[skuld::test]
fn an_undeterminable_candidate_is_skipped_by_an_ordinary_search() {
    let (_root, open, path) = loop_then_open();
    assert_eq!(search_tool(&path, false).unwrap(), open.join("tool.exe"));
}

/// The `EACCES` twin of [`an_undeterminable_candidate_is_skipped_by_an_ordinary_search`]: the
/// production case (`resolve.rs`'s `Err(e) => log::warn!(...)` skip arm). Runs in a re-exec.
#[cfg(unix)]
#[skuld::test]
fn a_denied_candidate_is_skipped_by_an_ordinary_search() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(
        fixture_a_denied_candidate_is_skipped_by_an_ordinary_search
    ));
}

/// The child half of [`a_denied_candidate_is_skipped_by_an_ordinary_search`].
#[cfg(unix)]
#[skuld::test]
fn fixture_a_denied_candidate_is_skipped_by_an_ordinary_search() {
    if !crate::test_child::is_fixture_reexec() {
        return; // picked up by an ordinary suite run — deliberately inert
    }
    let (_root, _locked, open, path) = locked_then_open();
    assert_eq!(search_tool(&path, false).unwrap(), open.join("tool.exe"));
}

/// An `execve` from the fixture must not give DAC bypass back. `test_privilege` sets
/// `no_new_privs` for exactly that: without it, a uid-0 `execve` regains the capabilities from the
/// bounding set (`capabilities(7)`, set-user-ID-root compatibility). The driver needs a DAC bypass
/// for there to be anything to drop, root or not; see [`crate::test_privilege::root_tests_enabled`].
#[cfg(unix)]
#[skuld::test]
fn a_denied_candidate_is_denied_by_an_exec_child() {
    if !crate::test_privilege::root_tests_enabled() {
        return;
    }
    crate::test_child::run_fixture(crate::test_child::fixture_path!(
        fixture_a_denied_candidate_is_denied_by_an_exec_child
    ));
}

/// The child half of [`a_denied_candidate_is_denied_by_an_exec_child`]: an exec'd probe must be
/// denied too.
#[cfg(unix)]
#[skuld::test]
fn fixture_a_denied_candidate_is_denied_by_an_exec_child() {
    if !crate::test_child::is_fixture_reexec() {
        return; // picked up by an ordinary suite run — deliberately inert
    }
    let (_root, locked, open, _path) = locked_then_open();
    assert_eq!(
        stat_errno_via_grandchild(&open.join("tool.exe")),
        None,
        "positive control: an exec'd child must reach the unlocked directory, or a denial below \
         proves nothing"
    );
    let errno = stat_errno_via_grandchild(&locked.0.join("tool.exe"));
    assert_eq!(
        errno,
        Some(libc::EACCES),
        "an exec'd child must not regain access this process was denied"
    );
}

/// Which metadata errors are a definite "not here": absence, a non-directory in the path, or no
/// such drive. A denied or failed check is not.
#[skuld::test]
fn only_definite_misses_count_as_absent() {
    #[cfg(windows)]
    let cases = [
        (2, true),
        (3, true),
        (15, true),
        (123, true),
        (161, true),
        (267, true),
        (5, false),
        (21, false),
        // Unreachable share: std calls it `NotFound`, but it may only be unreachable for now.
        (53, false),
        (67, false),
    ];
    #[cfg(unix)]
    let cases = [
        (libc::ENOENT, true),
        (libc::ENOTDIR, true),
        (libc::EACCES, false),
        (libc::EIO, false),
    ];
    for (code, want) in cases {
        let e = std::io::Error::from_raw_os_error(code);
        assert_eq!(is_absence(&e), want, "{e}");
    }
}

/// The execute-permission answer: only "denied" and a definite absence are "not executable"; any
/// other failure is undeterminable and reaches `resolve`'s disposition.
#[cfg(unix)]
#[skuld::test]
fn only_a_denied_or_absent_execute_check_is_a_no() {
    assert!(execute_permission(0, 0).unwrap());
    for errno in [libc::EACCES, libc::ENOENT, libc::ENOTDIR] {
        assert!(!execute_permission(-1, errno).unwrap(), "errno {errno}");
    }
    for errno in [libc::EIO, libc::ELOOP, libc::ENOMEM] {
        let e = execute_permission(-1, errno).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(errno));
    }
}

/// A Windows base must be fully qualified: the caller completes it as Win32 does. A relative one is
/// a contract violation, reported in debug at the call boundary and in release where it is used.
#[skuld::test]
#[should_panic(expected = "must be fully qualified")]
fn a_relative_windows_base_is_a_contract_violation() {
    _ = resolve(ResolveInput {
        program: Path::new(r"sub\tool.exe"),
        cwd: Some(Path::new("rel")),
        system_dirs: &no_system_dirs,
        path_var: None,
        windows: true,
        loadable_only: false,
        normalise: &as_written,
    });
}

/// `loadable_only` is a Windows rule; asking for it on the POSIX grammar is a contract violation.
#[cfg(debug_assertions)] // the contract is a debug assertion: release has none to trigger
#[skuld::test]
#[should_panic(expected = "loadable_only is a Windows rule")]
fn loadable_only_on_the_posix_grammar_is_a_contract_violation() {
    _ = resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: None,
        system_dirs: &no_system_dirs,
        path_var: None,
        windows: false,
        loadable_only: true,
        normalise: &as_written,
    });
}

/// A candidate made verbatim by its base, not by the caller, is normalised as Win32 completes a
/// relative name against a verbatim cwd, and the normalised path is the one probed and returned.
#[skuld::test]
fn a_candidate_made_verbatim_by_its_base_is_normalised() {
    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("tool.exe");
    std::fs::write(&tool, b"x").unwrap();
    let seen = std::cell::RefCell::new(Vec::new());
    let normalise = |p: &Path| {
        seen.borrow_mut().push(p.to_path_buf());
        Ok(tool.clone())
    };
    let got = resolve(ResolveInput {
        program: Path::new(r"sub.\tool.exe"),
        cwd: Some(Path::new(r"\\?\C:\d")),
        system_dirs: &no_system_dirs,
        path_var: None,
        windows: true,
        loadable_only: false,
        normalise: &normalise,
    });
    assert_eq!(got.unwrap(), tool);
    assert_eq!(*seen.borrow(), [PathBuf::from(r"\\?\C:\d\sub.\tool.exe")]);
}

/// A name made verbatim by its base is joined as written, `..` included, so `normalise` collapses
/// it with Win32's floor rather than std's: past a verbatim share, not at it.
#[skuld::test]
fn a_candidate_made_verbatim_by_its_base_is_joined_as_written() {
    let seen = std::cell::RefCell::new(Vec::new());
    let normalise = |p: &Path| {
        seen.borrow_mut().push(p.to_path_buf());
        Ok(p.to_path_buf())
    };
    _ = resolve(ResolveInput {
        program: Path::new(r"..\..\..\t.exe"),
        cwd: Some(Path::new(r"\\?\UNC\srv\shr\d")),
        system_dirs: &no_system_dirs,
        path_var: None,
        windows: true,
        loadable_only: false,
        normalise: &normalise,
    });
    assert_eq!(*seen.borrow(), [PathBuf::from(r"\\?\UNC\srv\shr\d\..\..\..\t.exe")]);
}

/// A rooted name on a verbatim base is refused: Win32 completes it off the base's volume.
#[skuld::test]
fn a_rooted_name_on_a_verbatim_base_is_refused() {
    let never = |p: &Path| -> std::io::Result<PathBuf> { panic!("{p:?} must not be probed") };
    for cwd in [r"\\?\UNC\srv\shr\d", r"\\?\C:\d"] {
        let got = resolve(ResolveInput {
            program: Path::new(r"\t.exe"),
            cwd: Some(Path::new(cwd)),
            system_dirs: &no_system_dirs,
            path_var: None,
            windows: true,
            loadable_only: false,
            normalise: &never,
        });
        match got {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{cwd:?}: {e}"),
            other => panic!("{cwd:?}: must be refused, got {other:?}"),
        }
    }
}

/// A name written verbatim, or joined onto a plain base, is probed as it stands.
#[skuld::test]
fn only_a_verbatim_base_makes_a_candidate_normalised() {
    let never = |p: &Path| -> std::io::Result<PathBuf> { panic!("{p:?} must not be normalised") };
    for (program, cwd) in [
        (r"\\?\C:\d\sub.\tool.exe", None),
        (r"sub.\tool.exe", Some(Path::new(r"C:\d"))),
    ] {
        let got = resolve(ResolveInput {
            program: Path::new(program),
            cwd,
            system_dirs: &no_system_dirs,
            path_var: None,
            windows: true,
            loadable_only: false,
            normalise: &never,
        });
        match got {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{program:?}: {e}"),
            other => panic!("{program:?} must miss, got {other:?}"),
        }
    }
}

/// A verbatim `PATH` or system directory is written verbatim by whoever set it, so a candidate
/// under it is probed as written: `\\?\C:\x\bin.` is the directory `bin.`, never `bin`.
#[skuld::test]
fn a_verbatim_search_directory_is_taken_as_written() {
    let never = |p: &Path| -> std::io::Result<PathBuf> { panic!("{p:?} must not be normalised") };
    let system = [PathBuf::from(r"\\?\C:\a\..\b")];
    let system_fn = || -> Result<Vec<PathBuf>, Error> { Ok(system.to_vec()) };
    let got = resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: None,
        system_dirs: &system_fn,
        path_var: Some(OsStr::new(r"\\?\C:\x\bin.")),
        windows: true,
        loadable_only: false,
        normalise: &never,
    });
    match got {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        other => panic!("nothing is on disk there, got {other:?}"),
    }
}

/// `UNC` marks a verbatim UNC prefix only before `\`, as NT reads it: after `UNC/` the prefix is
/// the namespace `\\?\UNC`, split on either separator as every prefix component is here, and
/// `tool.exe` is a file in it rather than a share.
#[skuld::test]
fn a_verbatim_unc_marker_needs_a_backslash() {
    assert_eq!(
        windows_prefix_len(br"\\?\UNC\srv\shr\tool.exe"),
        r"\\?\UNC\srv\shr".len()
    );
    assert_eq!(windows_prefix_len(br"\\?\UNC/srv\tool.exe"), r"\\?\UNC".len());
    assert_eq!(windows_prefix_len(br"\\?\UNC/srv"), r"\\?\UNC".len());
}

/// A made-verbatim candidate that Win32's completion turns into a share root, or a path on no
/// share, names no file: it is refused as `InvalidInput`, as `raw_executable()` refuses it, not
/// reported as a miss.
#[skuld::test]
fn a_normalised_candidate_that_names_no_file_is_refused() {
    for completed in [r"\\?\UNC\srv\t.exe", r"\\?\UNC\t.exe", r"\\?\t.exe"] {
        let normalise = |_: &Path| Ok(PathBuf::from(completed));
        let got = resolve(ResolveInput {
            program: Path::new(r"..\..\t.exe"),
            cwd: Some(Path::new(r"\\?\UNC\srv\shr\d")),
            system_dirs: &no_system_dirs,
            path_var: None,
            windows: true,
            loadable_only: false,
            normalise: &normalise,
        });
        match got {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{completed:?}: {e}"),
            other => panic!("{completed:?} must be refused, got {other:?}"),
        }
    }
}
