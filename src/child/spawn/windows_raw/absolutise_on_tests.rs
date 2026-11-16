//! [`super::complete_on`] and [`super::absolutise_exact_on`]: Win32's completion of a path, with
//! this process's cwd and a drive's own current directory read through readers, the cwd at most
//! once. No test changes this process's cwd or environment.

use std::cell::Cell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::{absolutise_exact_on, complete_on, Completed, DriveDirs};
use crate::child::spawn::windows_raw::env_snapshot::EnvSnapshot;
use crate::error::Error;

fn no_drive(_: &std::ffi::OsStr) -> Result<Option<OsString>, Error> {
    Ok(None)
}

/// The real `=X:` directory, as `GetFullPathNameW` uses it.
fn real_drive(drive: &std::ffi::OsStr) -> Result<Option<OsString>, Error> {
    let snapshot = EnvSnapshot::read()?;
    Ok(DriveDirs::new(&snapshot).get(drive))
}

/// A snapshot holding the one variable `var` (`NAME=value`).
fn snapshot_with(var: &str) -> EnvSnapshot {
    EnvSnapshot::from_block(format!("{var}\0\0").encode_utf16().collect())
}

fn letter_of(p: &Path) -> char {
    p.to_string_lossy().chars().next().unwrap().to_ascii_uppercase()
}

/// `GetFullPathNameW` on `token`, called directly: Win32's own completion against this process's
/// real cwd and `=X:` values.
fn win32_full_path(token: &str) -> std::io::Result<PathBuf> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetFullPathNameW;
    let wide: Vec<u16> = std::ffi::OsStr::new(token).encode_wide().chain([0]).collect();
    let mut buf = vec![0u16; 1];
    loop {
        // SAFETY: `wide` is NUL-terminated and outlives the call; `buf` is a writable slice whose
        // length the call is told.
        let n = unsafe { GetFullPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf), None) } as usize;
        if n == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Fits: `n` excludes the NUL. Too small: `n` is the size needed, NUL included.
        if n < buf.len() {
            buf.truncate(n);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        buf.resize(n, 0);
    }
}

/// With the real cwd and environment as readers, the result is Win32's for every shape, UNC-shaped
/// ones included: `GetFullPathNameW` on the token, with the name-no-file check on the token and on
/// the result, as `absolutise_exact_on` applies them.
#[skuld::test]
fn matches_get_full_path_name_given_the_real_cwd() {
    let cwd = std::env::current_dir().unwrap();
    let letter = letter_of(&cwd);
    let other = if letter == 'Q' { 'R' } else { 'Q' };
    for token in [
        "tool.exe".to_owned(),
        r".\a\..\tool.exe".to_owned(),
        r"\tool.exe".to_owned(),
        r"sub\tool.exe.".to_owned(),
        format!("{letter}:tool.exe"),
        format!("{}:tool.exe", letter.to_ascii_lowercase()),
        format!("{other}:tool.exe"),
        r"C:\abs\tool.exe".to_owned(),
        r"\\tool.exe".to_owned(),
        "//tool.exe".to_owned(),
        r"\/tool.exe".to_owned(),
        r"/\tool.exe".to_owned(),
        r"\\srv\\x.exe".to_owned(),
        r"\\srv\shr\tool.exe".to_owned(),
        // A drive's rest is appended as units, never parsed: `C:D:\x` is not `D:\x`.
        format!(r"{letter}:D:\x.exe"),
        "C:D:x.exe".to_owned(),
        // A separator in slot 0 is rooted, whatever follows it.
        r"\:x.exe".to_owned(),
        "/:x.exe".to_owned(),
        r"\:\x.exe".to_owned(),
        // Any one unit is a drive.
        "1:tool.exe".to_owned(),
    ] {
        // Compared as outcomes: some shapes (`\\srv\\x.exe` normalises to a share root) are
        // refused by both, and must be refused alike.
        let outcome = |r: Result<PathBuf, Error>| match r {
            Ok(p) => Ok(p),
            Err(Error::Io(e)) => Err(e.kind()),
            Err(other) => panic!("{token:?}: unexpected error {other:?}"),
        };
        let names_no_file = |p: &std::ffi::OsStr| crate::resolve::names_no_file(p, true);
        let oracle = || {
            if names_no_file(token.as_ref()) {
                return Err(std::io::ErrorKind::InvalidInput);
            }
            let full = win32_full_path(&token).map_err(|e| e.kind())?;
            if names_no_file(full.as_os_str()) {
                return Err(std::io::ErrorKind::InvalidInput);
            }
            Ok(full)
        };
        let want = oracle();
        let got = outcome(absolutise_exact_on(Path::new(&token), || Ok(cwd.clone()), real_drive).map(|c| c.path));
        assert_eq!(got, want, "{token:?}");
    }
}

fn counted<'a>(base: &str, reads: &'a Cell<u32>) -> impl FnOnce() -> Result<PathBuf, Error> + 'a {
    let base = PathBuf::from(base);
    move || {
        reads.set(reads.get() + 1);
        Ok(base)
    }
}

#[skuld::test]
fn a_relative_or_rooted_path_uses_one_read() {
    for (path, base, want) in [
        (r"sub\tool.exe", r"C:\base", r"C:\base\sub\tool.exe"),
        (r"\tool.exe", r"C:\base", r"C:\tool.exe"),
        (r"\tool.exe", r"\\srv\shr\d", r"\\srv\shr\tool.exe"),
        ("C:tool.exe", r"C:\base", r"C:\base\tool.exe"),
        ("c:tool.exe", r"C:\base", r"C:\base\tool.exe"),
        (r"C:D:\evil.exe", r"C:\base", r"C:\base\D:\evil.exe"),
        // Win32 upcases a drive unit by the Unicode table, not only ASCII.
        ("\u{e9}:tool.exe", "\u{c9}:\\dir", "\u{c9}:\\dir\\tool.exe"),
        (r"\:x.exe", r"C:\base", r"C:\:x.exe"),
    ] {
        let reads = Cell::new(0);
        let got = complete_on(Path::new(path), counted(base, &reads), no_drive).unwrap();
        assert_eq!(got.path, PathBuf::from(want), "{path:?} on {base:?}");
        assert!(got.used_cwd, "{path:?}");
        assert_eq!(reads.get(), 1, "{path:?}");
    }
}

/// Another drive's relative path takes that drive's own current directory (`=Q:`), or its root,
/// never this process's cwd. The cwd is read once, to learn the current drive, and not used.
#[skuld::test]
fn another_drives_relative_path_does_not_use_the_cwd() {
    let qcwd = tempfile::tempdir().unwrap();
    let qcwd = qcwd.path().to_str().unwrap();
    let under_qcwd = format!(r"{qcwd}\tool.exe");
    for (drive, want) in [(None, r"Q:\tool.exe"), (Some(qcwd), under_qcwd.as_str())] {
        let reads = Cell::new(0);
        let got = complete_on(Path::new("Q:tool.exe"), counted(r"D:\base", &reads), |d| {
            assert_eq!(d, "Q:");
            Ok(drive.map(OsString::from))
        })
        .unwrap();
        assert_eq!(got.path, PathBuf::from(want));
        assert!(!got.used_cwd);
        assert_eq!(reads.get(), 1, "the cwd is read once, to learn the current drive");
    }
}

#[skuld::test]
fn an_absolute_or_unc_shaped_path_reads_nothing() {
    for path in [
        r"C:\abs\tool.exe",
        "C:/abs/tool.exe",
        r"\\srv\shr\tool.exe",
        r"\\?\C:\abs\tool.exe",
        r"\\tool.exe",
        "//tool.exe",
    ] {
        let got = complete_on(
            Path::new(path),
            || panic!("{path:?} must not read the cwd"),
            |_| panic!("{path:?} must not read a drive's cwd"),
        )
        .unwrap();
        assert!(!got.used_cwd, "{path:?}");
    }
}

#[skuld::test]
fn completed_is_what_a_caller_reads() {
    let Completed { path, used_cwd } = complete_on(Path::new(r"C:\a\..\b"), || unreachable!(), no_drive).unwrap();
    assert_eq!(path, PathBuf::from(r"C:\b"));
    assert!(!used_cwd);
}

/// Any one unit is a drive: `1:tool.exe` is relative to drive `1`, never to this process's cwd.
#[skuld::test]
fn a_digit_drive_takes_that_drives_directory() {
    let reads = Cell::new(0);
    let got = complete_on(Path::new("1:tool.exe"), counted(r"C:\base", &reads), no_drive).unwrap();
    assert_eq!(got.path, PathBuf::from(r"1:\tool.exe"));
    assert!(!got.used_cwd);
}

/// `complete_on` completes a drive-relative name onto the directory its reader gives, on any drive. Which
/// value is usable is [`DriveDirs`]' rule.
#[skuld::test]
fn a_drive_directory_the_reader_gives_is_used() {
    for (dir, want) in [(r"Q:\qcwd", r"Q:\qcwd\tool.exe"), (r"Q:\", r"Q:\tool.exe")] {
        let got = complete_on(
            Path::new("Q:tool.exe"),
            || Ok(PathBuf::from(r"D:\base")),
            |_| Ok(Some(OsString::from(dir))),
        )
        .unwrap();
        assert_eq!(got.path, PathBuf::from(want), "{dir:?}");
    }
}

/// A spawn uses a drive's `=X:` value only when it is the drive's own directory by [`DriveDirs`]' rule,
/// on any drive; otherwise the drive's root, as `GetFullPathNameW` does (measured by
/// `tests/windows_path_resolution/drive_rule.rs`).
#[skuld::test]
fn only_an_existing_directory_given_as_a_drive_path_is_used() {
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().to_str().unwrap().to_owned();
    let file = dir.path().join("afile");
    std::fs::write(&file, b"x").unwrap();
    let file = file.to_str().unwrap().to_owned();
    let gone = format!(r"{existing}\gone");
    let under_existing = format!(r"{existing}\tool.exe");
    for (value, want) in [
        (existing.as_str(), under_existing.as_str()),
        (gone.as_str(), r"Q:\tool.exe"),
        (file.as_str(), r"Q:\tool.exe"),
        ("Q:rel", r"Q:\tool.exe"),
        ("rel", r"Q:\tool.exe"),
        (r"\rooted", r"Q:\tool.exe"),
    ] {
        let snapshot = snapshot_with(&format!("=Q:={value}"));
        let got = super::effective_cwd(Some(Path::new("Q:tool.exe")), &DriveDirs::new(&snapshot), || {
            Ok(PathBuf::from(r"D:\base"))
        })
        .unwrap();
        assert_eq!(got, PathBuf::from(want), "=Q:={value:?}");
    }
}

/// `=Q:` values that [`DriveDirs`] ignores although every probe finds a directory, so only the
/// spelling decides: each is one Win32 ignores (measured), where a value spelled as Win32 normalises
/// it is used.
const IGNORED_DRIVE_VALUES: &[&str] = &[
    r"\\?\Q:\qcwd",
    r"\\?\UNC\srv\shr\d",
    r"\\?\q:\qcwd",
    r"//?/Q:/qcwd",
    r"\\.\Q:\qcwd",
    r"\\srv\shr\d",
    "Q:/qcwd",
    r"Q:\qcwd/sub",
    r"Q:\qcwd\\sub",
    r"Q:\qcwd\..\qcwd",
    r"Q:\qcwd\.",
    r"Q:\qcwd.",
    "Q:\\qcwd ",
    "Q:",
    "Q:rel",
    "rel",
    r"\rooted",
    "",
];

/// `=Q:` values [`DriveDirs`] uses when its probe finds a directory.
const USED_DRIVE_VALUES: &[&str] = &[r"Q:\qcwd", r"q:\qcwd", r"Q:\qcwd\", r"Q:\PROGRA~1", r"Q:\"];

#[skuld::test]
fn a_drive_value_win32_ignores_answers_as_no_directory() {
    for value in IGNORED_DRIVE_VALUES {
        let snapshot = snapshot_with(&format!("=Q:={value}"));
        let dirs = DriveDirs::with_probe(&snapshot, |_| true);
        assert_eq!(dirs.get("Q:".as_ref()), None, "=Q:={value:?}");
    }
    for value in USED_DRIVE_VALUES {
        let snapshot = snapshot_with(&format!("=Q:={value}"));
        let dirs = DriveDirs::with_probe(&snapshot, |_| true);
        assert_eq!(dirs.get("Q:".as_ref()), Some(OsString::from(value)), "=Q:={value:?}");
    }
}

/// A value of 260 UTF-16 units or more is ignored, 259 used: Win32's own limit (measured, in a child
/// that is long-path aware too), and the value is measured before anything is asked of the filesystem.
#[skuld::test]
fn a_drive_value_of_260_units_or_more_answers_as_no_directory() {
    thread_local! {
        static PROBED: Cell<bool> = const { Cell::new(false) };
    }
    fn probe(_: &Path) -> bool {
        PROBED.with(|p| p.set(true));
        true
    }
    let of_len = |units: usize| format!(r"Q:\{}", "a".repeat(units - 3));
    for (units, fits) in [(259, true), (260, false), (261, false)] {
        let value = of_len(units);
        assert_eq!(value.encode_utf16().count(), units);
        let snapshot = snapshot_with(&format!("=Q:={value}"));
        PROBED.with(|p| p.set(false));
        let got = DriveDirs::with_probe(&snapshot, probe).get("Q:".as_ref());
        assert_eq!(got.is_some(), fits, "{units} units");
        assert_eq!(PROBED.with(Cell::get), fits, "{units} units: probed only when it fits");
    }
}

/// The drive-directory reader of one spawn, as `absolutise_exact_on` takes it.
fn drive_reader<'a>(dirs: &'a DriveDirs<'_>) -> impl FnOnce(&std::ffi::OsStr) -> Result<Option<OsString>, Error> + 'a {
    |drive| Ok(dirs.get(drive))
}

/// The exact arm and a drive-relative `current_dir` follow the same rule as the search: a value Win32
/// ignores (a verbatim one, or a forward-slash one) answers as no directory, so `Q:tool.exe` completes
/// onto the drive's root.
#[skuld::test]
fn a_drive_value_win32_ignores_sends_an_exact_name_to_the_drives_root() {
    for value in [r"\\?\Q:\qcwd", "Q:/qcwd"] {
        let snapshot = snapshot_with(&format!("=Q:={value}"));
        let dirs = DriveDirs::with_probe(&snapshot, |_| true);
        let got = absolutise_exact_on(
            Path::new("Q:tool.exe"),
            || Ok(PathBuf::from(r"D:\base")),
            drive_reader(&dirs),
        )
        .unwrap();
        assert_eq!(got.path, PathBuf::from(r"Q:\tool.exe"), "=Q:={value:?}");
    }
}

#[skuld::test]
fn a_drive_value_win32_ignores_sends_a_current_dir_to_the_drives_root() {
    for value in [r"\\?\Q:\qcwd", "Q:/qcwd"] {
        let snapshot = snapshot_with(&format!("=Q:={value}"));
        let dirs = DriveDirs::with_probe(&snapshot, |_| true);
        let got = super::effective_cwd(Some(Path::new("Q:sub")), &dirs, || Ok(PathBuf::from(r"D:\base"))).unwrap();
        assert_eq!(got, PathBuf::from(r"Q:\sub"), "=Q:={value:?}");
    }
}

/// Each drive is probed once per spawn, however many steps ask, and however they spell it.
#[skuld::test]
fn a_drive_directory_is_probed_once() {
    thread_local! {
        static PROBES: Cell<usize> = const { Cell::new(0) };
    }
    fn probe(_: &Path) -> bool {
        PROBES.with(|p| p.set(p.get() + 1));
        true
    }
    let snapshot = snapshot_with(r"=Q:=Q:\qcwd");
    let dirs = DriveDirs::with_probe(&snapshot, probe);
    for drive in ["Q:", "q:", "Q:"] {
        assert_eq!(dirs.get(drive.as_ref()), Some(OsString::from(r"Q:\qcwd")), "{drive}");
    }
    // A relative value is never probed: it would read this process's cwd.
    let relative = snapshot_with("=R:=rel");
    assert_eq!(DriveDirs::with_probe(&relative, probe).get("R:".as_ref()), None);
    assert_eq!(PROBES.with(Cell::get), 1);
}

/// Two environments naming one directory share its probe: the answer one step got is the answer the
/// other gets, even if the directory has gone since, and a directory only the second names is its own.
#[skuld::test]
fn views_over_two_environments_share_what_was_probed() {
    thread_local! {
        static ANSWERS: Cell<usize> = const { Cell::new(0) };
    }
    fn probe(_: &Path) -> bool {
        // The first probe finds a directory; any later one would not.
        ANSWERS.with(|a| a.set(a.get() + 1));
        ANSWERS.with(Cell::get) == 1
    }
    let process = snapshot_with(r"=Q:=Q:\shared");
    let child = snapshot_with(r"=Q:=Q:\shared");
    let other = snapshot_with(r"=Q:=Q:\only-the-child");
    let process_dirs = DriveDirs::with_probe(&process, probe);
    assert_eq!(process_dirs.get("Q:".as_ref()), Some(OsString::from(r"Q:\shared")));
    assert_eq!(
        process_dirs.over(&child).get("Q:".as_ref()),
        Some(OsString::from(r"Q:\shared"))
    );
    assert_eq!(process_dirs.over(&other).get("Q:".as_ref()), None);
    assert_eq!(ANSWERS.with(Cell::get), 2);
}

/// On a verbatim cwd a relative name is joined as written and `GetFullPathNameW` collapses it,
/// with Win32's floor: after `\\?\UNC\`, not after the share (measured by
/// `tests/windows_process_cwd.rs`).
#[skuld::test]
fn a_relative_name_on_a_verbatim_unc_cwd_collapses_as_win32_does() {
    let cwd = || Ok(PathBuf::from(r"\\?\UNC\srv\shr\d"));
    for (name, want) in [
        (r"..\t.exe", r"\\?\UNC\srv\shr\t.exe"),
        (r"..\..\t.exe", r"\\?\UNC\srv\t.exe"),
        (r"..\..\..\t.exe", r"\\?\UNC\t.exe"),
    ] {
        let got = complete_on(Path::new(name), cwd, no_drive).unwrap();
        assert_eq!(got.path, PathBuf::from(want), "{name:?}");
    }
    let exact = absolutise_exact_on(Path::new(r"..\t.exe"), cwd, no_drive).unwrap();
    assert_eq!(exact.path, PathBuf::from(r"\\?\UNC\srv\shr\t.exe"));
    // Past the share, Win32's completion names a share root or no share at all, so no program.
    for name in [r"..\..\t.exe", r"..\..\..\t.exe"] {
        match absolutise_exact_on(Path::new(name), cwd, no_drive) {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{name:?}: {e}"),
            Err(other) => panic!("{name:?}: expected Io, got {other:?}"),
            Ok(done) => panic!("{name:?}: must be refused, got {:?}", done.path),
        }
    }
}

/// The same on a verbatim drive cwd, whose floor is after `\\?\`, not after the drive (measured).
#[skuld::test]
fn a_relative_name_on_a_verbatim_drive_cwd_collapses_as_win32_does() {
    let got = complete_on(Path::new(r"..\..\t.exe"), || Ok(PathBuf::from(r"\\?\C:\d")), no_drive).unwrap();
    assert_eq!(got.path, PathBuf::from(r"\\?\t.exe"));
}

/// On a verbatim cwd a rooted name is refused: Win32 completes it to `\\t.exe`, off the cwd's
/// volume and share (measured by `tests/windows_process_cwd.rs`).
#[skuld::test]
fn a_rooted_name_on_a_verbatim_cwd_is_refused() {
    for cwd in [r"\\?\UNC\srv\shr\d", r"\\?\C:\d"] {
        for complete in [complete_on, absolutise_exact_on] {
            match complete(Path::new(r"\t.exe"), || Ok(PathBuf::from(cwd)), no_drive) {
                Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{cwd:?}: {e}"),
                Err(other) => panic!("{cwd:?}: expected Io, got {other:?}"),
                Ok(done) => panic!("{cwd:?}: must be refused, got {:?}", done.path),
            }
        }
    }
}

/// An empty environment snapshot: no drive has a directory of its own.
fn empty_env() -> EnvSnapshot {
    EnvSnapshot::from_block(vec![0])
}

/// The raw backend's directory is completed by the same rule, so a digit-drive process cwd keeps
/// its drive for a rooted or relative `current_dir`, and another drive takes its own directory.
#[skuld::test]
fn the_effective_cwd_completes_current_dir_as_win32_does() {
    // The cwd is read once for every shape that needs it, the drive-relative one to learn the
    // current drive, and never for a drive-absolute one.
    for (cmd_cwd, want, want_reads) in [
        (None, r"1:\x", 1),
        (Some(r"\work"), r"1:\work", 1),
        (Some("sub"), r"1:\x\sub", 1),
        (Some("D:sub"), r"D:\sub", 1),
        (Some(r"C:\abs"), r"C:\abs", 0),
    ] {
        let reads = Cell::new(0);
        let got = super::effective_cwd(
            cmd_cwd.map(Path::new),
            &DriveDirs::new(&empty_env()),
            counted(r"1:\x", &reads),
        )
        .unwrap();
        assert_eq!(got, PathBuf::from(want), "{cmd_cwd:?}");
        assert_eq!(reads.get(), want_reads, "{cmd_cwd:?}");
    }
}

/// A drive's own directory comes from the spawn's snapshot, not a second read of the environment.
#[skuld::test]
fn the_effective_cwd_reads_a_drive_directory_from_the_given_snapshot() {
    let qcwd = tempfile::tempdir().unwrap();
    let qcwd = qcwd.path().to_str().unwrap();
    let block: Vec<u16> = format!("=Q:={qcwd}\0\0").encode_utf16().collect();
    let got = super::effective_cwd(
        Some(Path::new("Q:sub")),
        &DriveDirs::new(&EnvSnapshot::from_block(block)),
        || Ok(PathBuf::from(r"D:\x")),
    )
    .unwrap();
    assert_eq!(got, PathBuf::from(format!(r"{qcwd}\sub")));
}

/// With no `current_dir`, the effective cwd is one read of this process's cwd, whatever the program.
#[skuld::test]
fn the_effective_cwd_without_a_current_dir_is_one_read() {
    let reads = Cell::new(0);
    let got = super::effective_cwd(None, &DriveDirs::new(&empty_env()), counted(r"C:\x", &reads)).unwrap();
    assert_eq!(got, PathBuf::from(r"C:\x"));
    assert_eq!(reads.get(), 1);
}

/// A `current_dir` Win32 reads as UNC with no share completes to itself, a path on no drive or
/// share, and is refused rather than handed to the resolver, whose contract it would break.
#[skuld::test]
fn the_effective_cwd_refuses_a_share_less_unc_current_dir() {
    // `\\srv\\x` is not among them: Win32 collapses the doubled separator (measured), so it names
    // the share root `\\srv\x`.
    for dir in [r"\\server", "//server", r"\\?\UNC\srv", r"\\?\UNC\", r"\\?\UNC\srv/shr"] {
        match super::effective_cwd(Some(Path::new(dir)), &DriveDirs::new(&empty_env()), || {
            panic!("{dir:?} must not read the cwd")
        }) {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{dir:?}: {e}"),
            other => panic!("{dir:?}: expected Io(InvalidInput), got {other:?}"),
        }
    }
}

/// A NUL in `current_dir` is refused as a NUL in the working directory before anything completes
/// it, which would otherwise search a truncated directory the caller never named.
#[skuld::test]
fn the_effective_cwd_refuses_a_nul_before_completing() {
    use std::os::windows::ffi::OsStringExt;
    let dir = OsString::from_wide(&"sub\0x".encode_utf16().collect::<Vec<u16>>());
    match super::effective_cwd(Some(Path::new(&dir)), &DriveDirs::new(&empty_env()), || {
        panic!("a NUL-bearing directory must not read the cwd")
    }) {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
            assert!(e.to_string().contains("working directory"), "{e}");
        }
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
}

/// A verbatim base: `./tool.exe` is found in it, not probed as a literal `.` component, which a
/// `\\?\` path passes to the filesystem unparsed.
#[skuld::test]
fn a_verbatim_current_dir_finds_a_dot_relative_name() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tool.exe"), b"x").unwrap();
    let mut verbatim = OsString::from(r"\\?\");
    verbatim.push(dir.path());
    let got = super::resolve_executable(
        Path::new("./tool.exe"),
        Some(Path::new(&verbatim)),
        &crate::resolve::no_drive_dir,
        None,
    )
    .unwrap();
    assert_eq!(got, Path::new(&verbatim).join("tool.exe"));
}

/// Every caller NUL-checks a path before completing it, naming its field; a NUL reaching
/// `GetFullPathNameW` would complete a truncated path, and the assertion catches it.
#[cfg(debug_assertions)] // the contract is a debug assertion: release has none to trigger
#[skuld::test]
#[should_panic(expected = "path to complete")]
fn a_nul_reaching_get_full_path_name_is_a_contract_violation() {
    use std::os::windows::ffi::OsStringExt;
    let p = OsString::from_wide(&"C:\\a\0b".encode_utf16().collect::<Vec<u16>>());
    _ = complete_on(Path::new(&p), || unreachable!(), no_drive);
}

/// What `GetFullPathNameW` makes of a verbatim path, as measured on both CI architectures: it
/// normalises after the `\\?\` prefix as it does anywhere else.
const VERBATIM_REWRITES: &[(&str, &str)] = &[
    (r"\\?\C:\t\a", r"\\?\C:\t\a"),
    (r"\\?\C:\t\a.", r"\\?\C:\t\a"),
    (r"\\?\C:\t\x\..\y", r"\\?\C:\t\y"),
    (r"\\?\C:\t\a ", r"\\?\C:\t\a"),
];

#[skuld::test]
fn get_full_path_name_rewrites_a_verbatim_path_as_measured() {
    for (path, want) in VERBATIM_REWRITES {
        assert_eq!(
            super::full_path_name(Path::new(path)).unwrap(),
            PathBuf::from(want),
            "{path:?}"
        );
    }
}

/// A verbatim `current_dir` is kept as written when `GetFullPathNameW` leaves it alone, and refused
/// when it would rewrite it: whatever completes the child's `lpCurrentDirectory` may rewrite it the
/// same way, and the directory resolved against must be the one run in.
#[skuld::test]
fn a_verbatim_directory_is_kept_or_refused_never_rewritten() {
    for (path, rewritten) in VERBATIM_REWRITES {
        match complete_on(Path::new(path), || panic!("must not read the cwd"), no_drive) {
            Ok(got) => {
                assert_eq!(path, rewritten, "{path:?} is rewritten, so it must be refused");
                assert_eq!(got.path, PathBuf::from(path), "{path:?}");
            }
            Err(Error::Io(e)) => {
                assert_ne!(path, rewritten, "{path:?} is not rewritten, so it must be kept: {e}");
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{path:?}: {e}");
            }
            Err(other) => panic!("{path:?}: {other:?}"),
        }
    }
}

/// The raw backend takes a verbatim `raw_executable()` token as written, as `CreateProcessW` loads
/// it: `\\?\C:\t\tool.exe.` names that file, not its sibling `tool.exe`, and `...` is a file name
/// there.
#[skuld::test]
fn a_verbatim_exact_token_is_taken_as_written() {
    for token in [r"\\?\C:\t\tool.exe.", r"\\?\C:\t\x\..\tool.exe", r"\\?\C:\t\..."] {
        let got = absolutise_exact_on(Path::new(token), || panic!("must not read the cwd"), no_drive).unwrap();
        assert_eq!(got.path, PathBuf::from(token), "{token:?}");
    }
}

/// A relative name completed against a verbatim PROCESS cwd is normalised, as Win32 completes it:
/// the `\\?\` came from the base, not the caller, so what loads and where the child runs are what
/// `CreateProcessW` would make of the name.
#[skuld::test]
fn a_relative_name_on_a_verbatim_process_cwd_is_normalised() {
    let cwd = || Ok(PathBuf::from(r"\\?\C:\d"));
    let got = absolutise_exact_on(Path::new("tool.exe."), cwd, no_drive).unwrap();
    assert_eq!(got.path, PathBuf::from(r"\\?\C:\d\tool.exe"));
    let got = super::effective_cwd(Some(Path::new("sub.")), &DriveDirs::new(&empty_env()), cwd).unwrap();
    assert_eq!(got, PathBuf::from(r"\\?\C:\d\sub"));
}
