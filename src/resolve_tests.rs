use super::*;
use std::ffi::OsString;
use std::path::Path;

/// The host's own platform. Any test that touches the filesystem MUST use this rather than a
/// simulated flag: a simulated platform and real paths cannot agree. Simulating POSIX on Windows
/// splits `C:\\Users\\...` on its own drive colon, so every candidate is shredded and the test
/// either fails or — worse — passes vacuously. (Simulating Windows on POSIX happens to work only
/// because POSIX paths contain no `;`, which is luck, not a property to rely on.)
const HOST_WINDOWS: bool = cfg!(windows);

/// A `PATH` value in the HOST's syntax, for filesystem tests.
fn path_var(dirs: &[&Path]) -> OsString {
    std::env::join_paths(dirs).unwrap()
}

fn touch(dir: &Path, name: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, b"x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

fn go(program: &str, cwd: &Path, path: Option<&OsStr>) -> Result<std::path::PathBuf, Error> {
    resolve(ResolveInput {
        program: Path::new(program),
        cwd,
        path_var: path,
        windows: HOST_WINDOWS,
    })
}

// ── pure logic: safe to simulate either platform, since nothing touches the filesystem ──

#[test]
fn path_var_is_split_on_the_simulated_platforms_separator() {
    let win = split_path_var(Some(OsStr::new(r"C:\a;C:\b")), true);
    assert_eq!(win.len(), 2, "{win:?}");
    let nix = split_path_var(Some(OsStr::new("/a:/b")), false);
    assert_eq!(nix.len(), 2, "{nix:?}");
    // The cross case is exactly what broke the filesystem tests on Windows.
    let shredded = split_path_var(Some(OsStr::new(r"C:\a")), false);
    assert_eq!(
        shredded.len(),
        2,
        "a Windows path split POSIX-style is shredded: {shredded:?}"
    );
}

// ── N1: quoted PATH elements ─────────────────────────────────────────────────────────

#[test]
fn windows_path_var_quoting_protects_an_embedded_separator() {
    // A Windows PATH element may be wrapped in `"` so a directory containing a literal `;`
    // survives as ONE element rather than being torn in half by a naive byte-level `;` split.
    let got = split_path_var(Some(OsStr::new(r#""C:\a;b";C:\c"#)), true);
    assert_eq!(got, vec![PathBuf::from(r"C:\a;b"), PathBuf::from(r"C:\c")], "{got:?}");
}

#[test]
fn windows_path_var_quoting_strips_the_wrapping_quotes() {
    // A quoted-but-unstripped element (`"C:\bin"`, quote characters retained) fails the
    // `joined.is_absolute()` check inside `resolve()`'s search loop — a leading `"` is not a
    // recognised drive prefix — and is therefore SILENTLY DROPPED rather than erroring. That is
    // NOT a pre-existing hole this PR closes: the pre-PR splitter was `std::env::split_paths`,
    // which was already quote-aware, so quote-stripping was never missing before this PR
    // introduced its own hand-rolled `split_path_var_windows`. The hole (and its close) are both
    // internal to this PR's own splitter — this test pins that the stripping this splitter itself
    // needs is present. `is_absolute()` is host-specific (see this file's HOST_WINDOWS note), so
    // that half of the claim is proven separately, end to end, by
    // `a_quoted_path_entry_with_an_embedded_semicolon_is_not_silently_dropped` on a real Windows
    // host; this test pins only the quote-stripping itself, which is pure byte logic.
    let got = split_path_var(Some(OsStr::new(r#""C:\bin""#)), true);
    assert_eq!(got, vec![PathBuf::from(r"C:\bin")], "{got:?}");
}

#[test]
fn posix_path_var_quotes_are_not_special() {
    // On POSIX, `"` is an ordinary filename character and `;` is not a PATH separator: quoting
    // must NOT be applied there. Only `:` splits, and any quote characters in an element are
    // preserved literally (they are part of the path, not delimiters).
    let got = split_path_var(Some(OsStr::new(r#""/a;b":/c"#)), false);
    assert_eq!(got, vec![PathBuf::from(r#""/a;b""#), PathBuf::from("/c")], "{got:?}");
}

#[test]
fn exe_is_appended_only_on_windows_and_only_without_an_extension() {
    let names = |n, w| {
        filename_candidates(OsStr::new(n), w)
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names("tool", true),
        vec!["tool.exe", "tool"],
        "exe first, bare as a fallback"
    );
    assert_eq!(
        names("tool.bin", true),
        vec!["tool.bin"],
        "an extension is taken as given"
    );
    assert_eq!(names("tool", false), vec!["tool"], "no .exe rule off Windows");
}

// ── shape classification ─────────────────────────────────────────────────────────────

#[test]
fn a_drive_relative_name_is_located_not_bare() {
    // `C:tool` has no separator, so a naive rule calls it a bare name and searches PATH — but
    // joining a PATH directory onto it collapses back to `C:tool`, which resolves through drive
    // C's current directory. It must never reach the PATH search.
    assert_eq!(classify(OsStr::new("C:tool"), true), Shape::Located);
    assert_eq!(classify(OsStr::new("tool"), true), Shape::BareName);
    assert_eq!(classify(OsStr::new(r"dir\tool"), true), Shape::Located);
    assert_eq!(classify(OsStr::new("dir/tool"), true), Shape::Located);
    // Off Windows a backslash is an ordinary character and there are no drive prefixes.
    assert_eq!(classify(OsStr::new(r"dir\tool"), false), Shape::BareName);
    assert_eq!(classify(OsStr::new("dir/tool"), false), Shape::Located);
}

// ── the current directory is not searched ────────────────────────────────────────────

#[test]
fn bare_name_is_not_resolved_from_the_current_directory() {
    let cwd = tempfile::tempdir().unwrap();
    touch(cwd.path(), "tool");
    assert!(go("tool", cwd.path(), None).is_err(), "cwd must not be searched");
}

#[test]
fn bare_name_resolves_from_path() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let want = touch(bin.path(), "tool");
    let p = path_var(&[bin.path()]);
    assert_eq!(go("tool", cwd.path(), Some(&p)).unwrap(), want);
}

#[test]
fn path_wins_over_an_identically_named_file_in_cwd() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    touch(cwd.path(), "tool");
    let want = touch(bin.path(), "tool");
    let p = path_var(&[bin.path()]);
    assert_eq!(go("tool", cwd.path(), Some(&p)).unwrap(), want);
}

#[test]
fn a_name_with_a_separator_resolves_against_cwd() {
    let cwd = tempfile::tempdir().unwrap();
    let want = touch(cwd.path(), "tool");
    let got = go("./tool", cwd.path(), None).unwrap();
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

#[test]
fn empty_path_elements_are_skipped() {
    let cwd = tempfile::tempdir().unwrap();
    touch(cwd.path(), "tool");
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), "tool");
    // Positive control: the same lookup DOES succeed with a real element, so the assertion below
    // cannot pass merely because the PATH string was malformed for this host.
    assert!(go("tool", cwd.path(), Some(&path_var(&[bin.path()]))).is_ok());
    // An empty element means "the current directory" — resolving through it would reopen the
    // binary-planting hole `resolve()`'s doc on the current directory exists to close. This is
    // guarded by `resolve()`'s single `joined.is_absolute()` check (an empty `PATH` element joins
    // to a relative path), not by a dedicated filter over `PATH` elements themselves.
    let empty = if HOST_WINDOWS { ";;" } else { "::" };
    assert!(go("tool", cwd.path(), Some(OsStr::new(empty))).is_err());
}

#[test]
fn relative_path_elements_are_skipped() {
    let cwd = tempfile::tempdir().unwrap();
    touch(cwd.path(), "tool");
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), "tool");
    assert!(
        go("tool", cwd.path(), Some(&path_var(&[bin.path()]))).is_ok(),
        "positive control"
    );
    // `.` resolves against the process cwd just as surely as an empty element does — and is
    // rejected by the same `joined.is_absolute()` check `empty_path_elements_are_skipped`
    // exercises above, not a distinct code path.
    assert!(go("tool", cwd.path(), Some(OsStr::new("."))).is_err());
}

// ── the Windows .exe rule ────────────────────────────────────────────────────────────

#[cfg(windows)]
#[test]
fn exe_suffix_is_preferred_over_an_extensionless_file() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), "tool"); // a script, or anything Win32 cannot load
    let want = touch(bin.path(), "tool.exe");
    let p = path_var(&[bin.path()]);
    assert_eq!(go("tool", cwd.path(), Some(&p)).unwrap(), want);
}

#[cfg(windows)]
#[test]
fn an_extensionless_file_still_resolves_when_no_exe_exists() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let want = touch(bin.path(), "tool");
    let p = path_var(&[bin.path()]);
    assert_eq!(go("tool", cwd.path(), Some(&p)).unwrap(), want);
}

#[cfg(windows)]
#[test]
fn a_quoted_path_entry_with_an_embedded_semicolon_is_not_silently_dropped() {
    // N1, end to end: before quote handling, an unquoted split shredded `sub;dir` at the `;`,
    // and even a quoted-but-unstripped entry failed `is_absolute()` and vanished with no error —
    // a PATH entry that disappears rather than erroring. A real executable, reachable only
    // through a quoted entry naming a directory that itself contains a literal `;`, must resolve.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let semi_dir = bin.path().join("sub;dir");
    std::fs::create_dir(&semi_dir).unwrap();
    let want = touch(&semi_dir, "tool");
    let quoted = OsString::from(format!("\"{}\"", semi_dir.display()));
    assert_eq!(go("tool", cwd.path(), Some(&quoted)).unwrap(), want);
}

// ── the contract every backend depends on ────────────────────────────────────────────

#[test]
fn result_is_always_absolute() {
    let cwd = tempfile::tempdir().unwrap();
    touch(cwd.path(), "tool");
    let got = go("./tool", cwd.path(), None).unwrap();
    assert!(
        got.is_absolute(),
        "backends skip their own search only if this is absolute: {got:?}"
    );
}

// ── the execute bit, and the cwd ─────────────────────────────────────────────────────

#[cfg(unix)]
#[test]
fn a_readable_but_non_executable_match_is_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let cwd = tempfile::tempdir().unwrap();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let dud = touch(a.path(), "tool");
    std::fs::set_permissions(&dud, std::fs::Permissions::from_mode(0o644)).unwrap();
    let want = touch(b.path(), "tool");
    std::fs::set_permissions(&want, std::fs::Permissions::from_mode(0o755)).unwrap();
    let p = path_var(&[a.path(), b.path()]);
    // execvp skips the non-executable match and keeps searching; keying on existence alone
    // would return `a/tool` and hand it to exec as EACCES.
    assert_eq!(go("tool", cwd.path(), Some(&p)).unwrap(), want);
}

#[test]
fn a_relative_cwd_is_absolutised_so_it_cannot_be_applied_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let sub = tmp.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let want = touch(&sub, "tool");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&want, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // `resolve()` absolutises a relative `cwd` via `std::env::current_dir()` (see resolve.rs's
    // own "applied twice" note) — there is no way to exercise that fallback without actually
    // mutating the process cwd. `spawn_lock()` is NOT a general cwd lock — it is the lock every
    // spawn's OS call itself serializes on, taken well after program resolution runs (resolution
    // reads `std::env::current_dir()` before that lock is ever acquired; see
    // `child::spawn::windows_raw::resolve::resolve_executable`'s doc). Holding it here still
    // serializes this mutation against every OTHER test in this binary that also pairs
    // `spawn_lock()` with `crate::test_child::RestoreCwd` for its own cwd mutation (the shared
    // convention every such test in this crate follows), which is the only cwd race this test
    // needs to avoid. `RestoreCwd` is declared AFTER the lock guard, so it drops — and un-does the
    // mutation — BEFORE the lock releases, even if an assertion below panics.
    let _guard = crate::child::spawn::spawn_lock();
    let _restore = crate::test_child::RestoreCwd::capture();
    std::env::set_current_dir(tmp.path()).unwrap();
    let got = go("./tool", Path::new("sub"), None).unwrap();
    assert!(got.is_absolute(), "{got:?}");
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

#[cfg(windows)]
#[test]
fn a_drive_relative_name_fails_closed() {
    let cwd = tempfile::tempdir().unwrap();
    // Resolving it correctly needs drive C's own current directory, which cosca does not track.
    assert!(go("C:tool", cwd.path(), None).is_err());
}
