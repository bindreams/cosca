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

/// The filename resolution will actually look for, on the HOST platform, for a logical
/// extensionless name `base` searched via `go()` (which uses `HOST_WINDOWS`, per this file's own
/// doc above). Mirrors `filename_candidates`'s single-candidate rule — `.exe` appended on Windows,
/// `base` unchanged on POSIX — so a `go()`-driven filesystem test plants the exact file resolution
/// will look for on whichever host actually runs it, including a real Windows CI runner, where a
/// bare or located `tool` now only ever resolves via `tool.exe` (see the "FIX: single-candidate
/// filename rule" tests below for the rule itself; this just keeps host-touching tests in sync
/// with it rather than re-deriving it at each call site).
fn exe_name(base: &str) -> String {
    if HOST_WINDOWS {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn go(program: &str, cwd: &Path, path: Option<&OsStr>) -> Result<std::path::PathBuf, Error> {
    resolve(ResolveInput {
        program: Path::new(program),
        cwd,
        system_dirs: &[],
        path_var: path,
        windows: HOST_WINDOWS,
    })
}

/// Join directories into a `PATH` string using the GIVEN platform's separator, independent of the
/// host — unlike [`path_var`], which uses [`std::env::join_paths`] and therefore only agrees with
/// a `windows` flag that matches the real host (see this file's `HOST_WINDOWS` doc). The
/// system-directory tests below deliberately force `windows: true`/`false` regardless of host —
/// that IS the point (system directories are a Windows-only policy, exercised from any host per
/// this module's own design) — so they need a `PATH` string built for the SIMULATED platform, not
/// the host's.
fn path_var_for(dirs: &[&Path], windows: bool) -> OsString {
    let sep = if windows { ";" } else { ":" };
    OsString::from(
        dirs.iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(sep),
    )
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

// ── FIX: single-candidate filename rule (merge blocker) ──────────────────────────────
//
// Replaces the old two-candidate rule (`tool.exe` then a `tool` fallback, gated on "does the name
// already contain a dot"). Measured on real Windows CI (amd64 and arm64): `CreateProcessW` with a
// NULL `lpApplicationName`, `cmd.exe`, `pwsh` 7, and Windows PowerShell 5.1 all refuse to run an
// extensionless PE by bare name, so the old fallback candidate never ran on any of those four
// surfaces — dropping it is a narrowing. But those same three shells (unlike `CreateProcessW`) DO
// resolve a bare DOTTED name via PATHEXT (`foo.bar` runs `foo.bar.exe`), which the old has-a-dot
// heuristic could never produce — `python3.11` could never resolve even though every shell finds
// `python3.11.exe`. So the new rule also widens for a dotted name. See `filename_candidates`'s doc
// in `src/resolve.rs` for the full rationale, including why exactly `.exe`/`.com` (not scripts).
//
// Every case below also asserts there is exactly ONE candidate: two candidates whose second one
// never matches would pass every assertion here while quietly leaving the pre-fix ordering hazard
// (an ambient extensionless file able to win in some future directory ordering) in place.

fn candidate(n: &str, w: bool) -> Vec<String> {
    filename_candidates(OsStr::new(n), w)
        .iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn bare_extensionless_name_gets_only_the_exe_candidate() {
    // Catches the extensionless fallback candidate coming back: if `tool` (unchanged) were still a
    // candidate, this would fail on the `vec!["tool"] not in the list` half of the assertion below
    // even though it currently passes on the `contains "tool.exe"` half alone.
    let got = candidate("tool", true);
    assert_eq!(got, vec!["tool.exe"], "{got:?}");
}

#[test]
fn dotted_name_without_a_loadable_extension_still_gets_exe_appended() {
    // Catches the OLD has-a-dot heuristic returning: under that rule `python3.11` (already
    // containing a dot) would have been left unchanged and never resolved, even though
    // `python3.11.exe` is exactly what every shell finds for it.
    let got = candidate("python3.11", true);
    assert_eq!(got, vec!["python3.11.exe"], "{got:?}");
}

#[test]
fn a_name_already_ending_in_exe_is_not_doubled() {
    let got = candidate("tool.exe", true);
    assert_eq!(got, vec!["tool.exe"], "{got:?}");
}

#[test]
fn the_exe_extension_check_is_case_insensitive() {
    // Catches a `== ".exe"` (exact-case) comparison: `TOOL.EXE`/`Tool.Exe` must not become
    // `TOOL.EXE.exe`/`Tool.Exe.exe`.
    assert_eq!(candidate("TOOL.EXE", true), vec!["TOOL.EXE"]);
    assert_eq!(candidate("Tool.Exe", true), vec!["Tool.Exe"]);
}

#[test]
fn a_com_extension_is_in_the_allowlist() {
    // `more.com`/`chcp.com`/`tree.com` are ordinary PEs shipped in System32 with a cosmetic `.com`
    // extension; `.com` missing from the allowlist would break resolving them.
    let got = candidate("more.com", true);
    assert_eq!(got, vec!["more.com"], "{got:?}");
}

#[test]
fn a_bat_extension_is_not_yet_in_the_allowlist() {
    // Batch resolution is a separate, not-yet-implemented feature (planned as its own follow-up),
    // not a statement that scripts are unsafe — see `filename_candidates`'s doc. Until it lands,
    // `.bat` is treated like any other non-`.exe`/`.com` dotted name: `.exe` is appended, which
    // will simply miss.
    let got = candidate("tool.bat", true);
    assert_eq!(got, vec!["tool.bat.exe"], "{got:?}");
}

#[test]
fn a_located_name_gets_the_exe_rule_too() {
    // Extension handling and PATH search are independent axes: a pathed name (containing a
    // separator, so `Shape::Located`) still gets exactly the same exe-appending rule as a bare
    // name. Catches a regression that scoped the rule to `Shape::BareName` only.
    let got = candidate("bin/my-program", true);
    assert_eq!(got, vec!["bin/my-program.exe"], "{got:?}");
}

#[test]
fn posix_never_appends_exe_for_any_of_the_above() {
    for n in [
        "tool",
        "python3.11",
        "tool.exe",
        "TOOL.EXE",
        "more.com",
        "tool.bat",
        "bin/my-program",
    ] {
        let got = candidate(n, false);
        assert_eq!(
            got,
            vec![n.to_string()],
            "POSIX must never append .exe: {n:?} -> {got:?}"
        );
    }
}

#[test]
fn every_case_produces_exactly_one_candidate() {
    for (n, w) in [
        ("tool", true),
        ("python3.11", true),
        ("tool.exe", true),
        ("TOOL.EXE", true),
        ("more.com", true),
        ("tool.bat", true),
        ("bin/my-program", true),
        ("tool", false),
        ("python3.11", false),
    ] {
        let got = filename_candidates(OsStr::new(n), w);
        assert_eq!(got.len(), 1, "{n:?} (windows={w}) -> {got:?}");
    }
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
    let want = touch(bin.path(), &exe_name("tool"));
    let p = path_var(&[bin.path()]);
    assert_eq!(go("tool", cwd.path(), Some(&p)).unwrap(), want);
}

#[test]
fn path_wins_over_an_identically_named_file_in_cwd() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    touch(cwd.path(), &exe_name("tool"));
    let want = touch(bin.path(), &exe_name("tool"));
    let p = path_var(&[bin.path()]);
    assert_eq!(go("tool", cwd.path(), Some(&p)).unwrap(), want);
}

#[test]
fn a_name_with_a_separator_resolves_against_cwd() {
    let cwd = tempfile::tempdir().unwrap();
    // Located (contains a separator) gets the SAME single-candidate exe rule as a bare name — see
    // the "FIX: single-candidate filename rule" tests below for why that is deliberate, not an
    // oversight.
    let want = touch(cwd.path(), &exe_name("tool"));
    let got = go("./tool", cwd.path(), None).unwrap();
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

#[test]
fn empty_path_elements_are_skipped() {
    let cwd = tempfile::tempdir().unwrap();
    touch(cwd.path(), &exe_name("tool"));
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), &exe_name("tool"));
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
    touch(cwd.path(), &exe_name("tool"));
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), &exe_name("tool"));
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
fn only_the_exe_file_is_ever_tried_even_alongside_an_extensionless_namesake() {
    // Renamed from `exe_suffix_is_preferred_over_an_extensionless_file`: under the old two-
    // candidate rule this was a preference between two matches in the same directory. Under the
    // single-candidate rule there is only ever one filename tried (`tool.exe`), so an extensionless
    // `tool` sitting right next to it is never even looked at — this end-to-end (real filesystem)
    // test still passes, but for a different reason than its old name claimed.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), "tool"); // must be ignored entirely, not merely lose a preference
    let want = touch(bin.path(), "tool.exe");
    let p = path_var(&[bin.path()]);
    assert_eq!(go("tool", cwd.path(), Some(&p)).unwrap(), want);
}

#[cfg(windows)]
#[test]
fn an_extensionless_file_no_longer_resolves_even_with_no_exe_on_path() {
    // INVERTED from the pre-fix behaviour (renamed from
    // `an_extensionless_file_still_resolves_when_no_exe_exists`, which asserted the opposite):
    // the extensionless fallback candidate is gone, so a bare `tool` with only an extensionless
    // `tool` file on PATH — no `tool.exe` anywhere — must now fail to resolve, matching
    // `CreateProcessW`/`cmd.exe`/`pwsh`/`powershell.exe`, all of which refuse to run it (measured
    // on real Windows CI). Catches the old two-candidate rule coming back.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), "tool");
    let p = path_var(&[bin.path()]);
    let got = go("tool", cwd.path(), Some(&p));
    assert!(got.is_err(), "{got:?}");
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
    // `tool.exe`, not extensionless `tool`: the single-candidate rule (see the "FIX: single-
    // candidate filename rule" tests above) means a bare `tool` only ever looks for `tool.exe` on
    // Windows now, so this quoting test must plant the file it can actually find.
    let want = touch(&semi_dir, "tool.exe");
    let quoted = OsString::from(format!("\"{}\"", semi_dir.display()));
    assert_eq!(go("tool", cwd.path(), Some(&quoted)).unwrap(), want);
}

// ── the contract every backend depends on ────────────────────────────────────────────

#[test]
fn result_is_always_absolute() {
    let cwd = tempfile::tempdir().unwrap();
    touch(cwd.path(), &exe_name("tool"));
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
    let want = touch(&sub, &exe_name("tool"));
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

// ── FIX: Windows system directories precede PATH for a bare name (merge blocker) ────────
//
// The maintainer's rule for landing a stacked PR one squashed commit at a time is that no commit
// may make any route WORSE than it was on `main`, even while a LATER commit narrows a different
// vulnerability on that same route. Before this crate resolved anything, a `Command` routed to the
// raw backend purely by `fd >= 3` (no `executable()` set) passed a NULL `lpApplicationName`, so
// `CreateProcessW` ran its OWN documented search order: app dir -> parent cwd -> System32 ->
// Windows dir -> PATH. This crate's fix to stop searching the parent cwd (a binary-planting
// hazard: a fd-mapped decoy planted in a tempdir cwd must not be picked up — see
// `bare_name_is_not_resolved_from_the_current_directory` above) is a strict narrowing of that
// order. But the NAIVE way to implement "stop searching the cwd" is "search PATH only" — which
// ALSO drops system-directory precedence, a change nobody asked for and a strict WIDENING on this
// route: a user-writable directory placed early on PATH (a dev toolchain install, an
// `%LOCALAPPDATA%\...\WindowsApps` shim) would then shadow e.g. `System32\find.exe`, a new way to
// get the wrong binary that did not exist even in the pre-patch code. These four tests exercise
// `ResolveInput::system_dirs` directly with `windows` forced explicitly true/false — never
// `HOST_WINDOWS` — because the policy under test is Windows-only by definition and this module is
// deliberately built to be exercised from any host; forcing the flag (rather than relying on the
// host actually being Windows) is what makes these tests run in ordinary CI, not just the Windows
// runner.

#[test]
fn bare_name_in_a_system_dir_and_on_path_resolves_from_the_system_dir() {
    // THE regression gate. If system-directory precedence over PATH is ever silently dropped
    // again (e.g. by a future edit that forgets to prepend `system_dirs` before `split_path_var`,
    // or that gates it on the wrong condition), this test starts finding the PATH decoy instead of
    // the system-dir file, and fails. That is the entire point of this test's existence: pin the
    // ordering, not just that resolution succeeds.
    let cwd = tempfile::tempdir().unwrap();
    let sysdir = tempfile::tempdir().unwrap();
    let pathdir = tempfile::tempdir().unwrap();
    // `tool.exe`, not extensionless `tool`: forced `windows: true` below means resolution only
    // ever looks for `tool.exe` (the single-candidate rule — see the "FIX: single-candidate
    // filename rule" tests above), so an extensionless file here would never be found by either
    // side and `resolve(...).unwrap()` would panic on `NotFound` instead of exercising the
    // ordering this test exists to pin.
    let want = touch(sysdir.path(), "tool.exe");
    touch(pathdir.path(), "tool.exe"); // PATH decoy: same name, must lose to the system dir.
    let system_dirs = [sysdir.path().to_path_buf()];
    let path = path_var_for(&[pathdir.path()], true);
    let got = resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: cwd.path(),
        system_dirs: &system_dirs,
        path_var: Some(&path),
        windows: true,
    })
    .unwrap();
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

#[test]
fn bare_name_only_on_path_still_resolves_from_path() {
    // Adding a search step ahead of PATH must not turn into REPLACING PATH: a name that exists
    // only on PATH, with real (non-matching) system dirs present, must still resolve — otherwise
    // this "fix" would trade the widening it closes for a new, opposite regression: real commands
    // installed only via PATH (which is most of them) breaking outright.
    let cwd = tempfile::tempdir().unwrap();
    let sysdir = tempfile::tempdir().unwrap(); // present, but has nothing named "tool.exe"
    let pathdir = tempfile::tempdir().unwrap();
    let want = touch(pathdir.path(), "tool.exe"); // forced windows: true below -> only "tool.exe" is tried
    let system_dirs = [sysdir.path().to_path_buf()];
    let path = path_var_for(&[pathdir.path()], true);
    let got = resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: cwd.path(),
        system_dirs: &system_dirs,
        path_var: Some(&path),
        windows: true,
    })
    .unwrap();
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

#[test]
fn empty_system_dirs_reproduces_the_pre_fix_path_only_search() {
    // Every test in this file predating this fix calls `go()`, which passes `system_dirs: &[]`
    // (see `go`'s definition above). That is only a safe default if an empty slice is truly a
    // no-op — otherwise those tests would have silently stopped meaning what their own doc
    // comments say the day this field was added, without a single one of them failing to notice.
    // This test pins the no-op directly: positive control resolves via PATH exactly as
    // `bare_name_resolves_from_path` above expects, and the negative control (nothing anywhere)
    // still fails closed exactly as `bare_name_is_not_resolved_from_the_current_directory` expects.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let want = touch(bin.path(), "tool.exe"); // forced windows: true below -> only "tool.exe" is tried
    let path = path_var_for(&[bin.path()], true);
    let got = resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: cwd.path(),
        system_dirs: &[],
        path_var: Some(&path),
        windows: true,
    })
    .unwrap();
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());

    // Negative control: nothing on PATH and an empty system_dirs must still fail closed, not
    // silently succeed by, say, treating an empty slice as "search the cwd instead".
    let miss = resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: cwd.path(),
        system_dirs: &[],
        path_var: None,
        windows: true,
    });
    assert!(miss.is_err(), "{miss:?}");
}

#[test]
fn posix_ignores_system_dirs_entirely() {
    // `system_dirs` exists to reproduce a WINDOWS-only search order (`CreateProcessW`'s
    // NULL-`lpApplicationName` rule) — POSIX's own `execvp`/`posix_spawn` PATH search has no
    // system-directory step at all, so consulting `system_dirs` off Windows would fabricate a
    // search step POSIX resolution never had, which is a widening with no upstream justification
    // (and directly contradicts this module's own POSIX-coverage doc). Gating on `input.windows`
    // itself — rather than trusting every POSIX caller to always pass an empty slice — is what
    // makes that impossible even if a future POSIX caller passes a non-empty `system_dirs` by
    // mistake. The system dir here genuinely contains a matching, executable file: if the guard
    // were ever weakened to "non-empty implies consult it", this test starts passing where it
    // should keep failing, and that flip is exactly what it exists to catch.
    let cwd = tempfile::tempdir().unwrap();
    let sysdir = tempfile::tempdir().unwrap();
    touch(sysdir.path(), "tool");
    let system_dirs = [sysdir.path().to_path_buf()];
    let got = resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: cwd.path(),
        system_dirs: &system_dirs,
        path_var: None,
        windows: false,
    });
    assert!(got.is_err(), "{got:?}");
}
