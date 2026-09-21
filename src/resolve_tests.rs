use super::*;
use std::ffi::OsString;
use std::path::Path;

/// The host's own platform.
///
/// The rule this encodes is DIRECTIONAL, not symmetric. Simulating POSIX on Windows is never safe
/// for a filesystem test: `C:\\Users\\...` is split on its own drive colon, so every candidate is
/// shredded and the test either fails or — worse — passes vacuously. Any filesystem test that
/// could run POSIX-simulated must therefore use this flag.
///
/// Simulating WINDOWS on a POSIX host is the carve-out, and several filesystem tests below take
/// it deliberately (`go_win`/`go_win_path`, plus the system-directory block). It works because a
/// POSIX tempdir path contains no `;` and no drive prefix, so `;`-splitting is a no-op and
/// `is_absolute()` agrees with the host — the Windows rules then apply to paths they cannot
/// mangle. That is a property of the paths these tests construct, not a general licence: a
/// `windows: true` filesystem test that used a path containing `;` would be back in the shredding
/// case. The carve-out exists because the alternative is worse — the located candidate order, the
/// `PATH` quoting rule and the system-directory precedence would otherwise be gated only on the
/// Windows runner.
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

/// A filename resolution is guaranteed to look for on the HOST platform, for a logical
/// extensionless name `base` searched via `go()` (which uses `HOST_WINDOWS`, per this file's own
/// doc above) — `.exe` appended on Windows, `base` unchanged on POSIX. Planting this keeps a
/// `go()`-driven filesystem test working on whichever host actually runs it, including a real
/// Windows CI runner, rather than re-deriving the rule at each call site.
///
/// `.exe` is the candidate a BARE name resolves through, and it is also the second candidate a
/// LOCATED name falls back to, so planting it is correct for either shape (see the "filename
/// candidate rule" tests below). Tests that care about the located axis specifically — that the
/// exact name is tried, and tried FIRST — force `windows: true` via `go_win`/`go_win_path` and
/// plant real filenames, so they gate in ordinary CI rather than only on the Windows runner.
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

// ── the filename candidate rule ──────────────────────────────────────────────────────
//
// `.exe` belongs to names that get SEARCHED, not to files that get LOADED, so the rule differs by
// shape. Replaces an old rule gated on "does the name already contain a dot".
//
// SEARCHED (bare): one candidate, `tool.exe`. Measured on real Windows CI (amd64 and arm64):
// `CreateProcessW` with a NULL `lpApplicationName`, `cmd.exe`, `pwsh` 7, and Windows PowerShell
// 5.1 all refuse to run an extensionless PE by bare name, so an extensionless fallback candidate
// never ran on any of those four surfaces — omitting it is a narrowing. `PATHEXT` has no entry
// meaning "try the bare name", so there is nothing to be compatible with either. Those same three
// shells (unlike `CreateProcessW`) DO resolve a bare DOTTED name via PATHEXT (`foo.bar` runs
// `foo.bar.exe`), which the old has-a-dot heuristic could never produce — `python3.11` could never
// resolve even though every shell finds `python3.11.exe`. So the rule also widens for a dotted
// bare name.
//
// LOADED (located): the exact name FIRST, always. The PE format makes no extension normative and
// `CreateProcessW` documents "no default extension is assumed" for the `lpApplicationName` this
// resolver feeds, so a file the caller named by path must stay nameable. A second `.exe` candidate
// follows ONLY when the name has no extension at all, keeping `executable("bin/my-program")`
// portable while leaving a dotted name (`thing.bin`) with exactly one candidate — which is what
// `main` did, and what keeps this axis a no-op rather than a widening.
//
// See `filename_candidates`'s doc in `src/resolve.rs` for the full rationale, including why
// exactly `.exe`/`.com` (not scripts).
//
// A BARE name asserts there is exactly ONE candidate: a second, never-matching candidate would
// pass every assertion here while quietly leaving the pre-fix ordering hazard (an ambient
// extensionless file able to win in some future directory ordering) in place. A LOCATED name may have
// two, but only when it carries no extension and names a file — see `takes_the_exe_fallback`.

fn candidate(n: &str, w: bool) -> Vec<String> {
    filename_candidates(OsStr::new(n), w, classify(OsStr::new(n), w))
        .iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn bare_extensionless_name_gets_only_the_exe_candidate() {
    // Catches the extensionless fallback candidate coming back: under the old two-candidate rule
    // this would have been `vec!["tool.exe", "tool"]`, which this exact-equality `assert_eq!`
    // against the single-element `vec!["tool.exe"]` rejects just as surely as a candidate list of
    // `vec!["tool"]` alone would be.
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
fn a_located_name_tries_the_exact_name_before_the_exe_one() {
    // The `.exe` convention belongs to names that get SEARCHED, not to files that get LOADED:
    // the PE/COFF format makes no extension normative, and `CreateProcessW` documents
    // "no default extension is assumed" for the `lpApplicationName` this resolver feeds. So a
    // pathed name keeps naming the file the caller wrote — exact FIRST — while still appending
    // `.exe` as a fallback so `executable("bin/my-program")` stays portable across platforms.
    //
    // Catches both regressions: dropping the exact candidate (which made an extensionless or
    // `.bin` PE unnameable, the `main` -> this-branch regression) and dropping the `.exe` one
    // (which would break the cross-platform ergonomic the rule exists for).
    let got = candidate("bin/my-program", true);
    assert_eq!(got, vec!["bin/my-program", "bin/my-program.exe"], "{got:?}");
}

#[test]
fn a_located_dotted_name_gets_only_the_exact_candidate() {
    // `.bin` is not a LOADABLE extension, but it IS an extension — and `main` keyed its `.exe`
    // fallback on `Path::extension().is_none()`. Appending here would let
    // `executable(r"tools\thing.bin")` resolve to `thing.bin.exe` when `thing.bin` is absent,
    // which `main` refused: a widening on the located axis, and one a writer of that directory
    // could exploit. One candidate, the name as written.
    let got = candidate(r"tools\thing.bin", true);
    assert_eq!(got, vec![r"tools\thing.bin"], "{got:?}");
}

#[test]
fn a_located_name_with_only_a_leading_dot_still_gets_the_exe_fallback() {
    // `Path::extension()` treats a leading dot as part of the stem, not an extension separator,
    // so `.helper` has NO extension and keeps the portable `.exe` fallback. Pinned because
    // `has_any_extension` reimplements that rule byte-wise and could easily get it backwards.
    let got = candidate(r"bin\.helper", true);
    assert_eq!(got, vec![r"bin\.helper", r"bin\.helper.exe"], "{got:?}");
}

#[test]
fn a_located_name_already_ending_in_exe_or_com_gets_one_candidate() {
    // Nothing to append: appending would only ever produce `x.exe.exe`, which names a file the
    // caller did not write. One candidate, same as the bare case.
    for n in [r"bin\tool.exe", r"bin\TOOL.EXE", r"bin\more.com"] {
        let got = candidate(n, true);
        assert_eq!(got.len(), 1, "{n:?} -> {got:?}");
        assert_eq!(got[0], n, "{got:?}");
    }
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
fn every_searched_name_produces_exactly_one_candidate() {
    // BARE names only — the ones that visit `system_dirs`/`PATH`. A second candidate here would
    // reintroduce the ordering hazard: an ambient extensionless file winning in some directory
    // the search visits. A LOCATED name visits exactly one directory, the one the caller named,
    // so it carries no such hazard and may have a second candidate (tested above).
    for (n, w) in [
        ("tool", true),
        ("python3.11", true),
        ("tool.exe", true),
        ("TOOL.EXE", true),
        ("more.com", true),
        ("tool.bat", true),
        ("tool", false),
        ("python3.11", false),
    ] {
        let got = filename_candidates(OsStr::new(n), w, classify(OsStr::new(n), w));
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
    // A drive prefix is a WINDOWS notion: off Windows `C:tool` is an ordinary one-component
    // filename, and calling it located would stop it being searched for on `PATH` at all.
    assert_eq!(classify(OsStr::new("C:tool"), false), Shape::BareName);
    // And it takes a drive LETTER: `1:tool` has none, so it is bare on either platform.
    assert_eq!(classify(OsStr::new("1:tool"), true), Shape::BareName);
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
    // `&exe_name("tool")`, not literal `"tool"`: on a Windows host the candidate this resolution
    // actually looks for is `tool.exe` (see the "filename candidate rule" tests above).
    // Planting extensionless `tool` here made this vacuous on the one platform this test exists
    // for — re-adding `cwd` to `Shape::BareName`'s dir list would still find nothing named
    // `tool.exe` and this would keep passing for the wrong reason.
    touch(cwd.path(), &exe_name("tool"));
    // A miss, not a refusal: the name is fine, the cwd is simply not a place this searches.
    assert_not_found("tool", go("tool", cwd.path(), None));
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
    // Located (contains a separator) tries the exact name first and `.exe` second, so planting
    // either one resolves; `exe_name` plants whichever the HOST would find first.
    let want = touch(cwd.path(), &exe_name("tool"));
    let got = go("./tool", cwd.path(), None).unwrap();
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

/// Drive `resolve` with the WINDOWS rules regardless of host, so rules that only ship on Windows
/// are still gated in ordinary CI rather than only on the Windows runner.
///
/// Nothing here touches a Windows API: `is_execable` reduces to `is_file()` when `windows` is
/// true, and the `PATH` splitting that the bare-name callers exercise is pure byte logic over
/// tempdir paths that contain no `;`. See `HOST_WINDOWS` for why simulating Windows on POSIX is
/// safe here while the reverse never is.
fn go_win_path(program: &str, cwd: &Path, path: Option<&OsStr>) -> Result<std::path::PathBuf, Error> {
    resolve(ResolveInput {
        program: Path::new(program),
        cwd,
        system_dirs: &[],
        path_var: path,
        windows: true,
    })
}

fn go_win(program: &str, cwd: &Path) -> Result<std::path::PathBuf, Error> {
    go_win_path(program, cwd, None)
}

#[test]
fn a_located_extensionless_image_resolves_on_windows() {
    // THE REGRESSION GATE. `main` returned an existing absolute/pathed file verbatim; extending
    // the bare-name rule to the located axis briefly made `executable(r"C:\tools\myapp")` a hard
    // `NotFound` for any image not named `.exe`/`.com`. Neither `CreateProcessW` mode does that —
    // the command-line mode
    // documents "if the file name contains a path, .exe is not appended", and `lpApplicationName`
    // (what this resolver actually feeds) documents "no default extension is assumed".
    let cwd = tempfile::tempdir().unwrap();
    let want = touch(cwd.path(), "myapp");
    let got = go_win("./myapp", cwd.path()).expect("an extensionless pathed image must resolve");
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

#[test]
fn a_located_image_with_an_unrelated_extension_resolves_on_windows() {
    // Same gate, for the `.bin`/`.dat`/staged-payload shape: the PE/COFF format makes no
    // extension normative, so cosca must not invent one for a file the caller named by path.
    let cwd = tempfile::tempdir().unwrap();
    let want = touch(cwd.path(), "thing.bin");
    let got = go_win("./thing.bin", cwd.path()).expect("a .bin image must resolve");
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

#[test]
fn a_located_name_prefers_the_exact_file_over_the_exe_one() {
    // Candidate ORDER, pinned: with both `myapp` and `myapp.exe` present, the exact name the
    // caller wrote wins. This is `main`'s ordering, kept deliberately — "you named this file"
    // is the whole point of the located axis. Flipping the two candidates fails here.
    let cwd = tempfile::tempdir().unwrap();
    let want = touch(cwd.path(), "myapp");
    touch(cwd.path(), "myapp.exe");
    let got = go_win("./myapp", cwd.path()).unwrap();
    assert_eq!(got.canonicalize().unwrap(), want.canonicalize().unwrap());
}

#[test]
fn a_located_name_still_falls_back_to_exe_when_only_that_exists() {
    // The cross-platform ergonomic the `.exe` rule exists for: `executable("bin/my-program")`
    // written once must find `my-program.exe` on Windows without the caller appending it. Losing
    // the second candidate fails here, so neither candidate can be dropped without a red test.
    let cwd = tempfile::tempdir().unwrap();
    let want = touch(cwd.path(), "my-program.exe");
    let got = go_win("./my-program", cwd.path()).unwrap();
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
    // guarded by `resolve()`'s single `joined.is_absolute()` check: an empty `PATH` element joins
    // to a RELATIVE path (`Shape::BareName` never puts `cwd` itself in `dirs`), which `is_execable`
    // would then stat against the PROCESS's real OS cwd, not the `cwd` parameter `go()` was handed.
    // For that hazard to be live, the process's real cwd must actually BE `cwd.path()` (holding the
    // planted file) for the duration — otherwise deleting `joined.is_absolute() &&` still finds
    // nothing there and this passes for the wrong reason, on any host.
    let _guard = crate::child::spawn::spawn_lock();
    let _restore = crate::test_child::RestoreCwd::capture();
    std::env::set_current_dir(cwd.path()).unwrap();
    let empty = if HOST_WINDOWS { ";;" } else { "::" };
    assert_not_found("tool", go("tool", cwd.path(), Some(OsStr::new(empty))));
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
    // exercises above, not a distinct code path. Same reasoning as there: the process's real OS cwd
    // must actually be `cwd.path()` for this to be a live check.
    let _guard = crate::child::spawn::spawn_lock();
    let _restore = crate::test_child::RestoreCwd::capture();
    std::env::set_current_dir(cwd.path()).unwrap();
    assert_not_found("tool", go("tool", cwd.path(), Some(OsStr::new("."))));
}

// ── the Windows .exe rule ────────────────────────────────────────────────────────────

#[test]
fn the_exe_file_wins_over_an_extensionless_namesake_beside_it() {
    // Named for what it can actually observe. Re-adding an extensionless SECOND candidate for a
    // bare name would NOT fail this test — `tool.exe` is tried first and wins either way — so it
    // cannot gate the one-candidate property despite the directory being set up for it. That
    // property is gated by `bare_extensionless_name_gets_only_the_exe_candidate`, which compares
    // the candidate list directly; this one pins the end-to-end outcome on a real filesystem.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), "tool"); // must be ignored entirely, not merely lose a preference
    let want = touch(bin.path(), "tool.exe");
    let p = path_var_for(&[bin.path()], true);
    assert_eq!(go_win_path("tool", cwd.path(), Some(&p)).unwrap(), want);
}

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
    let p = path_var_for(&[bin.path()], true);
    assert_not_found("tool", go_win_path("tool", cwd.path(), Some(&p)));

    // Positive control: the SAME directory and PATH resolve once `tool.exe` is present, so the
    // miss above is the candidate rule and not a broken `path_var_for` silently dropping the
    // entry — which would leave this test green for the wrong reason.
    let want = touch(bin.path(), "tool.exe");
    assert_eq!(go_win_path("tool", cwd.path(), Some(&p)).unwrap(), want);
}

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
    // `tool.exe`, not extensionless `tool`: the bare-name rule (see the "filename
    // candidate rule" tests above) means a bare `tool` only ever looks for `tool.exe` on
    // Windows now, so this quoting test must plant the file it can actually find.
    let want = touch(&semi_dir, "tool.exe");
    let quoted = OsString::from(format!("\"{}\"", semi_dir.display()));
    assert_eq!(go_win_path("tool", cwd.path(), Some(&quoted)).unwrap(), want);
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

/// The end-to-end half of [`a_drive_relative_name_is_refused_on_shape`], on a real Windows runner
/// with a plantable file where the process's own current directory is.
///
/// The refusal itself no longer depends on the host: `resolve` states it explicitly, before any
/// candidate is built, so the host-independent test pins it on every platform. What only a
/// Windows runner can show is that a drive-relative name does not resolve through the process's
/// REAL current directory on drive C — the directory the `cwd` parameter never names, since
/// `PathBuf::push` clears for any prefixed path.
#[cfg(windows)]
#[test]
fn a_drive_relative_name_fails_closed() {
    let cwd = tempfile::tempdir().unwrap();
    // Planted where the process's actual OS cwd is about to be, so any route that reached drive
    // C's current directory has something to find; a tempdir under `%TEMP%`, as here, lives on the
    // runner's system drive, which is `C:` on every GitHub-hosted Windows runner this crate targets.
    touch(cwd.path(), "tool.exe");
    let _guard = crate::child::spawn::spawn_lock();
    let _restore = crate::test_child::RestoreCwd::capture();
    std::env::set_current_dir(cwd.path()).unwrap();
    assert_refused_on_shape("C:tool", go("C:tool", cwd.path(), None));
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
    // ever looks for `tool.exe` (the bare-name rule — see the "filename candidate
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
    assert_not_found("tool", miss);
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
    assert_not_found("tool", got);
}

// ── the located axis does not search, and a miss is NotFound ─────────────────────────

#[test]
fn a_located_name_never_falls_back_to_a_search() {
    // `resolve_executable_in`'s doc promises a name containing a separator "resolves against
    // base_cwd with NO SEARCH AT ALL". Nothing gated that: making `Shape::Located` also visit
    // `system_dirs`/`PATH` passed the whole suite. The consequence is concrete —
    // `executable("./helper")` with no `./helper` present would silently load a `helper.exe` from
    // `PATH`, a file the caller explicitly did not name.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    // A decoy the search WOULD find, under both located candidate spellings.
    touch(bin.path(), "helper");
    touch(bin.path(), "helper.exe");
    let pv = path_var_for(&[bin.path()], true);
    // A miss, not a refusal: `./helper` is a perfectly good name, it just is not there.
    assert_not_found("./helper", go_win_path("./helper", cwd.path(), Some(&pv)));
}

#[test]
fn a_miss_is_reported_as_not_found() {
    // `resolve_executable_in`'s doc promises `ErrorKind::NotFound` for a miss. Nothing asserted
    // the kind, so changing it was invisible. (A drive-relative name is a REFUSAL, not a miss —
    // see the module doc's kind rule and `a_drive_relative_name_is_refused_on_shape`.)
    let cwd = tempfile::tempdir().unwrap();
    let err = go_win_path("no-such-program-41d9", cwd.path(), None).unwrap_err();
    match err {
        Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e:?}"),
        other => panic!("a miss must be an Io(NotFound), got {other:?}"),
    }
}

#[test]
fn a_directory_named_like_the_program_is_not_returned() {
    // `is_execable` keys on `is_file()`, not `exists()`. It matters most on POSIX, where
    // `faccessat(X_OK)` SUCCEEDS on a directory — so an `exists()`-based check would hand a
    // directory to exec. Both existing gates for this live in the `#[cfg(windows)]` module, which
    // is the wrong platform for the hazard.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    std::fs::create_dir(bin.path().join(exe_name("tool"))).unwrap();
    let p = path_var(&[bin.path()]);
    // A directory is not a match, so this is an ordinary miss.
    assert_not_found("tool", go("tool", cwd.path(), Some(&p)));

    // Positive control: a real file in the same slot DOES resolve, so the assertion above is
    // gating `is_file()` rather than an unrelated lookup failure.
    let bin2 = tempfile::tempdir().unwrap();
    let want = touch(bin2.path(), &exe_name("tool"));
    let p2 = path_var(&[bin2.path()]);
    assert_eq!(go("tool", cwd.path(), Some(&p2)).unwrap(), want);
}

#[test]
fn a_separator_terminated_located_name_gets_no_exe_fallback() {
    // THE WIDENING GUARD. Appending to a name that ends in a separator produces a DOTFILE INSIDE
    // the named directory — `C:\tools\thing.bin\.exe` — which a writer of that directory can
    // plant, and which `main` never looked for (it appended via `Path::with_extension`, a no-op
    // when the path has no file name). Catches both halves: treating the empty final component as
    // "no extension", and appending a raw string instead of replacing an extension.
    for n in [r"tools\thing.bin\", r"bin\tool\", "bin/tool/", r"C:\"] {
        let got = candidate(n, true);
        assert_eq!(
            got,
            vec![n.to_string()],
            "{n:?} must yield exactly one candidate: {got:?}"
        );
    }
}

#[test]
fn an_empty_program_never_resolves() {
    // `classify("")` is a bare name, and the `.exe` rule turned it into the single candidate
    // `.exe` — so `executable("")` resolved to any file literally named `.exe` sitting in a PATH
    // or system directory, which is trivially plantable. An empty name names no file; it must
    // fail closed on every axis.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    touch(bin.path(), ".exe");
    let pv = path_var_for(&[bin.path()], true);
    assert_refused_on_shape("", go_win_path("", cwd.path(), Some(&pv)));
    assert_refused_on_shape("", go_win_path("", cwd.path(), None));
}

/// A refused name must be refused for its SHAPE, not merely missed by the search. Asserting
/// `is_err()` alone passes vacuously — the file does not exist either — so it would not have
/// caught the planted-sibling case at all. See `resolve`'s module doc for the kind rule.
fn assert_refused_on_shape(name: &str, got: Result<std::path::PathBuf, Error>) {
    match got {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        other => panic!("{name:?} names no file and must be refused on shape, got {other:?}"),
    }
}

/// The other half of the kind rule: the name was ACCEPTED and searched, and nothing matched.
fn assert_not_found(name: &str, got: Result<std::path::PathBuf, Error>) {
    match got {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        other => panic!("{name:?} was searched and missed, so it must be NotFound, got {other:?}"),
    }
}

#[test]
fn a_drive_relative_name_is_refused_on_shape() {
    // `C:tool` names a file relative to drive C's OWN current directory — state cosca does not
    // track and never will, so no filesystem can make it resolve. Under the kind rule that is a
    // refusal, not a search miss. It reported `NotFound` only incidentally: `PathBuf::push` clears
    // for a prefixed path, so every candidate failed `resolve`'s `is_absolute()` filter and the
    // loop fell through to the generic trailing error, which would have changed kind silently if
    // that filter ever did.
    let cwd = tempfile::tempdir().unwrap();
    for n in ["C:tool", "D:sub/x", "C:tool.exe", r"Z:a\b"] {
        assert_refused_on_shape(n, go_win_path(n, cwd.path(), None));
    }
}

#[test]
fn an_accepted_name_that_is_simply_absent_is_not_found() {
    // The negative control for every refusal in this block, and the other half of the kind rule:
    // each of these IS accepted, IS searched, and merely misses — a different disk (or `PATH`)
    // resolves any of them, so none may be reported as refused.
    let cwd = tempfile::tempdir().unwrap();
    // `1:tool` is in the list on purpose: a drive prefix takes a LETTER, so this is an ordinary
    // bare name that gets searched, not a drive-relative refusal.
    for n in [
        "tool",
        "1:tool",
        // `std` recognises a verbatim drive whichever separator follows it, so this is
        // `\\?\C:` plus a path, not a bare prefix. Pins the parser against `std`'s own rule.
        r"\\?\C:/x",
        "./missing",
        r"C:\abs\missing.exe",
        // A dot-run INTERIOR component is an ordinary directory name, and the final component
        // names the file — neither is trimmed, so this is searched like any other pathed name.
        r"C:\dir\...\tool.exe",
        r"sub\missing",
        "sub/missing",
    ] {
        assert_not_found(n, go_win_path(n, cwd.path(), None));
    }
    assert_not_found("tool", go(&exe_name("tool"), cwd.path(), None));
}

#[test]
fn a_program_with_no_stem_is_refused() {
    // A path whose final component is empty, `.` or `..` names a DIRECTORY, so it cannot name an
    // executable — and resolving it anyway is not merely futile, it invents names. `C:\t\.` grew
    // the candidate `C:\t\..exe`, a file in `C:\t` that the caller never wrote; a bare `.` grew
    // `..exe` and searched `PATH` for it. Refusing on the shape closes every such spelling at
    // once, where guarding one candidate rule at a time leaves the next one open.
    let cwd = tempfile::tempdir().unwrap();
    for n in [
        "",
        r"C:\t\thing.bin\",
        r"C:\t\dir\",
        "bin/",
        r"C:\t\.",
        r"C:\t\..",
        ".",
        "..",
        r"C:\",
        "C:",
        "C:.",
        "C:..",
    ] {
        assert_refused_on_shape(n, go_win_path(n, cwd.path(), None));
    }
}

#[test]
fn a_stemless_program_is_refused_on_posix_too() {
    // The rule is not a Windows one: `execvp("bin/")`, `execvp(".")` and `execvp("..")` fail for
    // the same reason. Only the separator set is platform-dependent, so `bin\` stays a legitimate
    // single-component filename here — a backslash is an ordinary character on POSIX.
    let cwd = tempfile::tempdir().unwrap();
    for n in ["", "bin/", ".", "..", "/"] {
        assert_refused_on_shape(n, go(n, cwd.path(), None));
    }
}

#[test]
fn a_dot_terminated_name_never_invents_a_planted_sibling() {
    // The live half of the bug, on the filesystem: with `..exe` planted beside it, `C:\t\.` used
    // to resolve to that file. The directory it names is real and the plant is real, so nothing
    // but the stem rule stops this one.
    let cwd = tempfile::tempdir().unwrap();
    let dir = cwd.path().join("t");
    std::fs::create_dir(&dir).unwrap();
    touch(&dir, "..exe");
    let named = format!("{}/.", dir.display());
    assert_refused_on_shape(&named, go_win_path(&named, cwd.path(), None));
}

#[test]
fn a_trailing_dot_or_space_is_an_ordinary_name_on_both_platforms() {
    // The resolver does PURE path manipulation, on either platform. Win32's trimming of a
    // component's trailing dots and spaces describes what an API does to a path STRING on its way
    // in; it says nothing about what may exist on disk, and Microsoft's own rule concedes such a
    // file CAN be created. The reference is `PureWindowsPath`, which normalises separators and
    // nothing else: `C:\dir\...` has name `...`, and a lone space is a name.
    let cwd = tempfile::tempdir().unwrap();
    for n in [
        "...",
        "....",
        ". ",
        " .",
        ".. ",
        "   ",
        "tool.",
        "tool ",
        r"C:\t\...",
        r"C:\t\. ",
        r"C:\t\dir\.. ",
    ] {
        assert!(!names_no_file(OsStr::new(n), true), "{n:?} names a file on Windows");
        assert_not_found(n, go_win_path(n, cwd.path(), None));
    }
    for n in ["tool.", "tool ", "...", ". ", " .", "....", "a.", "bin/tool."] {
        assert!(!names_no_file(OsStr::new(n), false), "{n:?} names a file on POSIX");
        assert_eq!(candidate(n, false), vec![n.to_string()], "POSIX never rewrites a name");
    }
}

#[test]
fn a_dot_run_name_is_searched_for_like_any_other_bare_name() {
    // The live half, on the filesystem: `...` is a NAME, so the bare rule appends `.exe` to it and
    // the search finds `....exe` exactly as it finds `tool.exe` for `tool`. Not a plantable
    // invention — the candidate is the caller's own bytes plus the documented suffix, and a writer
    // who can drop `....exe` into a searched directory can drop `tool.exe` there just as easily.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let planted = touch(bin.path(), "....exe");
    let pv = path_var_for(&[bin.path()], true);
    let got = go_win_path("...", cwd.path(), Some(&pv)).expect("`...` names a file and must resolve");
    assert_eq!(got, planted, "{got:?}");
}

#[test]
fn the_exe_rule_appends_to_the_name_as_written() {
    // No normalisation of any kind before appending. `tool.` yields `tool..exe` — the SAME rule
    // as `tool` -> `tool.exe`, applied to a name that merely looks odd, not a special case.
    // Trimming the trailing dot first would search for `tool.exe`, a DIFFERENT file from the one
    // the caller named, in every system and `PATH` directory.
    assert_eq!(candidate("tool.", true), vec!["tool..exe"]);
    assert_eq!(candidate("tool ", true), vec!["tool .exe"]);
    assert_eq!(candidate("tool. ", true), vec!["tool. .exe"]);
    assert_eq!(candidate("...", true), vec!["....exe"]);
    // `tool.exe.` does not END in `.exe`, so the allowlist does not match and the rule applies.
    assert_eq!(candidate("tool.exe.", true), vec!["tool.exe..exe"]);
    // LOCATED: `tool ` carries no extension, so it keeps the portable fallback — `main`, keying on
    // `Path::extension()`, looked for `bin\tool .exe` too.
    assert_eq!(candidate(r"bin\tool ", true), vec![r"bin\tool ", r"bin\tool .exe"]);
    // `tool.` carries an empty one (`Path::extension()` is `Some("")`), so it gets no fallback —
    // the same rule that gives `tools\thing.bin` exactly one candidate.
    assert_eq!(candidate(r"bin\tool.", true), vec![r"bin\tool."]);
}

#[test]
fn a_prefix_only_located_name_is_refused_like_a_drive_root() {
    // A share, a volume or a device namespace is a ROOT, not a file — the same shape as `C:\`,
    // which was already refused while these were not. On Windows `Path::file_name()` is `None`
    // for every one of them (they parse as a prefix plus a root, with no `Normal` component), so
    // `main`'s `with_extension("exe")` was a NO-OP — `set_extension` returns false when there is
    // no file stem — and `main` never looked for `\\server\share.exe`. Stripping only a DRIVE
    // prefix read `share` as a filename and grew exactly that candidate.
    let cwd = tempfile::tempdir().unwrap();
    for n in [
        r"\\server\share",
        r"\\server\share\",
        "//server/share",
        r"\\?\C:",
        r"\\?\C:\",
        r"\\?\UNC\server\share",
        // `std` matches the `UNC\` marker through the same `/`-for-`\` normalisation it applies
        // to the rest of a prefix, so this is a share root too.
        r"\\?\UNC/server\share",
        r"\\?\GLOBALROOT",
        r"\\.\pipe",
        r"\\",
        r"\\?\",
    ] {
        assert_refused_on_shape(n, go_win_path(n, cwd.path(), None));
    }
}

#[test]
fn a_prefix_only_located_name_never_grows_an_exe_candidate() {
    // `resolve` refuses these before `filename_candidates` runs; this pins the candidate rule
    // itself, which `takes_the_exe_fallback`'s own doc promises is defence in depth for any
    // future caller that does not go through `resolve`.
    for n in [r"\\server\share", r"\\?\C:", r"\\?\UNC\server\share", r"\\.\pipe"] {
        let got = candidate(n, true);
        assert_eq!(got, vec![n.to_string()], "{n:?} must not grow a candidate: {got:?}");
    }
}

#[test]
fn a_stemless_bare_name_grows_no_candidate_either() {
    // `resolve` refuses these before `filename_candidates` runs, but the candidate rule must not
    // depend on that — the same defence in depth `takes_the_exe_fallback` keeps for the located
    // axis. Appending to a name that names no file hands a bypassing caller exactly the plantable
    // `.exe`/`..exe` the refusal exists to prevent.
    for n in ["", ".", ".."] {
        assert_eq!(candidate(n, true), vec![n.to_string()], "{n:?}");
    }
}

#[test]
fn a_name_under_a_windows_prefix_is_still_a_filename() {
    // The negative control: only the PREFIX itself is not a filename. Everything below it is one,
    // with the ordinary candidate rule — including `\\.\pipe\x`, whose `x` IS a `Normal`
    // component on Windows, so `main` appended there too and this stays main-parity.
    for (n, want) in [
        (
            r"\\server\share\tool",
            vec![r"\\server\share\tool", r"\\server\share\tool.exe"],
        ),
        (r"\\?\C:\tools\thing.bin", vec![r"\\?\C:\tools\thing.bin"]),
        (r"\\?\UNC\server\share\tool.exe", vec![r"\\?\UNC\server\share\tool.exe"]),
        (r"\\.\pipe\x", vec![r"\\.\pipe\x", r"\\.\pipe\x.exe"]),
    ] {
        assert!(!names_no_file(OsStr::new(n), true), "{n:?} names a file");
        let got = candidate(n, true);
        assert_eq!(got, want, "{n:?} -> {got:?}");
    }
}

/// `#[cfg(unix)]`, not a `windows: false` simulation: this touches the filesystem, and
/// POSIX-simulating on a Windows host shreds every candidate on its drive colon (see
/// `HOST_WINDOWS`). On a POSIX host `go` already applies the POSIX rules.
#[cfg(unix)]
#[test]
fn a_posix_name_with_a_stem_still_resolves() {
    // The POSIX twin, and the negative control for the separator set — the one half of the stem
    // rule that is platform-dependent. A backslash is an ordinary filename character here, so
    // `bin\` and `a\.` are single-component names WITH a stem: a rule reading them through the
    // Windows separator set would see `bin/` and `a/.` and refuse both.
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let pv = path_var_for(&[bin.path()], false);
    for n in [r"bin\", r"a\.", ".helper", "..helper"] {
        touch(bin.path(), n);
        let got = go(n, cwd.path(), Some(&pv));
        assert!(got.is_ok(), "{n:?} has a stem on POSIX and must resolve, got {got:?}");
    }
}

#[test]
fn a_name_with_a_stem_still_resolves() {
    // Negative control for the three tests above: the refusal must key on a MISSING stem, not on
    // a leading dot. `.helper` and `..helper` are ordinary filenames and must survive.
    let cwd = tempfile::tempdir().unwrap();
    let bin = cwd.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    for n in [".helper", "..helper", "tool.exe"] {
        touch(&bin, n);
        let got = go_win_path(&format!("{}/{}", bin.display(), n), cwd.path(), None);
        assert!(got.is_ok(), "{n:?} has a stem and must resolve, got {got:?}");
    }
}
