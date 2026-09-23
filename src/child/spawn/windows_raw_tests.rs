//! Unit tests for the raw `CreateProcessW` backend's pre-spawn program gate
//! ([`super::reject_batch_program`]) and command-line builder
//! ([`super::raw_program_and_line`]), which run before resolution and decide what a malformed
//! program token or argument is BLAMED on. Driven directly rather than through `spawn_raw`, so no
//! child is created and the verdict is the checks' alone.

use super::*;
use crate::command::Command;
use crate::error::Error;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

/// A token carrying an interior NUL — `PCWSTR` truncates at it, so `prefix` is what Win32 acts on.
fn nul_between(prefix: &str, suffix: &str) -> OsString {
    OsString::from_wide(
        &prefix
            .encode_utf16()
            .chain([0])
            .chain(suffix.encode_utf16())
            .collect::<Vec<u16>>(),
    )
}

/// The `Display` of an `Io(InvalidInput)` refusal; panics on anything else, naming what came back.
fn invalid_input_message(via: &str, r: Result<(), Error>) -> String {
    match r {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => e.to_string(),
        other => panic!("{via}: expected Io(InvalidInput), got {other:?}"),
    }
}

/// Every way a caller can name a program, in one place: `reject_batch_program` reads
/// `executable()` when set and otherwise the argv[0] / command-line first token, so each arm needs
/// its own leg.
fn commands_with_token(token: &OsString) -> Vec<(&'static str, Command)> {
    let mut by_argv = Command::new();
    by_argv.args([token.clone()]);

    // argv[0] is deliberately clean and DIFFERENT from `token`: with the probe in both fields a
    // passing leg would not say which one the gate read.
    let mut by_executable = Command::new();
    by_executable.executable(token).args(["ordinary.exe"]);

    let mut by_commandline = Command::new();
    by_commandline.commandline(token.clone());

    vec![
        ("argv[0]", by_argv),
        ("executable()", by_executable),
        ("commandline()", by_commandline),
    ]
}

/// `C:\tools\setup` + NUL + `.bat`. Win32 truncates it to `C:\tools\setup`, which is no batch file
/// at all, so neither gate may blame CVE-2024-24576 — the caller would be sent to audit a vector
/// they do not carry, over a token that launches a program they did not name.
#[test]
fn a_nul_before_a_batch_extension_is_diagnosed_as_a_nul_not_a_batch_refusal() {
    let token = nul_between(r"C:\tools\setup", ".bat");
    // Premise: the shared gate refuses this as a NUL as well, never as a batch file — so an
    // `Unsupported` reaching the caller could only be the batch rule misfiring.
    invalid_input_message(
        "the shared gate",
        crate::child::spawn::reject_batch_path(std::path::Path::new(&token)),
    );
    for (via, c) in commands_with_token(&token) {
        // An `Ok`, or any downstream error kind, panics in the helper.
        let msg = invalid_input_message(via, reject_batch_program(&c));
        assert!(
            !msg.contains('\0'),
            "{via}: the refusal must not carry a raw NUL into logs: {msg:?}"
        );
    }
}

/// The batch gate must still refuse a clean `.bat`. Without this leg the ordering could be
/// "satisfied" by deleting the gate outright and every NUL test here would stay green.
#[test]
fn a_clean_batch_token_is_still_refused_as_a_batch() {
    for (via, c) in commands_with_token(&OsString::from(r"C:\tools\setup.bat")) {
        assert!(
            matches!(reject_batch_program(&c), Err(Error::Unsupported { .. })),
            "{via}: a clean .bat must still be refused by the batch gate"
        );
    }
}

/// A NUL in the PROGRAM TOKEN must be blamed on the program token. The raw backend shares one NUL
/// checker with the environment-block builder, so a message hardcoded to the environment sends the
/// caller off to audit `env()` over a defect in `args()` or `executable()` — the same class of
/// misattribution the NUL-before-batch ordering exists to prevent, one field over.
#[test]
fn a_nul_in_the_program_token_is_not_blamed_on_the_environment() {
    let token = nul_between("setup.bat", "junk");
    // Premise: the shared gate refuses this too, so the assertions below are about WHICH FIELD the
    // refusal names and not about whether one arrives.
    invalid_input_message(
        "the shared gate",
        crate::child::spawn::reject_batch_path(std::path::Path::new(&token)),
    );
    for (via, c) in commands_with_token(&token) {
        let msg = invalid_input_message(via, reject_batch_program(&c));
        assert!(
            msg.contains("program token"),
            "{via}: must name the program token, got {msg}"
        );
        assert!(
            !msg.contains("environment"),
            "{via}: a program token is not the environment, got {msg}"
        );
    }
}

/// A NUL in a middle argv element must name WHICH element. By the time `CreateProcessW` reads it
/// the command line is one joined string, so an unindexed label leaves the caller to bisect
/// `args([..])` by hand — and `args(["a", "b\0c", "d"])` would name no element at all.
#[test]
fn a_nul_in_an_argument_is_blamed_on_its_index() {
    let mut c = Command::new();
    c.args([OsString::from("a"), nul_between("b", "c"), OsString::from("d")]);
    let msg = invalid_input_message("argv", super::raw_program_and_line(&c).map(|_| ()));
    assert!(msg.contains("argument 1"), "must name the offending element, got {msg}");
}

// ===== command-line builder: a usable first token when executable() is unset =====

// ── `lpApplicationName` must never silently end up NULL ────────────────────────────────
//
// `CreateProcessW` performs its OWN image search when `lpApplicationName` is NULL, including
// the CALLING process's current directory — the exact binary-planting hole this module's
// resolution otherwise closes (see `program_token`'s doc). `spawn_raw` keeps `lpApplicationName`
// non-NULL by falling back to `program_token(cmd)` when `executable()` is unset, but
// `program_token`'s `CommandLine` arm calls `first_token_wide`, which is documented to return
// `None` for an empty or whitespace-only line. `raw_program_and_line`'s sibling arms (`Empty`,
// `Argv`) both already error out loudly when `executable()` is unset and they have no usable
// token; the `CommandLine` arm had no matching check, so an empty/whitespace `commandline()`
// with no `executable()` silently produced `app_name: None` (`lpApplicationName == NULL`)
// instead of erroring.

#[test]
fn raw_program_and_line_rejects_an_empty_command_line_with_no_executable_set() {
    let mut cmd = Command::new();
    cmd.commandline("");
    let err = raw_program_and_line(&cmd).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
}

#[test]
fn raw_program_and_line_rejects_a_whitespace_only_command_line_with_no_executable_set() {
    let mut cmd = Command::new();
    cmd.commandline("   ");
    let err = raw_program_and_line(&cmd).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
}

#[test]
fn raw_program_and_line_allows_an_empty_command_line_when_executable_is_set() {
    let mut cmd = Command::new();
    // executable() alone still supplies lpApplicationName, so an empty command line here is not
    // the NULL-lpApplicationName hazard the check above exists to close — matches the existing
    // `Empty` arm's own "executable() alone" case.
    cmd.executable(std::path::PathBuf::from(r"C:\some\app.exe"));
    cmd.commandline("");
    assert!(raw_program_and_line(&cmd).is_ok());
}

#[test]
fn raw_program_and_line_allows_a_non_empty_command_line_with_no_executable_set() {
    let mut cmd = Command::new();
    cmd.commandline("tool --flag");
    assert!(raw_program_and_line(&cmd).is_ok());
}

/// The containment marker is an op after the user's, so it takes the name std gives it: after a
/// user's `env_remove("__cosca_group_root")`, that spelling, as on the std path.
#[test]
fn the_containment_marker_is_named_as_std_names_it() {
    let removed = "__cosca_group_root";
    let mut std_cmd = std::process::Command::new("unused");
    std_cmd.env_remove(removed).env(crate::containment::NESTED_ENV, "1");
    let std_name: Vec<_> = std_cmd.get_envs().map(|(k, _)| k.to_os_string()).collect();
    assert_eq!(std_name, [OsString::from(removed)], "std control");

    let snapshot = env_snapshot::EnvSnapshot::from_block("A=1\0\0".encode_utf16().collect());
    let user_ops = [EnvOp::Remove(removed.into())];
    let ops = child_ops(&user_ops, true);
    let block = resolve::ChildEnv::capture(&snapshot, &ops).into_block().unwrap();
    assert_eq!(String::from_utf16(&block).unwrap(), "A=1\0__cosca_group_root=1\0\0");
}

// `target`: the Search/Exact distinction, at the one site that applies it ────────────
//
// These run on the Windows CI runner rather than the host, because `target` is inside the
// `cfg(windows)` raw backend — the `Exact` arm touches no Win32 API, but it cannot be compiled
// off Windows to be reached.

/// [`target`]'s image, against the environment a spawn of `cmd` would read.
fn image(cmd: &Command) -> Result<Option<PathBuf>, Error> {
    Ok(target(cmd, &spawn_env(cmd)?)?.image)
}

#[test]
fn image_for_leaves_an_exact_program_completely_unresolved() {
    // The contract in one assertion: a BARE name, which `executable()` would look up on PATH and
    // turn absolute (and would append `.exe` to), survives byte-for-byte.
    let mut cmd = Command::new();
    cmd.raw_executable("tool").args(["tool"]);
    let image = image(&cmd).expect("an exact program is never resolved, so it cannot fail");
    assert_eq!(
        image.as_deref(),
        Some(Path::new("tool")),
        "raw_executable must reach lpApplicationName exactly as written"
    );
}

/// The file [`fixture_load_exact_probe`] loads by relative name: a copy of this test binary.
const PROBE: &str = "cosca_exact_cwd_probe.exe";
const FIXTURE_LOAD_EXACT_PROBE_TEST: &str = "child::spawn::windows_raw::windows_raw_tests::fixture_load_exact_probe";
/// The `current_dir()` [`fixture_load_exact_probe`] gives [`PROBE`]. Its presence also marks a
/// deliberate re-exec rather than an ordinary suite run.
const FIXTURE_LOAD_EXACT_PROBE_ENV: &str = "COSCA_FIXTURE_LOAD_EXACT_PROBE_CURRENT_DIR";
/// [`fixture_load_exact_probe`]'s exit codes.
const LOADED: i32 = 0;
const FILE_NOT_FOUND: i32 = 20;
const OTHER_FAILURE: i32 = 21;

/// Inert in an ordinary suite run. Re-executed with [`FIXTURE_LOAD_EXACT_PROBE_ENV`] set, it
/// spawns `raw_executable(PROBE)` with that `current_dir()` from whatever cwd its spawner gave it,
/// and exits with [`LOADED`], [`FILE_NOT_FOUND`] or [`OTHER_FAILURE`]. The spawner sets the cwd,
/// so no process in the test moves its own.
#[test]
fn fixture_load_exact_probe() {
    let Some(current_dir) = std::env::var_os(FIXTURE_LOAD_EXACT_PROBE_ENV) else {
        return;
    };
    let mut c = Command::new();
    // A filter that matches nothing, so the probe exits 0 without running a test.
    c.raw_executable(PROBE)
        .args([PROBE, "--exact", "__cosca_no_such_test__"])
        .current_dir(current_dir);
    c.stdout(crate::stdio::Stdio::null()).expect("stdout null");
    c.stderr(crate::stdio::Stdio::null()).expect("stderr null");
    assert_eq!(image(&c).expect("image_for").as_deref(), Some(Path::new(PROBE)));
    let not_found = windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    let code = match c.spawn() {
        Ok(child) if child.wait().expect("wait").success() => LOADED,
        Err(Error::Io(e))
            if e.raw_os_error() == Some(not_found.0 as i32)
                || e.raw_os_error() == Some(windows::core::HRESULT::from_win32(not_found.0).0) =>
        {
            FILE_NOT_FOUND
        }
        _ => OTHER_FAILURE,
    };
    std::process::exit(code);
}

/// [`fixture_load_exact_probe`]'s exit code when run with `process_cwd` as its cwd.
fn load_exact_probe(process_cwd: &Path, current_dir: &Path) -> Option<i32> {
    let mut c = Command::new();
    c.executable(std::env::current_exe().expect("current_exe"))
        .args(crate::test_child::fixture_argv(FIXTURE_LOAD_EXACT_PROBE_TEST))
        .env(FIXTURE_LOAD_EXACT_PROBE_ENV, current_dir)
        .current_dir(process_cwd);
    // libtest writes its banner to fd 1 directly, past its own capture.
    c.stdout(crate::stdio::Stdio::null()).expect("stdout null");
    c.stderr(crate::stdio::Stdio::null()).expect("stderr null");
    c.spawn().expect("spawn the fixture").wait().expect("wait").code()
}

/// `lpCurrentDirectory` takes no part in image lookup: a relative `Exact` image loads from the
/// process's cwd whatever `current_dir()` says. The Windows counterpart of the POSIX
/// `a_bare_exact_name_loads_the_file_in_the_childs_cwd_not_one_on_path` and
/// `a_relative_current_dir_is_entered_from_a_cwd_that_has_no_path`, where the child's directory
/// decides instead.
#[test]
fn an_exact_image_is_loaded_from_the_process_cwd_not_current_dir() {
    let (with, without) = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    std::fs::copy(std::env::current_exe().expect("current_exe"), with.path().join(PROBE)).expect("copy");
    assert_eq!(load_exact_probe(with.path(), without.path()), Some(LOADED));
    assert_eq!(
        load_exact_probe(without.path(), with.path()),
        Some(FILE_NOT_FOUND),
        "current_dir() holds the image but the process cwd does not"
    );
}

#[test]
fn image_for_resolves_a_search_program_to_an_absolute_path() {
    // The other half, so the test pair proves a DIFFERENCE rather than one arm in isolation:
    // the same bare name through `executable()` is resolved and absolute. `cmd` is chosen because
    // it lives in the System32 directory the bare-name search visits on any Windows host.
    let mut cmd = Command::new();
    cmd.executable("cmd").args(["cmd"]);
    let image = image(&cmd).expect("cmd resolves on any Windows host").unwrap();
    assert!(
        image.is_absolute(),
        "a Search program must be absolute by the time the backend sees it, got {image:?}"
    );
    assert_ne!(image, Path::new("cmd"), "it must actually have been resolved");
}

#[test]
fn image_for_rejects_an_empty_exact_program() {
    // An empty `lpApplicationName` is a pointer to a lone NUL, not the NULL pointer, and whether
    // CreateProcessW treats the two alike is undocumented. Fail closed rather than find out.
    let mut cmd = Command::new();
    cmd.raw_executable("").args(["tool"]);
    match image(&cmd) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        other => panic!("an empty exact program must be Io(InvalidInput), got {other:?}"),
    }
}

/// End to end, the batch gate's token check runs first, and it refuses a name that names no file
/// with the same `InvalidInput` `raw_executable()` and `executable()` document.
#[test]
fn a_spawn_of_a_program_that_names_no_file_is_invalid_input() {
    for n in [r"C:\t\dir\", ".", "..", "C:", r"x\.."] {
        let mut exact = Command::new();
        exact.raw_executable(n).args(["tool"]);
        let mut search = Command::new();
        search.executable(n).args(["tool"]);
        for (via, mut c) in [("raw_executable", exact), ("executable", search)] {
            match c.spawn() {
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
                other => panic!(
                    "{via}({n:?}) names no file and must be Io(InvalidInput), got {:?}",
                    other.map(|_| "a child")
                ),
            }
        }
    }
}

#[test]
fn image_for_rejects_an_exact_program_that_names_no_file() {
    // The raw backend's `Exact` arm passes the path through untouched, so a directory would reach
    // `lpApplicationName` verbatim. `CreateProcessW` would refuse it anyway, but as an OS error
    // after the spawn is under way; refusing here makes it `InvalidInput`, as on the elevated
    // sink. `C:\t\...` and `C:\t\. ` (one trailing space) name no file only after Win32
    // normalisation, so they pin the post-check.
    for n in [r"C:\t\dir\", r"C:\t\.", ".", "..", "C:", r"C:\t\...", r"C:\t\. "] {
        let mut cmd = Command::new();
        cmd.raw_executable(n).args(["tool"]);
        match image(&cmd) {
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
            other => panic!("{n:?} names no file and must be Io(InvalidInput), got {other:?}"),
        }
    }
}

#[test]
fn image_for_passes_an_exact_program_as_written() {
    // `absolutise_exact` reads Win32's normalisation; what reaches `lpApplicationName` must still
    // be the caller's token, relative and with its trailing dot, for the loader to complete.
    let mut cmd = Command::new();
    cmd.raw_executable(r"t\tool.").args(["tool"]);
    assert_eq!(image(&cmd).unwrap().as_deref(), Some(Path::new(r"t\tool.")));
}

/// `CreateProcessW` loads the name Win32 normalises the token to, so a batch file reached only
/// through normalisation is refused as a plainly-spelled one is — by the token gate, the raw
/// backend's one batch check, which judges that name.
#[test]
fn the_token_gate_refuses_an_exact_batch_reached_through_win32_normalisation() {
    // Trailing dot; one trailing space; a file named `.bat`, which has no extension to `Path`.
    for n in ["setup.bat.", "setup.bat ", r"C:\t\.bat"] {
        let mut cmd = Command::new();
        cmd.raw_executable(n).args(["tool"]);
        match reject_batch_program(&cmd) {
            Err(Error::Unsupported { platform, detail, .. }) => {
                assert_eq!(platform, "windows");
                assert!(detail.contains("CVE-2024-24576"), "{n:?}: {detail}");
            }
            other => panic!("{n:?} reaches a batch file and must be refused, got {other:?}"),
        }
    }
}

/// Negative control: a name that merely contains `.bat` loads as written.
#[test]
fn image_for_passes_an_exact_program_that_is_not_a_batch_file() {
    for n in ["setup.exe", "setup.bat.exe"] {
        let mut cmd = Command::new();
        cmd.raw_executable(n).args(["tool"]);
        assert_eq!(image(&cmd).unwrap().as_deref(), Some(Path::new(n)));
    }
}

#[test]
fn image_for_falls_back_to_the_program_token_when_no_executable_is_set() {
    // The fd>=3 route: neither setter was called, so `lpApplicationName` would be NULL without
    // this fallback — and a NULL makes CreateProcessW search, including the calling process's cwd.
    let mut cmd = Command::new();
    cmd.args(["cmd", "/C", "exit 0"]);
    let image = image(&cmd).expect("argv[0] resolves").unwrap();
    assert!(image.is_absolute(), "the fallback must resolve too, got {image:?}");
}

// `program_token`: which string the gate judges when `executable()` is unset =====

/// A command with no `executable()` that routes to the raw backend anyway, through the
/// `fd >= 3` arm of `routes_to_raw_backend`. On this route `program_token` alone picks the string
/// `reject_batch_program` judges, so a wrong pick skips the gate entirely.
fn high_fd_command() -> Command {
    let mut c = Command::new();
    c.fd(3, crate::stdio::Stdio::pipe_out()).expect("fd 3");
    c
}

/// The argv arm reads `argv.first()`. Probes put the batch name FIRST with clean names after it,
/// and a clean name first with a batch name after it — a lone element cannot tell `first()` from
/// `last()` or from "any".
#[test]
fn program_token_reads_the_first_argv_element() {
    let mut refused = high_fd_command();
    refused.args(["x.bat", "ordinary.exe", "tail.exe"]);
    assert!(crate::child::spawn::routes_to_raw_backend(&refused));
    assert_eq!(program_token(&refused), Some(PathBuf::from("x.bat")));
    assert!(
        matches!(reject_batch_program(&refused), Err(Error::Unsupported { .. })),
        "argv[0] is a batch file"
    );

    let mut allowed = high_fd_command();
    allowed.args(["ordinary.exe", "x.bat", "y.cmd"]);
    assert_eq!(program_token(&allowed), Some(PathBuf::from("ordinary.exe")));
    reject_batch_program(&allowed).expect("only argv[0] is the program");
}

/// The command-line arm reads `first_token_wide` — different extraction code from the argv arm,
/// with quoting of its own. A whole-line read would judge `x.bat --flag` (no batch suffix) and let
/// the first probe through; a last-token read would miss it the same way.
#[test]
fn program_token_reads_the_first_command_line_token() {
    for (line, token) in [
        ("x.bat --flag", "x.bat"),
        (r#""C:\dir with space\x.bat" --flag"#, r"C:\dir with space\x.bat"),
        (r"\\srv\x.bat\.. & calc", r"\\srv\x.bat\.."),
    ] {
        let mut c = high_fd_command();
        c.commandline(line);
        assert!(crate::child::spawn::routes_to_raw_backend(&c));
        assert_eq!(program_token(&c), Some(PathBuf::from(token)), "{line:?}");
        assert!(
            matches!(reject_batch_program(&c), Err(Error::Unsupported { .. })),
            "{line:?}: the first token is a batch file"
        );
    }

    let mut allowed = high_fd_command();
    allowed.commandline(r#"ordinary.exe x.bat "y.cmd""#);
    assert_eq!(program_token(&allowed), Some(PathBuf::from("ordinary.exe")));
    reject_batch_program(&allowed).expect("only the first token is the program");
}

/// End to end on the same route: `spawn()` must refuse before any child exists.
#[test]
fn a_high_fd_spawn_without_an_executable_is_gated_on_its_program_token() {
    let mut by_argv = high_fd_command();
    by_argv.args(["x.bat", "--flag"]);
    let mut by_line = high_fd_command();
    by_line.commandline("x.bat --flag");
    for (via, mut c) in [("argv", by_argv), ("commandline", by_line)] {
        let err = c.spawn().expect_err("a batch program token must be refused");
        assert!(matches!(err, Error::Unsupported { .. }), "{via}: got {err:?}");
    }
}

/// The raw backend runs the child in the directory its image was resolved against: one read of the
/// process cwd serves both, so a `set_current_dir` in between cannot split them.
#[test]
fn target_pins_the_resolved_directory_as_the_childs() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("tool.exe"), b"x").unwrap();
    for (cmd_cwd, want_dir) in [(Some("sub"), dir.path().join("sub")), (None, dir.path().to_path_buf())] {
        let token = if cmd_cwd.is_some() {
            r".\tool.exe"
        } else {
            r"sub\tool.exe"
        };
        let mut cmd = Command::new();
        cmd.executable(token).args([token]);
        if let Some(c) = cmd_cwd {
            cmd.current_dir(c);
        }
        let reads = std::cell::Cell::new(0);
        let got = target_with(&cmd, &spawn_env(&cmd).unwrap(), || {
            reads.set(reads.get() + 1);
            Ok(dir.path().to_path_buf())
        })
        .unwrap();
        assert_eq!(reads.get(), 1, "{cmd_cwd:?}");
        assert_eq!(got.cwd.as_deref(), Some(want_dir.as_path()), "{cmd_cwd:?}");
        let image = got.image.unwrap();
        assert!(image.starts_with(&want_dir), "{cmd_cwd:?}: {image:?}");
    }
}

/// A share-less UNC `current_dir` is refused with `InvalidInput`, never a panic in the resolver.
#[test]
fn target_refuses_a_share_less_unc_current_dir() {
    let mut cmd = Command::new();
    cmd.executable(r".\tool.exe")
        .args([r".\tool.exe"])
        .current_dir(r"\\server");
    match target(&cmd, &spawn_env(&cmd).unwrap()) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}"),
        Err(other) => panic!("expected Io(InvalidInput), got {other:?}"),
        Ok(_) => panic!("a share-less UNC directory must be refused"),
    }
}

/// `raw_executable()` keeps `current_dir` as written: `CreateProcessW` completes both in one call.
#[test]
fn target_passes_an_exact_programs_current_dir_as_written() {
    let mut cmd = Command::new();
    cmd.raw_executable("tool.exe").args(["tool.exe"]).current_dir("sub");
    let got = target_with(&cmd, &spawn_env(&cmd).unwrap(), || panic!("must not read the cwd")).unwrap();
    assert_eq!(got.cwd.as_deref(), Some(Path::new("sub")));
}
