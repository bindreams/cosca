//! Unit tests for the sync spawn error-path teardown, driven by the shared `fault` seam (defined
//! in `super`; also used by `src/tokio/spawn_tests.rs`). In the library (not `tests/`) because the
//! seam is `pub(crate)`/`#[cfg(test)]` and only reachable from within the crate.

use super::fault;
use crate::command::Command;
use crate::error::Error;

// A long-lived child, so a teardown leak would show as an alive process at the assert rather than
// self-exiting.
fn blocker() -> Command {
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd
}

// A failed sync spawn must fully reap its child, not leak it. Each error arm is forced via the seam
// (which records the child's real identity); `fault::assert_child_reaped` then proves it was reaped.

#[test]
fn identity_failure_reaps_the_spawned_child() {
    fault::set_force_identity_vanished(true);
    let mut cmd = blocker();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    let err = err.expect("forced identity-vanish must make spawn return Err");
    assert!(
        matches!(err, Error::Io(_)),
        "identity-vanish surfaces as an Io error, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

#[test]
fn attach_failure_reaps_the_spawned_child() {
    fault::set_force_attach_failure(true);
    let mut cmd = blocker();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);

    let err = err.expect("forced attach failure must make spawn return Err");
    assert!(
        matches!(err, Error::Containment { .. }),
        "a real attach failure surfaces as Error::Containment, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

#[test]
fn spawn_unelevated_runs_a_plain_child() {
    let mut c = crate::command::Command::new();
    #[cfg(unix)]
    c.args(["true"]);
    #[cfg(windows)]
    c.args(["cmd", "/C", "exit 0"]);
    let kill_on_drop = c.kill_on_drop_flag();
    let child = super::spawn_unelevated(&mut c, kill_on_drop).expect("spawn");
    assert!(child.wait().expect("wait").success());
}

// A NON-elevated command must reach spawn_unelevated unchanged: the elevation branch
// is gated on `elevation_request().enabled`, so a plain command never routes through it.
#[test]
fn non_elevated_spawn_skips_the_elevation_branch() {
    let mut c = crate::command::Command::new();
    #[cfg(unix)]
    c.args(["true"]);
    #[cfg(windows)]
    c.args(["cmd", "/C", "exit 0"]);
    let child = super::spawn(&mut c).expect("non-elevated spawn");
    assert!(child.wait().expect("wait").success());
}

#[cfg(windows)]
#[test]
fn elevated_pipe_is_rejected_deterministically_regardless_of_privilege() {
    // DETERMINISTIC (no ambient-privilege branch): the honest config gate now runs BEFORE
    // the already-elevated short-circuit, so a piped elevated child is
    // Unsupported whether or not the runner is elevated — never a UAC prompt, never a hang.
    let mut c = crate::command::Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(crate::stdio::Stdio::pipe()).unwrap();
    assert!(matches!(
        super::spawn(&mut c),
        Err(crate::error::Error::Unsupported { .. })
    ));
}

// ===== Windows backend routing =====

/// The rule both Windows routers read, in both directions and for all four shapes.
///
/// `tests/windows_creation_flags.rs` names a backend in every test name; its `executable()` legs
/// carry their own behavioural proof (the child's `argv[0]`), but its argv legs have none — an
/// argv-only command would report the same `argv[0]` whichever backend spawned it. Their
/// std-path claim rests on this rule, which is now one function rather than two copies.
///
/// The **high-descriptor-only** shape is the branch with no coverage anywhere today: every
/// shipped Windows high-descriptor test also sets an explicit `executable()`, which
/// short-circuits the rule before the fd term is ever evaluated.
#[cfg(windows)]
#[test]
fn routes_to_raw_backend_answers_for_executables_and_high_descriptors() {
    use crate::stdio::Stdio;

    let mut argv_only = Command::new();
    argv_only.args(["cmd", "/C", "exit 0"]);
    assert!(
        !super::routes_to_raw_backend(&argv_only),
        "an argv-only command stays on the std path"
    );

    let mut exe_only = Command::new();
    exe_only.executable("cmd").args(["cmd", "/C", "exit 0"]);
    assert!(super::routes_to_raw_backend(&exe_only), "an executable() routes to raw");

    let mut high_fd_only = Command::new();
    high_fd_only.args(["cmd", "/C", "exit 0"]);
    high_fd_only.fd(3, Stdio::pipe_out()).unwrap();
    assert!(
        super::routes_to_raw_backend(&high_fd_only),
        "a descriptor >= 3 routes to raw even with no executable(): std cannot carry it, and the \
         std path's fd >= 3 collection is unix-only, so it would be dropped in silence"
    );

    let mut both = Command::new();
    both.executable("cmd").args(["cmd", "/C", "exit 0"]);
    both.fd(3, Stdio::pipe_out()).unwrap();
    assert!(super::routes_to_raw_backend(&both));
}

/// A refused spawn must not have mutated this process first. `clear_std_handle_inheritance` is a
/// real, process-global, un-undone `SetHandleInformation` on our own std handles, so running it
/// before the refusal would leave a disposition-less side effect behind.
///
/// The two legs differ by one bit and are one `#[test]` so their order is guaranteed; `cargo
/// test` gives each test its own thread, so the thread-local seam starts clean. The positive leg
/// is what stops the negative one passing on a seam that was never wired.
///
/// The real handle flags are deliberately NOT measured instead: the mutation is process-global
/// and permanent, so any earlier contained spawn in this binary would already have made that
/// observation meaningless.
#[cfg(windows)]
#[test]
fn a_refused_raw_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.executable("cmd").args(["cmd", "/C", "exit 0"]).contain();
    let child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().expect("reap");
}

/// The std-path counterpart of the test above. The std backend reaches the same process-global
/// mutation through `containment::prepare`, which composes and validates the creation-flag word
/// at its top — a separate ordering the raw backends' tests cannot see.
///
/// Argv-only and no `executable()`, asserted through `routes_to_raw_backend` so a future routing
/// change cannot quietly turn this into a third raw-backend test.
#[cfg(windows)]
#[test]
fn a_refused_std_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    assert!(
        !super::routes_to_raw_backend(&refused),
        "this leg is only a std-path proof while the command stays off the raw backend"
    );
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.args(["cmd", "/C", "exit 0"]).contain();
    let child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().expect("reap");
}

// The batch gate reads the prefix Win32 would load =====

/// An `OsString` carrying an interior NUL, built natively on either platform family (`OsStr` has
/// no portable constructor that can express one).
fn with_interior_nul(prefix: &str, suffix: &str) -> std::ffi::OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = prefix.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(suffix.as_bytes());
        std::ffi::OsString::from_vec(bytes)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let units: Vec<u16> = prefix.encode_utf16().chain([0]).chain(suffix.encode_utf16()).collect();
        std::ffi::OsString::from_wide(&units)
    }
}

/// `Path::extension()` of `token` — the value [`super::reject_batch_path_on`] must NOT key on.
fn extension_of(token: &std::ffi::OsStr) -> Option<String> {
    std::path::Path::new(token)
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
}

/// The `op` of an `Unsupported` refusal; panics on anything else, naming what came back.
fn unsupported_op<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
    match r {
        Err(Error::Unsupported { op, .. }) => op,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// The `Display` of an `Io(InvalidInput)` refusal; panics on anything else.
fn invalid_input_message<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
    match r {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => e.to_string(),
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
}

/// The gate under a Win32 verdict, spelled as a value so this host can ask for it.
fn on_win32(token: &std::ffi::OsStr) -> Result<(), Error> {
    super::reject_batch_path_on(std::path::Path::new(token), true)
}

/// The gate under a POSIX verdict, ditto.
fn on_posix(token: &std::ffi::OsStr) -> Result<(), Error> {
    super::reject_batch_path_on(std::path::Path::new(token), false)
}

/// `\0` is not a path separator, so `Path::extension()` reads straight through it — and on both
/// NUL/batch shapes it reports the INVERSE of what Win32 loads:
///
/// - `setup` + NUL + `.bat` → `extension() == "bat"`, but Win32 truncates to `setup`, which is no
///   batch file. Keying on the extension blames CVE-2024-24576 for a program that does not carry
///   that vector, and formats a raw U+0000 into a message bound for logs and terminals.
/// - `setup.bat` + NUL + `junk` → `extension() == "bat\0junk"`, but Win32 truncates back to the
///   real batch file `setup.bat`.
///
/// So the gate keys on the truncated prefix, which fixes both shapes for every backend at one
/// site — including the std backend, which has no NUL check to order in front of it.
#[test]
fn the_batch_gate_reads_the_prefix_win32_would_load_not_the_whole_token() {
    let nul_then_bat = with_interior_nul("setup", ".bat");
    let bat_then_nul = with_interior_nul("setup.bat", "junk");

    // Premise: the extension is inverted on both shapes, which is why the gate cannot use it.
    assert_eq!(extension_of(&nul_then_bat), Some("bat".to_owned()));
    assert_ne!(extension_of(&bat_then_nul), Some("bat".to_owned()));

    assert!(
        on_win32(&nul_then_bat).is_ok(),
        "`setup` is not a batch file; refusing it as one sends the caller to audit the wrong defect"
    );

    let op = unsupported_op(on_win32(&bat_then_nul));
    assert!(
        !op.contains('\0'),
        "the refusal must not carry a raw NUL into logs: {op:?}"
    );
    assert!(op.contains("setup.bat"), "the refusal must name what Win32 loads: {op}");
}

/// The truncation is a WIN32 fact, so it decides nothing off Win32. On POSIX `x.bat` + NUL +
/// `junk` names no file at all — there is nothing to truncate, no cmd.exe, and no CVE-2024-24576
/// to audit — so the honest verdict is the NUL, and blaming batch escaping is the very
/// misattribution the prefix rule exists to remove, one platform over.
#[test]
fn a_nul_bearing_program_is_diagnosed_as_a_nul_off_win32() {
    for token in [
        with_interior_nul("x.bat", "junk"),
        with_interior_nul("x", ".bat"),
        with_interior_nul("/usr/bin/ls", "junk"),
    ] {
        let msg = invalid_input_message(on_posix(&token));
        for wrong in ["cmd.exe", "CVE-2024-24576", "windows", "Win32"] {
            assert!(
                !msg.contains(wrong),
                "a POSIX refusal must not mention {wrong:?}: {msg}"
            );
        }
        assert!(msg.contains("NUL"), "the refusal must name the NUL: {msg}");
        assert!(
            !msg.contains('\0'),
            "the refusal must not carry a raw NUL into logs: {msg:?}"
        );
    }
}

/// The same token, the two platform verdicts, from one host: `win32` is data rather than a `cfg!`
/// precisely so both are reachable here. Without this pair the POSIX arm could be "satisfied" by
/// making the gate refuse NULs everywhere, which would take the Win32 diagnosis away again.
#[test]
fn the_win32_and_posix_verdicts_differ_for_the_same_token() {
    let bat_then_nul = with_interior_nul("x.bat", "junk");
    assert!(unsupported_op(on_win32(&bat_then_nul)).contains("x.bat"));
    invalid_input_message(on_posix(&bat_then_nul));
}

/// A clean `.bat` is still refused on either platform: the verdict is a property of the REQUEST,
/// not of the host, and the NUL arm above must not have swallowed the batch rule.
#[test]
fn a_clean_batch_program_is_refused_under_either_verdict() {
    let token = std::ffi::OsString::from(r"C:\tools\setup.bat");
    for r in [on_win32(&token), on_posix(&token)] {
        assert!(unsupported_op(r).contains("setup.bat"));
    }
}

/// The std backend is the DEFAULT Windows path: `args([..])` with no `executable()` and no
/// fd >= 3 is false for `routes_to_raw_backend`, so it reaches the gate through
/// [`super::build_std_command`] with no NUL check of its own.
///
/// Host-independent on purpose: what it pins is that the gate judges the token the CALLER named.
/// Before this round it read `std::process::Command::get_program()`, and std's Unix constructor
/// had already swapped a NUL-bearing program for a `<string-with-nul>` sentinel — so on this host
/// the call returned `Ok` and the token reached `spawn`. Which refusal comes back is the platform
/// verdict tested above; that one comes back at all is the wiring.
#[test]
fn the_std_backend_judges_the_program_token_the_caller_named() {
    let mut c = Command::new();
    c.args([with_interior_nul(r"C:\tools\setup.bat", "junk")]);
    let err = super::build_std_command(&c).expect_err("a NUL-bearing program token must be refused");
    let msg = err.to_string();
    assert!(
        !msg.contains('\0'),
        "the refusal must not carry a raw NUL into logs: {msg:?}"
    );
}

/// The mirror shape on the same default path: the std backend must never tell the caller to audit
/// batch escaping for `C:\tools\setup`, which is what Win32 would load and is not a batch file.
/// Asserted as "not the batch refusal" rather than as an `Ok`, because the token is still refused
/// — as a NUL here, and by std's own wide-string conversion a step later on Windows.
#[test]
fn the_std_backend_does_not_blame_the_batch_vector_for_a_truncated_prefix() {
    let mut c = Command::new();
    c.args([with_interior_nul(r"C:\tools\setup", ".bat")]);
    assert!(
        !matches!(super::build_std_command(&c), Err(Error::Unsupported { .. })),
        "the truncated prefix is not a batch file, so the batch vector is the wrong diagnosis"
    );
}
