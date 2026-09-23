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

/// A reap that FAILS during teardown must leave a trace in a release build, where the
/// `debug_assert` beside it is compiled out: a `log::warn!` naming the error. Both teardown arms —
/// attach failure and unresolved identity — share the one teardown, and each is driven here.
///
/// Each leg's forced error carries its own marker, and records are scanned from a mark taken just
/// before, so a concurrent test's warning cannot satisfy this one.
#[test]
fn a_failed_teardown_reap_is_logged_on_both_arms() {
    a_failed_teardown_step_is_logged_on_both_arms(
        ["cosca-reap-fail-attach-7c1e", "cosca-reap-fail-identity-b93d"],
        fault::set_force_reap_failure,
        fault::take_force_reap_failure,
    );
}

/// A KILL that fails is logged, and the teardown does NOT go on to a blocking reap: a child it
/// could not kill may still be running (EPERM from a setuid child), and `wait()` would hang the
/// spawn for as long as it runs. The reap fault is armed as a tripwire — left unconsumed, it proves
/// the reap step was never reached. Any failure but EPERM is also `debug_assert`ed; EPERM is
/// reachable without a bug.
#[test]
fn a_failed_teardown_kill_is_logged_and_skips_the_blocking_reap_on_both_arms() {
    use std::io::ErrorKind;
    crate::log_capture::install();
    let force_arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    let cases = [
        ("cosca-kill-fail-attach-4e02", ErrorKind::Other, true),
        ("cosca-kill-eperm-attach-61c7", ErrorKind::PermissionDenied, false),
        ("cosca-kill-fail-identity-d51a", ErrorKind::Other, true),
        ("cosca-kill-eperm-identity-0a8b", ErrorKind::PermissionDenied, false),
    ];
    for (index, (marker, kind, asserted)) in cases.into_iter().enumerate() {
        let force_arm = force_arms[index / 2];
        let mark = crate::log_capture::mark();
        force_arm(true);
        fault::set_force_kill_failure(marker, kind);
        fault::set_force_reap_failure("cosca-reap-tripwire-9f31");
        let outcome = std::panic::catch_unwind(|| blocker().spawn().err());
        force_arm(false);
        assert_eq!(
            fault::take_force_kill_failure(),
            None,
            "{marker}: the kill failure must be consumed"
        );
        assert_eq!(
            fault::take_force_reap_failure(),
            Some("cosca-reap-tripwire-9f31"),
            "{marker}: a failed kill must not be followed by a blocking reap"
        );
        assert_eq!(
            outcome.is_err(),
            asserted && cfg!(debug_assertions),
            "{marker}: the debug_assert fires for {kind:?} in exactly the builds that keep it"
        );
        if let Ok(err) = outcome {
            err.expect("the forced arm must fail the spawn");
        }
        assert!(
            crate::log_capture::contains_since(mark, marker),
            "{marker}: a failed teardown kill must be logged"
        );
        fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    }
}

/// A child the teardown could not kill is not left a zombie: it is handed to a detached thread
/// that reaps it once it exits on its own. Here it is blocked reading stdin, and exits when the
/// failed spawn drops the pipe's parent end; the thread signals the reap on a channel.
#[test]
fn a_child_the_teardown_cannot_kill_is_reaped_once_it_exits() {
    use crate::stdio::Stdio;
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["cat"]);
    #[cfg(windows)]
    cmd.args(["findstr", "x"]);
    cmd.stdin(Stdio::pipe_in()).unwrap().stdout(Stdio::null()).unwrap();
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive("cosca-kill-fail-alive-3b7e");
    fault::set_background_reap_notifier(reaped_tx);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || cmd.spawn().err()));
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    assert!(
        fault::take_background_reap_notifier().is_none(),
        "the teardown must take the notifier"
    );
    // `Other` is asserted in debug builds; the handoff must already have happened by then.
    assert_eq!(outcome.is_err(), cfg!(debug_assertions));
    // Blocks until the child exits and the thread has reaped it.
    let reaped = reaped_rx.recv().expect("the reaper thread must report");
    reaped.expect("the background wait must succeed");
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// Force one teardown step to fail with each marker, once per teardown arm, and check the failure
/// is consumed, logged, `debug_assert`ed in exactly the builds that keep it, and leaks no child.
fn a_failed_teardown_step_is_logged_on_both_arms(
    markers: [&'static str; 2],
    set_failure: fn(&'static str),
    take_failure: fn() -> Option<&'static str>,
) {
    crate::log_capture::install();
    let force_arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    for (marker, force_arm) in markers.into_iter().zip(force_arms) {
        let mark = crate::log_capture::mark();
        force_arm(true);
        set_failure(marker);
        let outcome = std::panic::catch_unwind(|| blocker().spawn().err());
        force_arm(false);
        assert_eq!(
            take_failure(),
            None,
            "{marker}: the teardown must consume the forced failure"
        );
        // Debug builds also trip the `debug_assert`; release builds must not panic at all.
        assert_eq!(
            outcome.is_err(),
            cfg!(debug_assertions),
            "{marker}: the debug_assert fires in exactly the builds that keep it"
        );
        if let Ok(err) = outcome {
            err.expect("the forced arm must fail the spawn");
        }
        assert!(
            crate::log_capture::contains_since(mark, marker),
            "{marker}: a failed teardown step must be logged"
        );
        fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    }
}

/// A child that exited before the teardown's kill, and whose kill still failed — a setuid zombie
/// keeps its credentials, so `kill(2)` refuses it with EPERM — is reaped, not left a zombie: an
/// exited child is reaped at once, and one not yet exited is handed to the background reaper.
/// Either way it ends reaped.
#[test]
fn a_child_whose_kill_failed_after_it_exited_is_reaped() {
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-eperm-exited-8e41",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_background_reap_notifier(reaped_tx);
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    err.expect("the forced arm must fail the spawn");
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    // Still set: the child had exited, so the teardown reaped it without the background reaper.
    // Taken: it had not, and the reaper reports once it has.
    if fault::take_background_reap_notifier().is_none() {
        let reaped = reaped_rx.recv().expect("the reaper thread must report");
        reaped.expect("the background wait must succeed");
    }
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

    // BOTH setters must route here. The rule reads `executable_path()`, which is deliberately
    // variant-agnostic, so this holds today — the case exists to stop it being "tightened" to
    // `Search` only. That would send `raw_executable()` down the std path, where std resolves a
    // bare name itself, breaking the no-resolution contract at the one backend that honours it.
    let mut raw_exe_only = Command::new();
    raw_exe_only.raw_executable("cmd").args(["cmd", "/C", "exit 0"]);
    assert!(
        super::routes_to_raw_backend(&raw_exe_only),
        "a raw_executable() routes to raw too"
    );

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

/// An environment key with an embedded NUL is refused before the process-global handle mutation
/// too. The seam's wiring is proven by the positive leg of the test above.
#[cfg(windows)]
#[test]
fn a_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .env("A\0B", "x");
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("an embedded NUL must be refused");
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput),
        "got {err:?}"
    );
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );
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

/// Normalisation leaves batch names `Path::extension()` cannot see: `.bat` is a bare name to it,
/// and a data-stream piece hides behind `:`.
#[test]
fn a_normalised_batch_path_is_refused_by_suffix_on_every_stream_piece() {
    for p in [
        r"C:\t\.bat",
        r"C:\t\SETUP.CMD",
        r"C:\t\x.exe:payload.bat",
        r"C:\t\x.bat::$DATA",
        r"C:\t\x.bat.:s",
        r"C:\t\x.bat :s",
    ] {
        assert_eq!(
            unsupported_op(super::reject_normalised_batch_path(std::path::Path::new(p))),
            format!("running {p}")
        );
    }
    for p in [
        r"C:\t\setup.exe",
        r"C:\t\setup.bat.exe",
        r"C:\t.bat\setup.exe",
        r"C:\t\batch",
    ] {
        assert!(
            super::reject_normalised_batch_path(std::path::Path::new(p)).is_ok(),
            "{p}"
        );
    }
}

/// Argv and command-line commands on the default std route (no `executable()`, no fd >= 3).
#[cfg(windows)]
fn std_routed(args: &[&str], lines: &[&str]) -> Vec<(String, Command)> {
    let mut out = Vec::new();
    for &n in args {
        let mut c = Command::new();
        c.args([n]);
        out.push((format!("args([{n:?}])"), c));
    }
    for &l in lines {
        let mut c = Command::new();
        c.commandline(l);
        out.push((format!("commandline({l:?})"), c));
    }
    for (via, c) in &out {
        assert!(!super::routes_to_raw_backend(c), "{via} must take the std route");
    }
    out
}

/// std runs a batch file through cmd.exe once `GetFullPathNameW` has trimmed the name, and a
/// `commandline()` tail reaches it unescaped, so these must be refused as they are on the raw route.
#[cfg(windows)]
#[test]
fn the_std_route_refuses_a_batch_only_normalisation_exposes() {
    // Trailing dot; one trailing space; a file named `.bat`.
    for (via, c) in std_routed(&["x.bat.", "x.bat ", ".bat"], &["x.bat. a&b"]) {
        match super::build_std_command(&c) {
            Err(Error::Unsupported { .. }) => {}
            other => panic!("{via}: expected Unsupported, got {:?}", other.map(|_| "a command")),
        }
    }
}

#[cfg(windows)]
#[test]
fn the_std_route_accepts_an_exe_named_like_a_batch() {
    for (via, c) in std_routed(&["x.bat.exe", "tool.exe"], &["x.bat.exe a&b"]) {
        if let Err(e) = super::build_std_command(&c) {
            panic!("{via}: {e:?}");
        }
    }
}

/// The Win32 verdict refuses an interior NUL too, on BOTH NUL/batch shapes — the derivation is in
/// [`super::reject_batch_path_on`]'s doc. Neither may come back as the batch refusal: on
/// `setup` + NUL + `.bat` Win32 loads `setup`, which carries no batch vector at all, and on
/// `setup.bat` + NUL + `junk` the caller's defect is the NUL that made a `.bat`-suffixed token
/// load a batch file.
///
/// Pinned on the gate itself because the gate is the std backend's ONLY NUL check: an `Ok` here is
/// a token the crate hands to `std::process` for its internals to catch or not.
#[test]
fn an_interior_nul_is_refused_on_the_win32_verdict_too() {
    let nul_then_bat = with_interior_nul("setup", ".bat");
    let bat_then_nul = with_interior_nul("setup.bat", "junk");

    // Premise: the extension is inverted on both shapes, which is why the gate cannot use it.
    assert_eq!(extension_of(&nul_then_bat), Some("bat".to_owned()));
    assert_ne!(extension_of(&bat_then_nul), Some("bat".to_owned()));

    for token in [&nul_then_bat, &bat_then_nul] {
        // An `Ok`, or the `Unsupported` batch refusal, panics in the helper.
        let msg = invalid_input_message(on_win32(token));
        assert!(msg.contains("NUL"), "the refusal must name the NUL: {msg}");
        assert!(
            !msg.contains('\0'),
            "the refusal must not carry a raw NUL into logs: {msg:?}"
        );
    }
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
/// precisely so both are reachable here. Both refuse the NUL, but each names its own reason — off
/// Win32 nothing truncates, so citing the truncation would send a Linux caller to audit a platform
/// they are not on.
#[test]
fn each_verdict_gives_the_nul_refusal_its_own_reason() {
    let bat_then_nul = with_interior_nul("x.bat", "junk");
    assert!(invalid_input_message(on_win32(&bat_then_nul)).contains("truncate"));
    assert!(!invalid_input_message(on_posix(&bat_then_nul)).contains("truncate"));
}

/// The WRAPPER, which none of the tests above reach: they spell `win32` out as data, so pinning
/// [`super::reject_batch_path`]'s `cfg!(windows)` argument to `true` leaves every one of them
/// green while POSIX callers get the Win32 diagnosis back — the regression this round already
/// fixed once, in the gate the helper is only half of.
#[test]
fn the_gate_wrapper_asks_for_this_hosts_verdict() {
    let bat_then_nul = with_interior_nul("setup.bat", "junk");
    let nul_then_bat = with_interior_nul("setup", ".bat");
    let via_host = |t: &std::ffi::OsStr| super::reject_batch_path(std::path::Path::new(t));

    let clean_bat = std::ffi::OsString::from(r"C:\tools\setup.bat");

    if cfg!(windows) {
        assert!(unsupported_op(via_host(&clean_bat)).contains("setup.bat"));
    } else {
        assert!(via_host(&clean_bat).is_ok(), "no cmd.exe here to blame");
    }
    // The NUL verdict is the same either way; the clean `.bat` above is what the argument decides.
    for token in [&bat_then_nul, &nul_then_bat] {
        let msg = invalid_input_message(via_host(token));
        assert!(msg.contains("NUL"), "the refusal must name the NUL: {msg}");
    }
}

/// The batch rule is a WIN32 verdict — why, in [`super::reject_batch_path_on`]'s doc. Both legs
/// matter: the NUL arm above must not have swallowed the rule where it does apply, and the rule
/// must not reach a host with no cmd.exe to blame.
#[test]
fn a_clean_batch_program_is_a_win32_verdict_only() {
    let token = std::ffi::OsString::from(r"C:\tools\setup.bat");
    assert!(unsupported_op(on_win32(&token)).contains("setup.bat"));
    assert!(
        on_posix(&token).is_ok(),
        "off Win32 a .bat is judged by the host that will actually run it"
    );
}

/// What makes that POSIX arm a correction rather than a preference: here `.bat` is an ordinary
/// suffix, and the gate refused a command this host executes.
#[cfg(unix)]
#[test]
fn a_posix_host_runs_its_own_executable_named_bat() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let script = dir.path().join("deploy.bat");
    // The write is serialized against every other spawn's `fork`, and the guard is dropped before
    // OUR spawn — `spawn_unelevated` takes the same lock, and a `std::sync::Mutex` is not
    // reentrant, so holding it across `spawn()` deadlocks. Scoping it to the write is what the
    // race needs anyway: `fs::write`'s descriptor is writable, and a `fork` inside that window
    // leaves the forked child holding it until it execs, during which `execve` on this script
    // returns ETXTBSY. Measured: CI's linux/amd64 lane failed exactly that way while every other
    // lane passed. Once the descriptor is closed, no later spawn can inherit it.
    {
        let _guard = crate::child::spawn::spawn_lock();
        std::fs::write(&script, "#!/bin/sh\nexit 7\n").expect("write");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let mut c = Command::new();
    c.args([script.as_os_str()]);
    let child = c.spawn().expect("a .bat this host can run must not be refused");
    assert_eq!(
        child.wait().expect("wait").code(),
        Some(7),
        "the host ran the script, so its own exit code must come back"
    );
}

/// The std backend is the DEFAULT Windows path: `args([..])` with no `executable()` and no
/// fd >= 3 is false for `routes_to_raw_backend`, so it reaches the gate through
/// [`super::build_std_command`] with no NUL check of its own.
///
/// Host-independent on purpose: what it pins is that the gate judges the token the CALLER named.
/// Before this round it read `std::process::Command::get_program()`, and std's Unix constructor
/// had already swapped a NUL-bearing program for a `<string-with-nul>` sentinel — so on this host
/// the call returned `Ok` and the token reached `spawn`.
///
/// The KIND is asserted on every host, not just off Win32: this token's extension is the one the
/// batch rule could plausibly claim, so an `.expect_err` alone would be satisfied on a Windows run
/// by the very misattribution the gate exists to prevent.
#[test]
fn the_std_backend_judges_the_program_token_the_caller_named() {
    let mut c = Command::new();
    c.args([with_interior_nul(r"C:\tools\setup.bat", "junk")]);
    // An `Ok`, or the `Unsupported` batch refusal, panics in the helper.
    let msg = invalid_input_message(super::build_std_command(&c));
    assert!(
        !msg.contains('\0'),
        "the refusal must not carry a raw NUL into logs: {msg:?}"
    );
}

/// The mirror shape on the same default path: `C:\tools\setup` + NUL + `.bat` must come back as
/// the NUL, never as the batch vector — what Win32 would load is `C:\tools\setup`, which carries
/// no batch vector at all.
///
/// Asserted as an `Io(InvalidInput)` and not merely as "not `Unsupported`": an `Ok` satisfies the
/// negative form, which cannot tell "refused for the right reason" from "not refused at all" —
/// and what follows an `Ok` here is `std::process`, whose own NUL check is an internal of another
/// crate for this one to be leaning on.
#[test]
fn the_std_backend_does_not_blame_the_batch_vector_for_a_truncated_prefix() {
    let mut c = Command::new();
    c.args([with_interior_nul(r"C:\tools\setup", ".bat")]);
    invalid_input_message(super::build_std_command(&c));
}
