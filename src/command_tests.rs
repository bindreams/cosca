use crate::command::{Command, CommandInput, ExecutableSpec};
use crate::containment::Nesting;
use crate::stdio::{Direction, ResolvedStdio, Stdio};
use crate::test_child::Console;
use crate::{ContainMode, Fd};
use std::ffi::OsString;
use std::path::Path;

fn argv(cmd: &Command) -> Vec<String> {
    match cmd.input() {
        CommandInput::Argv(v) => v.iter().map(|s| s.to_string_lossy().into_owned()).collect(),
        other => panic!("expected Argv, got {:?}", other),
    }
}

#[skuld::test]
fn new_is_empty() {
    let cmd = crate::test_child::command(Console::Hidden);
    assert!(matches!(cmd.input(), CommandInput::Empty));
    assert!(cmd.executable_path().is_none());
}

#[skuld::test]
fn args_sets_and_extends_argv() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(["git", "status"]).args(["--short"]);
    assert_eq!(argv(&cmd), ["git", "status", "--short"]);
}

#[skuld::test]
fn arg_appends_one() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.arg("echo").arg("hi");
    assert_eq!(argv(&cmd), ["echo", "hi"]);
}

#[skuld::test]
fn commandline_sets_string_source() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.commandline(r#"git "status""#);
    match cmd.input() {
        CommandInput::CommandLine(s) => assert_eq!(s, &OsString::from(r#"git "status""#)),
        other => panic!("expected CommandLine, got {:?}", other),
    }
}

#[skuld::test]
fn commandline_then_args_switches_source_and_discards() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.commandline("ignored string").args(["real", "argv"]);
    assert_eq!(argv(&cmd), ["real", "argv"]);
}

#[skuld::test]
fn args_then_commandline_switches_to_string() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(["a", "b"]).commandline("c d");
    assert!(matches!(cmd.input(), CommandInput::CommandLine(_)));
}

#[skuld::test]
fn executable_overrides_load_path_independently_of_argv() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.executable("/bin/busybox").args(["sh", "-c", "echo hi"]);
    assert_eq!(cmd.executable_path(), Some(Path::new("/bin/busybox")));
    assert_eq!(argv(&cmd), ["sh", "-c", "echo hi"]);
}

#[skuld::test]
fn stdout_shorthand_records_resolved_pipe_out() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(["x"]);
    cmd.stdout(Stdio::pipe()).unwrap();
    let fds = cmd.fds();
    assert!(matches!(
        fds.get(&Fd::STDOUT),
        Some(ResolvedStdio::Pipe(Direction::Out))
    ));
}

#[skuld::test]
fn stdin_pipe_infers_in() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.stdin(Stdio::pipe()).unwrap();
    assert!(matches!(
        cmd.fds().get(&Fd::STDIN),
        Some(ResolvedStdio::Pipe(Direction::In))
    ));
}

#[skuld::test]
fn bare_pipe_on_fd3_errs_at_attach() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    assert!(cmd.fd(3, Stdio::pipe()).is_err());
}

#[skuld::test]
fn explicit_pipe_out_on_fd3_attaches() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.fd(3, Stdio::pipe_out()).unwrap();
    assert!(matches!(
        cmd.fds().get(&Fd::from(3)),
        Some(ResolvedStdio::Pipe(Direction::Out))
    ));
}

/// A negative fd number must be refused explicitly, in both debug and release builds — not
/// silently accepted (and later dropped or aborted downstream), and not left to a debug-only
/// `debug_assert!` inside `Fd`'s `From<i32>` (which would panic here rather than return `Err`,
/// and would do nothing at all in release).
#[skuld::test]
fn fd_rejects_negative_slot_with_invalid_input() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    let err = cmd.fd(-1, Stdio::null()).expect_err("a negative fd must be rejected");
    match err {
        crate::error::Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
    // The rejection must not have inserted anything into the map.
    assert!(cmd.fds().is_empty());
}

/// `i32::MIN` is the sharpest edge for the non-negativity check: `.abs()` or a naive negation
/// would overflow on it. Also must be an explicit `Err`, not a panic.
#[skuld::test]
fn fd_rejects_i32_min_slot_with_invalid_input() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    let err = cmd.fd(i32::MIN, Stdio::null()).expect_err("i32::MIN must be rejected");
    match err {
        crate::error::Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
}

#[skuld::test]
fn kill_on_drop_defaults_true_and_toggles() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    assert!(cmd.kill_on_drop_flag());
    cmd.kill_on_drop(false);
    assert!(!cmd.kill_on_drop_flag());
}

#[skuld::test]
fn fd_last_set_wins_for_same_slot() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stdout(Stdio::null()).unwrap();
    assert!(matches!(cmd.fds().get(&Fd::STDOUT), Some(ResolvedStdio::Null)));
}

#[skuld::test]
fn inherit_resolves_through_builder() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.stderr(Stdio::inherit()).unwrap();
    assert!(matches!(cmd.fds().get(&Fd::STDERR), Some(ResolvedStdio::Inherit)));
}

#[skuld::test]
fn null_resolves_through_builder() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.stdin(Stdio::null()).unwrap();
    assert!(matches!(cmd.fds().get(&Fd::STDIN), Some(ResolvedStdio::Null)));
}

#[skuld::test]
fn merge_resolves_through_builder() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.stderr(Stdio::merge(Fd::STDOUT)).unwrap();
    assert!(matches!(
        cmd.fds().get(&Fd::STDERR),
        Some(ResolvedStdio::Merge(Fd::STDOUT))
    ));
}

#[skuld::test]
fn env_ops_recorded_in_order() {
    use crate::command::EnvOp;
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.env_clear();
    cmd.env("A", "1");
    cmd.env_remove("B");
    cmd.envs([("C", "3"), ("D", "4")]);
    let ops = cmd.env_ops();
    assert!(matches!(ops[0], EnvOp::Clear));
    assert!(matches!(&ops[1], EnvOp::Set(k, v) if k == "A" && v == "1"));
    assert!(matches!(&ops[2], EnvOp::Remove(k) if k == "B"));
    assert!(matches!(&ops[3], EnvOp::Set(k, v) if k == "C" && v == "3"));
    assert!(matches!(&ops[4], EnvOp::Set(k, v) if k == "D" && v == "4"));
    assert_eq!(ops.len(), 5);
}

#[skuld::test]
fn envs_empty_iterator_records_nothing() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.envs::<_, &str, &str>([]);
    assert!(cmd.env_ops().is_empty());
}

#[skuld::test]
fn cwd_recorded() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.current_dir("/tmp");
    assert_eq!(cmd.cwd(), Some(Path::new("/tmp")));
}

#[skuld::test]
fn contain_records_strongest_request() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.contain();
    let req = cmd.contain_request();
    assert_eq!(req.mode, Some(ContainMode::Strongest));
    assert_eq!(req.nesting, Nesting::Mark);
}

#[skuld::test]
fn uncontained_by_default() {
    assert_eq!(crate::test_child::command(Console::Hidden).contain_request().mode, None);
}

#[skuld::test]
fn contain_with_and_nesting_recorded() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.contain_with(ContainMode::TreeWalk).nesting(Nesting::Opaque);
    let req = cmd.contain_request();
    assert_eq!(req.mode, Some(ContainMode::TreeWalk));
    assert_eq!(req.nesting, Nesting::Opaque);
}

#[skuld::test]
fn elevate_enables_with_defaults() {
    let mut c = crate::test_child::command(Console::Hidden);
    c.args(["id", "-u"]).elevate();
    let req = c.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Auto);
    assert!(matches!(req.auth, crate::elevation::Auth::Interactive));
}

#[skuld::test]
fn elevation_overrides_apply_and_enable() {
    let mut c = crate::test_child::command(Console::Hidden);
    c.arg("id")
        .elevation_backend(crate::elevation::Backend::Doas)
        .elevation_auth(crate::elevation::Auth::NonInteractive);
    let req = c.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Doas);
    assert!(matches!(req.auth, crate::elevation::Auth::NonInteractive));
}

#[skuld::test]
fn command_without_elevate_is_disabled() {
    let c = crate::test_child::command(Console::Hidden);
    assert!(!c.elevation_request().enabled);
}

// output()/status()/read() each force their own stdin default (null or inherit) before
// spawning. Auth::Stdin needs SOLE ownership of fd0 to feed the backend the password, so
// that internal default must not trip the same "caller-configured stdin" rejection a real
// user-supplied stdin would — that would make Auth::Stdin unusable via any of the three
// convenience methods, a regression this pins at the builder level (no live spawn needed).
#[skuld::test]
fn default_stdin_is_not_forced_when_auth_stdin_reserves_fd0() {
    let mut c = crate::test_child::command(Console::Hidden);
    c.args(["id"])
        .elevation_auth(crate::elevation::Auth::Stdin(crate::elevation::Secret::new("pw")));
    c.apply_default_stdin(Stdio::null()).unwrap();
    assert!(
        c.fds().get(&Fd::STDIN).is_none(),
        "Auth::Stdin must keep fd0 unconfigured until the elevation rewrite wires its password channel"
    );
}

#[skuld::test]
fn default_stdin_is_forced_without_auth_stdin() {
    let mut c = crate::test_child::command(Console::Hidden);
    c.args(["id"]);
    c.apply_default_stdin(Stdio::null()).unwrap();
    assert!(matches!(c.fds().get(&Fd::STDIN), Some(ResolvedStdio::Null)));
}

#[skuld::test]
fn suppress_fd_marker_sets_the_flag_a_fresh_command_does_not_have() {
    let mut derived = crate::test_child::command(Console::Hidden);
    assert!(!derived.fd_marker_suppressed(), "a fresh command suppresses nothing");
    derived.suppress_fd_marker();
    assert!(derived.fd_marker_suppressed());
}

// ===== creation flags =====

/// `no_window()` is the one portable flag intent: it records the same request on every platform,
/// and only the lowering differs (a creation flag / a show-command / nothing at all).
#[skuld::test]
fn no_window_is_recorded_on_every_platform() {
    let mut cmd = crate::test_child::command(Console::Asked);
    assert!(!cmd.flags_request().no_window, "the default requests nothing");
    cmd.no_window();
    assert!(cmd.flags_request().no_window);
}

#[cfg(windows)]
#[skuld::test]
fn detached_and_raw_flags_are_recorded() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    let before = *cmd.flags_request();
    assert!(!before.detached);
    assert_eq!(before.raw, 0);
    cmd.detached().creation_flags(0x0000_0040);
    let after = *cmd.flags_request();
    assert!(after.detached);
    assert_eq!(after.raw, 0x0000_0040);
}

/// `creation_flags` REPLACES, matching `std::os::windows::process::CommandExt::creation_flags`
/// (`self.flags = flags;`). Or-in would make a bit unclearable, which is the one thing a raw
/// hatch must never do — so `creation_flags(0)` is the documented way to clear a word set
/// earlier, and this test would fail under an or-in implementation at both later calls.
#[cfg(windows)]
#[skuld::test]
fn repeated_creation_flags_calls_replace_rather_than_accumulate() {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.creation_flags(0x0000_0040);
    assert_eq!(cmd.flags_request().raw, 0x0000_0040);
    cmd.creation_flags(0x0000_0080);
    assert_eq!(
        cmd.flags_request().raw,
        0x0000_0080,
        "the second call replaces the first"
    );
    cmd.creation_flags(0);
    assert_eq!(cmd.flags_request().raw, 0, "zero clears a word set earlier");
}

// ===== executable vs raw_executable =====

/// The two setters differ only in whether the path is later resolved, so the discriminant IS the
/// feature: with one field and no variant, nothing downstream can tell "find this for me" from
/// "load exactly this", and both contracts cannot coexist.
#[skuld::test]
fn executable_records_search_and_raw_executable_records_exact() {
    let mut a = crate::test_child::command(Console::Hidden);
    a.executable("helper");
    assert!(matches!(a.executable_spec(), Some(ExecutableSpec::Search(p)) if p == Path::new("helper")));

    let mut b = crate::test_child::command(Console::Hidden);
    b.raw_executable("helper");
    assert!(matches!(b.executable_spec(), Some(ExecutableSpec::Exact(p)) if p == Path::new("helper")));
}

/// One field, two setters: they are alternatives rather than additive, and the LAST call wins
/// whichever order they arrive in. A caller switching from one to the other must not end up
/// carrying both intents.
#[skuld::test]
fn last_executable_setter_wins_in_either_order() {
    let mut a = crate::test_child::command(Console::Hidden);
    a.executable("search-me").raw_executable("exact-me");
    assert!(matches!(a.executable_spec(), Some(ExecutableSpec::Exact(p)) if p == Path::new("exact-me")));

    let mut b = crate::test_child::command(Console::Hidden);
    b.raw_executable("exact-me").executable("search-me");
    assert!(matches!(b.executable_spec(), Some(ExecutableSpec::Search(p)) if p == Path::new("search-me")));
}

/// `executable_path()` stays variant-agnostic on purpose: most callers (the elevation `argv[0]`
/// guards, backend routing, the argv and command-line builders) want only the path and don't care
/// which setter produced it. Keeping this getter working means only the sites that actually
/// resolve need to special-case `Exact`.
#[skuld::test]
fn executable_path_is_variant_agnostic() {
    let mut a = crate::test_child::command(Console::Hidden);
    a.executable("/bin/busybox");
    assert_eq!(a.executable_path(), Some(Path::new("/bin/busybox")));

    let mut b = crate::test_child::command(Console::Hidden);
    b.raw_executable("/bin/busybox");
    assert_eq!(b.executable_path(), Some(Path::new("/bin/busybox")));
}

// A failure after the spawn reports what became of the child =====

#[cfg(unix)]
use crate::test_child::held_uncontained_blocker as held_blocker;
#[cfg(unix)]
use crate::test_groups::setuid;

/// A run-to-completion helper that fails after its spawn kills and reaps the child, as its drop
/// would, and says so.
///
/// Mutant: the failure reports `Unknown` without tearing the child down.
#[cfg(unix)]
#[skuld::test]
fn a_failure_after_the_spawn_tears_the_child_down_and_says_so() {
    let (child, writer) = held_blocker(true);
    let id = child.id();
    // Released after the kill: a kill that sent nothing exits 0.
    let teardown = crate::child::spawn::fault::release_at_drop_kill(writer);
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), child);
    teardown.assert_killed();
    assert_eq!(error.fate(), Some(crate::error::ChildFate::Reaped), "{error}");
    assert!(
        matches!(error, crate::error::Error::MayHaveStarted { unreaped: None, .. }),
        "{error}"
    );
    assert_eq!(id.is_alive(), crate::identity::Liveness::Dead, "{error}");
}

/// A child `kill_on_drop(false)` keeps is left alone, and the failure names it.
///
/// Mutant: the failure tears down a child that opted out of it.
#[cfg(unix)]
#[skuld::test]
fn a_failure_after_the_spawn_leaves_a_child_that_opted_out() {
    let (child, writer) = held_blocker(false);
    let id = child.id();
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), child);
    assert_eq!(
        error.fate(),
        Some(crate::error::ChildFate::Running { id: Some(id) }),
        "{error}"
    );
    assert!(
        matches!(error, crate::error::Error::MayHaveStarted { unreaped: None, .. }),
        "the caller chose to keep this child: {error}"
    );
    assert_eq!(id.is_alive(), crate::identity::Liveness::Alive, "{error}");
    drop(writer);
}

/// A child that opted out of the teardown and had its exit collected is reaped, not running.
///
/// Mutant: an opted-out child is always reported `Running`.
#[cfg(unix)]
#[skuld::test]
fn a_failure_after_the_spawn_does_not_call_a_collected_child_running() {
    let (child, writer) = held_blocker(false);
    drop(writer);
    child.wait().expect("the child exits once its stdin closes");
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), child);
    assert_eq!(error.fate(), Some(crate::error::ChildFate::Reaped), "{error}");
}

/// A failure after the spawn of an elevation backend says an elevated program behind it may still
/// run; one of a plain child does not.
///
/// Mutants: the note on a plain child; no note on a backend.
#[cfg(unix)]
#[skuld::test]
fn a_failure_after_the_spawn_notes_the_elevated_program_only_behind_a_backend() {
    use crate::elevation::{Backend, ElevatedVia};
    let note = "an elevated program behind it may still run";
    // Each writer is released after the kill: a kill that sent nothing exits 0.
    let (plain, w1) = held_blocker(true);
    let teardown = crate::child::spawn::fault::release_at_drop_kill(w1);
    let plain = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), plain);
    assert!(!plain.to_string().contains(note), "{plain}");
    teardown.assert_killed();
    drop(teardown);

    let (mut wrapped, w2) = held_blocker(true);
    let teardown = crate::child::spawn::fault::release_at_drop_kill(w2);
    wrapped.set_elevation(crate::child::front_kill_tests::report(ElevatedVia::Wrapped(
        Backend::Sudo,
    )));
    let wrapped = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), wrapped);
    teardown.assert_killed();
    assert_eq!(wrapped.fate(), Some(crate::error::ChildFate::Reaped), "{wrapped}");
    assert!(wrapped.to_string().contains(note), "{wrapped}");
}

/// A run-to-completion helper whose child refuses the kill of its teardown (a setuid-root process
/// the caller may not signal) hands the child back in the error, running, with the same identity.
///
/// Mutants: the child is left running and dropped; the fate is `Unknown`; the warn says the child
/// is left running.
#[cfg(unix)]
#[skuld::test]
fn a_failure_after_the_spawn_hands_back_a_child_whose_kill_is_refused(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    crate::log_capture::install();
    let (child, stdin) = crate::test_privilege::spawn_setuid_blocker();
    let id = child.id();
    let mark = crate::log_capture::mark();

    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), child);

    let (_, fate, handed_back) = crate::test_child::expect_may_have_started_parts(error, stdin);

    assert_eq!(fate, crate::error::ChildFate::Running { id: Some(id) });
    assert_eq!(handed_back.unreaped().pid(), Some(id.pid()));
    assert_eq!(id.is_alive(), crate::identity::Liveness::Alive);
    let warns = crate::log_capture::records_since_on_current_thread(mark, "handed back to the caller");
    assert_eq!(warns.len(), 1, "{warns:?}");
    let status = handed_back.wait();
    assert!(status.success(), "the helper exits on EOF: {status:?}");
}

// A run-to-completion helper that fails after its spawn =====

/// The answer of a run-to-completion helper that failed after its spawn: the program may have
/// started, the fate is `fate`, no child is handed back, the wrapper flag is `wrapper`, and the cause
/// is the seam's.
#[track_caller]
fn assert_failed_after_the_spawn(error: crate::error::Error, fate: crate::error::ChildFate, wrapper: bool) {
    let crate::error::Error::MayHaveStarted {
        fate: got,
        wrapper_elevated,
        source,
        unreaped,
    } = &error
    else {
        panic!("expected MayHaveStarted, got {error:?}");
    };
    assert!(unreaped.is_none(), "a reaped child is not handed back: {error:?}");
    assert_eq!(*got, fate, "{error}");
    assert_eq!(*wrapper_elevated, wrapper, "{error}");
    assert!(
        matches!(**source, crate::error::Error::Io(ref e) if e.to_string() == crate::child::spawn::failure::seams::FAILURE),
        "{source:?}"
    );
}

/// `output`, `status` and `read` each say the program may have started when their pump or wait
/// fails after the spawn, with the fate their teardown gave the child and the wrapper flag of the
/// child. Pins each public method's routing through `after_the_spawn`.
///
/// Mutants: a helper returns the cause bare; drops the fate; drops the wrapper flag.
#[skuld::test]
fn output_status_and_read_fail_as_may_have_started_after_the_spawn() {
    use crate::child::spawn::failure::seams;
    use crate::error::ChildFate;
    for wrapper in [false, true] {
        let _wrapper = wrapper.then(seams::pretend_wrapper);
        let mut cmd = crate::test_child::command(Console::Hidden);
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        let _pump = seams::fail_the_next_pump();
        assert_failed_after_the_spawn(
            cmd.output().expect_err("a failed pump fails `output`"),
            ChildFate::Reaped,
            wrapper,
        );
        let _pump = seams::fail_the_next_pump();
        assert_failed_after_the_spawn(
            cmd.read().expect_err("a failed pump fails `read`"),
            ChildFate::Reaped,
            wrapper,
        );
        let _wait = seams::fail_the_next_wait();
        assert_failed_after_the_spawn(
            cmd.status().expect_err("a failed wait fails `status`"),
            ChildFate::Reaped,
            wrapper,
        );
    }
}

/// `read`'s invalid UTF-8 of a wrapper-elevated child keeps the wrapper flag, as the pump's and
/// wait's failures do.
///
/// Mutant: `read` builds the invalid-UTF-8 error without the child's wrapper flag.
#[cfg(unix)]
#[skuld::test]
fn read_of_invalid_utf8_behind_a_wrapper_keeps_the_wrapper_flag() {
    for wrapper in [false, true] {
        let _wrapper = wrapper.then(crate::child::spawn::failure::seams::pretend_wrapper);
        let mut cmd = crate::test_child::command(Console::Hidden);
        cmd.args(["printf", "\\377"]);
        let error = cmd.read().expect_err("invalid UTF-8 fails `read`");
        let crate::error::Error::MayHaveStarted {
            fate,
            wrapper_elevated,
            source,
            ..
        } = &error
        else {
            panic!("expected MayHaveStarted, got {error:?}");
        };
        assert_eq!(*fate, crate::error::ChildFate::Reaped, "`read` collected the exit");
        assert_eq!(*wrapper_elevated, wrapper, "{error}");
        assert!(
            matches!(**source, crate::error::Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData),
            "{source:?}"
        );
    }
}
