use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _, RawFd};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};

use crate::test_own_process::{
    child_args, child_completion, drain, is_reexecution, own_process, role, run, test_path, Completion, FailureKind,
    Role, ENV,
};
use crate::test_spawn::spawn;

const FIXTURE: &str = "test_own_process_tests::fixture_records_its_pid_and_misbehaves_on_request";
const MODE: &str = "COSCA_TEST_OWN_PROCESS_FIXTURE_MODE";
const PIDFILE: &str = "COSCA_TEST_OWN_PROCESS_FIXTURE_PIDFILE";

// The gated body =====

#[test]
fn the_body_runs_only_in_the_re_executed_process() {
    let Some(_done) = own_process(test_path!(the_body_runs_only_in_the_re_executed_process), spawn) else {
        return;
    };
    assert_eq!(
        std::env::var(ENV).unwrap().splitn(3, ':').nth(2),
        Some("test_own_process_tests::the_body_runs_only_in_the_re_executed_process")
    );
}

/// Fixture driven by `MODE` and `PIDFILE`; the tests below run it via `run` or a subprocess.
#[test]
fn fixture_records_its_pid_and_misbehaves_on_request() {
    let Some(_done) = own_process(test_path!(fixture_records_its_pid_and_misbehaves_on_request), spawn) else {
        return;
    };
    if let Some(path) = std::env::var_os(PIDFILE) {
        std::fs::write(path, std::process::id().to_string()).expect("record the pid");
    }
    match std::env::var(MODE).as_deref() {
        Ok("panic") => panic!("asked to fail"),
        Ok("exit") => std::process::exit(0),
        Ok("exit-after-done") => {
            drop(_done);
            std::process::exit(1);
        }
        Ok("spawn-child") => {
            let token_fd: RawFd = std::env::var(ENV).unwrap().split(':').nth(1).unwrap().parse().unwrap();
            // The control: a pipe end of the token's kind, deliberately not close-on-exec.
            let (control, _write) = std::io::pipe().expect("pipe");
            fcntl(control.as_fd(), FcntlArg::F_SETFD(FdFlag::empty())).expect("clear close-on-exec");
            assert!(
                child_inherits(control.as_raw_fd()),
                "the probe must see a descriptor the child does inherit"
            );
            assert!(
                !child_inherits(token_fd),
                "the body's child inherited the token fd {token_fd}"
            );
        }
        _ => {}
    }
}

/// Whether a child spawned now inherits descriptor `fd`. `/dev/fd/<n>` exists in the child only if
/// it did.
fn child_inherits(fd: RawFd) -> bool {
    let status = crate::test_spawn::status(std::process::Command::new("sh").args([
        "-c",
        "if test -e /dev/fd/$0; then exit 7; fi",
        &fd.to_string(),
    ]))
    .expect("spawn the body's child");
    match status.code() {
        Some(7) => true,
        Some(0) => false,
        other => panic!("the probe failed: {other:?}"),
    }
}

// The run reports the body =====

#[test]
fn a_returning_body_passes_the_run() {
    run(FIXTURE, &[], spawn).expect("a body that returns normally passes");
}

#[test]
fn a_failing_body_fails_the_run() {
    let failure = run(FIXTURE, &[(MODE, "panic")], spawn).expect_err("a body that panics must fail the run");
    assert!(matches!(failure.kind, FailureKind::Exited(_)), "got {:?}", failure.kind);
    assert!(
        failure.to_string().contains("asked to fail"),
        "the report must carry the panic: {failure}"
    );
}

#[test]
fn a_body_that_exits_zero_mid_way_fails_the_run() {
    let failure = run(FIXTURE, &[(MODE, "exit")], spawn).expect_err("exit(0) mid-body must not count as a pass");
    assert!(matches!(failure.kind, FailureKind::DidNotReturn), "got {failure}");
}

#[test]
fn a_body_that_reports_completion_then_exits_non_zero_fails_the_run() {
    let failure = run(FIXTURE, &[(MODE, "exit-after-done")], spawn).expect_err("a non-zero exit is not a pass");
    assert!(matches!(failure.kind, FailureKind::Exited(_)), "got {failure}");
}

/// A child the body spawns must not hold the token pipe's write end: it would outlive the body
/// with a copy of the parent's token.
#[test]
fn the_bodys_children_do_not_inherit_the_token_fd() {
    run(FIXTURE, &[(MODE, "spawn-child")], spawn).expect("the body's child must not hold the token fd");
}

#[test]
fn a_filter_that_matches_no_test_fails_the_run() {
    let failure = run("test_own_process_tests::no_such_test", &[], spawn).expect_err("nothing ran, so nothing passed");
    assert!(matches!(failure.kind, FailureKind::NeverStarted), "got {failure}");
}

// The verdict does not wait for EOF =====

/// A long-lived process holding a write end of the token pipe, standing in for an unrelated
/// process that forked while the end was not yet close-on-exec.
struct Bystander(std::process::Child);

impl Bystander {
    fn holding(write: std::io::PipeWriter) -> Bystander {
        Bystander(
            crate::test_spawn::spawn(
                std::process::Command::new("cat")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::from(write)),
            )
            .expect("spawn the bystander"),
        )
    }
}

impl Drop for Bystander {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        self.0.wait().expect("reap the bystander");
    }
}

fn nonblocking_pipe() -> (std::io::PipeReader, std::io::PipeWriter) {
    let (read, write) = std::io::pipe().expect("pipe");
    fcntl(read.as_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).expect("non-blocking read end");
    (read, write)
}

#[test]
fn drain_returns_what_an_exited_writer_left_while_a_bystander_holds_the_write_end() {
    let (mut read, mut write) = nonblocking_pipe();
    let bystander = Bystander::holding(write.try_clone().expect("dup the write end"));
    write.write_all(b"started returned").expect("write");
    drop(write);
    assert_eq!(drain(&mut read).expect("drain"), b"started returned");
    drop(bystander);
}

#[test]
fn drain_returns_what_is_left_at_end_of_file() {
    let (mut read, mut write) = nonblocking_pipe();
    write.write_all(b"abc").expect("write");
    drop(write);
    assert_eq!(drain(&mut read).expect("drain"), b"abc");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "nonblocking")]
fn drain_refuses_a_blocking_pipe() {
    let (mut read, write) = std::io::pipe().expect("pipe");
    // No writer left, so a mutant that skips the check reads EOF instead of blocking.
    drop(write);
    drain(&mut read).expect("unreachable: drain panics first");
}

// The gate =====

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

const TEST: &str = "m::t";

fn value(pid: u32, fd: i32, test: &str) -> String {
    format!("{pid}:{fd}:{test}")
}

fn genuine_args() -> Vec<OsString> {
    child_args(TEST).iter().map(OsString::from).collect()
}

#[test]
fn role_without_the_variable_is_parent() {
    assert_eq!(role(None, 42, &genuine_args(), TEST), Role::Parent);
}

#[test]
fn role_accepts_the_parents_pid_the_test_and_the_exact_argv() {
    assert_eq!(
        role(Some(&value(42, 7, TEST)), 42, &genuine_args(), TEST),
        Role::Child { token_fd: 7 }
    );
}

#[test]
fn role_rejects_a_value_set_by_another_process() {
    assert_eq!(role(Some(&value(41, 7, TEST)), 42, &genuine_args(), TEST), Role::Parent);
}

#[test]
fn role_rejects_a_value_naming_another_test() {
    assert_eq!(
        role(Some(&value(42, 7, "m::other")), 42, &genuine_args(), TEST),
        Role::Parent
    );
}

#[test]
fn role_rejects_every_argv_that_is_not_exactly_the_single_test_shape() {
    let shared: &[&[&str]] = &[
        &[],
        &["--exact", TEST],
        &["--exact", TEST, "--test-threads=1"],
        &["--exact", TEST, "--test-threads=4", "--include-ignored", "--nocapture"],
        &["--exact", TEST, "--test-threads=1", "--include-ignored"],
        &["--exact", TEST, "--test-threads=1", "--nocapture", "--include-ignored"],
        &["--exact", TEST, "--test-threads=1", "--include-ignored", "other"],
        &[TEST, "--exact", "--test-threads=1", "--include-ignored", "--nocapture"],
        &[
            "--exact",
            "m::other",
            "--test-threads=1",
            "--include-ignored",
            "--nocapture",
        ],
        &["--test-threads=1", "--include-ignored", "--exact", TEST, "--nocapture"],
    ];
    for argv in shared {
        assert_eq!(
            role(Some(&value(42, 7, TEST)), 42, &args(argv), TEST),
            Role::Parent,
            "{argv:?}"
        );
    }
}

#[test]
fn role_rejects_malformed_values() {
    for bad in [
        "",
        TEST,
        "42",
        "42:7",
        "x:7:m::t",
        "42:x:m::t",
        "42:-1:m::t",
        "42:2:m::t",
    ] {
        assert_eq!(role(Some(bad), 42, &genuine_args(), TEST), Role::Parent, "{bad:?}");
    }
}

/// A process with a forged `ENV` (right test, and where possible right parent) but not the exact
/// argv must not run the body itself.
#[test]
fn a_forged_environment_never_runs_the_body_in_a_shared_process() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pidfile = dir.path().join("pid");
    let shared: Vec<String> = ["--exact", FIXTURE].map(String::from).to_vec();
    let exact: Vec<String> = child_args(FIXTURE).map(String::from).to_vec();
    let forged = [
        // Forged values with a shared argv: the bare test name, and a value naming another parent.
        (shared.clone(), FIXTURE.to_string()),
        (shared.clone(), value(u32::MAX, 3, FIXTURE)),
        // The exact argv, but a value another process set (`u32::MAX` is never a pid, so never our
        // child's parent), or no shape of the scheme at all.
        (exact.clone(), value(u32::MAX, 3, FIXTURE)),
        (exact.clone(), FIXTURE.to_string()),
    ];
    for (argv, forged_value) in forged {
        let child = crate::test_spawn::spawn(
            crate::test_reexec::command(std::env::current_exe().expect("current_exe"))
                .args(&argv)
                .env(ENV, &forged_value)
                .env(PIDFILE, &pidfile)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()),
        )
        .expect("spawn the forged process");
        let forged_pid = child.id();
        child.wait_with_output().expect("wait for the forged process");
        let ran_in = std::fs::read_to_string(&pidfile).expect("the body must run somewhere");
        assert_ne!(
            ran_in,
            forged_pid.to_string(),
            "{forged_value:?} with {argv:?} made the body run in a shared process"
        );
        std::fs::remove_file(&pidfile).expect("reset the pid file");
    }
}

// The completion guard =====

fn token_pipe() -> (std::io::PipeReader, Completion) {
    let (read, write) = std::io::pipe().expect("pipe");
    (read, Completion(File::from(std::os::fd::OwnedFd::from(write))))
}

fn drained(mut read: std::io::PipeReader) -> Vec<u8> {
    use std::io::Read as _;
    let mut got = Vec::new();
    read.read_to_end(&mut got)
        .expect("read to EOF: the only write end is dropped");
    got
}

#[test]
fn a_completion_dropped_normally_reports() {
    let (read, done) = token_pipe();
    drop(done);
    assert!(!drained(read).is_empty());
}

#[test]
fn a_completion_dropped_while_panicking_reports_nothing() {
    let (read, done) = token_pipe();
    std::panic::catch_unwind(move || {
        let _done = done;
        panic!("the body failed");
    })
    .expect_err("the closure panics");
    assert_eq!(drained(read), b"");
}

// Pins the flag until #234 removes the last `#[ignore]`; a behavioural test would need an
// `#[ignore]`d fixture, which the project forbids.
#[test]
fn the_child_runs_ignored_tests_too() {
    assert!(child_args("m::t").contains(&"--include-ignored"));
}

// A re-executed child that is not accepted panics instead of re-executing =====

#[test]
fn a_reexecution_is_named_by_this_test_and_the_real_parent() {
    assert!(is_reexecution(Some(&value(42, 7, TEST)), 42, TEST));
    assert!(!is_reexecution(None, 42, TEST));
    assert!(!is_reexecution(Some(&value(41, 7, TEST)), 42, TEST));
    assert!(!is_reexecution(Some(&value(42, 7, "m::other")), 42, TEST));
    assert!(!is_reexecution(Some("garbage"), 42, TEST));
}

/// A process this one launched with a value that names it as parent and the fixture as the test,
/// but without the exact argv, is a re-executed child that was not accepted: it must panic, not
/// run the body and not re-execute.
#[test]
fn a_reexecuted_child_that_is_not_accepted_panics_instead_of_re_executing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pidfile = dir.path().join("pid");
    let output = crate::test_spawn::output_captured(
        crate::test_reexec::command(std::env::current_exe().expect("current_exe"))
            .args(["--exact", FIXTURE])
            .env(ENV, value(std::process::id(), 3, FIXTURE))
            .env(PIDFILE, &pidfile),
    )
    .expect("spawn the unaccepted child");
    assert!(!output.status.success(), "an unaccepted child must fail");
    assert!(!pidfile.exists(), "the body must not run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        format!("{stdout}{stderr}").contains("not accepted as its own process"),
        "{stdout}{stderr}"
    );
}

#[test]
fn child_completion_in_an_ordinary_process_is_none_and_runs_nothing() {
    assert!(child_completion(test_path!(
        child_completion_in_an_ordinary_process_is_none_and_runs_nothing
    ))
    .is_none());
}
