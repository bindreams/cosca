//! `Unreaped`'s contract, on a child held as a spawn teardown holds it: `wait` reaps and returns
//! the status, `leak` gives the child up unreaped, and `Drop` blocks until the child exits.

use super::{Held, Unreaped};
use crate::identity::{ProcessId, Resolved};

/// A child blocked reading stdin until the returned end drops, and its identity.
fn blocked_child() -> (std::process::Child, std::process::ChildStdin, ProcessId) {
    let mut child = {
        // Raw std bypasses cosca's spawn path and its internal `spawn_lock()`, so it is taken here
        // by hand: a macOS fork must not transiently inherit another test's fd-marker write end.
        let _guard = crate::child::spawn::spawn_lock();
        let mut cmd = if cfg!(windows) {
            let mut cmd = std::process::Command::new("findstr");
            cmd.arg("x");
            cmd
        } else {
            std::process::Command::new("cat")
        };
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child blocked on stdin")
    };
    let stdin = child.stdin.take().expect("piped stdin");
    let Resolved::Found(id) = ProcessId::of(child.id()) else {
        panic!("an unreaped child resolves");
    };
    (child, stdin, id)
}

/// `releases_ownership` is cosca's single Unix ownership classification: only `ECHILD` — something
/// else already reaped the child — says the pid may now name another process. Every other errno,
/// including a too-old kernel's `EINVAL` from `waitid(P_PIDFD)`, and any non-OS `io::Error` other
/// than `tokio_wait_blocking`'s own `ReapedElsewhere` marker (see the next test), says nothing
/// about ownership and must not release the child.
#[cfg(unix)]
#[test]
fn releases_ownership_is_true_only_for_echild() {
    assert!(
        super::releases_ownership(&std::io::Error::from_raw_os_error(libc::ECHILD)),
        "ECHILD means something else already reaped the child"
    );
    assert!(
        !super::releases_ownership(&std::io::Error::from_raw_os_error(libc::EINVAL)),
        "EINVAL (a too-old kernel's waitid(P_PIDFD)) says nothing about ownership"
    );
    assert!(
        !super::releases_ownership(&std::io::Error::from_raw_os_error(libc::EAGAIN)),
        "a transient errno says nothing about ownership"
    );
    assert!(
        !super::releases_ownership(&std::io::Error::other("transient failure")),
        "a non-OS error says nothing about ownership"
    );
}

/// `tokio_wait_blocking`'s own marker for the one case with no real errno to carry it: the child
/// was confirmed reapable, then `try_wait` found no exit waiting for it. `releases_ownership` must
/// recognize it exactly as it recognizes a genuine `ECHILD` — see
/// `wait_forgets_a_tokio_child_that_loses_tokios_own_reap_race` for the end-to-end proof through
/// `Unreaped::wait`.
#[cfg(all(unix, feature = "tokio"))]
#[test]
fn releases_ownership_is_true_for_the_reaped_elsewhere_marker() {
    assert!(super::releases_ownership(&std::io::Error::other(
        super::ReapedElsewhere("the child exited, yet tokio could not reap it")
    )));
}

/// `wait_status_raw` is `bare_wait`'s pure encoding of a `waitid` result as `waitpid` would report
/// it. A signalled exit's core-dump bit (`0x80`) must survive alongside the signal number, not be
/// dropped by the `& 0x7f` mask: `status.dumped()` (rustix's `WaitIdStatus::dumped`) is the only
/// input that tells the two apart, since a coredumped exit still reports the signal that caused it.
#[cfg(target_os = "linux")]
#[test]
fn wait_status_raw_sets_the_coredump_bit_only_when_the_child_dumped() {
    use std::os::unix::process::ExitStatusExt;

    let dumped = std::process::ExitStatus::from_raw(super::wait_status_raw(None, Some(libc::SIGSEGV), true));
    assert_eq!(dumped.signal(), Some(libc::SIGSEGV), "{dumped:?}");
    assert!(
        dumped.core_dumped(),
        "the core-dump bit must survive the encoding: {dumped:?}"
    );

    let not_dumped = std::process::ExitStatus::from_raw(super::wait_status_raw(None, Some(libc::SIGSEGV), false));
    assert_eq!(not_dumped.signal(), Some(libc::SIGSEGV), "{not_dumped:?}");
    assert!(
        !not_dumped.core_dumped(),
        "a signalled exit that did not dump core must not report one: {not_dumped:?}"
    );

    let exited = std::process::ExitStatus::from_raw(super::wait_status_raw(Some(0), None, false));
    assert_eq!(exited.code(), Some(0), "{exited:?}");
    assert!(!exited.core_dumped(), "a clean exit never dumps core: {exited:?}");

    // Raw status `0` is indistinguishable from a real clean exit: `WIFEXITED(0)` is true (the
    // low 7 bits are 0) and `WEXITSTATUS(0)` is 0, on every POSIX encoding, so `wait_status_raw`'s
    // `(None, None)` fallback decodes as `code() == Some(0)`, not as "nothing happened".
    let neither = std::process::ExitStatus::from_raw(super::wait_status_raw(None, None, false));
    assert_eq!(neither.code(), Some(0), "{neither:?}");
    assert_eq!(neither.signal(), None, "{neither:?}");
}

#[test]
fn wait_blocks_until_the_child_exits_and_reaps_it() {
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    assert_eq!(unreaped.pid(), id.pid());
    drop(stdin);
    let status = unreaped.wait().expect("wait for the child");
    // Its own exit, on end of input: `cat` succeeds, and `findstr` finds no match.
    assert_eq!(status.code(), Some(if cfg!(windows) { 1 } else { 0 }), "{status:?}");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// `Drop` waits: the child is still running when the `Unreaped` drops, and reaped once it returns
/// — a `Drop` that did not wait would leave it running, or a zombie still holding its identity.
#[test]
fn drop_blocks_until_the_child_exits_and_reaps_it() {
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    drop(stdin);
    drop(unreaped);
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// `leak` gives the child up without reaping it, and says so: here the child, once it exits, is
/// still this process's to reap, which only an unreaped child is.
#[cfg(unix)]
#[test]
fn leak_gives_the_child_up_unreaped_and_logs_it() {
    crate::log_capture::install();
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    let mark = crate::log_capture::mark();
    unreaped.leak();
    assert!(
        crate::log_capture::contains_since(mark, &format!("leaking unkillable child {}", id.pid())),
        "a leak must be logged"
    );
    drop(stdin);
    let pid = nix::unistd::Pid::from_raw(id.pid() as i32);
    nix::sys::wait::waitpid(pid, None).expect("a leaked child is left unreaped");
}

/// A tokio child that exits promptly, needing no external binary: this same test binary, re-run
/// with a `--exact` filter that matches nothing, so libtest runs zero tests and exits 0. Mirrors
/// `crate::test_child::spawn_a_process_that_exits`'s std-`Command` twin and
/// `crate::tokio::child::child_reap_tests`'s own copy of this idiom (private to each, so neither
/// can share it with this file).
#[cfg(all(unix, feature = "tokio"))]
fn spawn_a_tokio_child_that_exits() -> ::tokio::process::Child {
    // Raw tokio bypasses cosca's spawn path and its internal `spawn_lock()`, so it is taken here
    // by hand: a macOS fork must not transiently inherit another test's fd-marker write end.
    let _guard = crate::child::spawn::spawn_lock();
    ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn")
}

/// `Unreaped::wait`'s sync blocking path (`tokio_wait_blocking`) loses tokio's own reap race: the
/// child is confirmed reapable (`block_until_reapable`), then `try_wait` finds no exit waiting for
/// it, exactly as something else winning the race and reaping it first would. `wait` must classify
/// that as ownership-uncertain — the same `releases_ownership` predicate a genuine `ECHILD` trips —
/// and release the held tokio child by forgetting it (see the module's **Releasing**), not by
/// dropping it into tokio's orphan queue, which would `waitpid` a pid that may already name another
/// process. This is the regression `tokio_wait_blocking` (f2ec8532) fixes.
#[cfg(all(unix, feature = "tokio"))]
#[tokio::test]
async fn wait_forgets_a_tokio_child_that_loses_tokios_own_reap_race() {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    // Real: the child must already be a genuine zombie before the seam below makes
    // `tokio_wait_blocking`'s OWN `try_wait` miss it, or this would not be the race it reproduces.
    super::block_until_reapable(pid).expect("the child exits promptly");
    crate::child::spawn::fault::set_force_tokio_wait_blocking_lost();
    let unreaped = Unreaped::new(Held::Tokio(Box::new(child)));
    let err = unreaped.wait().expect_err("the forced race must fail the wait");
    assert!(
        super::releases_ownership(&err),
        "losing tokio's own reap race must classify exactly as ECHILD does: {err}"
    );
    // Forgotten, not handed to tokio's orphan queue: this test's own child, reaped by hand.
    nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None).expect("reap the child");
}
