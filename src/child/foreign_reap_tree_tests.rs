//! `kill_tree` and `terminate_tree` of a group whose root was reaped behind its handle's back. Only
//! the handle can tell: the root's number names nothing, or (macOS) nothing the number shows to be
//! another process. The group recorders stand in for `killpg`, so a mutant that still sends one
//! reaches no process.

use crate::containment::unix::fault::{record_kill_group, record_term_group};
#[cfg(target_os = "linux")]
use crate::test_child::reaped_elsewhere::ROOT_KILLED_BY_PIDFD;
use crate::test_child::reaped_elsewhere::{
    assert_one_reaped_elsewhere_warn, assert_one_untrusted_number_warn, foreign_reaped_group_root, kill_own_child,
    session_sleep, warns_since,
};

/// Mutants: `killpg` sent; the decision taken on the number alone (it shows no recycle).
#[skuld::test]
fn kill_tree_after_a_foreign_reap_sends_no_killpg() {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let recorder = record_kill_group();
    let (child, pgid) = foreign_reaped_group_root();

    let mark = crate::log_capture::mark();
    let err = child
        .kill_tree()
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pgid);
}

/// The twin of [`kill_tree_after_a_foreign_reap_sends_no_killpg`]. Same mutants.
#[skuld::test]
fn terminate_tree_after_a_foreign_reap_sends_no_signal() {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let recorder = record_term_group();
    let (child, pgid) = foreign_reaped_group_root();

    let mark = crate::log_capture::mark();
    let err = child
        .terminate_tree()
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pgid);
}

/// After this handle's own reap, a pid that cannot be read may name another process (a pid that
/// names none reads `Gone`): `kill_tree` sends no `killpg` and answers `Unassessable`.
///
/// Mutant: an unreadable pid after our own reap is taken as free, and `killpg` is sent.
#[skuld::test]
fn kill_tree_after_own_wait_whose_pid_reads_unknown_sends_no_killpg() {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    kill_own_child(pid);
    child.wait().expect("this handle reaps the root");
    let _unknown = crate::child::fault::force_next_root_read(crate::identity::Resolved::Unknown);

    let mark = crate::log_capture::mark();
    let err = child
        .kill_tree()
        .expect_err("a group whose root's pid cannot be read is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "no killpg by a number that may name another process"
    );
    assert_one_untrusted_number_warn(mark, pid);
}

/// A root whose own handle cannot say whether it was reaped: its pid may name another process, so
/// `kill_tree` sends no `killpg`, kills the root through its pidfd, which names it exactly, and
/// answers `Unassessable`. (macOS answers this earlier, through its untrusted-root path.)
///
/// Mutants: a `RootState::Unknown` root's group is signalled; the root is not killed through its
/// pidfd; the warn does not say it was.
#[cfg(target_os = "linux")]
#[skuld::test]
fn kill_tree_of_a_root_its_handle_cannot_read_kills_it_through_its_pidfd_alone() {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    use crate::test_child::reaped_elsewhere::session_cat;
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use std::os::unix::process::ExitStatusExt as _;
    crate::log_capture::install();
    let recorder = record_kill_group();
    let mut child = session_cat().spawn().expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let sends = crate::send_log::Capture::start();
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    let err = child
        .kill_tree()
        .expect_err("a group whose root nothing can answer for is not assessable");
    assert_peeks_exhausted();
    drop(forced);

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "no killpg by a number that may name another process"
    );
    assert_eq!(
        sends.entries(),
        [(pid, crate::signal::Sig::Kill, crate::send_log::Via::Pidfd)],
        "the root is killed through its pidfd, and nothing else is sent"
    );
    assert_one_untrusted_number_warn(mark, pid);
    let warns = warns_since(mark);
    assert!(warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    drop(stdin);
    let status = child.wait().expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "the pidfd kill ended the root");
}

/// A root whose own handle cannot say whether it was reaped: `terminate_tree` sends no `SIGTERM` by
/// its number, sends it one through its pidfd, which names it exactly, and answers `Unassessable`.
///
/// Mutants: nothing is sent to the root; a `SIGTERM` goes to its group; the warn does not say it was
/// sent.
#[cfg(target_os = "linux")]
#[skuld::test]
fn terminate_tree_of_a_root_its_handle_cannot_read_terms_it_through_its_pidfd_alone() {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    use crate::test_child::reaped_elsewhere::{session_cat, ROOT_TERMED_BY_PIDFD};
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use std::os::unix::process::ExitStatusExt as _;
    crate::log_capture::install();
    let termed = record_term_group();
    let mut child = session_cat().spawn().expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let sends = crate::send_log::Capture::start();
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    let err = child
        .terminate_tree()
        .expect_err("a group whose root nothing can answer for is not assessable");
    assert_peeks_exhausted();
    drop(forced);

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a number that may name another process"
    );
    assert_eq!(
        sends.entries(),
        [(pid, crate::signal::Sig::Term, crate::send_log::Via::Pidfd)],
        "the root is signalled through its pidfd, and nothing else is sent"
    );
    assert_one_untrusted_number_warn(mark, pid);
    let warns = warns_since(mark);
    assert!(warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
    drop(stdin);
    let status = child.wait().expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "the pidfd SIGTERM ended the root");
}

/// A root whose own handle cannot say whether it was reaped and ignores `SIGTERM`:
/// `graceful_shutdown_tree` sends it the `SIGTERM` through its pidfd, and after the grace the kill
/// through its pidfd, and nothing by its number. It ends `Unassessable` with one warn that says so.
///
/// Mutants: nothing is sent to the root; the kill after the grace is not sent; a second `SIGTERM`
/// in its place; a `killpg` or a `SIGTERM` to the group.
#[cfg(target_os = "linux")]
#[skuld::test]
fn graceful_shutdown_tree_of_a_root_its_handle_cannot_read_escalates_through_its_pidfd_alone() {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    use crate::signal::Sig::{Kill, Term};
    use crate::test_child::reaped_elsewhere::{term_ignoring_session_cat, ROOT_TERMED_BY_PIDFD};
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use std::os::unix::process::ExitStatusExt as _;
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let mut child = term_ignoring_session_cat().spawn().expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    let pid = child.id().pid();
    let mut ready = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout().expect("stdout pipe")),
        &mut ready,
    )
    .expect("the root ignores SIGTERM");

    let mark = crate::log_capture::mark();
    let sends = crate::send_log::Capture::start();
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    // A root that ignores the SIGTERM is alive after any grace, so the kill follows.
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("a group whose root nothing can answer for is not assessable");
    assert_peeks_exhausted();
    drop(forced);

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(killed.killed(), Vec::<i32>::new(), "no killpg by the root's number");
    assert_eq!(termed.termed(), Vec::<i32>::new(), "no SIGTERM by the root's number");
    let via_pidfd = crate::send_log::Via::Pidfd;
    assert_eq!(
        sends.entries(),
        [(pid, Term, via_pidfd), (pid, Kill, via_pidfd)],
        "the SIGTERM, then the kill, both through the pidfd"
    );
    assert_one_untrusted_number_warn(mark, pid);
    let warns = warns_since(mark);
    assert!(warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
    assert!(warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    drop(stdin);
    let status = child.wait().expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "the kill ended the root");
}

/// The same root, but it exits on the `SIGTERM`: `graceful_shutdown_tree` sends no kill, and the one
/// warn does not say it did. A hook after the `SIGTERM` checks it went out, releases the root's
/// stdin, then waits for the root to exit, so the grace's one look at the pidfd at expiry finds it
/// readable. A `SIGTERM` that was not delivered lets the release end the root by itself, which shows
/// in its status.
///
/// Mutants: the kill is sent whatever the root did; the warn says it was; the grace wait misses the
/// pidfd's exit.
#[cfg(target_os = "linux")]
#[skuld::test]
fn graceful_shutdown_tree_of_a_root_its_handle_cannot_read_sends_no_kill_to_one_that_exited() {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    use crate::graceful_hooks::{at, HookPoint};
    use crate::signal::Sig::Term;
    use crate::test_child::reaped_elsewhere::{session_cat, ROOT_TERMED_BY_PIDFD};
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use std::os::unix::process::ExitStatusExt as _;
    crate::log_capture::install();
    let mut child = session_cat().spawn().expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let sends = std::rc::Rc::new(crate::send_log::Capture::start());
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    let exited_first = at(HookPoint::AfterTerminate, {
        let sends = std::rc::Rc::clone(&sends);
        move || {
            assert_eq!(
                sends.entries(),
                [(pid, Term, crate::send_log::Via::Pidfd)],
                "the SIGTERM went out before the grace"
            );
            drop(stdin);
            crate::test_child::wait_until_zombie(pid);
        }
    });
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("a group whose root nothing can answer for is not assessable");
    drop(exited_first);
    assert_peeks_exhausted();
    drop(forced);

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        sends.entries(),
        [(pid, Term, crate::send_log::Via::Pidfd)],
        "only the SIGTERM, through the pidfd"
    );
    assert_one_untrusted_number_warn(mark, pid);
    let warns = warns_since(mark);
    assert!(warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
    assert!(!warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    let status = child.wait().expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "the SIGTERM ended the root");
}

/// After a foreign reap, `graceful_shutdown_tree` ends `Unassessable` with one warn and no sweep by
/// the root's number, which would warn again and claim a `SIGTERM` was sent. (A macOS fd marker's
/// holders still get their shutdown; here there are none left.)
///
/// Mutant: the `Unassessable` falls through to the grace and the sweep.
#[skuld::test]
fn graceful_shutdown_tree_after_a_foreign_reap_warns_once_and_ends() {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let (child, pgid) = foreign_reaped_group_root();

    let mark = crate::log_capture::mark();
    let err = child
        .graceful_shutdown_tree(std::time::Duration::from_secs(1))
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        killed.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pgid);
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn: {warns:?}");
    assert!(
        !warns[0].contains("was sent before it"),
        "no SIGTERM was sent: {warns:?}"
    );
}

/// After this handle's own reap, with the pid held by another process, `graceful_shutdown_tree`
/// sends no `SIGTERM` by the number: the group is empty. When its sweep then finds the pid
/// unreadable, the warn says what the shutdown really sent before it: nothing on Linux, the
/// `SIGTERM` to any marker holders on macOS.
///
/// Mutant: the sweep is told that "the SIGTERM" went out whatever the shutdown sent.
#[skuld::test]
fn graceful_shutdown_tree_after_own_wait_claims_no_sigterm_it_did_not_send() {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    use crate::child::fault::force_next_root_read;
    use crate::identity::{ProcessId, Resolved};
    use crate::test_child::reaped_elsewhere::UNTRUSTED_NUMBER;
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    kill_own_child(pid);
    child.wait().expect("this handle reaps the root");
    let other = ProcessId::from_parts_for_test(pid, child.id().start_token_raw() + 1);
    // The shutdown's look finds another process; the sweep's, after the terminate, cannot read the
    // pid. This guard clears the second force too, should it go unconsumed.
    let _reads = force_next_root_read(Resolved::Found(other));
    let _unreadable = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, || {
        std::mem::forget(force_next_root_read(Resolved::Unknown))
    });

    let mark = crate::log_capture::mark();
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("a sweep whose root's pid cannot be read is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_eq!(
        killed.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn: {warns:?}");
    assert!(warns[0].contains(UNTRUSTED_NUMBER), "{warns:?}");
    #[cfg(target_os = "linux")]
    assert!(
        !warns[0].contains("was sent before it"),
        "no SIGTERM was sent: {warns:?}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        warns[0].contains("though the SIGTERM to any marker holders was sent before it"),
        "the SIGTERM went to the marker holders alone: {warns:?}"
    );
}

/// After this handle's own reap, with the pid reused, an fd marker still kills its holders by the
/// pipe they hold, which no pid reuse redirects, including one that left the group. `Ok` follows
/// the sweep, and the tree counts as killed, so the drop has nothing to warn about.
///
/// Mutants: `Ok` without the holders sweep; the tree not marked killed.
#[cfg(target_os = "macos")]
#[skuld::test]
fn kill_tree_after_own_wait_and_reuse_kills_a_holder_that_left_the_group() {
    use crate::identity::{ProcessId, Resolved};
    use crate::test_child::reaped_elsewhere::escaped_holder_tree;
    crate::log_capture::install();
    let groups = record_kill_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (child, holder) = escaped_holder_tree(crate::ContainMode::Session, false);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().expect("this handle reaps the root");
    let other = ProcessId::from_parts_for_test(pid, child.id().start_token_raw() + 1);
    let _reused = crate::child::fault::force_next_root_read(Resolved::Found(other));

    child.kill_tree().expect("every holder was reached");

    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert!(
        holders.killed().contains(&holder.pid),
        "the holder that left the group is killed: {:?}",
        holders.killed()
    );
    let mark = crate::log_capture::mark();
    drop(child);
    assert_eq!(
        warns_since(mark),
        Vec::<String>::new(),
        "the tree was killed: the drop does not warn"
    );
    holder.assert_dies();
}

/// After this handle's own reap, with the pid naming nothing, an fd marker with a group (the default
/// containment) kills its group and its holders, and walks nothing from the pid. `Ok` follows, and
/// the tree counts as killed, so the drop neither sweeps again nor warns.
///
/// Mutants: the tree not marked killed; `no_walk_signal` returns an error.
#[cfg(target_os = "macos")]
#[skuld::test]
fn kill_tree_after_own_wait_of_a_marker_with_a_group_is_ok_and_marks_the_tree_killed() {
    use crate::identity::Resolved;
    use crate::test_child::reaped_elsewhere::escaped_holder_tree;
    crate::log_capture::install();
    let groups = record_kill_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (child, holder) = escaped_holder_tree(crate::ContainMode::Session, false);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().expect("this handle reaps the root");
    let _gone = crate::child::fault::force_root_reads(Resolved::Gone);

    child.kill_tree().expect("the group and every holder were reached");

    // A pid that names nothing is still killed as the group's id.
    let by_id = groups.killed();
    assert!(
        !by_id.is_empty() && by_id.iter().all(|g| *g == pid as i32),
        "the group is killed by its id: {by_id:?}"
    );
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert_eq!(
        holders.signals_to(holder.pid),
        [nix::sys::signal::Signal::SIGKILL],
        "the holder that left the group is killed"
    );
    let mark = crate::log_capture::mark();
    drop(child);
    assert_eq!(
        warns_since(mark),
        Vec::<String>::new(),
        "the tree was killed: the drop does not warn"
    );
    holder.assert_dies();
}

/// `graceful_shutdown_tree` after this handle's own reap, with the pid naming nothing: the group and
/// the holders get the `SIGTERM`, then the kill, and no walk runs from the pid. The holder ignores
/// the `SIGTERM`, so only the kill ends it. The call answers the status the wait collected, and the
/// tree counts as killed, so the drop does not warn.
///
/// Mutants: the `SIGTERM` skipped or answered with an error; the tree not marked killed;
/// `no_walk_signal` returns an error.
#[cfg(target_os = "macos")]
#[skuld::test]
fn graceful_shutdown_tree_after_own_wait_of_a_marker_with_a_group_answers_the_collected_status() {
    use crate::identity::Resolved;
    use crate::test_child::reaped_elsewhere::escaped_holder_tree;
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (child, holder) = escaped_holder_tree(crate::ContainMode::Session, true);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    let collected = child.wait().expect("this handle reaps the root");
    let _gone = crate::child::fault::force_root_reads(Resolved::Gone);

    let status = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect("the group and every holder were reached");

    assert_eq!(status, collected, "the status the wait collected");
    // A pid that names nothing is still signalled as the group's id.
    for (what, by_id) in [("SIGTERM", termed.termed()), ("kill", killed.killed())] {
        assert!(
            !by_id.is_empty() && by_id.iter().all(|g| *g == pid as i32),
            "the group's {what} by its id: {by_id:?}"
        );
    }
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert_eq!(
        holders.signals_to(holder.pid),
        [nix::sys::signal::Signal::SIGTERM, nix::sys::signal::Signal::SIGKILL],
        "the SIGTERM, then the kill"
    );
    let mark = crate::log_capture::mark();
    drop(child);
    assert_eq!(
        warns_since(mark),
        Vec::<String>::new(),
        "the tree was killed: the drop does not warn"
    );
    holder.assert_dies();
}

/// After a foreign reap, an fd marker still kills its holders, by the pipe they hold, including one
/// that left the group. Only what names the tree by the root's number is skipped, so the call is
/// `Unassessable`, with one warn naming the group.
///
/// Mutant: no holders sweep after a foreign reap.
#[cfg(target_os = "macos")]
#[skuld::test]
fn kill_tree_after_a_foreign_reap_kills_a_holder_that_left_the_group() {
    use crate::test_child::reaped_elsewhere::{escaped_holder_tree, reap_behind};
    crate::log_capture::install();
    let groups = record_kill_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (child, holder) = escaped_holder_tree(crate::ContainMode::Session, false);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    reap_behind(pid);

    let mark = crate::log_capture::mark();
    let err = child
        .kill_tree()
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert!(
        holders.killed().contains(&holder.pid),
        "the holder that left the group is killed: {:?}",
        holders.killed()
    );
    assert_one_reaped_elsewhere_warn(mark, pid);
    holder.assert_dies();
}

/// After a foreign reap, `graceful_shutdown_tree` still shuts an fd marker's holders down by the
/// pipe they hold: the `SIGTERM`, then, after the grace, a kill of any left. This holder ignores the
/// `SIGTERM`, so only that kill ends it. Nothing goes out by the root's number, and the call is
/// `Unassessable`, with one warn.
///
/// Mutants: no kill after the grace; a second `SIGTERM` in place of the kill. Either fails by
/// assertion before the wait for the holder's death.
#[cfg(target_os = "macos")]
#[skuld::test]
fn graceful_shutdown_tree_after_a_foreign_reap_kills_a_holder_that_ignores_sigterm() {
    use crate::test_child::reaped_elsewhere::{escaped_holder_tree, reap_behind};
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (child, holder) = escaped_holder_tree(crate::ContainMode::Session, true);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    reap_behind(pid);

    let mark = crate::log_capture::mark();
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        killed.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert_eq!(
        holders.signals_to(holder.pid),
        [nix::sys::signal::Signal::SIGTERM, nix::sys::signal::Signal::SIGKILL],
        "the SIGTERM, then the kill"
    );
    assert_one_reaped_elsewhere_warn(mark, pid);
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn: {warns:?}");
    holder.assert_dies();
}

/// A `TreeWalk` fd marker has no group, but its sweep walks from the root's pid. After a foreign
/// reap that pid may name another process, so the walk is skipped; the holders are still killed by
/// the pipe they hold. The call is `Unassessable`, with one warn naming the walk.
///
/// Mutant: the root is checked only for a mechanism with a pgid.
#[cfg(target_os = "macos")]
#[skuld::test]
fn kill_tree_of_a_walk_marker_after_a_foreign_reap_walks_nothing_and_kills_the_holder() {
    use crate::test_child::reaped_elsewhere::{
        assert_one_reaped_elsewhere_walk_warn, escaped_holder_tree, reap_behind,
    };
    crate::log_capture::install();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (child, holder) = escaped_holder_tree(crate::ContainMode::TreeWalk, false);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    reap_behind(pid);

    let mark = crate::log_capture::mark();
    let result = child.kill_tree();

    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert!(
        matches!(result, Err(crate::error::Error::Unassessable { .. })),
        "a walk whose root was reaped elsewhere is not assessable: {result:?}"
    );
    assert!(
        holders.killed().contains(&holder.pid),
        "the holder is killed: {:?}",
        holders.killed()
    );
    assert_one_reaped_elsewhere_walk_warn(mark, pid);
    holder.assert_dies();
}

/// After this handle's own reap, with the pid reused, a `TreeWalk` fd marker's walk from that pid
/// would name only the reuser's children: it is skipped, and the holders are killed by the pipe
/// they hold. `Ok` follows their sweep.
///
/// Mutant: the root is checked only for a mechanism with a pgid.
#[cfg(target_os = "macos")]
#[skuld::test]
fn kill_tree_of_a_walk_marker_after_own_wait_and_reuse_walks_nothing_and_kills_the_holder() {
    use crate::identity::{ProcessId, Resolved};
    use crate::test_child::reaped_elsewhere::escaped_holder_tree;
    crate::log_capture::install();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (child, holder) = escaped_holder_tree(crate::ContainMode::TreeWalk, false);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().expect("this handle reaps the root");
    let other = ProcessId::from_parts_for_test(pid, child.id().start_token_raw() + 1);
    let _reused = crate::child::fault::force_next_root_read(Resolved::Found(other));

    let result = child.kill_tree();

    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    result.expect("every holder was reached");
    assert!(
        holders.killed().contains(&holder.pid),
        "the holder is killed: {:?}",
        holders.killed()
    );
    holder.assert_dies();
}
