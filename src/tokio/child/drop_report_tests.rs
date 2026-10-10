//! One event, one warn: every path of the async `Child`'s drop and of `finish_elevated` reports an
//! event once, however many steps (the front, the skipped kills, the forget, the failed signal)
//! each had to say. Each test forces the looks it counts on and asserts they were all made.

use super::root_state_tests::{failed_peek, session_blocker, warns_since};
use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peeks};
use crate::wait::exit_only::{Foreign, Peek};

fn gone() -> std::io::Result<Peek> {
    Ok(Peek::Foreign(Foreign::Gone))
}

fn running() -> std::io::Result<Peek> {
    Ok(Peek::Running)
}

/// A trusted root behind a closed front gate whose second look shows a foreign reap: the forget is
/// the one event, so one warn, and it does not claim the root is left running.
///
/// Mutants: the forget warns on its own, besides the drop's; the drop's "left running" warn follows
/// a second look that showed the reap.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_closed_front_and_a_second_look_that_shows_a_reap_warn_once_without_claiming_it_runs() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (mut child, _writer) = session_blocker(true);
    child.set_front(Some(crate::elevation::front::Front::Sudo));
    let mark = crate::log_capture::mark();
    // The read, then the gate's look at the front, then the second look.
    let _looks = force_peeks([running(), running(), gone()]);

    drop(child);

    assert_peeks_exhausted();
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("reaped by someone else") && warns[0].contains("leaks"),
        "{warns:?}"
    );
    assert!(!warns[0].contains("left running"), "the reap was seen: {warns:?}");
}

/// The same drop whose second look shows the root still ours: the front is left running, and that is
/// the one warn. Nothing is forgotten.
///
/// Mutant: the second look forgets a root it shows ours.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_closed_front_and_a_second_look_that_shows_the_root_ours_warn_once_about_the_front() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (mut child, _writer) = session_blocker(true);
    child.set_front(Some(crate::elevation::front::Front::Sudo));
    let forgets = super::drop_fault::record();
    let mark = crate::log_capture::mark();
    let _looks = force_peeks([running(), running(), running()]);

    drop(child);

    assert_peeks_exhausted();
    assert_eq!(forgets.forgets(), 0);
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("left running") && !warns[0].contains("leaks"), "{warns:?}");
}

/// A root the handle shows reaped behind a closed front gate: the forget on that evidence is the one
/// event, so one warn, and a reaped root is not "left running".
///
/// Mutants: the forget warns on its own; the front's "left running" warn follows.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_reaped_root_behind_a_closed_front_gate_warns_once_without_claiming_it_runs() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (mut child, _writer) = session_blocker(true);
    child.set_front(Some(crate::elevation::front::Front::Sudo));
    let mark = crate::log_capture::mark();
    // The read shows the reap; the gate's look at the front sees it run.
    let _looks = force_peeks([gone(), running()]);

    drop(child);

    assert_peeks_exhausted();
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("reaped by someone else") && warns[0].contains("leaks"),
        "{warns:?}"
    );
    assert!(!warns[0].contains("left running"), "{warns:?}");
}

/// A reaped root in a process group: the skipped `killpg` and the forget of tokio's `Child` are one
/// event, so one warn that names both.
///
/// Mutants: the skip warns on its own; the forget warns on its own.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_reaped_root_in_a_process_group_warns_once_for_the_skip_and_the_forget() {
    crate::log_capture::install();
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let mark = crate::log_capture::mark();
    let _looks = force_peeks([gone()]);

    drop(child);

    assert_peeks_exhausted();
    assert_eq!(recorder.killed(), Vec::<i32>::new(), "no killpg by a reaped root's number");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("does not kill its process group") && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// A trusted root whose second look shows a foreign reap, with no front: the forget is the one
/// warn, and it names the reap and the leak.
///
/// Mutant: the forget warns on its own and the drop adds a second.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_second_look_that_shows_a_reap_after_the_kills_warns_once() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let mark = crate::log_capture::mark();
    let _looks = force_peeks([running(), gone()]);

    drop(child);

    assert_peeks_exhausted();
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("Child::drop:")
            && warns[0].contains("reaped by someone else")
            && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// A refused root kill on an unknown root that the second look shows ours: the refusal and the
/// unknown state are one event, so one warn.
///
/// Mutant: the refusal warns on its own ("could not be terminated on drop"), besides the unknown
/// state's.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_refused_kill_on_an_unknown_root_that_stays_ours_warns_once() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let _looks = force_peeks([failed_peek("forced"), running()]);
    let _kill = super::fault::force_kill_failure();

    drop(child);

    assert_peeks_exhausted();
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("RootState::Unknown")
            && warns[0].contains(&format!("async child {pid} could not be terminated on drop")),
        "{warns:?}"
    );
}

/// A failed spawn's cleanup with a closed front and a foreign reap seen by the second look: one
/// warn, which names the reap and carries the leak.
///
/// Mutant: the forget warns on its own, besides the cleanup's.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn finish_elevated_with_a_closed_front_and_a_foreign_reap_warns_once() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (mut child, _writer) = session_blocker(true);
    child.set_front(Some(crate::elevation::front::Front::Sudo));
    let mark = crate::log_capture::mark();
    let _looks = force_peeks([running(), running(), gone()]);

    let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
        .expect_err("the spawn fails");

    assert_peeks_exhausted();
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
    assert!(
        warns[0].starts_with("finish_elevated:")
            && warns[0].contains("reaped by someone else")
            && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// The wait's failure is named in the one warn: the cause of a foreign wait result is carried, not
/// only logged at `debug`.
///
/// Mutant: the cause is dropped on the way to the warn.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn finish_elevated_names_why_the_wait_found_the_child_foreign() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let _reap = crate::child::spawn::fault::set_between_kill_and_wait(move || {
        super::child_reap_tests::reap_behind_the_owner(pid);
    });

    let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
        .expect_err("the spawn fails");

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
    assert!(warns[0].contains("waitid"), "the wait's cause is in the warn: {warns:?}");
}

/// `wait_and_reap_at` logs a wait that failed at the level it is given. The failure is a contract
/// breach, asserted in debug builds, after the log.
///
/// Mutant: the pidfd wait logs at `warn` whatever the level.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_pidfd_wait_is_logged_at_the_level_the_caller_gave() {
    use crate::signal::Sig;
    use crate::wait::exit_only::seams::force_visible_errno_once;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (mut child, _writer) = session_blocker(true);
    let pid = child.id().pid();
    child.proc_mut().signal(Sig::Kill).expect("kill the blocker");
    let mark = crate::log_capture::mark();
    let _errno = force_visible_errno_once(libc::EIO);

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        child.proc_mut().wait_and_reap_at(pid, log::Level::Debug)
    }));

    assert!(panicked.is_err(), "a failed wait on the child's own pidfd is asserted in debug");
    assert_eq!(warns_since(mark), Vec::<String>::new());
    assert!(
        crate::log_capture::contains_since(mark, "waitid on child"),
        "the failure is still logged, at the level given"
    );
}

/// A failed spawn's cleanup whose root kill is refused leaves the handle armed, so its drop retries
/// the kill: the cleanup did not settle the root. The retry adds no second warn.
///
/// Mutant: the cleanup disarms the handle whatever became of the root.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn finish_elevated_leaves_the_handle_armed_when_the_root_kill_was_refused() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let drops = super::drop_fault::record();
    let mark = crate::log_capture::mark();
    let _kill = super::fault::force_kill_failure();

    let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
        .expect_err("the spawn fails");

    assert_eq!(drops.kills(), 1, "the handle's drop retries the refused root kill ({err:?})");
    assert_eq!(warns_since(mark), Vec::<String>::new());
}
