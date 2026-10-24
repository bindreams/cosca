//! macOS: the sync `Child`'s graceful shutdowns while the root's state is `Unpinned` (launchd holds
//! its zombie) or `Unknown`. The refusal is the one report: the waits on the way stay quiet and
//! never reap a zombie launchd holds. Each refusal is followed by a call on the same child once its
//! state reads true, which must send, so a refusal that never lets go fails too.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::graceful::fault as graceful_fault;
use super::unpinned_public_tests::{
    assert_nothing_sent, assert_refused, assert_tree_refused, group_blocker, orphaned, session_tree, walked_blocker,
    warns_since, Untrusted, BOTH,
};
use crate::error::Error;
use crate::send_log::Capture;
use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peeks, forced_peeks_left, Forced};
use crate::wait::exit_only::{Foreign, Peek};

/// A hook slot that holds a forced peek until the test is over, so the guard is not dropped (and the
/// force disarmed) before the shutdown reads it.
fn hold_forced() -> (Arc<Mutex<Option<Forced>>>, impl Fn(Forced) + Clone + 'static) {
    let slot: Arc<Mutex<Option<Forced>>> = Arc::default();
    let set = {
        let slot = Arc::clone(&slot);
        move |forced| *slot.lock().expect("the hook's slot") = Some(forced)
    };
    (slot, set)
}

// graceful_shutdown =====

/// A root that is orphaned when the shutdown begins is refused by its `terminate`, with no grace
/// and no kill. Once it reads true the same call shuts it down.
///
/// Mutants: `terminate` sends without reading the root's state, so the shutdown goes on; the
/// refusal never lets go.
#[skuld::test]
fn graceful_shutdown_of_an_orphaned_root_sends_nothing() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let looks = orphaned();

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .expect_err("a root this process does not pin is not shut down");

    assert_peeks_exhausted();
    assert_refused(&err, "terminate");
    assert_nothing_sent(&sends);
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(looks);

    child
        .graceful_shutdown(Duration::ZERO)
        .expect("a root that reads true is shut down");
    assert_ne!(sends.by_identity(), vec![], "the second call sent nothing");
    drop(writer);
}

/// A root that goes orphaned during the grace is not killed by the escalation. The child ignores
/// `SIGTERM`, so the escalation is reached; the hook makes the next peek `Orphaned`. The refusal
/// says the `SIGTERM` was sent. Once the root reads true the escalation kills it.
///
/// Mutants: the escalation kills through the handle without reading the root's state; it says it
/// sent nothing at all; the refusal never lets go.
#[skuld::test]
fn graceful_shutdown_does_not_escalate_to_a_root_orphaned_during_the_grace() {
    crate::log_capture::install();
    let (child, writer) = crate::test_child::term_ignoring_blocker();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let (slot, set) = hold_forced();
    let hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::BeforeEscalation, move || {
        set(orphaned())
    });

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .expect_err("a root this process does not pin is not killed");

    assert_peeks_exhausted();
    assert_refused(&err, "kill");
    assert!(
        matches!(&err, Error::Unassessable { detail, .. } if detail.contains("though the SIGTERM was sent before it")),
        "{err:?}"
    );
    assert_eq!(
        sends.entries(),
        vec![],
        "the escalation must send nothing to a root we do not pin"
    );
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(hook);
    drop(slot);

    let status = child
        .graceful_shutdown(Duration::ZERO)
        .expect("a root that reads true is escalated to");
    crate::test_child::assert_killed("the term-ignoring root", status);
    drop(writer);
}

/// The grace wait itself observes the orphaned root: it stays quiet, and the escalation's refusal is
/// the only report.
///
/// Mutant: the grace wait warns that the zombie is not ours to reap.
#[skuld::test]
fn graceful_shutdown_wait_that_sees_an_orphaned_root_is_quiet() {
    crate::log_capture::install();
    let (child, writer) = crate::test_child::term_ignoring_blocker();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    // The terminate's read, the wait's own peek, the escalation's read.
    let _looks = force_peeks([
        Ok(Peek::Running),
        Ok(Peek::Foreign(Foreign::Orphaned)),
        Ok(Peek::Foreign(Foreign::Orphaned)),
    ]);

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .expect_err("a root this process does not pin is not killed");

    assert_peeks_exhausted();
    assert_refused(&err, "kill");
    assert_eq!(sends.entries(), vec![], "nothing by pid");
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(writer);
}

/// Control for the quiet wait: the public `wait_timeout` still reports a zombie launchd holds.
///
/// Mutant: every wait is quiet.
#[skuld::test]
fn wait_timeout_still_warns_of_an_orphaned_root() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    child
        .wait_timeout(Duration::ZERO)
        .expect_err("a zombie launchd holds is not reaped");

    assert_peeks_exhausted();
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("not ours to reap"), "{warns:?}");
    drop(writer);
}

// graceful_shutdown_tree =====

/// Mechanisms with no channel by identity (a tree walk, a process group) have nothing to signal,
/// wait for or sweep: the shutdown ends up front, before the grace. The hook at the first point
/// after the terminate fails the test if the shutdown gets that far. Once the root reads true the
/// same call shuts the tree down.
///
/// Mutants: the check is dropped, or moved after the terminate or the grace wait; the refusal never
/// lets go; `Unknown` is let through.
#[skuld::test]
fn graceful_shutdown_tree_of_an_untrusted_root_with_no_identity_channel_ends_up_front() {
    crate::log_capture::install();
    for state in BOTH {
        for group in [false, true] {
            let groups = crate::containment::unix::fault::record_term_group();
            let (child, writer) = if group { group_blocker() } else { walked_blocker() };
            let sends = Capture::start();
            let mark = crate::log_capture::mark();
            let hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, || {
                panic!("the grace wait began on a root this process cannot vouch for")
            });
            let looks = state.peek();

            let err = child
                .graceful_shutdown_tree(Duration::from_secs(3600))
                .expect_err("a root this process cannot vouch for is not shut down");

            assert_peeks_exhausted();
            assert_tree_refused(&err, "graceful_shutdown_tree", state);
            assert_nothing_sent(&sends);
            assert_eq!(groups.termed(), Vec::<i32>::new(), "{state:?}, group: {group}");
            assert_eq!(warns_since(mark), Vec::<String>::new(), "{state:?}, group: {group}");
            drop(hook);
            drop(looks);

            child
                .graceful_shutdown_tree(Duration::ZERO)
                .expect("a root that reads true is shut down");
            drop(writer);
        }
    }
}

/// An fd marker still has its holders: they get the `SIGTERM` by identity, and no `killpg`. A hook
/// right after the terminate reads who was signalled, before the sweep: the descendant, and the
/// root only when it is `Unknown`, not `Unpinned`. The grace is zero, so the sweep follows at
/// once.
///
/// Mutants: the terminate fires `killpg`; it signals the `Unpinned` root; it spares the `Unknown`
/// root; it signals no holder.
#[skuld::test]
fn graceful_shutdown_tree_of_an_untrusted_session_root_signals_its_holders_only() {
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_term_group();
        let _holders = crate::containment::fdmarker::fault::record_holder_kills();
        let (child, writer, descendant) = session_tree();
        let pid = child.id().pid();
        let mark = crate::log_capture::mark();
        let after_terminate: Arc<Mutex<Option<Vec<u32>>>> = Arc::default();
        let hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, {
            let seen = Arc::clone(&after_terminate);
            move || {
                *seen.lock().expect("the hook's slot") =
                    Some(crate::containment::fdmarker::fault::holder_kills_so_far())
            }
        });
        let _looks = state.peek();

        child
            .graceful_shutdown_tree(Duration::ZERO)
            .expect("the tree is swept and the root reaped");

        drop(hook);
        assert_eq!(groups.termed(), Vec::<i32>::new(), "{state:?}");
        let mut signalled = after_terminate
            .lock()
            .expect("the hook's slot")
            .clone()
            .expect("the terminate ran");
        signalled.sort_unstable();
        signalled.dedup();
        let want = match state {
            Untrusted::Unpinned => vec![descendant],
            Untrusted::Unknown => {
                let mut both = vec![pid, descendant];
                both.sort_unstable();
                both
            }
        };
        assert_eq!(signalled, want, "{state:?}");
        assert_eq!(warns_since(mark), Vec::<String>::new(), "{state:?}");
        drop(writer);
    }
}

/// The cooperative signal is decided on one look at the root's state, as `terminate_tree`'s is. The
/// hook right after it counts the looks left.
///
/// Mutant: the untrusted-root check and the reaped-root check each look, and the second look's
/// `Unpinned` is let through to the group signal.
#[skuld::test]
fn graceful_shutdown_tree_decides_its_signal_on_one_look_at_the_root() {
    let _termed = crate::containment::unix::fault::record_term_group();
    let _killed = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = group_blocker();
    let left: Arc<Mutex<Option<usize>>> = Arc::default();
    let _hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, {
        let left = Arc::clone(&left);
        move || *left.lock().expect("the hook's slot") = Some(forced_peeks_left())
    });
    let looks = force_peeks([Ok(Peek::Running), Ok(Peek::Foreign(Foreign::Orphaned))]);

    // The sweep and the reap that follow are not under test.
    let _ = child.graceful_shutdown_tree(Duration::ZERO);

    drop(looks);
    assert_eq!(
        *left.lock().expect("the hook's slot"),
        Some(1),
        "the signal's decision looked at the root twice"
    );
    drop(writer);
}

/// A root orphaned during the grace is refused by the sweep, which sends it nothing, and the
/// refusal says the `SIGTERM` was sent. The hook flips the next peek between the terminate and the
/// sweep.
///
/// Mutants: the sweep (`kill_tree`) does not read the root's state; it says it sent nothing at all.
#[skuld::test]
fn graceful_shutdown_tree_sweep_refuses_a_root_orphaned_during_the_grace() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let (slot, set) = hold_forced();
    let _hook = crate::graceful_hooks::at(
        crate::graceful_hooks::HookPoint::AfterTerminate,
        move || set(orphaned()),
    );

    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect_err("a root this process does not pin is not swept");

    assert_peeks_exhausted();
    assert_tree_refused(&err, "kill_tree", Untrusted::Unpinned);
    assert!(
        matches!(&err, Error::Unassessable { detail, .. } if detail.contains("though the SIGTERM was sent before it")),
        "{err:?}"
    );
    assert_eq!(sends.entries(), vec![]);
    assert!(
        !sends.by_identity().iter().any(|(_, signo)| *signo == libc::SIGKILL),
        "{:?}",
        sends.by_identity()
    );
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(slot);
    drop(writer);
}

/// The best-effort reap after a failed sweep skips a root launchd holds: it is an exited zombie, so
/// the root reads as exited, but waiting on it only warns. The root is a real zombie; the sweep and
/// the reap's own look both read it `Orphaned`.
///
/// Mutant: the best-effort reap waits on an `Unpinned` root.
#[skuld::test]
fn graceful_shutdown_tree_does_not_reap_an_exited_orphaned_root_after_a_failed_sweep() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let pid = child.id().pid();
    // SAFETY: `pid` is this test's own child.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) }, 0);
    crate::test_child::wait_until_zombie(pid);
    graceful_fault::set_force_terminate(graceful_fault::Forced::Containment);
    let mark = crate::log_capture::mark();
    // The entry's read, the sweep's, the reap's.
    let _looks = force_peeks([
        Ok(Peek::Running),
        Ok(Peek::Foreign(Foreign::Orphaned)),
        Ok(Peek::Foreign(Foreign::Orphaned)),
    ]);

    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect_err("a root this process does not pin is not swept");

    assert_peeks_exhausted();
    assert_tree_refused(&err, "kill_tree", Untrusted::Unpinned);
    assert!(
        crate::test_child::is_unreaped_child(pid),
        "the zombie launchd holds was waited on"
    );
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(writer);
}

/// A root orphaned after the sweep is not waited on: its status cannot be collected, and the error
/// says so instead of the wait warning. The zombie is left as it was.
///
/// Mutant: the reap waits on an `Unpinned` root.
#[skuld::test]
fn graceful_shutdown_tree_does_not_wait_for_a_root_orphaned_before_its_reap() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let (slot, set) = hold_forced();
    let _hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::BeforeReap, move || set(orphaned()));

    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect_err("the status of a zombie launchd holds cannot be collected");

    assert_peeks_exhausted();
    assert!(
        matches!(&err, Error::Unassessable { detail, source: None } if detail.contains("exit status cannot be collected")),
        "{err:?}"
    );
    assert!(
        crate::test_child::is_unreaped_child(pid),
        "the zombie launchd holds was waited on"
    );
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(slot);
    drop(writer);
}
