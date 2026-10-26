//! macOS: the async `Child`'s graceful shutdowns while the root's state is `Unpinned` (launchd holds
//! its zombie) or `Unknown`. The twin of the sync `Child`'s `unpinned_graceful_tests`, which says
//! what each case asserts and why.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::graceful::fault as graceful_fault;
use super::unpinned_public_tests::{group_blocker, session_tree, walked_blocker};
use crate::child::unpinned_public_tests::{
    assert_nothing_sent, assert_refused, assert_tree_refused, orphaned, warns_since, Untrusted, BOTH,
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

/// Mutants: `terminate` sends without reading the root's state, so the shutdown goes on; the
/// refusal never lets go.
#[skuld::test]
async fn graceful_shutdown_of_an_orphaned_root_sends_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let looks = orphaned();

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("a root this process does not pin is not shut down");

    assert_peeks_exhausted();
    assert_refused(&err, "terminate");
    assert_nothing_sent(&sends);
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(looks);

    child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect("a root that reads true is shut down");
    assert_ne!(sends.by_identity(), vec![], "the second call sent nothing");
    drop(writer);
}

/// Mutants: the escalation kills through the handle without reading the root's state; it says it
/// sent nothing at all; the refusal never lets go.
#[skuld::test]
async fn graceful_shutdown_does_not_escalate_to_a_root_orphaned_during_the_grace() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = crate::test_child::term_ignoring_blocker_async().await;
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let (slot, set) = hold_forced();
    let hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::BeforeEscalation, move || {
        set(orphaned())
    });

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
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
        .await
        .expect("a root that reads true is escalated to");
    crate::test_child::assert_killed("the term-ignoring root", status);
    drop(writer);
}

/// The async grace watch takes no look at the root's state, so it cannot report an orphaned root: the
/// terminate's read and the escalation's are the only two, and the refusal is the only report.
///
/// Mutant: the grace watch reads the root's state and warns of a zombie that is not ours to reap.
#[skuld::test]
async fn graceful_shutdown_watch_stays_quiet_for_an_orphaned_root() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = crate::test_child::term_ignoring_blocker_async().await;
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = force_peeks([Ok(Peek::Running), Ok(Peek::Foreign(Foreign::Orphaned))]);

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("a root this process does not pin is not killed");

    assert_peeks_exhausted();
    assert_refused(&err, "kill");
    assert_eq!(sends.entries(), vec![], "nothing by pid");
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(writer);
}

// graceful_shutdown_tree =====

/// Mutants: the check is dropped, or moved after the terminate or the grace wait; the refusal never
/// lets go; `Unknown` is let through.
#[skuld::test]
async fn graceful_shutdown_tree_of_an_untrusted_root_with_no_identity_channel_ends_up_front() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    for state in BOTH {
        for group in [false, true] {
            let groups = crate::containment::unix::fault::record_term_group();
            let (mut child, writer) = if group { group_blocker() } else { walked_blocker() };
            let sends = Capture::start();
            let mark = crate::log_capture::mark();
            let hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, || {
                panic!("the grace wait began on a root this process cannot vouch for")
            });
            let looks = state.peek();

            let err = child
                .graceful_shutdown_tree(Duration::from_secs(3600))
                .await
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
                .await
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
async fn graceful_shutdown_tree_of_an_untrusted_session_root_signals_its_holders_only() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_term_group();
        let _holders = crate::containment::fdmarker::fault::record_holder_kills();
        let (mut child, writer, descendant) = session_tree().await;
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
            .await
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

/// The sync `graceful_shutdown_tree_decides_its_signal_on_one_look_at_the_root`'s twin. Same mutant.
#[skuld::test]
async fn graceful_shutdown_tree_decides_its_signal_on_one_look_at_the_root() {
    crate::tokio::test_runtime::assert_current_thread();
    let _termed = crate::containment::unix::fault::record_term_group();
    let _killed = crate::containment::unix::fault::record_kill_group();
    let (mut child, writer) = group_blocker();
    let left: Arc<Mutex<Option<usize>>> = Arc::default();
    let _hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, {
        let left = Arc::clone(&left);
        move || *left.lock().expect("the hook's slot") = Some(forced_peeks_left())
    });
    let looks = force_peeks([Ok(Peek::Running), Ok(Peek::Foreign(Foreign::Orphaned))]);

    // The sweep and the reap that follow are not under test.
    _ = child.graceful_shutdown_tree(Duration::ZERO).await;

    drop(looks);
    assert_eq!(
        *left.lock().expect("the hook's slot"),
        Some(1),
        "the signal's decision looked at the root twice"
    );
    drop(writer);
}

/// Mutants: the sweep (`kill_tree`) does not read the root's state; it says it sent nothing at all.
#[skuld::test]
async fn graceful_shutdown_tree_sweep_refuses_a_root_orphaned_during_the_grace() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let (slot, set) = hold_forced();
    let _hook = crate::graceful_hooks::at(
        crate::graceful_hooks::HookPoint::AfterTerminate,
        move || set(orphaned()),
    );

    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
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

/// Mutant: the best-effort reap waits on an `Unpinned` root.
#[skuld::test]
async fn graceful_shutdown_tree_does_not_reap_an_exited_orphaned_root_after_a_failed_sweep() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
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
        .await
        .expect_err("a root this process does not pin is not swept");

    assert_peeks_exhausted();
    assert_tree_refused(&err, "kill_tree", Untrusted::Unpinned);
    assert!(
        crate::test_child::is_unreaped_child(pid),
        "the zombie launchd holds was waited on"
    );
    // A wait on it would fail at the gate and log the best-effort reap's failure.
    assert!(
        !crate::log_capture::records_since_on_current_thread(mark, "")
            .iter()
            .any(|(_, text)| text.contains("best-effort reap")),
        "the zombie launchd holds was waited on"
    );
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(writer);
}

/// Mutant: the reap waits on an `Unpinned` root.
#[skuld::test]
async fn graceful_shutdown_tree_does_not_wait_for_a_root_orphaned_before_its_reap() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let (slot, set) = hold_forced();
    let _hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::BeforeReap, move || set(orphaned()));

    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
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
