//! `StopTarget` (see `crate::stop::target`).

use std::time::Duration;

use super::{StopTarget, TreeCall};
use crate::os_process::fake::FakeProcess;
use crate::test_child::over_fake::child_over;

/// A target names its child, and says whether it stands for the tree.
#[skuld::test]
fn a_root_target_stands_for_the_root_and_a_tree_target_for_the_tree() {
    let child = child_over(&FakeProcess::new([]));
    let root = StopTarget::from(&child);
    let tree = StopTarget::tree(&child, TreeCall::SignalOnly);
    for target in [&root, &tree] {
        assert_eq!(target.pid(), child.pid());
        assert_eq!(target.id(), child.id());
    }
    assert!(!root.covers_tree());
    assert!(tree.covers_tree());
}

/// A refused send is the last send's record, over an earlier one that went out, for either kind of
/// target: the call goes on from what the last send did, as the action's own answer is not what decides.
///
/// Mutants: a refusal is left unrecorded; it is recorded for one kind of target only.
#[skuld::test]
fn a_refused_send_replaces_the_record_of_an_earlier_one() {
    use super::{RootRecord, TreeRecord};

    let refusal = || crate::error::Error::Unsupported {
        op: "the test".into(),
        platform: "test",
        detail: "refused by the test".into(),
        source: None,
    };
    let child = child_over(&FakeProcess::new([]));

    let root = StopTarget::from(&child);
    root.note_root_send("SIGTEST", &Ok(()));
    assert!(matches!(
        &*root.root_record.lock().unwrap(),
        Some(RootRecord::Sent("SIGTEST"))
    ));
    root.note_refused(&refusal());
    assert!(
        matches!(root.into_root_record(), Some(RootRecord::Refused(report)) if report.contains("refused by the test"))
    );

    let tree = StopTarget::tree(&child, TreeCall::SignalOnly);
    tree.note_tree(TreeRecord::Sent {
        earlier: None,
        walk: None,
    });
    tree.note_refused(&refusal());
    assert!(
        matches!(tree.into_tree_record(), Some(TreeRecord::NotSent(report)) if report.contains("refused by the test"))
    );

    // A send that answered an error is recorded as the refusal too.
    let root = StopTarget::from(&child);
    root.note_root_send("SIGTEST", &Err(refusal()));
    assert!(matches!(root.into_root_record(), Some(RootRecord::Refused(_))));
}

/// `wait_exit` waits for the root through the child's handle, for a root target and a tree target alike,
/// and reaps nothing: the child's own wait still gets its status.
///
/// Mutants: it answers `true` whatever the root did; it reaps the root.
#[skuld::test]
fn wait_exit_waits_for_the_root_and_reaps_nothing_for_both_kinds_of_target() {
    let (child, stdin) = crate::test_child::held_uncontained_blocker(true);
    let root = StopTarget::from(&child);
    let tree = StopTarget::tree(&child, TreeCall::SignalOnly);
    // One look: the root runs.
    assert!(!root.wait_exit(Duration::ZERO).expect("a look"));
    assert!(!tree.wait_exit(Duration::ZERO).expect("a look"));

    child.kill().expect("kill");
    // The wait ends on the root's exit, which the kill brings.
    assert!(root.wait_exit(Duration::from_secs(3600)).expect("the root exits"));
    assert!(tree.wait_exit(Duration::from_secs(3600)).expect("the root exited"));
    drop(stdin);
    crate::test_child::assert_killed(
        "the blocker",
        child.wait().expect("the status is still there to collect"),
    );
}

/// Windows: the recorded route is the group flag, with none of the flags that put the child on a console
/// of its own, and a console this process had at the spawn.
///
/// Mutant: one of the three conditions is left out.
#[cfg(windows)]
#[skuld::test]
fn leads_group_on_our_console_is_the_recorded_facts() {
    use crate::containment::windows::ConsoleFacts;

    let mut child = child_over(&FakeProcess::new([]));
    for (group, own_console_flags, caller_had_console, leads) in [
        (true, false, true, true),
        (false, false, true, false),
        (true, true, true, false),
        (true, false, false, false),
    ] {
        child.console = ConsoleFacts {
            group,
            own_console_flags,
            caller_had_console,
            elevated: false,
        };
        assert_eq!(
            StopTarget::from(&child).leads_group_on_our_console(),
            leads,
            "{:?}",
            child.console
        );
    }
}
