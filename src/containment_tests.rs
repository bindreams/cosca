use super::{ContainMode, Containment, Nesting};

#[skuld::test]
fn containment_display_names_the_mechanism() {
    assert_eq!(Containment::JobObject.to_string(), "job object");
    assert_eq!(Containment::CgroupV2.to_string(), "cgroup v2");
    assert_eq!(Containment::ProcessGroup.to_string(), "process group");
    assert_eq!(Containment::Session.to_string(), "session");
    assert_eq!(Containment::FdMarker.to_string(), "inherited-fd marker");
    assert_eq!(Containment::TreeWalk.to_string(), "process-tree walk");
    assert_eq!(Containment::Delegated.to_string(), "delegated");
    assert_eq!(Containment::None.to_string(), "none");
}

#[skuld::test]
fn containment_can_teardown() {
    assert!(!Containment::None.can_teardown());
    assert!(!Containment::Delegated.can_teardown());
    for c in [
        Containment::CgroupV2,
        Containment::JobObject,
        Containment::ProcessGroup,
        Containment::Session,
        Containment::FdMarker,
        Containment::TreeWalk,
    ] {
        assert!(c.can_teardown(), "{c:?} must be teardown-capable");
    }
}

#[skuld::test]
fn nesting_defaults_to_mark() {
    assert_eq!(Nesting::default(), Nesting::Mark);
}

#[skuld::test]
fn contain_modes_are_distinct() {
    assert_ne!(ContainMode::Strongest, ContainMode::TreeWalk);
}

#[skuld::test]
fn contain_mode_session_is_distinct_from_strongest_and_treewalk() {
    assert_ne!(ContainMode::Session, ContainMode::Strongest);
    assert_ne!(ContainMode::Session, ContainMode::TreeWalk);
}

/// `BestEffort` contains a child on every platform, whatever the host offers, and `kill_tree` tears
/// it down.
#[skuld::test]
fn best_effort_contains_a_child_and_kill_tree_ends_it() {
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    cmd.contain_with(ContainMode::BestEffort);
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");

    assert!(child.containment().can_teardown(), "got {}", child.containment());
    child.kill_tree().expect("kill_tree");
    drop(stdin);
    assert!(!child.wait().expect("wait").success(), "the child was killed");
}

/// [`best_effort_contains_a_child_and_kill_tree_ends_it`] for the async `Command`.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn best_effort_contains_an_async_child_and_kill_tree_ends_it() {
    let mut cmd = crate::test_child::tokio_command(crate::test_child::Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    cmd.contain_with(ContainMode::BestEffort);
    let mut child = cmd.spawn().await.expect("spawn");
    let stdin = child.stdin().expect("piped stdin");

    assert!(child.containment().can_teardown(), "got {}", child.containment());
    child.kill_tree().await.expect("kill_tree");
    drop(stdin);
    assert!(!child.wait().await.expect("wait").success(), "the child was killed");
}
