use super::{ContainMode, Containment, Nesting, TreeStop};

/// The default tree stop is the platform's: `SIGTERM`, on Windows the `CTRL_BREAK`.
#[skuld::test]
fn the_default_tree_stop_names_the_platforms_graceful_signal() {
    let stop = TreeStop::default();
    #[cfg(unix)]
    {
        assert_eq!(stop.name(), "SIGTERM");
        assert_eq!(stop.earlier(), "the SIGTERM");
        assert_eq!(stop.signal(), crate::signal::Signal::Term);
        assert_eq!(stop.sig(), crate::signal::Sig::Graceful(crate::signal::Signal::Term));
    }
    #[cfg(windows)]
    {
        assert_eq!(stop.name(), "CTRL_BREAK");
        assert_eq!(stop.earlier(), "the CTRL_BREAK");
    }
}

/// A stop made of a signal carries and names that signal, not the default's.
#[cfg(unix)]
#[skuld::test]
fn a_tree_stop_of_a_signal_carries_and_names_it() {
    use crate::signal::{Sig, Signal};
    let stop = TreeStop::of(Signal::Usr1);
    assert_eq!(stop.signal(), Signal::Usr1);
    assert_eq!(stop.sig(), Sig::Graceful(Signal::Usr1));
    assert_eq!(stop.name(), "SIGUSR1");
    assert_eq!(stop.earlier(), "the SIGUSR1");
}

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
