use super::{ContainMode, Containment, Nesting, TreeStop};

/// The default tree stop is `SIGTERM`.
#[cfg(unix)]
#[skuld::test]
fn the_default_tree_stop_names_the_platforms_graceful_signal() {
    let stop = TreeStop::default();
    assert_eq!(stop.name(), "SIGTERM");
    assert_eq!(stop.earlier(), "the SIGTERM");
    assert_eq!(stop.signal(), crate::signal::Signal::Term);
    assert_eq!(stop.sig(), crate::signal::Sig::Graceful(crate::signal::Signal::Term));
}

/// Windows: a tree stop is the send its caller made, named as the sweep's error words it, and hands back
/// what that send answered: a console event's name and `WM_CLOSE` alike. Mutant: the name is always
/// `CTRL_BREAK`.
#[cfg(windows)]
#[skuld::test]
fn a_tree_stop_carries_the_name_and_the_answer_its_caller_sent() {
    use super::SendAnswer;
    use crate::stop::proxy::protocol::CtrlEvent;

    let stop = TreeStop::named(CtrlEvent::CtrlBreak.name(), SendAnswer::Sent(Ok(())));
    assert_eq!(stop.name(), "CTRL_BREAK");
    assert_eq!(stop.earlier(), "the CTRL_BREAK");
    assert!(matches!(stop.into_sent(), SendAnswer::Sent(Ok(()))));

    let ctrl_c = TreeStop::named(CtrlEvent::CtrlC.name(), SendAnswer::Sent(Ok(())));
    assert_eq!(ctrl_c.name(), "CTRL_C");
    assert_eq!(ctrl_c.earlier(), "the CTRL_C");

    let wm_close = TreeStop::named("WM_CLOSE", SendAnswer::Sent(Ok(())));
    assert_eq!(wm_close.name(), "WM_CLOSE");
    assert_eq!(wm_close.earlier(), "the WM_CLOSE");

    let refused = TreeStop::named(
        CtrlEvent::CtrlBreak.name(),
        SendAnswer::NotSent(crate::error::Error::NoConsole {
            detail: "the caller had none".into(),
        }),
    );
    assert!(matches!(
        refused.into_sent(),
        SendAnswer::NotSent(crate::error::Error::NoConsole { .. })
    ));
}

/// A send's answer says how it went as the public outcome, and flattens to the tree call's answer: `Err` for
/// nothing sent, for an exited root and for an unknown answer, else what the send answered. A terminate
/// outcome made of an answer gives the same answer back.
///
/// Mutants: an unknown answer reads as `Sent`; an exited root reads as `Sent` or `Unknown`; the flattening
/// of an unknown answer is `Ok`; the terminate outcome loses the unknown answer's difference.
#[skuld::test]
fn a_send_answer_says_how_it_went_and_flattens_to_one_tree_answer() {
    use super::{SendAnswer, TerminateOutcome};
    use crate::error::Error;
    use crate::stop::SendOutcome;

    let error = |detail: &str| Error::Unassessable {
        detail: detail.to_owned(),
        source: None,
    };
    type Make = fn(Error) -> SendAnswer;
    let rows: [(&str, Make, SendOutcome); 4] = [
        ("not sent", SendAnswer::NotSent, SendOutcome::NotSent),
        ("exited", SendAnswer::RootExited, SendOutcome::NotSent),
        ("checked", |e| SendAnswer::Sent(Err(e)), SendOutcome::Sent),
        ("unknown", SendAnswer::Unknown, SendOutcome::Unknown),
    ];
    for (detail, make, outcome) in rows {
        let answer = make(error(detail));
        assert_eq!(answer.outcome(), outcome, "{detail}");
        let round_trip = TerminateOutcome::of(make(error(detail)), None).into_answer();
        assert_eq!(round_trip.outcome(), outcome, "{detail}: through a terminate outcome");
        let flat = answer.into_tree_result();
        assert!(
            matches!(&flat, Err(Error::Unassessable { detail: d, .. }) if d == detail),
            "{detail}: {flat:?}"
        );
    }
    assert_eq!(SendAnswer::Sent(Ok(())).outcome(), SendOutcome::Sent);
    SendAnswer::Sent(Ok(()))
        .into_tree_result()
        .expect("a send that went out and checked");
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
