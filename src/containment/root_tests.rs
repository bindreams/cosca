use super::{look, number_holds, NumberLook, Refusal, Root as _};
use crate::signal::RootState;
use crate::test_support::stated_root::StatedRoot;

/// A pgid no test process holds: the checks only name it in their text.
const PGID: i32 = 999_999;

// look -----

/// What `look` answered, in a comparable shape.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Trusted,
    /// macOS: the root is `Unpinned` or `Unknown`.
    Untrusted,
    /// `MayNameAnother`, with `exact_root` and the refusal's kind.
    MayNameAnother(bool, &'static str),
}

fn answered(state: impl Fn() -> RootState) -> Answer {
    let root = StatedRoot::with_state(PGID as u32, state);
    match look(&root) {
        NumberLook::Trusted => Answer::Trusted,
        NumberLook::Untrusted(_) => Answer::Untrusted,
        NumberLook::GroupGone => panic!("only a look through the root's pidfd answers GroupGone"),
        NumberLook::MayNameAnother {
            refusal, exact_root, ..
        } => Answer::MayNameAnother(
            exact_root,
            match refusal {
                Refusal::ReapedElsewhere(_) => "elsewhere",
                Refusal::Unsure(..) => "unsure",
                Refusal::Unpinned(_) => "unpinned",
            },
        ),
    }
}

/// `look` over every state a root's own handle answers.
#[skuld::test]
fn look_answers_each_state() {
    // macOS trusts no number its root's handle cannot vouch for.
    #[cfg(target_os = "macos")]
    let unknown_answer = Answer::Untrusted;
    #[cfg(not(target_os = "macos"))]
    let unknown_answer = Answer::MayNameAnother(cfg!(target_os = "linux"), "unsure");
    assert_eq!(answered(|| RootState::Unreaped), Answer::Trusted);
    assert_eq!(
        answered(|| RootState::Unknown(std::sync::Arc::new(std::io::Error::other("forced")))),
        unknown_answer
    );
    assert_eq!(
        answered(|| RootState::Reaped),
        Answer::MayNameAnother(false, "elsewhere")
    );
}

/// macOS: an `Unpinned` root is `Untrusted`.
#[cfg(target_os = "macos")]
#[skuld::test]
fn look_answers_an_unpinned_root_untrusted() {
    assert_eq!(answered(|| RootState::Unpinned), Answer::Untrusted);
}

/// A root seen by its caller is decided on that look, and each send's check still reads the root's
/// own state.
///
/// Mutants: `Seen` answers the root's own state for the look; it answers the look for every read.
#[skuld::test]
fn a_seen_root_is_decided_on_its_callers_look_and_checked_on_its_own_state() {
    let root = StatedRoot::with_state(PGID as u32, || {
        RootState::Unknown(std::sync::Arc::new(std::io::Error::other("forced")))
    });
    let seen = super::Seen::new(&root, RootState::Reaped);

    assert!(matches!(
        look(&seen),
        NumberLook::MayNameAnother {
            exact_root: false,
            refusal: Refusal::ReapedElsewhere(_),
            ..
        }
    ));
    assert!(matches!(seen.state(), RootState::Unknown(_)), "{:?}", seen.state());
}

// number_holds -----

/// A send by the group's number is allowed only while the root is unreaped.
#[skuld::test]
fn number_holds_only_for_an_unreaped_root() {
    let root = StatedRoot::with_state(PGID as u32, || RootState::Unreaped);
    assert!(number_holds(&root, RootState::Unreaped).is_ok());
    let refused = [
        (RootState::Reaped, "reaped elsewhere"),
        (
            RootState::Unknown(std::sync::Arc::new(std::io::Error::other("a failed peek"))),
            "could not say whether it",
        ),
        (RootState::Unpinned, "not pinned"),
    ];
    for (state, why) in refused {
        let label = format!("{state:?}");
        let err = number_holds(&root, state).expect_err(&label).to_string();
        assert!(err.contains(why), "{label}: {err}");
    }
}

/// A handle that could not say whether the root was reaped refuses with its error as the `source()`,
/// with its OS code, and not in the text, for the refusal and for the group's check that wraps it.
///
/// Mutant: the refusal formats the error into its text, or drops it.
#[skuld::test]
fn an_unsure_refusal_has_the_peeks_error_as_its_source() {
    use crate::containment::NotItsGroup;

    let os_error = std::io::Error::from_raw_os_error(libc::EPERM).to_string();
    let refusal = number_holds(
        &StatedRoot::unreaped(),
        RootState::Unknown(std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EPERM))),
    )
    .expect_err("an unsure handle refuses");
    assert!(!refusal.to_string().contains(&os_error), "{refusal}");
    let code = |e: &dyn std::error::Error| {
        e.source()
            .and_then(|s| s.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error)
    };
    assert_eq!(code(&refusal), Some(libc::EPERM));
    let unproven = NotItsGroup::unproven(refusal, None);
    assert!(!unproven.to_string().contains(&os_error), "{unproven}");
    assert_eq!(code(&unproven), Some(libc::EPERM));
    assert!(std::error::Error::source(&NotItsGroup::Empty).is_none());
}

// check_number through the root's pidfd -----

#[cfg(target_os = "linux")]
mod pidfd {
    use std::os::fd::AsFd as _;
    use std::os::unix::process::ExitStatusExt as _;

    use crate::containment::{check_number, NotItsGroup};
    use crate::signal::RootState;
    use crate::test_child::{await_member_ready, member_command, StdChild};
    use crate::test_groups::{pidfd_group_signal, Group};
    use crate::test_support::stated_root::StatedRoot;

    /// A leader in a group of its own, blocked on its stdin, and its pidfd.
    fn leader() -> (StdChild, std::os::fd::OwnedFd) {
        let mut leader = StdChild::spawn(&mut member_command(0));
        await_member_ready(&mut leader);
        let pidfd = crate::containment::cgroup::test_support::pidfd_of(leader.id());
        (leader, pidfd)
    }

    /// Kills and reaps `leader`, which leaves its group's number free once no member is left.
    fn kill_and_reap(mut leader: StdChild) {
        leader.kill().expect("kill the leader");
        let status = leader.wait().expect("reap the leader");
        assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
    }

    /// A root of `pid` whose own handle says it was reaped elsewhere, with `pidfd`.
    fn reaped_elsewhere(pid: u32, pidfd: std::os::fd::BorrowedFd<'_>) -> StatedRoot<'_> {
        StatedRoot::with_state(pid, || RootState::Reaped).with_pidfd(pidfd)
    }

    fn reaped_elsewhere_text(pid: u32) -> String {
        format!("the root (pid {pid}) was reaped elsewhere")
    }

    /// A reaped root's group with no member left has no tree to signal, but a root its handle cannot
    /// answer for may have left its group alive, so it keeps the reason it may name another process.
    #[skuld::test]
    fn through_the_pidfd_keeps_a_root_its_handle_cannot_answer_for(#[fixture(pidfd_group_signal)] _group: &Group) {
        use std::os::unix::process::CommandExt as _;

        use crate::containment::root::{through_the_pidfd, NumberLook};
        use crate::containment::Refusal;
        let mut lone = crate::test_spawn::spawn(std::process::Command::new("true").process_group(0)).expect("spawn");
        let pidfd = crate::containment::cgroup::test_support::pidfd_of(lone.id());
        lone.wait().expect("reap it");
        let root = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        let decide = |exact_root| {
            through_the_pidfd(
                NumberLook::MayNameAnother {
                    refusal: Refusal::ReapedElsewhere(super::PGID as u32),
                    exact_root,
                    probe: None,
                },
                &root,
            )
        };
        assert!(matches!(decide(false), NumberLook::GroupGone));
        assert!(matches!(
            decide(true),
            NumberLook::MayNameAnother { exact_root: true, .. }
        ));
    }

    /// A reaped root whose group has no member left fails the check, though its state would pass
    /// it: its number may name another group.
    #[skuld::test]
    fn check_fails_once_the_group_has_no_member(#[fixture(pidfd_group_signal)] _group: &Group) {
        let (leader, pidfd) = leader();
        kill_and_reap(leader);
        let root = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        assert!(matches!(check_number(Some(&root)), Err(NotItsGroup::Empty)));
    }

    /// A root reaped elsewhere whose group still has a member passes the check, though its state
    /// fails it: the group's number is still its own.
    #[skuld::test]
    fn check_passes_while_the_group_has_a_member(#[fixture(pidfd_group_signal)] _group: &Group) {
        let (leader, pidfd) = leader();
        let mut member = StdChild::spawn(&mut member_command(leader.id() as i32));
        await_member_ready(&mut member);
        let root = reaped_elsewhere(leader.id(), pidfd.as_fd());
        kill_and_reap(leader);
        check_number(Some(&root)).expect("a group with a member left");
    }

    /// A kernel that refuses `PIDFD_SIGNAL_PROCESS_GROUP` leaves the answer to the root's state,
    /// even for a group with a member.
    #[skuld::test]
    fn check_asks_the_roots_state_when_the_kernel_refuses_the_flag() {
        let (leader, pidfd) = leader();
        let pid = leader.id();
        let reaped = reaped_elsewhere(pid, pidfd.as_fd());
        let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();
        let failed = check_number(Some(&reaped));
        let unreaped = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        let passed = check_number(Some(&unreaped));
        drop(refused);
        assert_eq!(
            failed.expect_err("reaped elsewhere").to_string(),
            reaped_elsewhere_text(pid)
        );
        passed.expect("an unreaped root");
    }

    /// A signal-0 group send answered `EPERM` (as a seccomp filter may answer for a group whose
    /// number another group took) says nothing about the group: the root's state answers.
    #[skuld::test]
    fn check_asks_the_roots_state_when_the_group_probe_answers_eperm() {
        let (leader, pidfd) = leader();
        let pid = leader.id();
        let reaped = reaped_elsewhere(pid, pidfd.as_fd());
        let answered = crate::containment::unix::fault::answer_group_probes_with(libc::EPERM);
        let checked = check_number(Some(&reaped));
        drop(answered);
        assert_eq!(
            checked.expect_err("reaped elsewhere").to_string(),
            reaped_elsewhere_text(pid)
        );
    }

    /// A pidfd of this test's own process: a root for a check whose group probe is answered by the
    /// fault seam, so no process of its own is needed.
    fn own_pidfd() -> std::os::fd::OwnedFd {
        crate::containment::cgroup::test_support::pidfd_of(std::process::id())
    }

    /// A refusal that follows a failed group probe has the probe's errno as a cause: the only one
    /// when the root's state says nothing of its own, else after the state's.
    ///
    /// Mutant: the check drops the probe's errno, or puts it before the state's cause.
    #[skuld::test]
    fn a_refusal_after_a_failed_group_probe_keeps_the_probes_errno() {
        use crate::error::first_os_code;

        let pidfd = own_pidfd();
        let pid = std::process::id();
        let elsewhere = reaped_elsewhere(pid, pidfd.as_fd());
        let unsure = StatedRoot::with_state(pid, || {
            RootState::Unknown(std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EACCES)))
        })
        .with_pidfd(pidfd.as_fd());
        let answered = crate::containment::unix::fault::answer_group_probes_with(libc::EPERM);
        let alone = check_number(Some(&elsewhere));
        let beside = check_number(Some(&unsure));
        drop(answered);

        let alone = alone.expect_err("reaped elsewhere");
        assert_eq!(first_os_code(&alone), Some(libc::EPERM), "{alone:?}");
        assert_eq!(alone.to_string(), reaped_elsewhere_text(pid));
        let beside = beside.expect_err("the handle could not say");
        let cause = beside.cause().expect("two causes");
        let codes: Vec<_> = cause
            .failures()
            .expect("the state's cause and the probe's")
            .iter()
            .map(|member| first_os_code(&**member))
            .collect();
        assert_eq!(codes, [Some(libc::EACCES), Some(libc::EPERM)], "{beside:?}");
        assert_eq!(first_os_code(&beside), Some(libc::EACCES), "{beside:?}");
    }

    /// A look whose group probe failed keeps its refusal, and a skip built from it has the probe's
    /// errno as a cause, as the check's refusal does.
    ///
    /// The failure is also logged once at debug, with its errno, naming that the look keeps its
    /// refusal.
    ///
    /// Mutant: the look drops the probe's errno, or its failure without a word.
    #[skuld::test]
    fn a_look_after_a_failed_group_probe_keeps_the_probes_errno() {
        use crate::containment::root::{through_the_pidfd, NumberLook};
        use crate::containment::skip::Why;
        use crate::containment::Refusal;
        use crate::error::first_os_code;

        crate::log_capture::install();
        let pidfd = own_pidfd();
        let pid = std::process::id();
        let root = reaped_elsewhere(pid, pidfd.as_fd());
        let mark = crate::log_capture::mark();
        let answered = crate::containment::unix::fault::answer_group_probes_with(libc::EPERM);
        let decided = through_the_pidfd(
            NumberLook::MayNameAnother {
                refusal: Refusal::ReapedElsewhere(pid),
                exact_root: false,
                probe: None,
            },
            &root,
        );
        drop(answered);
        let NumberLook::MayNameAnother { refusal, probe, .. } = decided else {
            panic!("a failed probe leaves the look as it was");
        };
        let cause = Why::MayNameAnother(refusal, probe).cause().expect("the probe's errno");
        assert_eq!(first_os_code(&*cause), Some(libc::EPERM), "{cause:?}");
        let errno = crate::error::Report(&nix::errno::Errno::EPERM).to_string();
        let logged = crate::log_capture::records_since(mark, "the look keeps its refusal");
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains(&errno), "{logged:?} lacks {errno}");
    }

    /// A failed group probe that the root's state outvotes (an unreaped root) is still logged, once,
    /// at debug, with its errno.
    ///
    /// Mutant: the check drops a probe's failure without a word.
    #[skuld::test]
    fn a_failed_group_probe_of_an_unreaped_root_is_logged_once() {
        crate::log_capture::install();
        let pidfd = own_pidfd();
        let root = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        let mark = crate::log_capture::mark();
        let answered = crate::containment::unix::fault::answer_group_probes_with(libc::EPERM);
        let checked = check_number(Some(&root));
        drop(answered);
        checked.expect("an unreaped root holds its number");
        let errno = crate::error::Report(&nix::errno::Errno::EPERM).to_string();
        let logged = crate::log_capture::records_since(mark, "a signal-0 send to a process group");
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains(&errno), "{logged:?} lacks {errno}");
    }

    /// The check's signal-0 group send is a send like any other: recorded, through the root's
    /// pidfd, on any kernel.
    #[skuld::test]
    fn the_group_probe_is_a_recorded_send() {
        use crate::send_log::{GroupStep, Route};
        let (leader, pidfd) = leader();
        let root = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        let capture = crate::send_log::Capture::start();
        let checked = check_number(Some(&root));
        let steps = capture.group_steps_with_probes();
        kill_and_reap(leader);
        assert_eq!(steps, [GroupStep::Check, GroupStep::Group(Route::Pidfd, 0)]);
        checked.expect("the leader's group has a member");
    }
}
