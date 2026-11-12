use super::{look, number_holds, NumberLook, Refusal, Root as _};
use crate::identity::{ProcessId, Resolved};
use crate::signal::RootState;
use crate::test_support::stated_root::StatedRoot;

/// A pgid no test process holds: the checks only name it in their text.
const PGID: i32 = 999_999;

// look -----

/// What `look` answered, in a comparable shape.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Trusted,
    Empty,
    /// macOS: the root is `Unpinned` or `Unknown`.
    Untrusted,
    /// `MayNameAnother`, with `exact_root` and the refusal's kind.
    MayNameAnother(bool, &'static str),
}

fn answered(state: impl Fn() -> RootState, has_group: bool, read: Resolved<ProcessId>) -> Answer {
    let _read = crate::child::fault::force_root_reads(read);
    let root = StatedRoot::with_state(PGID as u32, state);
    match look(&root, has_group) {
        NumberLook::Trusted => Answer::Trusted,
        NumberLook::Empty => Answer::Empty,
        NumberLook::Untrusted(_) => Answer::Untrusted,
        NumberLook::GroupGone => panic!("only a look through the root's pidfd answers GroupGone"),
        NumberLook::MayNameAnother {
            refusal, exact_root, ..
        } => Answer::MayNameAnother(
            exact_root,
            match refusal {
                Refusal::ReapedPidGone(_) => "gone",
                Refusal::ReapedPidTaken(_) => "taken",
                Refusal::ReapedPidUnread(..) => "unread",
                Refusal::ReapedElsewhere(_) => "elsewhere",
                Refusal::Unsure(..) => "unsure",
                Refusal::Unpinned(_) => "unpinned",
            },
        ),
    }
}

/// `look` over every state, own-reap flag and identity read, for a mechanism with a group and one
/// without. The identity read matters only after this handle's own reap.
#[skuld::test]
fn look_answers_each_state_own_reap_and_identity_read() {
    let other = || ProcessId::from_parts_for_test(PGID as u32, crate::identity::Key::for_test(1));
    let reads = || [Resolved::Gone, Resolved::Found(other()), Resolved::Unknown];
    // macOS trusts no number its root's handle cannot vouch for, before the mechanism matters.
    #[cfg(target_os = "macos")]
    let unknown_answer = Answer::Untrusted;
    #[cfg(not(target_os = "macos"))]
    let unknown_answer = Answer::MayNameAnother(cfg!(target_os = "linux"), "unsure");
    for has_group in [true, false] {
        for read in reads() {
            assert_eq!(answered(|| RootState::Unreaped, has_group, read), Answer::Trusted);
        }
        for read in reads() {
            assert_eq!(
                answered(
                    || RootState::Unknown(std::sync::Arc::new(std::io::Error::other("forced"))),
                    has_group,
                    read
                ),
                unknown_answer,
                "unknown, group: {has_group}"
            );
        }
        for read in reads() {
            assert_eq!(
                answered(|| RootState::Reaped { own: false }, has_group, read),
                Answer::MayNameAnother(false, "elsewhere"),
                "reaped elsewhere, group: {has_group}"
            );
        }
        // This handle's own reap: another process at the pid means the group is empty; a pid that
        // names no process may be taken once the group has no member, so with a group nothing is
        // sent by it; a pid that cannot be read is no answer.
        let own = || RootState::Reaped { own: true };
        let [gone, found, unread] = reads();
        let gone_answer = if has_group {
            Answer::MayNameAnother(false, "gone")
        } else {
            Answer::Empty
        };
        assert_eq!(
            answered(own, has_group, gone),
            gone_answer,
            "own reap, gone, group: {has_group}"
        );
        assert_eq!(
            answered(own, has_group, found),
            Answer::Empty,
            "own reap, found, group: {has_group}"
        );
        assert_eq!(
            answered(own, has_group, unread),
            Answer::MayNameAnother(false, "unread"),
            "own reap, unreadable, group: {has_group}"
        );
    }
}

/// macOS: an `Unpinned` root is `Untrusted` whatever the identity read.
#[cfg(target_os = "macos")]
#[skuld::test]
fn look_answers_an_unpinned_root_untrusted() {
    let other = || ProcessId::from_parts_for_test(PGID as u32, crate::identity::Key::for_test(1));
    for read in [Resolved::Gone, Resolved::Found(other()), Resolved::Unknown] {
        assert_eq!(answered(|| RootState::Unpinned, true, read), Answer::Untrusted);
    }
}

/// A root seen by its caller is decided on that look, and each send's check still reads the root's
/// own state.
///
/// Mutants: `Seen` answers the root's own state for the look; it answers the look for every read.
#[skuld::test]
fn a_seen_root_is_decided_on_its_callers_look_and_checked_on_its_own_state() {
    let _read = crate::child::fault::force_root_reads(Resolved::Gone);
    let root = StatedRoot::with_state(PGID as u32, || {
        RootState::Unknown(std::sync::Arc::new(std::io::Error::other("forced")))
    });
    let seen = super::Seen::new(&root, RootState::Reaped { own: false });

    assert!(matches!(
        look(&seen, true),
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
    let own = std::process::id();
    assert!(number_holds(own, RootState::Unreaped).is_ok());
    let refused = [
        (RootState::Reaped { own: false }, "reaped elsewhere"),
        (
            RootState::Unknown(std::sync::Arc::new(std::io::Error::other("a failed peek"))),
            "could not say whether it",
        ),
        (RootState::Unpinned, "not pinned"),
        // This process holds its own pid, so the number names another process than the root.
        (RootState::Reaped { own: true }, "another process holds"),
    ];
    for (state, why) in refused {
        let label = format!("{state:?}");
        let err = number_holds(own, state).expect_err(&label).to_string();
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
        std::process::id(),
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

/// `number_holds` reads `own` from the state: a reap by someone else refuses whatever the pid's
/// identity read says, and an own reap is refused whatever that read says, each as its own variant.
#[skuld::test]
fn number_holds_reads_own_from_the_state() {
    let other = || ProcessId::from_parts_for_test(PGID as u32, crate::identity::Key::for_test(1));
    let reads = || [Resolved::Gone, Resolved::Found(other()), Resolved::Unknown];
    for read in reads() {
        let _read = crate::child::fault::force_root_reads(read);
        let err = number_holds(PGID as u32, RootState::Reaped { own: false }).expect_err("reaped elsewhere");
        assert!(matches!(err, Refusal::ReapedElsewhere(_)), "{err}");
    }
    let _gone = crate::child::fault::force_root_reads(Resolved::Gone);
    let err = number_holds(PGID as u32, RootState::Reaped { own: true }).expect_err("names no process");
    assert!(matches!(err, Refusal::ReapedPidGone(_)), "{err}");
    assert!(err.to_string().contains("names no process"), "{err}");
    drop(_gone);
    let _found = crate::child::fault::force_root_reads(Resolved::Found(other()));
    let err = number_holds(PGID as u32, RootState::Reaped { own: true }).expect_err("another process holds");
    assert!(matches!(err, Refusal::ReapedPidTaken(_)), "{err}");
    drop(_found);
    let _unknown = crate::child::fault::force_root_reads(Resolved::Unknown);
    let err = number_holds(PGID as u32, RootState::Reaped { own: true }).expect_err("unreadable");
    assert!(matches!(err, Refusal::ReapedPidUnread(..)), "{err}");
    assert!(err.to_string().contains("could not be read"), "{err}");
}

/// A reaped root whose pid could not be read refuses with the read's error as its `source()`, OS code
/// included, and the send that wraps the check keeps it as its own.
///
/// Mutant: the refusal drops the read's cause.
#[cfg(target_os = "linux")]
#[skuld::test]
fn an_unread_pid_refusal_has_the_reads_error_as_its_source() {
    use nix::sys::signal::Signal;

    use crate::containment::unix::send_to_group;
    use crate::error::first_os_code;
    use crate::identity::FailedCall;
    use crate::test_support::stated_root::StatedRoot;

    let _read = crate::child::fault::force_root_reads_failing(FailedCall::pidfd_open(rustix::io::Errno::MFILE));
    let refusal = number_holds(PGID as u32, RootState::Reaped { own: true }).expect_err("an unread pid refuses");
    assert_eq!(first_os_code(&refusal), Some(libc::EMFILE), "{refusal:?}");
    let root = StatedRoot::with_state(PGID as u32, || RootState::Reaped { own: true });
    let sent = send_to_group(PGID, Signal::SIGTERM, Some(&root)).expect_err("the check refuses the send");
    assert_eq!(first_os_code(&sent), Some(libc::EMFILE), "{sent:?}");
}

/// A probe's error joins a `Several` cause of the refusal as one more member of it, not as a list
/// inside a list.
///
/// Mutant: the join nests the refusal's `Several`.
#[skuld::test]
fn a_probe_extends_a_several_cause_of_the_refusal() {
    use std::sync::Arc;

    use crate::containment::NotItsGroup;
    use crate::error::{first_os_code, Error, Failures};

    let coded = |code| Error::io_cause(std::io::Error::from_raw_os_error(code));
    let own = Arc::new(Error::Several(Failures::new(
        coded(libc::EACCES),
        [coded(libc::EMFILE)],
    )));
    let probe = Error::Unassessable {
        detail: "a probe".to_owned(),
        source: Some(coded(libc::EPERM)),
    };
    let unproven = NotItsGroup::unproven(Refusal::ReapedPidUnread(PGID as u32, Some(own)), Some(probe));
    let cause = unproven.cause().expect("the causes");
    let codes: Vec<_> = cause
        .failures()
        .expect("a list")
        .iter()
        .map(|member| first_os_code(&**member))
        .collect();
    assert_eq!(codes, [Some(libc::EACCES), Some(libc::EMFILE), Some(libc::EPERM)]);
}

/// The two root-read seams each own their state: taking one while the other is alive neither
/// inherits its answer nor clears it when the guard drops.
///
/// Mutant: the failing seam rides on the plain one's state, so the plain read inherits its cause,
/// or its guard clears the other's.
#[cfg(target_os = "linux")]
#[skuld::test]
fn the_root_read_seams_do_not_leak_into_each_other() {
    use crate::child::{fault, root_identity_now};
    use crate::identity::FailedCall;

    let failing = || FailedCall::pidfd_open(rustix::io::Errno::MFILE);
    let read = || root_identity_now(PGID as u32);

    let failing_guard = fault::force_root_reads_failing(failing());
    let plain_guard = fault::force_root_reads(Resolved::Gone);
    let (gone, cause) = read();
    assert!(matches!(gone, Resolved::Gone));
    assert!(
        cause.into_error("pid").is_none(),
        "the plain read inherited the failing one's cause"
    );
    drop(plain_guard);
    let (unknown, cause) = read();
    assert!(matches!(unknown, Resolved::Unknown));
    assert!(
        cause.into_error("pid").is_some(),
        "the plain guard cleared the failing seam"
    );
    drop(failing_guard);

    let plain_guard = fault::force_root_reads(Resolved::Gone);
    let failing_guard = fault::force_root_reads_failing(failing());
    drop(failing_guard);
    let (gone, _) = read();
    assert!(
        matches!(gone, Resolved::Gone),
        "the failing guard cleared the plain seam"
    );
    drop(plain_guard);
}

// check_number through the root's pidfd -----

#[cfg(target_os = "linux")]
mod pidfd {
    use std::os::fd::AsFd as _;
    use std::os::unix::process::ExitStatusExt as _;

    use crate::containment::{check_number, NotItsGroup};
    use crate::signal::RootState;
    use crate::test_child::{await_member_ready, member_command};
    use crate::test_groups::{pidfd_group_signal, Group};
    use crate::test_support::stated_root::StatedRoot;

    /// A leader in a group of its own, blocked on its stdin, and its pidfd.
    fn leader() -> (std::process::Child, std::os::fd::OwnedFd) {
        let mut leader = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn the leader");
        await_member_ready(&mut leader);
        let pidfd = crate::containment::cgroup::test_support::pidfd_of(leader.id());
        (leader, pidfd)
    }

    /// Kills and reaps `leader`, which leaves its group's number free once no member is left.
    fn kill_and_reap(mut leader: std::process::Child) {
        leader.kill().expect("kill the leader");
        let status = leader.wait().expect("reap the leader");
        assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
    }

    /// A root of `pid` whose own handle says it was reaped elsewhere, with `pidfd`.
    fn reaped_elsewhere(pid: u32, pidfd: std::os::fd::BorrowedFd<'_>) -> StatedRoot<'_> {
        StatedRoot::with_state(pid, || RootState::Reaped { own: false }).with_pidfd(pidfd)
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
                    causes: None,
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
        let mut member = crate::test_spawn::spawn(&mut member_command(leader.id() as i32)).expect("spawn the member");
        await_member_ready(&mut member);
        let root = reaped_elsewhere(leader.id(), pidfd.as_fd());
        kill_and_reap(leader);
        let checked = check_number(Some(&root));
        member.kill().expect("kill the member");
        member.wait().expect("reap the member");
        checked.expect("a group with a member left");
    }

    /// A kernel that refuses `PIDFD_SIGNAL_PROCESS_GROUP` leaves the answer to the root's state,
    /// even for a group with a member.
    #[skuld::test]
    fn check_asks_the_roots_state_when_the_kernel_refuses_the_flag() {
        let (mut leader, pidfd) = leader();
        let pid = leader.id();
        let reaped = reaped_elsewhere(pid, pidfd.as_fd());
        let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();
        let failed = check_number(Some(&reaped));
        let unreaped = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        let passed = check_number(Some(&unreaped));
        drop(refused);
        leader.kill().expect("kill the leader");
        leader.wait().expect("reap the leader");
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
        let (mut leader, pidfd) = leader();
        let pid = leader.id();
        let reaped = reaped_elsewhere(pid, pidfd.as_fd());
        let answered = crate::containment::unix::fault::answer_group_probes_with(libc::EPERM);
        let checked = check_number(Some(&reaped));
        drop(answered);
        leader.kill().expect("kill the leader");
        leader.wait().expect("reap the leader");
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
    /// Mutant: the look drops the probe's errno.
    #[skuld::test]
    fn a_look_after_a_failed_group_probe_keeps_the_probes_errno() {
        use crate::containment::root::{through_the_pidfd, NumberLook};
        use crate::containment::skip::Why;
        use crate::containment::Refusal;
        use crate::error::first_os_code;

        let pidfd = own_pidfd();
        let pid = std::process::id();
        let root = reaped_elsewhere(pid, pidfd.as_fd());
        let answered = crate::containment::unix::fault::answer_group_probes_with(libc::EPERM);
        let decided = through_the_pidfd(
            NumberLook::MayNameAnother {
                refusal: Refusal::ReapedElsewhere(pid),
                exact_root: false,
                causes: None,
            },
            &root,
        );
        drop(answered);
        let NumberLook::MayNameAnother { refusal, causes, .. } = decided else {
            panic!("a failed probe leaves the look as it was");
        };
        let cause = Why::MayNameAnother(refusal, causes).cause().expect("the probe's errno");
        assert_eq!(first_os_code(&*cause), Some(libc::EPERM), "{cause:?}");
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
