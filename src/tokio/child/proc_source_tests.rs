use super::{refused_kill_answer, refused_kill_warning, Forgetting, TornDown};
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
#[cfg(target_os = "linux")]
use crate::test_child::Console;

/// What a refused teardown kill answers: the second teardown's answer wins over the forgetting's,
/// and either wins over the fallback.
///
/// Mutant: the forgetting wins over the second teardown, or an answer is dropped for the fallback.
#[skuld::test]
fn a_refused_kill_answers_with_the_second_teardown_then_the_forgetting() {
    let id = Some(ProcessId::current());
    assert_eq!(
        refused_kill_answer(Some(ChildFate::Reaped), Some(ChildFate::Gone), id),
        ChildFate::Reaped
    );
    assert_eq!(refused_kill_answer(None, Some(ChildFate::Gone), id), ChildFate::Gone);
    assert_eq!(
        refused_kill_answer(Some(ChildFate::Killed), None, id),
        ChildFate::Killed
    );
}

/// The warn for a refused teardown kill words what became of the child from what the second
/// teardown's outcome says, for every fate that teardown can give: "torn down through its pidfd"
/// only of a child it reaped; a child it left uncollected (still running, its look failed, its wait
/// failed) is "left uncollected", and one found reaped by someone else is that. The outcome's `left`
/// and the forget's leak follow.
///
/// Mutant: the wording follows whether the second teardown ran, or only whether its fate is
/// `Running`, or ignores `uncollected`.
#[skuld::test]
fn the_refused_kill_warning_words_every_fate_the_second_teardown_gives() {
    let e = Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    let torn = |fate, uncollected, left: Option<&str>| TornDown {
        fate,
        uncollected,
        leak: "a pidfd",
        left: left.map(str::to_owned),
    };
    let id = Some(ProcessId::current());
    let rows = [
        (
            torn(ChildFate::Reaped, false, None),
            "it is torn down through its pidfd",
        ),
        (torn(ChildFate::Killed, true, None), "it is left uncollected"),
        (torn(ChildFate::Killed, false, None), "it was reaped by someone else"),
        (torn(ChildFate::Gone, false, None), "it was reaped by someone else"),
        (torn(ChildFate::Unknown, true, None), "it is left uncollected"),
        (torn(ChildFate::Running { id }, true, None), "it is left uncollected"),
    ];
    for (torn_down, clause) in rows {
        let text = refused_kill_warning(7, &e, None, Some(&torn_down));
        assert!(
            text.starts_with(&format!("teardown kill of child 7 failed ({e}); {clause}")),
            "{:?} (uncollected: {}): {text}",
            torn_down.fate,
            torn_down.uncollected
        );
        assert!(
            text.contains("forgetting tokio's handle for it leaks a pidfd"),
            "{text}"
        );
        assert_eq!(
            text.contains("torn down"),
            clause.contains("torn down"),
            "{:?}: {text}",
            torn_down.fate
        );
    }

    let left = torn(ChildFate::Running { id }, true, Some("leaving it running"));
    assert!(refused_kill_warning(7, &e, None, Some(&left)).ends_with("; leaving it running"));

    // No second teardown ran: the child was forgotten, or released.
    let forgotten = Forgetting {
        leak: "a zombie",
        why: "was reaped by someone else".to_owned(),
        fate: ChildFate::Gone,
    };
    let text = refused_kill_warning(7, &e, Some(&forgotten), None);
    assert_eq!(
        text,
        format!(
            "teardown kill of child 7 failed ({e}); it is not waited on; the child was reaped by someone \
             else; forgetting tokio's handle for it leaks a zombie"
        )
    );
}

/// Off Linux a child whose kill was refused and that is not forgotten is released to tokio's orphan
/// queue, still running, with the identity the spawn had read.
///
/// Mutant: the fallback is `Unknown`, or drops the identity.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn a_refused_kill_with_no_other_answer_leaves_the_child_running() {
    let id = Some(ProcessId::current());
    assert_eq!(refused_kill_answer(None, None, id), ChildFate::Running { id });
    assert_eq!(refused_kill_answer(None, None, None), ChildFate::Running { id: None });
}

/// On Linux every child that is not forgotten is torn down again through its pidfd, so no answer from
/// either is a contract breach, asserted in debug.
///
/// Mutant: the fallback is silent on Linux.
#[cfg(target_os = "linux")]
#[skuld::test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "neither torn down through its pidfd nor forgotten")
)]
fn a_refused_kill_with_no_other_answer_asserts_on_linux() {
    let id = Some(ProcessId::current());
    assert_eq!(refused_kill_answer(None, None, id), ChildFate::Running { id });
}

/// `exit_visible_by` waits, so it refuses to run inside an async drop's bounded section, before it
/// looks at the backend.
///
/// Mutant: drop the assert from `exit_visible_by`.
#[cfg(unix)]
#[skuld::test]
#[should_panic(expected = "would block inside an async Drop")]
fn exit_visible_by_refuses_inside_a_section() {
    let proc = super::ProcSource::Foreign {
        stdin: None,
        stdout: None,
        stderr: None,
        fate: super::Forgotten::Unproven,
        #[cfg(target_os = "linux")]
        pid: None,
        // Never read: the refusal comes before the backend is looked at.
        #[cfg(target_os = "linux")]
        pidfd: super::PinnedPidfd(Some(std::fs::File::open("/dev/null").expect("open /dev/null").into())),
    };
    let _section = crate::bounded::Section::enter();
    proc.exit_visible_by(1, std::time::Instant::now());
}

/// `ECHILD` from the reap right after a look that showed the child's exit means something else
/// reaped it in between: the awaited reap says so, not that it cannot show the child is ours. The
/// child is killed (by the test's own kill: the signal routes are not the subject) and reaped behind
/// tokio's back, and the look is made to show the exit.
///
/// Mutant: a failed `try_wait` is `Waited::Unverified` whatever its errno.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn an_echild_after_a_look_that_showed_the_exit_is_a_foreign_reap() {
    use std::os::unix::process::ExitStatusExt as _;

    use crate::os_process::child::{ExitRecord, PeekOutcome};
    use crate::wait::exit_only::seams::force_peeks;

    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    let proc = child.proc_mut();
    crate::test_child::reaped_elsewhere::kill_own_child(pid);
    let raw = rustix::process::Pid::from_raw(pid as i32).expect("a positive pid");
    rustix::process::waitid(
        rustix::process::WaitId::Pid(raw),
        rustix::process::WaitIdOptions::EXITED,
    )
    .expect("reap behind tokio's back")
    .expect("an exit record");
    let _shows_exit = force_peeks([Ok(PeekOutcome::Exit(ExitRecord::Status(
        std::process::ExitStatus::from_raw(9),
    )))]);

    let (waited, cause) = proc.wait_and_reap_awaiting().await.expect("the exit can be watched");

    assert_eq!(waited, super::Waited::Foreign, "{cause:?}");
    drop(child);
}

/// The async reap's twin of `child::owned_tests::macos::a_wait_on_a_child_whose_tracer_dies_during_its_exit_is_woken_by_the_tracers_exit`:
/// XNU sends a traced child's `NOTE_EXIT` and `SIGCHLD` to its tracer alone, and a tracer that dies
/// while the child is exiting leaves it to launchd. The reap watches the tracer too, and its
/// `NOTE_EXIT` makes it look again, which finds launchd holding the child: `Unpinned`. This
/// process's own pid stands in for the child (`waitid` answers `ECHILD`, and its id resolves), and a
/// blocker for the tracer; the parent read is forced: the stand-in while it runs, launchd once it
/// has exited. The stand-in is this test's child, so its `SIGCHLD` wakes the reap too, and the
/// assertion is on the tracer's `NOTE_EXIT` among the reap's events.
///
/// Mutant: the async reap does not watch the tracer.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn an_async_reap_of_a_child_whose_tracer_dies_during_its_exit_is_woken_by_the_tracers_exit() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::identity::{ppid_fault, uniq_info, ReadPurpose, UniqRead, LAUNCHD};
    use crate::os_process::child::PeekOutcome;
    use crate::os_process::macos::kqueue::test_hooks;
    use crate::signal::RootState;

    let pid = std::process::id();
    let UniqRead::Found(info) = uniq_info(pid, ReadPurpose::Adopt) else {
        panic!("this process's unique id must read");
    };
    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let mut tracer = crate::test_spawn::spawn(&mut cmd).expect("spawn the stand-in tracer");
    let tracer_stdin = tracer.stdin.take().expect("piped stdin");
    let tracer_pid = tracer.id();
    let exited = Rc::new(Cell::new(false));
    let _parent = ppid_fault::force_ppid_with({
        let exited = Rc::clone(&exited);
        move || Ok(if exited.get() { LAUNCHD } else { tracer_pid })
    });
    let _end = crate::tokio::child::fault::set_reap_parked(move || {
        drop(tracer_stdin);
        crate::test_child::wait_until_zombie(tracer_pid);
        exited.set(true);
    });
    let _ = test_hooks::take_events();

    let looked = super::look_on_events(pid, info.unique_id, |looked| match looked {
        Ok(PeekOutcome::Running) => Ok(None::<()>),
        other => Err(super::Halt::State(RootState::of_peek(other))),
    })
    .await;

    let events = test_hooks::take_events();
    assert!(
        events
            .iter()
            .any(|&(filter, fflags)| filter == libc::EVFILT_PROC && fflags & libc::NOTE_EXIT != 0),
        "the tracer's exit must wake the reap: {events:?}"
    );
    assert!(
        matches!(looked, Err(super::Halt::State(RootState::Unpinned))),
        "launchd holds the child once its tracer is gone"
    );
    tracer.wait().expect("reap the stand-in tracer");
}

/// This process stands in for a traced child, as above, with a live blocker its parent read is forced
/// to name as its tracer: the child's pid and unique id, the blocker, and the forced read's guard.
#[cfg(target_os = "macos")]
fn stand_in_traced_by_a_blocker() -> (u32, u64, std::process::Child, crate::identity::ppid_fault::ForcedReads) {
    use crate::identity::{ppid_fault, uniq_info, ReadPurpose, UniqRead};

    let pid = std::process::id();
    let UniqRead::Found(info) = uniq_info(pid, ReadPurpose::Adopt) else {
        panic!("this process's unique id must read");
    };
    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let tracer = crate::test_spawn::spawn(&mut cmd).expect("spawn the stand-in tracer");
    let tracer_pid = tracer.id();
    let parent = ppid_fault::force_ppid_with(move || Ok(tracer_pid));
    (pid, info.unique_id, tracer, parent)
}

/// Ends and reaps a stand-in tracer.
#[cfg(target_os = "macos")]
fn end_stand_in(mut tracer: std::process::Child) {
    drop(tracer.stdin.take());
    tracer.wait().expect("reap the stand-in tracer");
}

/// A look that finds the child running asks for another; any other look ends the reap.
#[cfg(target_os = "macos")]
fn still_running(looked: std::io::Result<crate::os_process::child::PeekOutcome>) -> Result<Option<()>, super::Halt> {
    match looked {
        Ok(crate::os_process::child::PeekOutcome::Running) => Ok(None),
        other => Err(super::Halt::State(crate::signal::RootState::of_peek(other))),
    }
}

/// A refused registration on the tracer leaves the child unwatched, not unknown: the reap halts so
/// that its caller waits in place (principle 2), rather than forgetting a child that is ours.
///
/// Mutant: every walk error is `Halt::State(Unknown)`.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn an_async_reap_whose_tracer_registration_is_refused_cannot_watch() {
    use crate::identity::Link;
    use crate::wait::macos::tracer_seams::{force_links, refuse_next_registration};

    let (pid, unique, tracer, _parent) = stand_in_traced_by_a_blocker();
    let _links = force_links([Link::Found {
        unique: 1,
        parent: std::process::id(),
        at_attach: 0,
    }]);
    let _refused = refuse_next_registration(libc::EINVAL);

    let looked = super::look_on_events(pid, unique, still_running).await;

    assert!(matches!(looked, Err(super::Halt::Watch(_))), "{looked:?}");
    end_stand_in(tracer);
}

/// A tracer whose identity cannot be read leaves the child's state unknown, as a refused peek does.
///
/// Mutant: every walk error is `Halt::Watch`.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn an_async_reap_whose_tracer_cannot_be_read_finds_the_child_unknown() {
    use crate::identity::Link;
    use crate::signal::RootState;
    use crate::wait::macos::tracer_seams::force_links;

    let (pid, unique, tracer, _parent) = stand_in_traced_by_a_blocker();
    let _links = force_links([Link::Refused(libc::EPERM)]);

    let looked = super::look_on_events(pid, unique, still_running).await;

    assert!(
        matches!(looked, Err(super::Halt::State(RootState::Unknown(_)))),
        "{looked:?}"
    );
    end_stand_in(tracer);
}

/// A tracer that is gone sends this process no event, so only the re-check timer wakes the reap to
/// look again. The walks find the tracer gone twice: at once, then after 1 ms, which the reap's
/// timer must wait for. The third look ends the reap. A backstop polled only while the reap waits,
/// by which time it has armed what it waits on, ends the test if no timer was armed.
///
/// Mutant: `KqueueWatch::next` ignores the tracer watch's re-check.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn an_async_reap_whose_tracer_is_gone_looks_again_when_the_recheck_timer_fires() {
    use crate::identity::Link;
    use crate::os_process::child::PeekOutcome;
    use crate::os_process::macos::kqueue::test_hooks;
    use crate::wait::macos::tracer_seams::force_links;

    let (pid, unique, tracer, _parent) = stand_in_traced_by_a_blocker();
    let _links = force_links([Link::Gone, Link::Gone]);
    let _ = test_hooks::take_backoff_timers();
    let mut looks = 0;
    let look = super::look_on_events(pid, unique, |looked| match looked {
        Ok(PeekOutcome::Running) => {
            looks += 1;
            Ok((looks == 3).then_some(()))
        }
        other => Err(super::Halt::State(crate::signal::RootState::of_peek(other))),
    });
    let armed = std::cell::RefCell::new(Vec::new());
    let backstop = async {
        *armed.borrow_mut() = test_hooks::take_backoff_timers();
        if armed.borrow().is_empty() {
            return;
        }
        std::future::pending::<()>().await;
    };

    let looked = ::tokio::select! {
        biased;
        looked = look => Some(looked),
        () = backstop => None,
    };

    let looked = looked.expect("the walk asked for a re-check, but the reap armed no timer to wake it");
    assert!(looked.is_ok(), "{looked:?}");
    assert_eq!(
        *armed.borrow(),
        [std::time::Duration::from_millis(1)],
        "the timer waits the re-check's 1 ms"
    );
    end_stand_in(tracer);
}
