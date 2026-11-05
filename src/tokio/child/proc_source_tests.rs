use super::{refused_kill_answer, refused_kill_warning, Forgetting, Refused, TornDown};
use crate::child::owned::teardown::TeardownOutcome;
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
#[cfg(target_os = "linux")]
use crate::test_child::Console;

/// What a refused teardown kill answers: the second teardown's fate, the forgetting's, or, for a
/// child released to tokio's orphan queue, running with the identity the spawn had read.
///
/// Mutant: one state answers another's fate, or the release drops the identity or answers `Unknown`.
#[skuld::test]
fn a_refused_kill_answers_from_what_became_of_the_child() {
    let id = Some(ProcessId::current());
    let torn = |fate| {
        Refused::TornDown(TornDown {
            outcome: TeardownOutcome {
                fate,
                uncollected: false,
                look: None,
                left: None,
            },
            leak: "a pidfd",
        })
    };
    assert_eq!(refused_kill_answer(&torn(ChildFate::Reaped), id), ChildFate::Reaped);
    assert_eq!(refused_kill_answer(&torn(ChildFate::Killed), id), ChildFate::Killed);
    let forgotten = Refused::Forgotten(Forgetting {
        leak: "a zombie",
        why: String::new(),
        fate: ChildFate::Gone,
    });
    assert_eq!(refused_kill_answer(&forgotten, id), ChildFate::Gone);
    assert_eq!(refused_kill_answer(&Refused::Released, id), ChildFate::Running { id });
    assert_eq!(
        refused_kill_answer(&Refused::Released, None),
        ChildFate::Running { id: None }
    );
}

/// A child released to tokio's orphan queue is worded as the macOS late teardown words it.
///
/// Mutant: the release is worded apart from `reap_unreported`'s text, or not at all.
#[skuld::test]
fn a_released_child_is_worded_as_handed_to_tokios_orphan_reaper() {
    let e = Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert_eq!(
        refused_kill_warning(7, &e, &Refused::Released),
        format!(
            "teardown kill of child 7 failed ({e}); {}",
            super::HANDED_TO_ORPHAN_REAPER
        )
    );
}

/// The warn for a refused teardown kill carries the second teardown outcome's own words (`left`)
/// and nothing of its own about the child, for every fate that teardown can give: an outcome with
/// nothing to warn of (reaped, or found reaped by someone else) adds nothing, and one with words is
/// worded by them once, never beside a second clause of the warn's own.
///
/// Mutant: the warn words the fate or `uncollected` itself, beside or instead of `left`.
#[skuld::test]
fn the_refused_kill_warning_words_every_fate_the_second_teardown_gives() {
    let e = Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    let id = Some(ProcessId::current());
    // A second teardown's outcome, with the `left` that `Settlement::wording` gives that fate (warn
    // level only: a debug line is logged by the teardown and leaves `left` empty).
    let torn = |fate, uncollected, left: Option<&str>| {
        Refused::TornDown(TornDown {
            outcome: TeardownOutcome {
                fate,
                uncollected,
                look: None,
                left: left.map(str::to_owned),
            },
            leak: "a pidfd",
        })
    };
    let outcome_of = |after: &Refused| match after {
        Refused::TornDown(t) => (t.outcome.fate, t.outcome.left.clone()),
        _ => unreachable!("built by `torn`"),
    };
    // The warn up to what the outcome adds.
    let bare = format!("teardown kill of child 7 failed ({e}); forgetting tokio's handle for it leaks a pidfd");

    // An outcome with nothing to warn of adds nothing: no clause of the warn's own, whatever the fate.
    let silent = [
        torn(ChildFate::Reaped, false, None),
        torn(ChildFate::Killed, false, None),
        torn(ChildFate::Gone, false, None),
    ];
    for after in &silent {
        assert_eq!(refused_kill_warning(7, &e, after), bare, "{:?}", outcome_of(after).0);
    }

    // One that has something to warn of is worded by it alone, once.
    let spoken = [
        torn(
            ChildFate::Reaped,
            false,
            Some("teardown of child 7: reaped it after the kill; the child's exit record was unreadable"),
        ),
        torn(
            ChildFate::Gone,
            false,
            Some("teardown of child 7: not ours to reap (launchd holds its zombie, because its tracer died)"),
        ),
        torn(
            ChildFate::Killed,
            true,
            Some("teardown of child 7: the wait failed: cosca-wait-4d7b"),
        ),
        torn(
            ChildFate::Unknown,
            true,
            Some("teardown of child 7: the wait failed: cosca-wait-4d7b"),
        ),
        torn(
            ChildFate::Running { id },
            true,
            Some("child 7 could not be terminated (cosca); leaving it running"),
        ),
    ];
    for after in spoken {
        let (fate, left) = outcome_of(&after);
        let left = left.expect("a warn-level outcome has words");
        let text = refused_kill_warning(7, &e, &after);
        assert_eq!(text, format!("{bare}; {left}"), "{fate:?}");
        for clause in [
            "torn down through",
            "not waited on",
            "left uncollected",
            "reaped by someone else",
        ] {
            assert!(!text.contains(clause), "{fate:?} says {clause:?}: {text}");
        }
    }

    // No second teardown ran: the child was forgotten.
    let forgotten = Refused::Forgotten(Forgetting {
        leak: "a zombie",
        why: "was reaped by someone else".to_owned(),
        fate: ChildFate::Gone,
    });
    let text = refused_kill_warning(7, &e, &forgotten);
    assert_eq!(
        text,
        format!(
            "teardown kill of child 7 failed ({e}); the child was reaped by someone else; forgetting tokio's \
             handle for it leaks a zombie"
        )
    );
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
