#[cfg(target_os = "linux")]
use super::TornDown;
use super::{refused_kill_answer, refused_kill_warning, Forgetting, Refused};
#[cfg(any(target_os = "linux", windows))]
use crate::child::owned::owned_tests::teardown_lines;
use crate::child::owned::owned_tests::teardown_lines::PID;
#[cfg(target_os = "linux")]
use crate::child::owned::teardown::{Disposition, Expect, HandleTeardown, Kill, Past, TeardownOutcome};
#[cfg(target_os = "linux")]
use crate::child::owned::OwnedChild;
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
#[cfg(target_os = "linux")]
use crate::os_process::child::{ExitRecord, KillRefusal};
#[cfg(target_os = "linux")]
use crate::os_process::fake::{FakeProcess, ReapAnswer};
#[cfg(target_os = "linux")]
use crate::signal::Sent;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::test_child::Console;

/// The second teardown of a refused child, as `OwnedChild` runs it for a caller that leaves the child
/// (`tear_down_pidfd`'s), over a child 7 whose kill answers `kill` and whose wait or look answers
/// `reap`, for a spawn that read the identity `id`. Its outcome is the one the refused-kill warn is
/// built from.
#[cfg(target_os = "linux")]
fn second_teardown(kill: Result<Sent, std::io::Error>, reap: ReapAnswer, id: Option<ProcessId>) -> TeardownOutcome {
    let fake = FakeProcess::new([]).with_pid(7).reaps([reap]).signals([kill]);
    OwnedChild::new(Box::new(fake)).tear_down(
        id,
        Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        None,
    )
}

#[cfg(target_os = "linux")]
fn torn_down(outcome: TeardownOutcome) -> Refused {
    Refused::TornDown(TornDown {
        torn: HandleTeardown::new(
            outcome,
            Expect {
                refusal: KillRefusal::Permission,
                past: Past::Clean,
            },
        ),
        leak: Some("a pidfd"),
        why: None,
    })
}

/// What a refused teardown kill answers: the second teardown's fate, or the forgetting's.
///
/// Mutant: one state answers another's fate; a child left running answers without its identity.
#[skuld::test]
fn a_refused_kill_answers_from_what_became_of_the_child() {
    let id = Some(ProcessId::current());
    #[cfg(target_os = "linux")]
    {
        let exit = || ReapAnswer::Reaped(ExitRecord::Status(Default::default()));
        let failed = || ReapAnswer::Err(std::io::ErrorKind::Other);
        assert_eq!(
            refused_kill_answer(&torn_down(second_teardown(Ok(Sent::Delivered), exit(), id)), id),
            ChildFate::Reaped
        );
        assert_eq!(
            refused_kill_answer(&torn_down(second_teardown(Ok(Sent::Delivered), failed(), id)), id),
            ChildFate::Killed
        );
        // Refused again, and still running at the look: left, with the identity the spawn read.
        let refused = || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(
            refused_kill_answer(&torn_down(second_teardown(refused(), ReapAnswer::Running, id)), id),
            ChildFate::Running { id }
        );
    }
    let forgotten = Refused::Forgotten(Forgetting {
        leak: "a zombie",
        why: String::new(),
        fate: ChildFate::Gone,
    });
    assert_eq!(refused_kill_answer(&forgotten, id), ChildFate::Gone);
}

/// A child whose handle was released, with nothing else done to it, may still run: the answer is
/// `Running` with the identity the spawn had read.
///
/// Mutant: the release drops the identity or answers `Unknown`.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn a_released_child_answers_running_with_its_identity() {
    let id = Some(ProcessId::current());
    assert_eq!(refused_kill_answer(&Refused::Released, id), ChildFate::Running { id });
    assert_eq!(
        refused_kill_answer(&Refused::Released, None),
        ChildFate::Running { id: None }
    );
}

/// macOS: a child released to tokio's orphan queue is worded as the late teardown words it, from the
/// one text.
///
/// Mutant: the release is worded apart from `HANDED_TO_ORPHAN_REAPER`, or not at all.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_released_child_is_worded_as_handed_to_tokios_orphan_reaper() {
    let e = Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert_eq!(
        refused_kill_warning(7, &e, &Refused::Released),
        format!(
            "teardown kill of child 7 failed ({e}); it is {}",
            super::HANDED_TO_ORPHAN_REAPER
        )
    );
}

/// Windows: there is no orphan queue and nothing waits for the released child, and the warn says
/// that in the words of a child a caller leaves, not that anything will reap it.
///
/// Mutant: the release is worded as handed to an orphan reaper, or apart from the table's `LEFT`.
#[cfg(windows)]
#[skuld::test]
fn a_released_child_is_worded_as_a_child_left() {
    let e = Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    let text = refused_kill_warning(7, &e, &Refused::Released);
    assert_eq!(
        text,
        format!("teardown kill of child 7 failed ({e}){}", teardown_lines::LEFT)
    );
    assert!(!text.contains("orphan"), "{text}");
}

/// A refused kill of a backend already forgotten as not shown to be ours still holds the child's
/// pidfd, so Linux tears the child down through it, as for one it forgets now: killed, reaped, and
/// said in the one warn, which leaks nothing of its own. The child is a real one, ours.
///
/// Mutant: the case answers without a teardown, leaving the child running and its pidfd closed
/// unused; or panics.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_refused_kill_of_a_backend_already_forgotten_is_torn_down_through_its_pidfd() {
    let mut child =
        crate::test_spawn::spawn(&mut crate::test_child::held_std_killable_blocker()).expect("spawn the child");
    let guard = crate::containment::cgroup::test_support::KillOnDrop::of(&child);
    let pid = child.id();
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(pid as i32).expect("a positive pid"),
        rustix::process::PidfdFlags::empty(),
    )
    .expect("pidfd_open");
    let proc = super::ProcSource::Foreign {
        stdin: None,
        stdout: None,
        stderr: None,
        fate: super::Forgotten::Unproven,
        pid: Some(pid),
        pidfd: super::PinnedPidfd(Some(pidfd)),
    };
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let e = Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    let fate = proc.after_refused_kill(
        pid,
        Some(ProcessId::current()),
        &e,
        &mut crate::child::spawn::Diagnosis::default(),
    );
    assert_eq!(fate, ChildFate::Reaped);
    reaps.assert_killed();
    let already_reaped = child
        .wait()
        .expect_err("the teardown reaped the child through its pidfd");
    assert_eq!(already_reaped.raw_os_error(), Some(libc::ECHILD));
    // Reaped through the pidfd: the guard's pidfd would refuse a kill of it.
    _ = guard.defuse();
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(
        warns,
        vec![format!(
            "teardown after a failed spawn: teardown kill of child {pid} failed ({e}); tokio's handle for it was \
             already forgotten; teardown of child {pid}: reaped it after the kill"
        )]
    );
}

/// The warn for a refused teardown kill carries every row's clause of the table, whatever its level.
///
/// Mutant: the warn words the fate or `uncollected` itself, beside or instead of the clause, or
/// leaves out a clause below warn.
#[skuld::test]
fn the_refused_kill_warning_carries_every_clause_of_the_table() {
    let e = Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    // The warn up to what the outcome adds.
    #[cfg(target_os = "linux")]
    {
        let bare = format!("teardown kill of child {PID} failed ({e}); forgetting tokio's handle for it leaks a pidfd");
        for row in teardown_lines::rows() {
            let outcome = teardown_lines::outcome(&row, Disposition::Leave);
            let text = refused_kill_warning(PID, &e, &torn_down(outcome));
            assert_eq!(text, format!("{bare}; {}", row.leave), "{:?} {:?}", row.kill, row.found);
        }
    }

    // No second teardown ran: the child was forgotten.
    let forgotten = Refused::Forgotten(Forgetting {
        leak: "a zombie",
        why: "was reaped by someone else".to_owned(),
        fate: ChildFate::Gone,
    });
    let text = refused_kill_warning(PID, &e, &forgotten);
    assert_eq!(
        text,
        format!(
            "teardown kill of child {PID} failed ({e}); the child was reaped by someone else; forgetting tokio's \
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
    let pid = child.pid();
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

/// `held_os_process` reads a live child as a process whose look says running, and a child tokio has
/// reaped as nothing left to watch.
///
/// Mutant: a reaped tokio child still yields a process; a live child yields `None` (exited).
#[skuld::test]
async fn the_held_handle_reads_as_a_running_process_until_tokio_reaps_the_child() {
    use crate::os_process::Exit;

    let (mut child, _stdin) = crate::test_child::held_contained_blocker_on_console_async(crate::Stdio::pipe());
    let pid = child.pid();

    let held = child
        .proc()
        .held_os_process(pid)
        .expect("a live child's handle can be read")
        .expect("a live child has a process to watch");
    assert!(
        matches!(held.exited().expect("a look"), Exit::Running(_)),
        "a live child looks running"
    );
    drop(held);

    child.kill_tree().expect("kill the blocker");
    child.wait().await.expect("reap the blocker");
    let reaped = child
        .proc()
        .held_os_process(pid)
        .expect("a reaped child's handle can be read");
    assert!(reaped.is_none(), "a reaped child has nothing left to watch");
}

/// The look at a child on macOS requires the unique id read at spawn after the watch is armed: a pid
/// another process holds by then is exited, not watched as the child, and a refused read cannot be
/// assessed (`Unassessable`, with the errno).
///
/// Mutant: the look never reads the unique id; a mismatch is `Some`; a refused read is `None`.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn the_held_handle_look_checks_the_unique_id_after_arming_on_macos() {
    use crate::child::spawn::identity_macos_tests::other_unique_id;
    use crate::identity::uniq_fault::force_uniq_read_once;
    use crate::identity::{ReadPurpose, UniqRead};

    let (mut child, _stdin) = crate::test_child::held_contained_blocker_on_console_async(crate::Stdio::pipe());
    let pid = child.pid();

    {
        let _other = force_uniq_read_once(ReadPurpose::Open, other_unique_id(pid));
        let held = child.proc().held_os_process(pid).expect("a mismatch is not an error");
        assert!(held.is_none(), "a pid another process holds is exited, not watched");
    }
    {
        let _refused = force_uniq_read_once(ReadPurpose::Open, UniqRead::Refused(libc::EPERM));
        let Err(Error::Unassessable {
            source: Some(source), ..
        }) = child.proc().held_os_process(pid)
        else {
            panic!("a refused read is Unassessable with its errno");
        };
        assert_eq!(source.raw_os_error(), Some(libc::EPERM));
    }
    assert!(
        child.proc().held_os_process(pid).expect("a matching read").is_some(),
        "the child's own unique id is watched"
    );

    child.kill_tree().expect("kill the blocker");
    child.wait().await.expect("reap the blocker");
}

/// A macOS child forgotten as not shown to be ours is sent no `SIGTERM` (`Sent::Unverified`) and its
/// look is `Unassessable`, so a graceful shutdown escalates at once.
///
/// Mutant: the unproven child is sent the signal by number, or its look watches the number.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn an_unproven_child_is_sent_no_sigterm_and_cannot_be_looked_at_on_macos() {
    use crate::signal::{Sent, Sig};

    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.pid();
    child
        .proc_mut()
        .forget_as("was forgotten by a test", super::Forgotten::Unproven);

    assert_eq!(child.proc().signal(Sig::Term).expect("no error"), Sent::Unverified);
    assert!(
        matches!(child.proc().held_os_process(pid), Err(Error::Unassessable { .. })),
        "nothing proves the number is still the child's"
    );
    drop(writer);
}
