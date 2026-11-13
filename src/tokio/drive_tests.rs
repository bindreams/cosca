use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[cfg(unix)]
use super::absolute;
use super::{exited_held, run};
use crate::error::Error;
use crate::os_process::drive::ProcessExit;
use crate::os_process::fake::{Answer, FakeProcess};
use crate::wait::fault;
#[cfg(unix)]
use crate::{
    os_process::drive::{
        drive_tests::{ms, whole_ms, Move, Scripted},
        RunOutcome,
    },
    wait::block_probe,
};

fn fake(exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    FakeProcess::new(exits)
}

/// Poll `fut` once, with a waker that wakes nothing.
pub(crate) fn poll_once<F: Future>(fut: F) -> Poll<F::Output> {
    pin!(fut).as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

/// Mutant: await at a zero timeout, or look a second time.
#[skuld::test]
async fn zero_timeout_looks_once_and_never_waits() {
    let p = fake([Answer::Running]);
    let Poll::Ready(answer) = poll_once(exited_held(&p, Some(Duration::ZERO))) else {
        panic!("a zero timeout must not wait");
    };
    assert!(!answer.unwrap());
    assert_eq!(p.looks(), 1);
}

/// Mutant: swallow a failed look as a wake, or wait before returning it.
#[skuld::test]
async fn a_failed_look_is_returned_without_waiting() {
    let p = fake([Answer::Err(std::io::ErrorKind::PermissionDenied)]);
    let Poll::Ready(answer) = poll_once(exited_held(&p, None)) else {
        panic!("a failed look must not wait");
    };
    let err = answer.unwrap_err();
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
    assert_eq!(p.looks(), 1);
}

/// Mutant: wait before looking, or after an `Exited` look.
#[skuld::test]
async fn exited_before_first_look_returns_true_without_waiting() {
    let p = fake([Answer::Exited]);
    let Poll::Ready(answer) = poll_once(exited_held(&p, None)) else {
        panic!("an exited process must not wait");
    };
    assert!(answer.unwrap());
    assert_eq!(p.looks(), 1);
}

/// Mutant: trust the wake as the answer instead of looking again.
#[skuld::test]
async fn wakes_and_looks_again() {
    let p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_held(&p, Some(Duration::from_secs(60))).await.unwrap());
    assert_eq!(p.looks(), 2);
}

/// Mutant: answer `false` on the expiry itself, without a look after the deadline. The fake is never
/// woken, so only the deadline ends the wait.
#[skuld::test]
async fn expiry_ends_in_one_final_look() {
    let timeout = Duration::from_millis(50);
    let p = fake([Answer::Running, Answer::Running]);
    let start = crate::wait::now();
    assert!(!exited_held(&p, Some(timeout)).await.unwrap());
    assert_eq!(p.looks(), 2);
    let last = *p.look_times().last().unwrap();
    assert!(
        last >= start + timeout,
        "the final look must come at or after the deadline"
    );
}

/// Mutant: answer `false` on the expiry without trusting the final look, which finds an exit that
/// was pending when the deadline passed.
#[skuld::test]
async fn the_final_look_can_find_an_exit() {
    let p = fake([Answer::Running, Answer::Exited]);
    assert!(exited_held(&p, Some(Duration::from_millis(50))).await.unwrap());
    assert_eq!(p.looks(), 2);
}

/// Mutant: let `Duration::MAX` overflow the deadline sum.
#[skuld::test]
async fn duration_max_is_unbounded() {
    crate::tokio::test_runtime::assert_current_thread();
    #[cfg(unix)]
    let (tx, armed) = std::sync::mpsc::channel();
    #[cfg(unix)]
    let _seam = crate::tokio::wait::armed_deadline_seam::install(tx);
    // Windows: the clock reads of the driver, which arms the registered wait.
    #[cfg(windows)]
    let (log_tx, reads) = std::sync::mpsc::channel();
    #[cfg(windows)]
    let _log = crate::wait::read_probe::install(log_tx);
    let p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_held(&p, Some(Duration::MAX)).await.unwrap());
    #[cfg(unix)]
    assert_eq!(armed.try_iter().count(), 0, "an overflowing timeout arms no timer");
    #[cfg(windows)]
    {
        use crate::wait::read_probe::Event;

        let reads: Vec<Event> = reads.try_iter().collect();
        assert!(!reads.is_empty(), "the wait reads the clock");
        assert!(
            reads
                .iter()
                .all(|event| matches!(event, Event::Read { remaining: None, .. })),
            "an overflowing timeout registers an unbounded wait: {reads:?}"
        );
    }
}

/// Mutant: arm the timer for a duration re-derived later, or not at all.
#[cfg(unix)]
#[skuld::test]
async fn a_bounded_wait_arms_the_timer_at_the_deadline() {
    use crate::tokio::wait::armed_deadline_seam::{install, Armed};

    crate::tokio::test_runtime::assert_current_thread();
    let (tx, armed) = std::sync::mpsc::channel();
    let _seam = install(tx);
    let timeout = Duration::from_secs(60);
    let before = crate::tokio::wait::tokio_now();
    let p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_held(&p, Some(timeout)).await.unwrap());
    let after = crate::tokio::wait::tokio_now();
    let [Armed::At(at)] = armed.try_iter().collect::<Vec<_>>()[..] else {
        panic!("one wait arms one timer");
    };
    assert!(at >= before + timeout && at <= after + timeout, "{at:?}");
}

/// A `Running` fake whose wait is dropped, and then the runtime: nothing the wait registered keeps
/// the runtime from dropping.
#[skuld::test]
fn dropped_wait_releases_the_watch() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    let p = fake([Answer::Running]);
    runtime.block_on(async {
        let mut wait = pin!(exited_held(&p, None));
        assert!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
            "a running process with nothing fired waits"
        );
    }); // the wait is dropped here
    drop(runtime);
}

/// Open descriptors of this process (each count includes the directory handle that reads it).
#[cfg(target_os = "linux")]
pub(crate) fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("read /proc/self/fd").count()
}

/// A wait round opens no process descriptor of its own (no `pidfd_open`): the one descriptor it adds
/// is a duplicate of the pidfd the process already holds, which is what lets waits on one process
/// run at once (the reactor takes one registration per descriptor).
///
/// Mutant: open a pidfd for the round, which is a second added descriptor. Mutant: register the
/// held pidfd itself, which adds none (and fails a second concurrent wait; see
/// `async_foreign_concurrent_waits_both_resolve_on_exit`).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_wait_round_adds_only_a_duplicate_of_the_held_pidfd() {
    use crate::os_process::open;
    use crate::test_child::held_contained_blocker_without_cgroup;

    let (child, stdin) = held_contained_blocker_without_cgroup(crate::Stdio::null());
    let process = open(child.id().expect(crate::test_child::IDENTITY_READ))
        .unwrap()
        .expect("a live process opens");
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    let before = open_fds();
    let during = runtime.block_on(async {
        let mut wait = pin!(exited_held(&*process, None));
        assert!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
            "a running process waits"
        );
        open_fds()
    });
    assert_eq!(during, before + 1, "the round adds exactly one descriptor, a duplicate");
    drop(stdin);
    child.wait().expect("reap the blocker");
}

/// The futures cross threads on every platform: `spawn` needs it.
#[skuld::test]
fn async_waits_are_send() {
    fn assert_send<T: Send>(_: &T) {}

    let p = fake([]);
    assert_send(&exited_held(&p, None));
    assert_send(&run(&mut ProcessExit(&p), None));
    let process = crate::tokio::Process::current().expect("open this process");
    assert_send(&process.wait());
}

/// The pauses `run` recorded, in whole milliseconds.
#[cfg(unix)]
fn pauses() -> Vec<u64> {
    let pauses: Vec<_> = block_probe::take()
        .into_iter()
        .map(|pause| pause.expect("a pause is bounded"))
        .collect();
    whole_ms(&pauses)
}

/// Mutant: pause a constant, or restart the schedule at every pause, or arm no timer.
#[cfg(unix)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn async_run_pauses_on_the_backoff_for_a_recheck() {
    block_probe::take();
    let mut w = Scripted::new([Move::Recheck, Move::Recheck, Move::Recheck, Move::Done]);
    assert!(matches!(run(&mut w, None).await.unwrap(), RunOutcome::Done(())));
    assert_eq!(pauses(), [1, 2, 4]);
    assert_eq!(w.looks, 4, "one look per pause, and one more");
}

/// A pause never outlasts the deadline: the last one is cut to the time remaining, and the look
/// after it is the final one.
///
/// Mutant: pause the whole step; or make no final look after the last pause; or pause again at the
/// deadline.
#[cfg(unix)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn async_run_cuts_a_pause_to_the_deadline_and_looks_once_more() {
    block_probe::take();
    let mut w = Scripted::new([Move::Recheck; 3]);
    let outcome = run(&mut w, absolute(Some(ms(3)))).await.unwrap();
    assert!(matches!(outcome, RunOutcome::DeadlinePassed), "{outcome:?}");
    assert_eq!(pauses(), [1, 2]);
    assert_eq!(w.looks, 3, "the last look is made at the deadline");
}

/// A pause the deadline cuts is armed at the deadline instant, not at a duration from a later clock
/// read: the clock moves between the look and the arm, and the timer still ends at the deadline.
///
/// Mutant: arm `tokio_now() + <the step cut to the time left>`.
#[cfg(unix)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn async_run_arms_a_cut_pause_at_the_deadline_instant() {
    use crate::tokio::wait::armed_deadline_seam::{install, Armed};
    use crate::tokio::wait::{now_override, tokio_now};

    let (tx, armed) = std::sync::mpsc::channel();
    let _seam = install(tx);
    // Half of the first 1 ms step: the deadline cuts the first pause.
    let deadline = absolute(Some(Duration::from_micros(500))).expect("a finite deadline");
    // The clock reads later in the pause than when the look ended.
    let moved = std::rc::Rc::new(std::cell::RefCell::new(None));
    let _moves = block_probe::on_pause({
        let moved = moved.clone();
        move || *moved.borrow_mut() = Some(now_override::install(tokio_now() + Duration::from_micros(200)))
    });
    let mut w = Scripted::new([Move::Recheck, Move::Done]);
    assert!(matches!(
        run(&mut w, Some(deadline)).await.unwrap(),
        RunOutcome::Done(())
    ));
    assert!(moved.borrow().is_some(), "the clock moved before the arm");
    assert_eq!(armed.try_iter().collect::<Vec<_>>(), [Armed::At(deadline)]);
}

/// Mutant: keep the schedule across a wait.
#[cfg(unix)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn async_run_restarts_the_backoff_after_a_wait() {
    block_probe::take();
    let mut w = Scripted::new([Move::Recheck, Move::Recheck, Move::Wait, Move::Recheck, Move::Done]);
    assert!(matches!(run(&mut w, None).await.unwrap(), RunOutcome::Done(())));
    assert_eq!(pauses(), [1, 2, 1]);
}

/// A failed wait is the `Waitable`'s to answer: one that survives it is looked at again.
///
/// Mutant: end the loop on a wait error the `Waitable` survived; or never hand it to the `Waitable`.
#[cfg(target_os = "linux")]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn async_run_survives_a_failed_wait_when_the_waitable_does() {
    let mut w = Scripted::new([Move::WaitFails, Move::Recheck, Move::Done]);
    w.survive_block_errors = true;
    assert!(matches!(run(&mut w, None).await.unwrap(), RunOutcome::Done(())));
    assert_eq!(w.block_errors, 1);
    assert_eq!(w.looks, 3);
}

#[cfg(windows)]
mod windows {
    //! The Windows exit wait is a registered wait on the process handle: none occupies the blocking
    //! pool.

    use std::future::Future as _;
    use std::pin::pin;
    use std::task::{Context, Waker};
    use std::time::Duration;

    use crate::containment::drain_edge::DrainEdge;
    use crate::containment::windows::JobHandle;
    use crate::containment::TreeDrain;
    use crate::os_process::open;
    use crate::test_child::live_blocker as blocker;
    use crate::test_child::{let_member_exit, spawn_job_member, spawn_job_with_two_members};
    use crate::tokio::test_runtime::single_thread_pool_runtime;
    use crate::wait::test_clock::FrozenClockGuard;
    use crate::wait::{instant_near_ceiling, wait_ms_probe, TOKIO_TIMER_ROUNDING_MARGIN};

    /// Two children awaited together, the first exiting only after the second's wait has returned,
    /// both complete: the first's wait does not hold the pool the second's would need.
    ///
    /// Mutant: an exit wait runs on the blocking pool.
    #[skuld::test]
    fn two_awaited_children_do_not_queue_behind_each_other() {
        let rt = single_thread_pool_runtime();
        let (first, first_stdin, first_id) = blocker();
        let (second, second_stdin, second_id) = blocker();
        let first_process = open(first_id).unwrap().expect("a live process opens");
        let second_process = open(second_id).unwrap().expect("a live process opens");
        rt.block_on(async {
            // `join!` polls its first branch first: its wait is the one that would take the thread.
            ::tokio::join!(
                async { assert!(super::exited_held(&*first_process, None).await.unwrap()) },
                async {
                    drop(second_stdin);
                    assert!(super::exited_held(&*second_process, None).await.unwrap());
                    drop(first_stdin);
                },
            );
        });
        first.wait().expect("reap the first");
        second.wait().expect("reap the second");
    }

    /// A task awaiting a child's exit does not stop a spawn from completing.
    ///
    /// Mutant: an exit wait runs on the blocking pool, which the spawn needs.
    #[skuld::test]
    fn an_awaited_child_does_not_stop_a_spawn_from_completing() {
        use crate::test_child::{held_writer_stdin, tokio_command, Console, BLOCKER_ARGV};

        let rt = single_thread_pool_runtime();
        let (parked, parked_stdin, parked_id) = blocker();
        let parked_process = open(parked_id).unwrap().expect("a live process opens");
        rt.block_on(async {
            ::tokio::join!(
                async { assert!(super::exited_held(&*parked_process, None).await.unwrap()) },
                async {
                    let (stdin, writer) = held_writer_stdin();
                    let mut cmd = tokio_command(Console::Hidden);
                    cmd.args(BLOCKER_ARGV.iter().copied());
                    cmd.stdin(stdin).expect("stdin");
                    let mut spawned = cmd.spawn().await.expect("the spawn completes beside the wait");
                    drop(writer);
                    spawned.wait().await.expect("wait for the spawned child");
                    drop(parked_stdin);
                },
            );
        });
        parked.wait().expect("reap the parked child");
    }

    /// A job's drain wait and a process wait together complete: neither holds the pool the other
    /// would need.
    ///
    /// Mutant: the drain wait or the process wait runs on the blocking pool.
    #[skuld::test]
    fn a_drain_wait_and_a_process_wait_complete_together() {
        let rt = single_thread_pool_runtime();
        let (parked, parked_stdin, parked_id) = blocker();
        let parked_process = open(parked_id).unwrap().expect("a live process opens");
        let (mut member, job) = spawn_job_member();
        rt.block_on(async {
            ::tokio::join!(
                async { assert!(super::exited_held(&*parked_process, None).await.unwrap()) },
                async {
                    drop(member.stdin.take());
                    assert_eq!(drain(&job, None).await, TreeDrain::AllMembersExited);
                    drop(parked_stdin);
                },
            );
        });
        member.wait().expect("reap the member");
        parked.wait().expect("reap the parked child");
    }

    /// The timeouts the process wait on `process` registers with the OS for one poll of
    /// `exited_held(process, Some(timeout))`: none for an unbounded wait.
    fn registered_for(process: &dyn crate::os_process::OsProcess, timeout: Duration) -> Vec<wait_ms_probe::Arm> {
        wait_ms_probe::take();
        let polled = super::poll_once(super::exited_held(process, Some(timeout)));
        assert!(polled.is_pending(), "a live process is waited for");
        wait_ms_probe::take()
    }

    /// A timeout that overflows `Instant` is no timeout: the wait registers none.
    ///
    /// Mutant: an overflowing timeout becomes a far-future deadline, which the OS times out early.
    #[skuld::test]
    async fn a_process_wait_timeout_past_the_clock_registers_no_timeout() {
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        let arms = registered_for(&*process, Duration::MAX);
        drop(stdin);
        child.wait().expect("reap the child");
        assert!(arms.is_empty(), "an unbounded wait registered {arms:?}");
    }

    /// A timeout landing exactly the timer margin short of `Instant`'s ceiling registers a timeout;
    /// one nanosecond further registers none.
    ///
    /// Mutant: the margin is not applied to the deadline.
    #[skuld::test]
    async fn a_process_wait_timeout_at_the_margin_edge_registers_one_and_one_nanosecond_past_it_none() {
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        let (_clock, now) = FrozenClockGuard::install();
        let edge = instant_near_ceiling(now).saturating_duration_since(now) - TOKIO_TIMER_ROUNDING_MARGIN;
        let at_edge = registered_for(&*process, edge);
        let past_edge = registered_for(&*process, edge + Duration::from_nanos(1));
        drop(stdin);
        child.wait().expect("reap the child");
        assert_eq!(at_edge.len(), 1, "{at_edge:?}");
        assert_eq!(at_edge[0].requested, edge, "{at_edge:?}");
        assert!(past_edge.is_empty(), "an unbounded wait registered {past_edge:?}");
    }

    /// A bounded wait on a runtime built without a time driver answers: its deadline is the
    /// registered wait's own, not a tokio timer, which would panic here.
    ///
    /// Mutant: the wait arms tokio's timer.
    #[skuld::test]
    fn a_bounded_process_wait_on_a_runtime_without_a_time_driver_answers() {
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build a runtime with no drivers");
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        rt.block_on(async {
            assert!(!super::exited_held(&*process, Some(Duration::from_millis(50)))
                .await
                .unwrap());
        });
        drop(stdin);
        child.wait().expect("reap the child");
    }

    /// The same for a drain wait.
    ///
    /// Mutant: the wait arms tokio's timer.
    #[skuld::test]
    fn a_bounded_drain_on_a_runtime_without_a_time_driver_answers() {
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build a runtime with no drivers");
        let (member, job) = spawn_job_member();
        rt.block_on(async {
            let deadline = crate::wait::deadline_from(Duration::from_millis(50)).expect("a finite deadline");
            assert_eq!(drain(&job, Some(deadline)).await, TreeDrain::MembersRemain);
        });
        let_member_exit(member);
    }

    /// A child that exits after a pipe write is seen exited on a runtime whose clock is paused: a
    /// paused clock advances itself to a timer whenever the runtime is idle, which would time the
    /// wait out before the child could exit. The write waits until the wait is polled once, so the
    /// runtime goes idle with the child still running.
    ///
    /// Mutant: the wait arms tokio's timer, which the paused clock advances to.
    #[skuld::test(runtime = crate::tokio::test_runtime::paused)]
    async fn a_bounded_process_wait_on_a_paused_clock_sees_the_child_exit() {
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        let (go, written) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            written.recv().expect("told to write");
            drop(stdin);
        });
        let mut wait = pin!(super::exited_held(&*process, Some(Duration::from_secs(60))));
        assert!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
            "a running child is waited for"
        );
        go.send(()).expect("the writer waits");
        assert!(wait.await.unwrap(), "the child exited, the deadline did not pass");
        writer.join().expect("the writer ended");
        child.wait().expect("reap the child");
    }

    /// The same for a drain wait.
    ///
    /// Mutant: the wait arms tokio's timer, which the paused clock advances to.
    #[skuld::test(runtime = crate::tokio::test_runtime::paused)]
    async fn a_bounded_drain_on_a_paused_clock_sees_the_member_exit() {
        let (mut member, job) = spawn_job_member();
        let stdin = member.stdin.take().expect("piped stdin");
        let (go, written) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            written.recv().expect("told to write");
            drop(stdin);
        });
        let deadline = crate::tokio::wait::deadline_from(Duration::from_secs(60));
        let mut wait = pin!(drain(&job, deadline));
        assert!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
            "a running member is waited for"
        );
        go.send(()).expect("the writer waits");
        assert_eq!(wait.await, TreeDrain::AllMembersExited);
        writer.join().expect("the writer ended");
        member.wait().expect("reap the member");
    }

    /// The async wait over `job`'s members, until `deadline` (on tokio's clock).
    async fn drain(job: &JobHandle, deadline: Option<std::time::Instant>) -> TreeDrain {
        DrainEdge::Job(job).wait_async(deadline).await.expect("the drain wait")
    }

    /// A drain with no deadline ends when the last member has exited, and not before.
    ///
    /// Mutant: a round's wait ends on the first listing, or never re-lists after a member's exit.
    #[skuld::test]
    async fn a_drain_with_no_deadline_ends_when_the_member_exits() {
        let (mut member, job) = spawn_job_member();
        let mut wait = pin!(drain(&job, None));
        assert!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
            "a running member is waited for"
        );
        drop(member.stdin.take());
        assert_eq!(wait.await, TreeDrain::AllMembersExited);
        member.wait().expect("reap the member");
    }

    /// An empty job is drained at once, as in the sync wait.
    #[skuld::test]
    async fn a_drain_of_an_empty_job_answers_without_waiting() {
        let job = JobHandle::create_empty_for_test();
        assert_eq!(drain(&job, None).await, TreeDrain::AllMembersExited);
    }

    /// A deadline already past is the last round: a live member is polled, not waited for, and the
    /// drain answers `MembersRemain`.
    ///
    /// Mutant: the round registers its handles and waits out the member.
    #[skuld::test]
    async fn a_drain_with_a_deadline_already_past_polls_once() {
        let (member, job) = spawn_job_member();
        let past = crate::tokio::wait::deadline_from(Duration::ZERO);
        assert_eq!(drain(&job, past).await, TreeDrain::MembersRemain);
        let_member_exit(member);
    }

    /// A deadline already past on a job whose members have all gone: the last round lists and sees
    /// the job drained, however late the caller came. The drain with no deadline is what says the
    /// job is empty: the member's own exit is not enough, since its console host (`conhost.exe`)
    /// is a member too, and outlives it for a moment.
    ///
    /// Mutant: a round that starts past the deadline answers `MembersRemain` without looking.
    #[skuld::test]
    async fn a_drain_with_a_deadline_already_past_sees_a_drained_job() {
        let (mut member, job) = spawn_job_member();
        drop(member.stdin.take());
        assert_eq!(drain(&job, None).await, TreeDrain::AllMembersExited);
        member.wait().expect("reap the member");
        let past = crate::tokio::wait::deadline_from(Duration::ZERO);
        assert_eq!(drain(&job, past).await, TreeDrain::AllMembersExited);
    }

    /// A deadline that passes while a member runs answers `MembersRemain`, at or after it.
    ///
    /// Mutant: the timer is not armed, so the wait never ends; or it answers before the deadline.
    #[skuld::test]
    async fn a_drain_reports_members_remaining_at_its_deadline() {
        let (member, job) = spawn_job_member();
        let deadline = crate::tokio::wait::deadline_from(Duration::from_millis(50)).expect("a finite deadline");
        assert_eq!(drain(&job, Some(deadline)).await, TreeDrain::MembersRemain);
        assert!(
            crate::tokio::wait::tokio_now() >= deadline,
            "answered before its deadline"
        );
        let_member_exit(member);
    }

    /// An empty FIRST listing is no answer, as in the sync wait: the member is alive, in the job,
    /// when the listing (forced) comes back empty, so the drain, whose deadline has passed, finds it
    /// running in the snapshot and answers `MembersRemain`. The snapshot is taken on the blocking
    /// pool, so a poll cannot tell an answer from a wait still to come: the deadline decides.
    ///
    /// Mutant: an empty first listing answers `AllMembersExited` off the list alone.
    #[skuld::test]
    async fn a_drain_does_not_answer_an_empty_first_listing_while_a_member_runs() {
        use crate::containment::windows::fault::force_job_pid_list;

        let (member, job) = spawn_job_member();
        let _forced = force_job_pid_list(Vec::new());
        let verdict = drain(&job, crate::tokio::wait::deadline_from(Duration::ZERO)).await;
        let_member_exit(member);
        assert_eq!(
            verdict,
            TreeDrain::MembersRemain,
            "the drain answered off the empty listing while a member's process object was unsignalled"
        );
    }

    /// A member alive in the job when the first listing (forced) comes back empty is waited for under
    /// a drain with no deadline: the drain is still pending while it runs, and answers once it has
    /// exited. A first poll that is ready is an answer given off the empty listing.
    ///
    /// Mutant: `Round::Confirm` answers `AllMembersExited` without a snapshot.
    #[skuld::test]
    async fn a_drain_whose_listing_is_empty_ends_when_the_member_the_snapshot_names_exits() {
        use crate::containment::windows::fault::force_job_pid_list;

        let (mut member, job) = spawn_job_member();
        let _forced = force_job_pid_list(Vec::new());
        let mut wait = pin!(drain(&job, None));
        assert!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
            "the drain answered off the empty listing while a member runs"
        );
        drop(member.stdin.take());
        assert_eq!(wait.await, TreeDrain::AllMembersExited);
        member.wait().expect("reap the member");
    }

    /// A drain that moves from watching its round's members to confirming an empty listing waits for
    /// the member the snapshot names. Two members are listed (forced) and watched; the first exits,
    /// and the next listing (forced) is empty while the second runs. The snapshot runs on the blocking
    /// pool, which has one thread: a task queued after it ends after it, so once that task has run
    /// the snapshot's result has landed, and a drain that does not wait for the member it names
    /// answers on its next poll, where this one is still pending.
    ///
    /// Mutant: the confirmation takes the snapshot but does not wait for the members it names.
    #[skuld::test]
    fn a_drain_moving_from_watching_to_confirming_waits_for_the_member_the_snapshot_names() {
        use crate::containment::windows::fault::{force_job_pid_lists, job_pid_list_queries};

        let (mut first, mut second, job) = spawn_job_with_two_members();
        let stdin = second.stdin.take().expect("piped stdin");
        let rt = single_thread_pool_runtime();
        let _forced = force_job_pid_lists([vec![first.id(), second.id()], Vec::new()]);
        rt.block_on(async {
            let mut wait = pin!(drain(&job, None));
            assert!(
                wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
                "live members are watched"
            );
            first.kill().expect("end the first member");
            first.wait().expect("reap the first member");
            // The first member's exit ends the watch; the round after it reads the empty listing and
            // hands the snapshot to the pool.
            while job_pid_list_queries() < 2 {
                assert!(
                    wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
                    "the second member runs"
                );
                ::tokio::task::yield_now().await;
            }
            ::tokio::task::spawn_blocking(|| ())
                .await
                .expect("the task queued behind the snapshot");
            assert!(
                wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
                "the drain answered once the snapshot had run, without waiting for the member it names"
            );
            drop(stdin);
            assert_eq!(wait.await, TreeDrain::AllMembersExited);
        });
        second.wait().expect("reap the second member");
    }

    /// A process that joins the job after a confirmed drain is confirmed too, as in the sync wait: the
    /// job's count has risen, so the next empty listing (forced) takes the snapshot, finds the new
    /// member running and, at an elapsed deadline, answers `MembersRemain`.
    ///
    /// Mutant: a confirmed drain's stored count is trusted whatever the job's count is now.
    #[skuld::test]
    async fn a_member_assigned_after_a_confirmed_drain_is_confirmed_too() {
        use std::os::windows::io::AsRawHandle as _;

        use crate::containment::windows::fault::force_job_pid_list;

        let (child, job) = spawn_job_member();
        let_member_exit(child);
        assert_eq!(drain(&job, None).await, TreeDrain::AllMembersExited);
        let second = crate::test_child::spawn_more_blocker();
        job.assign_for_test(second.as_raw_handle())
            .expect("assign a new member to the job");
        let _forced = force_job_pid_list(Vec::new());
        let verdict = drain(&job, crate::tokio::wait::deadline_from(Duration::ZERO)).await;
        job.hard_kill().expect("end the member");
        let_member_exit(second);
        assert_eq!(
            verdict,
            TreeDrain::MembersRemain,
            "the drain stood for a member it never confirmed"
        );
    }

    /// A member the caller may open for its membership but not wait on is one whose exit cannot be
    /// observed: the async drain fails, naming it, with the OS error as the cause, as the sync one
    /// does, and never answers `AllMembersExited` while it runs.
    ///
    /// Mutant: membership is decided with the access the wait needs.
    #[skuld::test]
    fn a_drain_names_a_member_it_may_not_wait_on_when_the_listing_is_empty() {
        use std::error::Error as _;
        use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

        let Some(done) = crate::test_own_process::own_process(
            crate::test_own_process::test_path!(a_drain_names_a_member_it_may_not_wait_on_when_the_listing_is_empty),
            crate::test_spawn::spawn,
        ) else {
            return;
        };
        let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
        let job = JobHandle::create_empty_for_test();
        job.assign_for_test(member.handle().0)
            .expect("assign the restricted member to the job");
        let rt = single_thread_pool_runtime();
        let forced = crate::containment::windows::fault::force_job_pid_list(Vec::new());

        let verdict = rt.block_on(DrainEdge::Job(&job).wait_async(None));

        drop(forced);
        let error = verdict.expect_err("a member whose exit cannot be observed is not a drain");
        assert!(
            matches!(&error, crate::error::Error::Unassessable { detail, source: Some(_) }
                if detail.contains(&member.pid().to_string())),
            "{error:?}"
        );
        assert_eq!(
            crate::error::first_os_code(error.source().expect("the OS error is the cause")),
            Some(ERROR_ACCESS_DENIED.0 as i32),
            "{error:?}"
        );
    }

    /// A kill's awaited wait names a member it may not wait on once, as the sync wait does: the edge's
    /// confirmation does not report what the wait for the members already did.
    ///
    /// Mutant: the edge is awaited with no memory of the members the kill's wait settled.
    #[skuld::test]
    fn an_awaited_kill_wait_names_a_member_it_may_not_wait_on_once() {
        use crate::containment::dispatch::TreeKillOutcome;
        use crate::containment::TreeKill;

        let Some(done) = crate::test_own_process::own_process(
            crate::test_own_process::test_path!(an_awaited_kill_wait_names_a_member_it_may_not_wait_on_once),
            crate::test_spawn::spawn,
        ) else {
            return;
        };
        let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
        let id = crate::identity::windows_identity_from_handle_result(member.handle(), member.pid())
            .expect("the restricted member's identity");
        let job = JobHandle::create_empty_for_test();
        job.assign_for_test(member.handle().0)
            .expect("assign the restricted member to the job");
        let rt = single_thread_pool_runtime();
        let forced = crate::containment::windows::fault::force_job_pid_list(Vec::new());
        let (_, wait) =
            TreeKill::listed(TreeKillOutcome::Ran(Ok(())), vec![id], Vec::new(), DrainEdge::Job(&job)).split();

        let verdict = rt.block_on(wait.wait_async());

        drop(forced);
        let error = verdict.expect_err("a member whose exit cannot be observed is not a drain");
        let report = crate::error::Report(&error).to_string();
        assert_eq!(
            report.matches(&format!("pid {}", member.pid())).count(),
            1,
            "the member is named once: {report}"
        );
    }

    /// A member that left the listing in an earlier round is still waited for when a later listing
    /// is empty. The second member stays alive, so the bounded drain ends in `MembersRemain`.
    ///
    /// Mutant: an empty listing is answered off the earlier rounds' handles, not the snapshot.
    #[skuld::test]
    async fn a_drain_keeps_waiting_for_a_member_that_left_the_listing_in_an_earlier_round() {
        use crate::containment::windows::fault::force_job_pid_lists;

        let (mut first, second, job) = spawn_job_with_two_members();
        first.kill().expect("end the first member");
        first.wait().expect("reap the first member");
        let _forced = force_job_pid_lists([vec![first.id(), second.id()], vec![first.id()], Vec::new()]);
        let deadline = crate::tokio::wait::deadline_from(Duration::from_millis(50));
        let verdict = drain(&job, deadline).await;
        let_member_exit(second);
        assert_eq!(
            verdict,
            TreeDrain::MembersRemain,
            "the drain was answered while a member's process object was unsignalled"
        );
    }

    /// The async twin of `after_the_job_kill_the_drain_answers_only_once_every_member_is_signalled`,
    /// against the real OS with no forced listing: after the job's kill, the drain answers
    /// `AllMembersExited` only once every member the job held (each opened before the kill) is
    /// signalled.
    ///
    /// Mutant: the async drain answers an empty listing without the snapshot's members.
    #[skuld::test]
    async fn after_the_job_kill_the_async_drain_answers_only_once_every_member_is_signalled() {
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};

        use crate::containment::Contains as _;

        let (mut members, job) = crate::test_child::spawn_job_with_members(3);
        let pids = crate::containment::windows::query_job_pid_list(HANDLE(job.handle().as_raw_handle()))
            .expect("list the job's members");
        assert!(pids.len() >= members.len(), "the job holds its members: {pids:?}");
        let held: Vec<(u32, OwnedHandle)> = pids
            .into_iter()
            .map(|pid| {
                // SAFETY: a standard Win32 call; the handle returned is ours and owned from here.
                let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.expect("open a member of the job");
                // SAFETY: `OpenProcess` returned an open handle that nothing else owns.
                (pid, unsafe { OwnedHandle::from_raw_handle(handle.0) })
            })
            .collect();

        job.send_kill(None).into_result().expect("terminate the job");
        let verdict = drain(&job, None).await;

        assert_eq!(verdict, TreeDrain::AllMembersExited);
        for (pid, handle) in &held {
            // SAFETY: `handle` is open for the call.
            let waited = unsafe { WaitForSingleObject(HANDLE(handle.as_raw_handle()), 0) };
            assert_eq!(
                waited, WAIT_OBJECT_0,
                "pid {pid} is a member the drain answered before it was signalled"
            );
        }
        for member in &mut members {
            member.wait().expect("reap a member");
        }
    }

    /// A drain dropped while it waits unregisters its waits and leaves the job waitable: the next
    /// drain over it sees the member exit.
    #[skuld::test]
    async fn a_dropped_drain_leaves_the_job_waitable() {
        let (mut member, job) = spawn_job_member();
        {
            let mut wait = pin!(drain(&job, None));
            assert!(
                wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
                "a running member is waited for"
            );
        }
        drop(member.stdin.take());
        assert_eq!(drain(&job, None).await, TreeDrain::AllMembersExited);
        member.wait().expect("reap the member");
    }
}

/// Mutant: `exited_held` skips the seam, or looks at a process the seam should have refused.
#[skuld::test]
async fn exited_held_takes_the_watch_fault_seam() {
    crate::tokio::test_runtime::assert_current_thread();
    let p = fake([Answer::Exited]);
    fault::set_force_watch_error(true);
    assert!(super::exited_held(&p, None).await.is_err());
    assert!(!fault::armed(), "the seam is consumed");
    assert_eq!(p.looks(), 0, "the seam comes before any look");
}

/// The wait comes from the process's own [`crate::os_process::OsProcess::exit_wait`], made once, and
/// the loop runs on it.
///
/// Mutant: `exited_until` builds [`ProcessExit`] itself: the process's wait is never made and its
/// look (which the fake has no answer for) panics.
#[cfg(unix)]
#[skuld::test]
async fn exited_until_loops_on_the_wait_the_process_makes() {
    crate::tokio::test_runtime::assert_current_thread();
    let p = crate::os_process::drive::drive_tests::OwnWait::new(2, fake([]));
    assert!(super::exited_until(&p, None).await.unwrap());
    assert_eq!(p.made(), 1);
}

/// A deadline that has passed makes one look and no wait of the process's own.
///
/// Mutant: the probe makes the process's wait first.
#[skuld::test]
async fn exited_until_at_a_passed_deadline_looks_once_and_makes_no_wait() {
    crate::tokio::test_runtime::assert_current_thread();
    let own = crate::os_process::drive::drive_tests::OwnWait::new(0, fake([Answer::Running]));
    assert!(!super::exited_held(&own, Some(Duration::ZERO)).await.unwrap());
    assert_eq!(own.made(), 0);
    assert_eq!(own.process.looks(), 1);
}

/// Mutant: `exited_held` drops the timeout, or does not resolve for an exited process.
#[skuld::test]
async fn exited_held_resolves_for_an_exited_fake() {
    crate::tokio::test_runtime::assert_current_thread();
    let exited = fake([Answer::Exited]);
    assert!(super::exited_held(&exited, None).await.unwrap());
    let running = fake([Answer::Running]);
    assert!(!super::exited_held(&running, Some(Duration::ZERO)).await.unwrap());
    assert_eq!(running.looks(), 1);
}
