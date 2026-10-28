use std::os::fd::{AsRawFd, OwnedFd};

use super::{
    adopted_id, await_report, failed_spawn_error, read_report, register, seams, set_nonblocking, Report, Unadoptable,
};
use crate::error::Error;

/// A non-blocking pipe, as the parent's read end is.
fn pipe() -> (OwnedFd, std::io::PipeWriter) {
    let (r, w) = std::io::pipe().expect("pipe");
    let r = OwnedFd::from(r);
    set_nonblocking(&r).expect("non-blocking");
    (r, w)
}

fn report_bytes(tag: u32, value: u64) -> Vec<u8> {
    let mut bytes = tag.to_ne_bytes().to_vec();
    bytes.extend_from_slice(&value.to_ne_bytes());
    bytes
}

/// Mutant: `read_report` takes the value for the wrong field.
#[skuld::test]
fn a_report_with_an_id_reads_as_the_id() {
    use std::io::Write;
    let (r, mut w) = pipe();
    w.write_all(&report_bytes(1, 0xfeed_beef_1234)).unwrap();
    assert!(matches!(read_report(&r), Report::Id(0xfeed_beef_1234)));
}

/// Mutant: the errno tag reads as an id.
#[skuld::test]
fn a_report_with_an_errno_reads_as_the_childs_refusal() {
    use std::io::Write;
    let (r, mut w) = pipe();
    w.write_all(&report_bytes(2, libc::EPERM as u64)).unwrap();
    assert!(matches!(read_report(&r), Report::ChildRefused(e) if e == libc::EPERM));
}

/// A child killed mid-write leaves a few bytes and EOF. Mutant: a short read is taken as an id.
#[skuld::test]
fn a_short_report_then_eof_is_missing() {
    use std::io::Write;
    let (r, mut w) = pipe();
    w.write_all(&report_bytes(1, 7)[..5]).unwrap();
    drop(w);
    assert!(matches!(read_report(&r), Report::Missing));
}

/// A child killed before it wrote leaves an empty pipe, at EOF once the write end closes. Mutant:
/// EOF is a fabricated errno.
#[skuld::test]
fn an_empty_pipe_at_eof_is_missing() {
    let (r, w) = pipe();
    drop(w);
    assert!(matches!(read_report(&r), Report::Missing));
}

/// The channel's read end is non-blocking, so a stray copy of the write end (a foreign fork) cannot
/// hang the read: an open, empty pipe reads as `Unwritten`.
///
/// Mutant: `open` does not call `set_nonblocking` (the read would block).
#[skuld::test]
fn the_channels_read_end_is_non_blocking() {
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let pending = register(&mut cmd);
    let guard = crate::child::spawn::spawn_lock();
    let channel = pending.open(&guard).expect("open");
    // SAFETY: `fcntl` on an fd the channel owns.
    let flags = unsafe { libc::fcntl(channel.read_end.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(flags & libc::O_NONBLOCK, 0, "the read end must be non-blocking");
    assert!(matches!(read_report(&channel.read_end), Report::Unwritten));
}

/// An open, empty pipe is not a child that died: it may not have written yet.
///
/// Mutant: an open, empty pipe reads as `Missing`.
#[skuld::test]
fn an_open_empty_pipe_is_unwritten_not_missing() {
    let (r, _w) = pipe();
    set_nonblocking(&r).expect("non-blocking");
    assert!(matches!(read_report(&r), Report::Unwritten));
}

/// Mutant: an unknown tag reads as an id.
#[skuld::test]
fn an_unknown_tag_is_a_bad_tag() {
    use std::io::Write;
    let (r, mut w) = pipe();
    w.write_all(&report_bytes(99, 0)).unwrap();
    assert!(matches!(read_report(&r), Report::BadTag(99)));
}

/// Mutant: a missing report keeps a fabricated errno, or is described as running, or as a program
/// that may have started.
#[skuld::test]
fn a_missing_report_is_a_child_that_died_before_exec() {
    let not_adopted = adopted_id(Report::Missing, 4242).expect_err("no id");
    assert_eq!(not_adopted.why, Unadoptable::DiedBeforeExec);
    let Error::Io(e) = not_adopted.error else {
        panic!("a missing report is an io error, not an Unassessable refusal")
    };
    assert!(e.to_string().contains("died before exec"), "{e}");
    assert_eq!(e.raw_os_error(), None, "no errno is made up");
}

/// A refusal under `Ok` is a child killed between its report and std's own pipe: the hook failed
/// the spawn, so the program did not start.
///
/// Mutant: it is reported as a child that may have started.
#[skuld::test]
fn a_refusal_under_an_ok_spawn_means_the_program_did_not_start() {
    let not_adopted = adopted_id(Report::ChildRefused(libc::EPERM), 9).expect_err("no id");
    assert_eq!(not_adopted.why, Unadoptable::DiedBeforeExec);
    let Error::Unassessable { detail, .. } = not_adopted.error else {
        panic!("a refusal is Unassessable")
    };
    assert!(detail.contains("did not start"), "{detail}");
}

/// Mutant: the parent's own read failure is taken for the child's refusal, or for a program that did
/// not start.
#[skuld::test]
fn a_failed_read_is_unassessable_with_its_error_and_not_a_corpse() {
    let not_adopted =
        adopted_id(Report::ReadFailed(std::io::Error::from_raw_os_error(libc::EIO)), 7).expect_err("no id");
    assert_eq!(not_adopted.why, Unadoptable::Unverified);
    assert!(matches!(not_adopted.error, Error::Unassessable { source: Some(_), .. }));
}

/// A report that came after the spawn returned does not show the child died: it ran its hook, and
/// may have run the program, so it is not taken for a corpse. Its id is kept, to tear it down by.
///
/// Mutant: it is taken for a child that died before `exec`, or its id is dropped.
#[skuld::test]
fn a_late_report_may_have_started_and_keeps_its_id() {
    let not_adopted = adopted_id(Report::Late(77), 31).expect_err("not adopted");
    assert_eq!(not_adopted.why, Unadoptable::Late(77));
    let error = not_adopted.error;
    assert!(
        !error.to_string().contains("died before exec"),
        "a late child is not a corpse: {error}"
    );
    assert!(error.to_string().contains("exec cannot be confirmed"), "{error}");
    assert!(error.to_string().contains("at least two of"), "{error}");
    assert!(
        matches!(error, Error::Io(ref e) if e.raw_os_error().is_none()),
        "{error:?}"
    );
}

/// Only the child's refusal and a report missing at EOF prove the program did not run.
///
/// Mutant: any one answer flipped.
#[skuld::test]
fn only_a_refusal_or_a_missing_report_proves_no_exec() {
    use super::proves_no_exec;
    assert!(proves_no_exec(&Report::ChildRefused(libc::EPERM)));
    assert!(proves_no_exec(&Report::Missing));
    assert!(!proves_no_exec(&Report::Id(1)));
    assert!(!proves_no_exec(&Report::Late(1)));
    assert!(!proves_no_exec(&Report::Unwritten));
    assert!(!proves_no_exec(&Report::ReadFailed(std::io::Error::from_raw_os_error(
        libc::EIO
    ))));
    assert!(!proves_no_exec(&Report::BadTag(9)));
}

/// Only the child's own refusal changes a failed spawn's error.
///
/// Mutant: any report state maps to the refusal.
#[skuld::test]
fn only_a_childs_refusal_changes_a_failed_spawns_error() {
    let original = || Error::Io(std::io::Error::from_raw_os_error(libc::ENOENT));
    for report in [
        Report::Missing,
        Report::ReadFailed(std::io::Error::from_raw_os_error(libc::EIO)),
        Report::Id(1),
    ] {
        let kept = failed_spawn_error(original(), &report);
        assert!(
            matches!(&kept, Error::Io(e) if e.raw_os_error() == Some(libc::ENOENT)),
            "{report:?}: {kept:?}"
        );
    }
    assert!(matches!(
        failed_spawn_error(original(), &Report::ChildRefused(libc::EPERM)),
        Error::Unassessable { .. }
    ));
}

/// Runs `cmd` through a channel, as a spawn does.
fn run_through_channel(cmd: &mut std::process::Command) -> (std::io::Result<std::process::Child>, Report) {
    let pending = register(cmd);
    let guard = crate::child::spawn::spawn_lock();
    let channel = pending.open(&guard).expect("open");
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `guard`")]
    let (spawned, first) = channel.run(|| cmd.spawn(), |c| Some(c.id()));
    drop(guard);
    (spawned, first.finish())
}

/// A program that cannot be exec'd fails the spawn after the hook reported an id: std's own error
/// stays, and it is not an `Unassessable` refusal.
///
/// Mutant: a failed spawn with an id report is mapped to the refusal.
#[skuld::test]
fn a_nonexistent_program_fails_with_stds_io_error() {
    let mut cmd = std::process::Command::new("/nonexistent/cosca-no-such-program");
    let (spawned, report) = run_through_channel(&mut cmd);
    let io_error = spawned.expect_err("exec fails");
    assert!(matches!(report, Report::Id(_)), "{report:?}");
    let mapped = failed_spawn_error(Error::Io(io_error), &report);
    assert!(matches!(mapped, Error::Io(_)), "{mapped:?}");
}

/// The id a child reports is the one `proc_pidinfo` gives for it from outside.
///
/// Mutant: `own_unique_id` reads another flavor or another pid.
#[skuld::test]
fn own_unique_id_is_the_unique_id_of_this_process() {
    use crate::identity::{uniq_info, ReadPurpose, UniqRead};
    let own = crate::identity::own_unique_id().expect("own id");
    let UniqRead::Found(by_pid) = uniq_info(std::process::id(), ReadPurpose::Kill) else {
        panic!("this process has a unique id")
    };
    assert_eq!(own, by_pid.unique_id);
}

/// A child killed by a signal before it reports: `spawn()` is `Ok`, the report is `Missing`.
///
/// Mutant: a missing report on `Ok` is read as an errno.
#[skuld::test]
fn a_child_killed_before_its_report_is_missing_on_ok() {
    let _forced = seams::force_child_killed_before_report();
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let (spawned, report) = run_through_channel(&mut cmd);
    let mut child = spawned.expect("std reports Ok for a child killed before exec");
    assert!(matches!(report, Report::Missing), "{report:?}");
    child.wait().expect("reap the corpse");
}

/// A report found unwritten, and a child killed by a signal after that: the spawn waits on the
/// pipe, and the child's death closes it with no report, so the program did not start. The seam closes
/// the report pipe's write end before the child dies, and the parent's first read is forced to find
/// nothing.
///
/// Mutants: the spawn does not wait, and answers that the program may have started; the wait answers
/// a failure (`WaitFailed`), which is no proof the program did not start.
#[skuld::test]
fn an_unwritten_report_then_a_killed_child_is_answered_died_before_exec() {
    let _killed = seams::force_child_killed_before_report();
    let _unwritten = seams::find_the_report_unwritten();
    let mut cmd = crate::command::Command::new();
    cmd.args(["/usr/bin/true"]);
    let error = cmd
        .spawn()
        .expect_err("a child killed before its report is not adopted");
    assert!(
        !matches!(error, Error::MayHaveStarted { .. }),
        "the program did not start: {error:?}"
    );
    assert!(
        error
            .to_string()
            .contains("died before exec; the program did not start"),
        "the spawn is answered as a child that died before exec: {error}"
    );
}

// The wait for a report =====

/// A live child of this test (`cat` on a held stdin), so the wait has a real pid to watch. Dropping
/// the stdin ends it.
fn live_child() -> (std::process::Child, std::process::ChildStdin) {
    let mut cmd = std::process::Command::new("/bin/cat");
    cmd.stdin(std::process::Stdio::piped());
    let guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `guard`")]
    let mut child = cmd.spawn().expect("spawn cat");
    drop(guard);
    let stdin = child.stdin.take().expect("piped stdin");
    (child, stdin)
}

/// Ends and reaps a [`live_child`].
fn end(mut child: std::process::Child, stdin: std::process::ChildStdin) {
    drop(stdin);
    child.wait().expect("reap cat");
}

/// Arms a hook on the wait's first block that drops `copy`, a copy of the write end, so a wait that
/// blocks where it should not ends at EOF and fails its test's assertion instead of hanging.
fn release_on_block(copy: std::io::PipeWriter) -> crate::oneshot_hook::Armed {
    seams::on_first_block(move || drop(copy))
}

/// An id that is already in the pipe is a late report.
///
/// Mutant: the wait answers `Id`, not `Late`.
#[skuld::test]
fn awaiting_a_written_report_answers_late() {
    use std::io::Write;
    let (child, stdin) = live_child();
    let (r, mut w) = pipe();
    w.write_all(&report_bytes(1, 0xabc)).unwrap();
    assert!(matches!(await_report(&r, child.id()), Report::Late(0xabc)));
    end(child, stdin);
}

/// A pipe whose every write end closed with nothing written is EOF: no report.
///
/// Mutant: the wait answers `Unwritten`.
#[skuld::test]
fn awaiting_a_closed_empty_pipe_answers_missing() {
    let (child, stdin) = live_child();
    let (r, w) = pipe();
    drop(w);
    let report = await_report(&r, child.id());
    assert!(matches!(report, Report::Missing), "{report:?}");
    end(child, stdin);
}

/// Whether `kq` has an `EVFILT_READ` event pending, by a `kevent` that does not block. A level
/// event stays queued while the pipe is readable, so the look takes nothing from the wait.
fn read_pending(kq: &nix::sys::event::Kqueue) -> bool {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};
    let blank = KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0);
    let mut events = [blank; 2];
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let n = kq.kevent(&[], &mut events, Some(zero)).expect("poll the wait's kqueue");
    events[..n].iter().any(|e| e.filter() == Ok(EventFilter::EVFILT_READ))
}

/// The wait blocks until a report arrives, and the pipe's readability is what ends it. The hook on
/// the wait's first block writes the report and looks at the wait's kqueue for the pipe's event.
/// The child stays alive, so only the pipe can end a correct wait. A wait that missed it is ended by
/// the child's exit instead, never left hanging: the first block ends the child when no pipe event
/// is pending, and any later block ends it too.
///
/// Mutants: the wait returns at once with nothing; it does not register `EVFILT_READ` (no pipe
/// event); it takes a readable pipe for a spurious wake (a second block, and the child's exit ends
/// the wait).
#[skuld::test]
fn awaiting_is_woken_by_the_report_through_the_pipe() {
    use std::cell::{Cell, RefCell};
    use std::io::Write;
    use std::rc::Rc;
    let (child, stdin) = live_child();
    let (r, w) = pipe();
    let stdin = Rc::new(RefCell::new(Some(stdin)));
    let writer = RefCell::new(Some(w));
    let pending = Rc::new(Cell::new(None));
    let blocks = Rc::new(Cell::new(0));
    let _hook = seams::on_each_block({
        let (stdin, pending, blocks) = (Rc::clone(&stdin), Rc::clone(&pending), Rc::clone(&blocks));
        move |n, kq| {
            blocks.set(n);
            if n == 1 {
                let mut w = writer.borrow_mut().take().expect("the report's writer");
                w.write_all(&report_bytes(1, 0xdef)).unwrap();
                pending.set(Some(read_pending(kq)));
                if pending.get() == Some(true) {
                    return;
                }
            }
            drop(stdin.borrow_mut().take());
        }
    });
    let _ = seams::take_wake();
    let report = await_report(&r, child.id());
    assert_eq!(pending.get(), Some(true), "the wait must watch the pipe");
    assert_eq!(blocks.get(), 1, "a readable pipe ends the wait");
    assert_eq!(seams::take_wake(), Some(seams::Wake::Pipe));
    assert!(matches!(report, Report::Late(0xdef)), "{report:?}");
    let mut child = child;
    drop(stdin.borrow_mut().take());
    child.wait().expect("reap cat");
}

/// A child that exited without reporting, while another copy of the write end stays open (as a fork
/// that inherited it holds one): the pipe never hits EOF, but the child is gone, so the report never
/// comes. The wait answers `Missing` without blocking.
///
/// Mutant: the wait watches the pipe alone, so it blocks until every copy of the write end closes.
#[skuld::test]
fn awaiting_a_child_that_exited_unreported_answers_missing_without_blocking() {
    let (mut child, stdin) = live_child();
    let (r, copy) = pipe();
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id());
    let before = seams::block_count();
    let _release = release_on_block(copy);
    let report = await_report(&r, child.id());
    assert_eq!(seams::block_count(), before, "a child already gone is not waited for");
    assert!(matches!(report, Report::Missing), "{report:?}");
    child.wait().expect("reap cat");
}

/// A child that exits during the wait ends it, through the watch on the child, even while another
/// copy of the write end stays open. The hook on the wait's first block ends the child, waits until
/// it is a zombie, then drops that copy, so the next wake has both events pending and says which
/// one ended the wait.
///
/// Mutant: the wait watches the pipe alone.
#[skuld::test]
fn awaiting_a_child_that_exits_during_the_wait_is_ended_by_its_exit() {
    let (mut child, stdin) = live_child();
    let pid = child.id();
    let (r, copy) = pipe();
    let _hook = seams::on_first_block(move || {
        drop(stdin);
        crate::test_child::wait_until_zombie(pid);
        drop(copy);
    });
    let report = await_report(&r, pid);
    assert_eq!(
        seams::take_wake(),
        Some(seams::Wake::ChildGone),
        "the child's exit ends the wait"
    );
    assert!(matches!(report, Report::Missing), "{report:?}");
    child.wait().expect("reap cat");
}

/// A pid that names no child of this process (as after a foreign reap and a reuse of the number by
/// another process) shows the child gone: `waitid` answers `ECHILD`, and the wait does not block.
/// The test's own parent stands in for the stranger.
///
/// Mutant: `ECHILD` is not taken as the child gone, so the wait watches the stranger.
#[skuld::test]
fn awaiting_a_pid_that_is_not_our_child_answers_missing_without_blocking() {
    let (r, copy) = pipe();
    // SAFETY: `getppid` has no preconditions.
    let stranger = unsafe { libc::getppid() } as u32;
    let before = seams::block_count();
    let _release = release_on_block(copy);
    let report = await_report(&r, stranger);
    assert_eq!(seams::block_count(), before, "a stranger is not waited for");
    assert!(matches!(report, Report::Missing), "{report:?}");
}

/// A pid no process holds (a child this test reaped) cannot be watched: the registration's
/// `ESRCH` shows the child gone, and the wait does not block.
///
/// Mutant: the registration's `ESRCH` is an error (`ReadFailed`).
#[skuld::test]
fn awaiting_a_reaped_pid_answers_missing_without_blocking() {
    let (child, stdin) = live_child();
    let pid = child.id();
    end(child, stdin);
    let (r, copy) = pipe();
    let before = seams::block_count();
    let _release = release_on_block(copy);
    let report = await_report(&r, pid);
    assert_eq!(seams::block_count(), before, "a reaped child is not waited for");
    assert!(matches!(report, Report::Missing), "{report:?}");
}

/// The parents a `kinfo_proc` read reports for a child this process forked, held by `parent`:
/// `(p_oppid, e_ppid)`.
fn forked_by_us_held_by(parent: u32) -> (libc::pid_t, libc::pid_t) {
    (std::process::id() as libc::pid_t, parent as libc::pid_t)
}

/// A child that launchd holds, whose parent at a tracer's attach is this process: its tracer died
/// while it was exiting, and XNU gave it to launchd. It is gone, and the wait answers `Missing`
/// without blocking. The child really runs; its `waitid` and its parents are forced.
///
/// Mutant: the check takes a child this process forked for running, whoever holds it.
#[skuld::test]
fn awaiting_a_child_launchd_holds_after_its_tracer_died_answers_missing_without_blocking() {
    use crate::wait::exit_only::{seams::force_peek_once, Foreign, Peek};
    let (child, stdin) = live_child();
    let pid = child.id();
    let (r, copy) = pipe();
    let _echild = force_peek_once(Ok(Peek::Foreign(Foreign::Gone)));
    let _parents = crate::identity::kinfo::fault::force_parents(pid, || forked_by_us_held_by(crate::identity::LAUNCHD));
    let before = seams::block_count();
    let _release = release_on_block(copy);
    let report = await_report(&r, pid);
    assert_eq!(seams::block_count(), before, "a child launchd holds is not waited for");
    assert!(matches!(report, Report::Missing), "{report:?}");
    end(child, stdin);
}

/// A child whose tracer dies while the child is exiting: XNU sends the child's `NOTE_EXIT` to the
/// tracer alone, then gives the child to launchd, so no event of the child's reaches this process.
/// The wait watches the tracer as well, and the tracer's exit makes it check the child again, which
/// finds launchd holding it: `Missing`. A live `cat` stands in for the tracer. The child really runs;
/// its `waitid` and its parents are forced: held by the stand-in while that runs, by launchd once it
/// has exited. The hook on the wait's first block ends the stand-in and looks for an event pending on
/// the wait's kqueue; if there is none, it drops a copy of the write end, so a wait that missed the
/// tracer's exit ends at EOF instead of hanging.
///
/// Mutant: the wait does not watch the tracer.
#[skuld::test]
fn awaiting_a_child_whose_tracer_dies_during_its_exit_is_woken_by_the_tracers_exit() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use crate::wait::exit_only::{seams::force_peeks, Foreign, Peek};
    let (child, stdin) = live_child();
    let pid = child.id();
    let (mut tracer, tracer_stdin) = live_child();
    let tracer_pid = tracer.id();
    let (r, copy) = pipe();
    // More than the wait takes: the child stays `ECHILD` to this process throughout.
    let _echild = force_peeks((0..8).map(|_| Ok(Peek::Foreign(Foreign::Gone))));
    let tracer_exited = Rc::new(Cell::new(false));
    let _parents = crate::identity::kinfo::fault::force_parents(pid, {
        let exited = Rc::clone(&tracer_exited);
        move || {
            forked_by_us_held_by(if exited.get() {
                crate::identity::LAUNCHD
            } else {
                tracer_pid
            })
        }
    });
    let pending = Rc::new(Cell::new(None));
    let tracer_stdin = RefCell::new(Some(tracer_stdin));
    let copy = RefCell::new(Some(copy));
    let _hook = seams::on_each_block({
        let pending = Rc::clone(&pending);
        move |n, kq| {
            if n == 1 {
                drop(tracer_stdin.borrow_mut().take());
                crate::test_child::wait_until_zombie(tracer_pid);
                tracer_exited.set(true);
                pending.set(Some(crate::wait::backend::test_hooks::event_pending(kq)));
                if pending.get() == Some(true) {
                    return;
                }
            }
            drop(copy.borrow_mut().take());
        }
    });
    let _ = seams::take_wake();
    let report = await_report(&r, pid);
    assert_eq!(pending.get(), Some(true), "the tracer's exit must wake the wait");
    assert_eq!(
        seams::take_wake(),
        Some(seams::Wake::ChildGone),
        "the check after the tracer's exit ends the wait"
    );
    assert!(matches!(report, Report::Missing), "{report:?}");
    end(child, stdin);
    tracer.wait().expect("reap the stand-in tracer");
}

/// A tracer that attaches after the wait's check: XNU reparents the child to it and sends the child
/// `SIGSTOP` (see `wait::backend::TracerWatch`). The wait watches the child's signals,
/// so it checks again, finds the tracer and watches it too; the tracer's exit, with launchd then
/// holding the child, ends the wait: `Missing`. A live `cat` stands in for the tracer. The child
/// really runs; its `waitid` and its parents are forced: running until the attach, then held by the
/// stand-in, then by launchd once that has exited. A `SIGCONT` to the child stands in for the
/// attach's `SIGSTOP`. Each of the two hooks looks for an event pending on the wait's kqueue; if
/// there is none, it drops a copy of the write end, so a wait that missed it ends at EOF instead of
/// hanging.
///
/// Mutant: the wait registers no `NOTE_SIGNAL` on the child.
#[skuld::test]
fn awaiting_a_child_a_tracer_attaches_to_late_is_woken_by_the_attach() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use crate::wait::backend::test_hooks::{event_pending, send_signal};
    use crate::wait::exit_only::{seams::force_peeks, Foreign, Peek};
    let (child, stdin) = live_child();
    let pid = child.id();
    let (mut tracer, tracer_stdin) = live_child();
    let tracer_pid = tracer.id();
    let (r, copy) = pipe();
    // Running for the first check, then `ECHILD` throughout: more than the wait takes.
    let _peeks =
        force_peeks(std::iter::once(Ok(Peek::Running)).chain((0..8).map(|_| Ok(Peek::Foreign(Foreign::Gone)))));
    let holder = Rc::new(Cell::new(std::process::id()));
    let _parents = crate::identity::kinfo::fault::force_parents(pid, {
        let holder = Rc::clone(&holder);
        move || forked_by_us_held_by(holder.get())
    });
    let (attach_woke, exit_woke) = (Rc::new(Cell::new(None)), Rc::new(Cell::new(None)));
    let tracer_stdin = RefCell::new(Some(tracer_stdin));
    let copy = RefCell::new(Some(copy));
    let _hook = seams::on_each_block({
        let (attach_woke, exit_woke) = (Rc::clone(&attach_woke), Rc::clone(&exit_woke));
        move |n, kq| {
            let woke = match n {
                1 => {
                    holder.set(tracer_pid);
                    send_signal(pid, libc::SIGCONT);
                    attach_woke.set(Some(event_pending(kq)));
                    attach_woke.get()
                }
                2 => {
                    drop(tracer_stdin.borrow_mut().take());
                    crate::test_child::wait_until_zombie(tracer_pid);
                    holder.set(crate::identity::LAUNCHD);
                    exit_woke.set(Some(event_pending(kq)));
                    exit_woke.get()
                }
                _ => None,
            };
            if woke != Some(true) {
                drop(copy.borrow_mut().take());
            }
        }
    });
    let _ = seams::take_wake();
    let report = await_report(&r, pid);
    assert_eq!(attach_woke.get(), Some(true), "the attach's signal must wake the wait");
    assert_eq!(
        exit_woke.get(),
        Some(true),
        "the wait must block again, watching the tracer, and its exit must wake it"
    );
    assert_eq!(seams::take_wake(), Some(seams::Wake::ChildGone));
    assert!(matches!(report, Report::Missing), "{report:?}");
    end(child, stdin);
    tracer.wait().expect("reap the stand-in tracer");
}

/// A failed spawn's child was collected by std, or tokio dropped it with its pid, so there is no
/// child to wait on: the report is read once. A copy of the write end held elsewhere (as a foreign
/// fork holds one) keeps the empty pipe open, so it reads `Unwritten`.
///
/// Mutant: the spawn waits for the report after a failed spawn (the refused wait answers
/// `WaitFailed`).
#[skuld::test]
fn a_failed_spawn_reads_the_report_once_and_does_not_wait() {
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let pending = register(&mut cmd);
    let guard = crate::child::spawn::spawn_lock();
    let channel = pending.open(&guard).expect("open");
    let _foreign_copy = channel.write_end.try_clone().expect("dup the write end");
    let _refused = seams::refuse_the_wait();
    let (spawned, first) = channel.run(|| Err::<(), ()>(()), |_| unreachable!("a failed spawn has no child"));
    drop(guard);
    let report = first.finish();
    assert!(spawned.is_err());
    assert!(matches!(report, Report::Unwritten), "{report:?}");
}

// The wait's timeouts =====

/// The `warn`s on this thread since `mark` that say a child has not reported its id.
fn waiting_warns(mark: usize) -> usize {
    crate::log_capture::records_since_on_current_thread(mark, "the spawned child")
        .into_iter()
        .filter(|(level, text)| *level == log::Level::Warn && text.contains("has not reported its unique id"))
        .count()
}

/// A wait on `child` (a [`live_child`]) whose checks find it held by `tracer` (another live child),
/// with the tracer walks answering `links`. The hook on block `release_at` drops a copy of the write
/// end, so the wait ends at EOF. Answers the report, the blocks taken and each `kevent`'s timeout.
fn await_held(
    child: u32,
    tracer: u32,
    links: Vec<crate::identity::Link>,
    say_after: std::time::Duration,
    release_at: u32,
) -> (Report, u32, Vec<Option<std::time::Duration>>) {
    use std::cell::RefCell;

    use crate::wait::exit_only::{seams::force_peeks, Foreign, Peek};
    let (r, copy) = pipe();
    let _echild = force_peeks((0..16).map(|_| Ok(Peek::Foreign(Foreign::Gone))));
    let _parents = crate::identity::kinfo::fault::force_parents(child, move || forked_by_us_held_by(tracer));
    let _links = crate::wait::backend::tracer_seams::force_links(links);
    let recorded = seams::say_waiting_after_then_record(say_after);
    let copy = RefCell::new(Some(copy));
    let _hook = seams::on_each_block(move |n, _| {
        if n == release_at {
            drop(copy.borrow_mut().take());
        }
    });
    let before = seams::block_count();
    let report = await_report(&r, child);
    (report, seams::block_count() - before, recorded.timeouts())
}

/// A walk that finds the tracer gone checks again at once without blocking, then blocks for no
/// longer than the backoff asks, while the warning is far off.
///
/// Mutants: the wait blocks with no timeout on `Recheck(after)`; `Recheck(0)` blocks.
#[skuld::test]
fn a_tracer_found_gone_arms_the_wait_with_its_backoff() {
    use crate::identity::Link;
    let (child, stdin) = live_child();
    let (tracer, tracer_stdin) = live_child();
    let (report, blocks, timeouts) = await_held(
        child.id(),
        tracer.id(),
        vec![Link::Gone, Link::Gone],
        std::time::Duration::from_secs(3600),
        1,
    );
    assert!(matches!(report, Report::Missing), "{report:?}");
    assert_eq!(blocks, 1, "a re-check at once does not block");
    assert_eq!(timeouts, [Some(std::time::Duration::from_millis(1))]);
    end(child, stdin);
    end(tracer, tracer_stdin);
}

/// The wait blocks for the sooner of the backoff and the time left to its warning.
///
/// Mutants: the backoff alone times the block; the later of the two does.
#[skuld::test]
fn a_wait_held_by_a_tracer_blocks_for_the_sooner_of_its_backoff_and_its_warning() {
    use crate::identity::Link;
    crate::log_capture::install();
    let (child, stdin) = live_child();
    let (tracer, tracer_stdin) = live_child();
    let (report, blocks, timeouts) = await_held(
        child.id(),
        tracer.id(),
        vec![Link::Gone, Link::Gone, Link::Gone],
        std::time::Duration::ZERO,
        2,
    );
    assert!(matches!(report, Report::Missing), "{report:?}");
    assert_eq!(blocks, 2);
    let ms = std::time::Duration::from_millis;
    assert_eq!(
        timeouts,
        [Some(ms(0)), Some(ms(2))],
        "the warning, due at once, times the first block; the backoff alone the next"
    );
    end(child, stdin);
    end(tracer, tracer_stdin);
}

/// The wait warns once, when its warning is due, and blocks with no timeout after that.
///
/// Mutants: the warning repeats on every block; it never fires.
#[skuld::test]
fn a_wait_warns_once_that_the_report_is_late() {
    use std::cell::RefCell;
    crate::log_capture::install();
    let (child, stdin) = live_child();
    let (r, copy) = pipe();
    let recorded = seams::say_waiting_after_then_record(std::time::Duration::ZERO);
    let copy = RefCell::new(Some(copy));
    let _hook = seams::on_each_block(move |n, _| {
        if n == 2 {
            drop(copy.borrow_mut().take());
        }
    });
    let mark = crate::log_capture::mark();
    let report = await_report(&r, child.id());
    assert!(matches!(report, Report::Missing), "{report:?}");
    assert_eq!(waiting_warns(mark), 1, "one warning, however long the wait");
    let timeouts = recorded.timeouts();
    assert_eq!(timeouts.first(), Some(&Some(std::time::Duration::ZERO)), "{timeouts:?}");
    assert!(
        timeouts[1..].iter().all(Option::is_none),
        "once it has warned the wait has no timeout: {timeouts:?}"
    );
    end(child, stdin);
}

/// A wait in a test warns only under a guard (a verdict must not depend on elapsed time), and the
/// threshold production warns at is 1 s.
///
/// Mutants: a wait with no guard gets a threshold; production's is not 1 s.
#[skuld::test]
fn production_warns_after_one_second_and_a_test_only_with_a_guard() {
    assert_eq!(super::SAY_WAITING_AFTER, std::time::Duration::from_secs(1));
    assert_eq!(seams::say_waiting_after(), None);
}
