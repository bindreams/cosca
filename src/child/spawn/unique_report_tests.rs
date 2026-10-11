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
    channel.run(|| cmd.spawn())
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
/// Mutant: the spawn does not wait, and answers that the program may have started.
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
}

// The wait for a report =====

/// An id that is already in the pipe is a late report.
///
/// Mutant: the wait answers `Id`, not `Late`.
#[skuld::test]
fn awaiting_a_written_report_answers_late() {
    use std::io::Write;
    let (r, mut w) = pipe();
    w.write_all(&report_bytes(1, 0xabc)).unwrap();
    assert!(matches!(await_report(&r), Report::Late(0xabc)));
}

/// A pipe whose every write end closed with nothing written is EOF: no report.
///
/// Mutant: the wait answers `Unwritten`, or never returns.
#[skuld::test]
fn awaiting_a_closed_empty_pipe_answers_missing() {
    let (r, w) = pipe();
    drop(w);
    assert!(matches!(await_report(&r), Report::Missing));
}

/// The wait blocks until a report arrives from another thread, whichever of the two runs first.
///
/// Mutant: the wait returns at once with nothing.
#[skuld::test]
fn awaiting_waits_for_a_report_written_by_another_thread() {
    use std::io::Write;
    let (r, mut w) = pipe();
    let writer = std::thread::spawn(move || w.write_all(&report_bytes(1, 0xdef)).unwrap());
    let report = await_report(&r);
    writer.join().expect("the writer thread");
    assert!(matches!(report, Report::Late(0xdef)), "{report:?}");
}
