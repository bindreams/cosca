use std::os::fd::{AsRawFd, OwnedFd};

use super::{adopted_id, failed_spawn_error, read_report, register, seams, set_nonblocking, Report};
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
/// hang the read: an open, empty pipe reads as `Missing`.
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
    assert!(matches!(read_report(&channel.read_end), Report::Missing));
}

/// Mutant: an unknown tag reads as an id.
#[skuld::test]
fn an_unknown_tag_is_a_bad_tag() {
    use std::io::Write;
    let (r, mut w) = pipe();
    w.write_all(&report_bytes(99, 0)).unwrap();
    assert!(matches!(read_report(&r), Report::BadTag(99)));
}

/// Mutant: a missing report keeps a fabricated errno, or is described as running.
#[skuld::test]
fn a_missing_report_is_a_child_that_died_before_exec() {
    let not_adopted = adopted_id(Report::Missing, 4242).expect_err("no id");
    assert!(not_adopted.died_before_exec);
    let Error::Io(e) = not_adopted.error else {
        panic!("a missing report is an io error, not an Unassessable refusal")
    };
    assert!(e.to_string().contains("died before exec"), "{e}");
    assert_eq!(e.raw_os_error(), None, "no errno is made up");
}

/// A refusal under `Ok` is not a child that provably did not start: the hook fails the spawn after
/// reporting it, so either the child ran on or a signal raced std's pipe.
///
/// Mutant: it is reported as "did not start" and the child is treated as a corpse.
#[skuld::test]
fn a_refusal_under_an_ok_spawn_may_have_started_the_program() {
    let not_adopted = adopted_id(Report::ChildRefused(libc::EPERM), 9).expect_err("no id");
    assert!(!not_adopted.died_before_exec);
    let Error::Unassessable { detail, .. } = not_adopted.error else {
        panic!("an Ok spawn with a refusal is Unassessable")
    };
    assert!(detail.contains("may have started"), "{detail}");
}

/// Mutant: the parent's own read failure is taken for the child's refusal.
#[skuld::test]
fn a_failed_read_is_unassessable_with_its_error_and_not_a_corpse() {
    let not_adopted =
        adopted_id(Report::ReadFailed(std::io::Error::from_raw_os_error(libc::EIO)), 7).expect_err("no id");
    assert!(!not_adopted.died_before_exec);
    assert!(matches!(not_adopted.error, Error::Unassessable { source: Some(_), .. }));
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

/// Spawning the same command again after its spawn ended fails in the hook, not by writing to a
/// reused descriptor number.
///
/// Mutant: the hook ignores `is_live`.
#[skuld::test]
fn a_command_spawned_again_fails_in_the_hook() {
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let (first, report) = run_through_channel(&mut cmd);
    first.expect("first spawn").wait().expect("wait");
    assert!(matches!(report, Report::Id(_)));
    let _guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard`")]
    let second = cmd.spawn();
    assert_eq!(
        second.expect_err("a withdrawn channel").raw_os_error(),
        Some(libc::ENOTCONN)
    );
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
