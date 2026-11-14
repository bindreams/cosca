//! Whether a process's exit has begun, from `/proc`: every thread of its group shows `PF_EXITING` in
//! field 9 of its `stat`.
//!
//! The kernel sets the flag in `exit_signals`, before `exit_notify` hands the process's children to
//! another parent, and the flag never clears. So a read that finds the flag clear on a thread, and
//! proves the id after, saw a process none of whose children had been reparented by its exit; a read
//! that finds it on every thread saw an exit under way, whose children may be on their way out of
//! the walk. Measured on Linux 6.12.113, for a same-uid, an other-uid and a non-root reader (60 of 60
//! held exits each): the flag shows while the children still name the group, and a zombie keeps it.
//!
//! The leader alone proves nothing: `pthread_exit` sets the flag on the leader while the process runs,
//! and the children stay with the group. A group that exits sets the flag on every thread before the
//! children move, so the read takes the flag of every thread. A thread created after a listing is in
//! the next one (measured: a listing opened afresh holds it), so the list is read again until a pass
//! shows no thread not yet read, with no cap. The loop ends: a thread that is not exiting ends the
//! read, and a group whose threads all exit creates no thread.

use std::collections::HashSet;

use super::kernel::Kernel;
use super::pid_file::{self, ReadOutcome};
use super::proc_read::ProcDir;
use super::{exists, proc_view, resolve_unreadable, Key};
use crate::identity::stat_parse::exiting_from_stat;
use crate::identity::{Existence, RawPid, Resolved, UnknownCause};

/// Whether the exit of the process `key` names, at `pid`, has begun: `Found(true)` when every thread
/// shows `PF_EXITING`, `Found(false)` when one does not. `Gone` when the pid holds no such process
/// when the reads are done, which is an exit (or a reuse) past its beginning. `Unknown` when the
/// threads cannot be listed or read, or the id cannot be proved.
pub(crate) fn exit_begun(kernel: &dyn Kernel, pid: RawPid, key: Key) -> (Resolved<bool>, UnknownCause) {
    let dir = match proc_view::proc_view_with(kernel).into_dir() {
        Ok(dir) => dir,
        Err(why) => {
            let report = format!(
                "the /proc view could not be established: {report}",
                report = crate::error::Report(&why)
            );
            return (gone_or_unknown(kernel, pid, report), UnknownCause::of_view(Some(why)));
        }
    };
    let begun = match group_exiting(kernel, &dir, pid) {
        Ok(begun) => begun,
        Err(unread) => return unread,
    };
    // After the reads: a process that holds the pid now held it from when the id was made, so the
    // flags read are its own.
    match exists(kernel, pid, key) {
        (Existence::Present, _) => (Resolved::Found(begun), UnknownCause::default()),
        (Existence::Gone, cause) => (Resolved::Gone, cause),
        (Existence::Unknown, cause) => (Resolved::Unknown, cause),
    }
}

/// Whether every thread of `pid`'s group shows `PF_EXITING`, the threads listed again until a listing
/// holds none not yet read. A read that cannot say is the `Err`, as [`exit_begun`] answers it.
fn group_exiting(kernel: &dyn Kernel, dir: &ProcDir, pid: RawPid) -> Result<bool, (Resolved<bool>, UnknownCause)> {
    let mut read: HashSet<u32> = HashSet::new();
    loop {
        let listed = match pid_file::read_tasks(kernel, dir, pid) {
            Ok(ReadOutcome::Read(tids)) => tids,
            Ok(ReadOutcome::Exited(e) | ReadOutcome::Hidden(e)) => {
                return Err((
                    gone_or_unknown(kernel, pid, crate::error::Report(&e)),
                    UnknownCause::default(),
                ));
            }
            Ok(ReadOutcome::Refused(refusal)) => {
                return Err((
                    gone_or_unknown(kernel, pid, refusal.requirement()),
                    UnknownCause::of_refusal(refusal),
                ));
            }
            Err(unreadable) => {
                return Err((
                    gone_or_unknown(kernel, pid, crate::error::Report(&unreadable)),
                    UnknownCause::of_unreadable(unreadable),
                ));
            }
        };
        let mut new = false;
        for tid in listed {
            if !read.insert(tid) {
                continue;
            }
            new = true;
            if !thread_exiting(kernel, dir, pid, tid)? {
                return Ok(false);
            }
        }
        if !new {
            break;
        }
    }
    if read.is_empty() {
        // A held pid with no thread: the record contradicts itself, which says nothing of the exit.
        log::debug!("/proc/{pid}/task lists no thread");
        return Err((Resolved::Unknown, UnknownCause::default()));
    }
    Ok(true)
}

/// Whether the thread `tid` of `pid` shows `PF_EXITING`. A thread that is gone is exiting: it is not
/// a live one.
fn thread_exiting(
    kernel: &dyn Kernel,
    dir: &ProcDir,
    pid: RawPid,
    tid: u32,
) -> Result<bool, (Resolved<bool>, UnknownCause)> {
    match pid_file::read_task_stat(kernel, dir, pid, tid) {
        Ok(ReadOutcome::Read(stat)) => exiting_from_stat(&stat).ok_or_else(|| {
            // A task that exits mid-read can hand back a truncated record.
            log::debug!("/proc/{pid}/task/{tid}/stat has no parseable flags");
            (Resolved::Unknown, UnknownCause::default())
        }),
        Ok(ReadOutcome::Exited(_)) => Ok(true),
        // `ENOENT` of a thread the listing named: it exited and was reaped since. Any other `Hidden`
        // is `hidepid`, which hides the whole pid and so fails the listing first: nothing is known.
        Ok(ReadOutcome::Hidden(e)) if e.raw_os_error() == Some(libc::ENOENT) => Ok(true),
        Ok(ReadOutcome::Hidden(_)) => Err((Resolved::Unknown, UnknownCause::default())),
        Ok(ReadOutcome::Refused(refusal)) => Err((Resolved::Unknown, UnknownCause::of_refusal(refusal))),
        Err(unreadable) => Err((Resolved::Unknown, UnknownCause::of_unreadable(unreadable))),
    }
}

/// What `pid`'s `/proc` files being unavailable (`why`) says about it, as an unreadable `stat` does:
/// `Gone` only if `kill(pid, 0)` says `ESRCH`, else `Unknown`.
fn gone_or_unknown(kernel: &dyn Kernel, pid: RawPid, why: impl std::fmt::Display) -> Resolved<bool> {
    match resolve_unreadable(kernel, pid, why) {
        Resolved::Gone => Resolved::Gone,
        Resolved::Found(_) | Resolved::Unknown => Resolved::Unknown,
    }
}

#[cfg(test)]
#[path = "exit_tests.rs"]
mod exit_tests;
