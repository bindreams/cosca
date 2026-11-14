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
//! the next one (measured: a listing opened afresh holds it), so the list is read again, and every
//! thread of each listing is read again with it: a thread id can change hands (a thread that calls
//! `execve` takes the leader's id, and the process runs on). A thread that is gone when it is read is
//! no evidence of an exit, so it starts the passes over from a fresh listing.
//!
//! The exit has begun when a pass finds every thread of a listing exiting, and the pass before it
//! did too over a listing that held every thread this one does. The loop ends when a pass finds a
//! thread running, or a listing is covered by the one before; a group that keeps creating and ending
//! threads keeps it going for as long as it does. It has no cap.

use std::collections::HashSet;

use super::kernel::Kernel;
use super::pid_file::{self, ReadOutcome};
use super::proc_read::ProcDir;
use super::{exists_in_explained, Key};
use crate::identity::stat_parse::exiting_from_stat;
use crate::identity::{Existence, RawPid, Resolved, UnknownCause};

/// [`exit_begun_in`], through a `/proc` view of its own. A view that cannot be had says nothing of the
/// exit, `Gone` only if the id's process does not hold the pid.
#[cfg(test)]
pub(crate) fn exit_begun(kernel: &dyn Kernel, pid: RawPid, key: Key) -> (Resolved<bool>, UnknownCause) {
    match super::proc_view::proc_view_with(kernel).into_dir() {
        Ok(dir) => exit_begun_in(kernel, &dir, pid, key),
        Err(why) => unsaid(super::exists(kernel, pid, key), UnknownCause::of_view(Some(why))),
    }
}

/// Whether the exit of the process `key` names, at `pid`, has begun, reading through `dir`: `Found(true)`
/// when every thread shows `PF_EXITING`, `Found(false)` when one does not. `Gone` when the pid holds no
/// such process when the reads are done, which is an exit (or a reuse) past its beginning. `Unknown`
/// when the threads cannot be listed or read, or the id cannot be proved.
pub(crate) fn exit_begun_in(
    kernel: &dyn Kernel,
    dir: &ProcDir,
    pid: RawPid,
    key: Key,
) -> (Resolved<bool>, UnknownCause) {
    // After the reads, whatever they said: a process that holds the pid now held it from when the id
    // was made, so the flags read are its own, and a process that does not has exited.
    match group_exiting(kernel, dir, pid) {
        Ok(begun) => match exists_in_explained(kernel, dir, pid, key) {
            (Existence::Present, _) => (Resolved::Found(begun), UnknownCause::default()),
            (Existence::Gone, cause) => (Resolved::Gone, cause),
            (Existence::Unknown, cause) => (Resolved::Unknown, cause),
        },
        Err(unread) => unsaid(exists_in_explained(kernel, dir, pid, key), unread),
    }
}

/// What a read that could not say leaves, given what the id's process now holds (`settled`): `Gone` when
/// it holds the pid no more, else `Unknown` for `unread`, the read's own cause.
fn unsaid(settled: (Existence, UnknownCause), unread: UnknownCause) -> (Resolved<bool>, UnknownCause) {
    match settled {
        (Existence::Gone, cause) => (Resolved::Gone, cause),
        (Existence::Present | Existence::Unknown, _) => (Resolved::Unknown, unread),
    }
}

/// Whether every thread of `pid`'s group shows `PF_EXITING`, as the module doc says. A read that cannot
/// say is the `Err`, with its cause, as [`exit_begun_in`] answers it.
fn group_exiting(kernel: &dyn Kernel, dir: &ProcDir, pid: RawPid) -> Result<bool, UnknownCause> {
    // The listing of the last pass that found every thread exiting.
    let mut covered_by: Option<HashSet<u32>> = None;
    loop {
        let listed = list_threads(kernel, dir, pid)?;
        let mut vanished = false;
        for tid in &listed {
            match thread_exiting(kernel, dir, pid, *tid)? {
                Thread::Exiting => {}
                Thread::Running => return Ok(false),
                Thread::Vanished => vanished = true,
            }
        }
        if vanished {
            covered_by = None;
            continue;
        }
        let listed: HashSet<u32> = listed.into_iter().collect();
        if covered_by.as_ref().is_some_and(|earlier| listed.is_subset(earlier)) {
            return Ok(true);
        }
        covered_by = Some(listed);
    }
}

/// The thread ids of `pid`, listed afresh.
fn list_threads(kernel: &dyn Kernel, dir: &ProcDir, pid: RawPid) -> Result<Vec<u32>, UnknownCause> {
    match pid_file::read_tasks(kernel, dir, pid) {
        Ok(ReadOutcome::Read(tids)) if tids.is_empty() => {
            // A held pid with no thread: the record contradicts itself, which says nothing of the exit.
            log::debug!("/proc/{pid}/task lists no thread");
            Err(UnknownCause::default())
        }
        Ok(ReadOutcome::Read(tids)) => Ok(tids),
        Ok(ReadOutcome::Exited(_) | ReadOutcome::Hidden(_)) => Err(UnknownCause::default()),
        Ok(ReadOutcome::Refused(refusal)) => Err(UnknownCause::of_refusal(refusal)),
        Err(unreadable) => Err(UnknownCause::of_unreadable(unreadable)),
    }
}

/// What one read of a thread's `stat` showed.
enum Thread {
    /// `PF_EXITING` is set.
    Exiting,
    /// `PF_EXITING` is clear.
    Running,
    /// The thread is gone, which says nothing of whether its group exits.
    Vanished,
}

/// The state of the thread `tid` of `pid`.
fn thread_exiting(kernel: &dyn Kernel, dir: &ProcDir, pid: RawPid, tid: u32) -> Result<Thread, UnknownCause> {
    match pid_file::read_task_stat(kernel, dir, pid, tid) {
        Ok(ReadOutcome::Read(stat)) => match exiting_from_stat(&stat) {
            Some(true) => Ok(Thread::Exiting),
            Some(false) => Ok(Thread::Running),
            None => {
                // A task that exits mid-read can hand back a truncated record.
                log::debug!("/proc/{pid}/task/{tid}/stat has no parseable flags");
                Err(UnknownCause::default())
            }
        },
        Ok(ReadOutcome::Exited(_)) => Ok(Thread::Vanished),
        // `ENOENT` of a thread the listing named: it exited and was reaped since. Any other `Hidden`
        // is `hidepid`, which hides the whole pid and so fails the listing first: nothing is known.
        Ok(ReadOutcome::Hidden(e)) if e.raw_os_error() == Some(libc::ENOENT) => Ok(Thread::Vanished),
        Ok(ReadOutcome::Hidden(_)) => Err(UnknownCause::default()),
        Ok(ReadOutcome::Refused(refusal)) => Err(UnknownCause::of_refusal(refusal)),
        Err(unreadable) => Err(UnknownCause::of_unreadable(unreadable)),
    }
}

#[cfg(test)]
#[path = "exit_tests.rs"]
mod exit_tests;
