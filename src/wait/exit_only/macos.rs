//! macOS `exit_only`: `waitid(P_PID, ...)` by number, on a child that is this process's own and
//! unreaped. Never `waitpid`: XNU's `wait4` reports a stopped child to its tracer as if
//! `WUNTRACED` were set (`kern_exit.c:3028-3041`), while `waitid` reports stops only under
//! `WSTOPPED` (`:3270-3277`).

use std::io;

use crate::identity::{kinfo_read, pbi_read_quiet, pbi_start_quiet, ReadPurpose, Resolved, StartToken};

use super::{is_exit_record, reaped_from_record, Foreign, Peek, Reap, Record, Target};

fn pid_and_start(target: &Target<'_>) -> (u32, Option<StartToken>) {
    match target {
        Target::Pid { pid, start, .. } => (*pid, *start),
    }
}

/// One `waitid(P_PID, pid, options)`. `Ok(None)` when nothing matched: XNU leaves a `siginfo_t`
/// untouched then (`kern_exit.c:3364-3380`), so it is zeroed first and `si_pid == 0` means none.
pub(crate) fn waitid_record(pid: u32, options: libc::c_int) -> io::Result<Option<Record>> {
    // SAFETY: `siginfo_t` is plain old data; all-zero is a valid value.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: `info` is a valid, writable `siginfo_t` for the whole call.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, options) };
        if r == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
    if info.si_pid == 0 {
        return Ok(None);
    }
    Ok(Some(Record {
        si_code: info.si_code,
        si_status: info.si_status,
    }))
}

fn is_echild(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ECHILD)
}

/// The non-consuming look: `waitid(WEXITED | WNOHANG | WNOWAIT)`, with no start check.
fn peek_raw(pid: u32) -> io::Result<Peek> {
    #[cfg(test)]
    if let Some(forced) = super::seams::take_forced_peek() {
        return forced;
    }
    match waitid_record(pid, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) {
        Ok(Some(record)) if is_exit_record(record.si_code) => Ok(Peek::Exit(reaped_from_record(record))),
        Ok(_) => Ok(Peek::Running),
        Err(e) if is_echild(&e) => Ok(Peek::Foreign(Foreign::Gone)),
        Err(e) => Err(e),
    }
}

/// Whether `pid`'s start time, read for `purpose`, is `start`'s.
enum StartCheck {
    Matches,
    Other,
    Gone,
    Unreadable,
}

fn check_start(pid: u32, start: StartToken, purpose: ReadPurpose) -> StartCheck {
    match pbi_start_quiet(pid, purpose) {
        Resolved::Found(now) if now == start => StartCheck::Matches,
        Resolved::Found(_) => StartCheck::Other,
        Resolved::Gone => StartCheck::Gone,
        Resolved::Unknown => StartCheck::Unreadable,
    }
}

pub(super) fn peek(target: &Target<'_>) -> io::Result<Peek> {
    let (pid, start) = pid_and_start(target);
    let knote = matches!(target, Target::Pid { knote: true, .. });
    let peeked = peek_raw(pid)?;
    let Some(start) = start else { return Ok(peeked) };
    match peeked {
        // The start is read only when the peek says `Exit`, just before the consume: a reusing
        // process of another user would provoke the same-user `EPERM` (`proc_info.c:2197-2212`).
        Peek::Exit(_) => match check_start(pid, start, ReadPurpose::Peek) {
            StartCheck::Matches => Ok(peeked),
            StartCheck::Other => Ok(Peek::Foreign(Foreign::Other)),
            StartCheck::Gone => Ok(Peek::Foreign(Foreign::Gone)),
            // Unreadable start: the caller gets the start-less peek's answer. `Unassessable` is
            // a later unit's; a start that cannot be read is never taken as a mismatch.
            StartCheck::Unreadable => Ok(peeked),
        },
        // `waitid` found a child of ours that has not exited. A foreign reap followed by a reuse
        // of the pid by another child of ours also looks like this, so the start decides.
        Peek::Running => match check_start(pid, start, ReadPurpose::Running) {
            StartCheck::Other => Ok(Peek::Foreign(Foreign::Other)),
            StartCheck::Matches | StartCheck::Gone | StartCheck::Unreadable => Ok(peeked),
        },
        // `ECHILD` is not proof of a reap: while a tracer holds our child the parent's `waitid`
        // answers `ECHILD` (`src/test_support/tracer.rs`), and the tracer's hand-back re-sends
        // `NOTE_EXIT`. It is a reap when the pid no longer names the child, and equally when it
        // still does but launchd owns it: a zombie whose tracer died is reparented there, and
        // no `waitid` of ours will ever see it.
        Peek::Foreign(Foreign::Gone) => match pbi_read_quiet(pid, ReadPurpose::Echild) {
            Resolved::Found(read) if read.start != start => Ok(Peek::Foreign(Foreign::Other)),
            Resolved::Found(read) if read.orphaned => Ok(peeked),
            Resolved::Found(_) => Ok(Peek::Running),
            // The start read cannot see a process between `P_REF_DEAD` and the zombie, which is
            // exactly when a traced child's exit wakes the wait.
            Resolved::Gone if knote => Ok(Peek::Running),
            Resolved::Gone => Ok(echild_gone(pid, start)),
            // An unreadable start is a pid of another user: not our child.
            Resolved::Unknown => Ok(peeked),
        },
        Peek::Foreign(Foreign::Other) => Ok(peeked),
    }
}

/// An `ECHILD` whose start read says `ESRCH`, with no knote to say whether a reap happened:
/// asks the `kinfo` sysctl, which sees a process that is exiting but not yet a zombie.
fn echild_gone(pid: u32, start: StartToken) -> Peek {
    match kinfo_read(pid, ReadPurpose::EchildExiting) {
        Resolved::Found(read) if read.start != start => Peek::Foreign(Foreign::Other),
        Resolved::Found(read) if !read.orphaned => Peek::Running,
        Resolved::Found(_) | Resolved::Gone | Resolved::Unknown => Peek::Foreign(Foreign::Gone),
    }
}

/// The consuming `waitid(WEXITED | WNOHANG)`. `Ok(None)` when it finds nothing.
fn consume(pid: u32) -> io::Result<Option<Record>> {
    #[cfg(test)]
    if let Some(forced) = super::seams::take_forced_reap() {
        return match forced {
            super::seams::ForcedReap::None => Ok(None),
            super::seams::ForcedReap::Errno(e) => Err(io::Error::from_raw_os_error(e)),
        };
    }
    waitid_record(pid, libc::WEXITED | libc::WNOHANG).map(|r| r.map(super::consumed))
}

pub(super) fn try_reap(target: &Target<'_>) -> io::Result<Reap> {
    let (pid, start) = pid_and_start(target);
    match peek(target)? {
        Peek::Exit(_) => {}
        Peek::Running => return Ok(Reap::Running),
        Peek::Foreign(f) => return Ok(Reap::Foreign(f)),
    }
    // Our own zombie's start, read before the first reap: the first reap does not change it
    // (`proc_reparentlocked` returns early when the parent is unchanged, `kern_exit.c:3411`),
    // and the second peek checks it.
    let second_start = start.or_else(|| match pbi_start_quiet(pid, ReadPurpose::PreReap) {
        Resolved::Found(t) => Some(t),
        Resolved::Gone => None,
        Resolved::Unknown => None,
    });
    let first = match consume(pid) {
        Ok(Some(record)) => reaped_from_record(record),
        // A by-pid consume is never pinned: a foreign reap between the peek and here, then a
        // reuse of the pid by a child that is still running, finds nothing. A reuser that is our
        // own child and already a zombie has its exit record consumed instead: the start check
        // above is a check, not a pin.
        Ok(None) => return Ok(Reap::Foreign(Foreign::Gone)),
        Err(e) if is_echild(&e) => return Ok(Reap::Foreign(Foreign::Gone)),
        Err(e) => return Err(e),
    };
    second_reap(pid, second_start);
    Ok(Reap::Reaped(first))
}

/// The second peek-and-consume every first reap is followed by. When this process traces its own
/// child, `p_oppid == p_ppid`: the first consuming reap only reparents the zombie to this same
/// process, re-sends `NOTE_EXIT` and returns before it reaps (`kern_exit.c:2721-2773`), so the
/// zombie is still there. Not gated on a tracer: for an untraced child the peek answers `ECHILD`
/// and this is a no-op.
///
/// The first status is already in hand, so nothing here panics: every outcome is a quiet skip
/// or a `warn`.
pub(crate) fn second_reap(pid: u32, start: Option<StartToken>) {
    #[cfg(test)]
    super::seams::step(super::seams::HolderStep::SecondPeek);
    match peek_raw(pid) {
        Ok(Peek::Exit(_)) => {}
        Ok(Peek::Running) => {
            log::debug!("second reap of pid {pid}: nothing to consume");
            return;
        }
        Ok(Peek::Foreign(_)) => {
            log::debug!("second reap of pid {pid}: already reaped elsewhere");
            return;
        }
        Err(e) if is_echild(&e) => {
            log::debug!("second reap of pid {pid}: already reaped elsewhere");
            return;
        }
        Err(e) => {
            log::warn!("second reap of pid {pid}: peek failed ({e}); a zombie may be left");
            return;
        }
    }
    // A consume by a bare pid could take a reusing process's exit record.
    let Some(start) = start else {
        log::warn!("second reap of pid {pid}: no start to check it against; a zombie may be left");
        return;
    };
    match check_start(pid, start, ReadPurpose::SecondPeek) {
        StartCheck::Matches => {}
        StartCheck::Other | StartCheck::Gone => {
            log::debug!("second reap of pid {pid}: the pid names another process now");
            return;
        }
        StartCheck::Unreadable => {
            log::warn!("second reap of pid {pid}: its start could not be read; a zombie may be left");
            return;
        }
    }
    match consume(pid) {
        Ok(_) => {}
        Err(e) if is_echild(&e) => log::debug!("second reap of pid {pid}: already reaped elsewhere"),
        Err(e) => log::warn!("second reap of pid {pid} failed ({e}); a zombie may be left"),
    }
}
