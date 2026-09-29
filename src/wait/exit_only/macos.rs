//! macOS `exit_only`: `waitid(P_PID, ...)` by number, on a child that is this process's own and
//! unreaped. Never `waitpid`: XNU's `wait4` reports a stopped child to its tracer as if
//! `WUNTRACED` were set (`kern_exit.c:3028-3041`), while `waitid` reports stops only under
//! `WSTOPPED` (`:3270-3277`).

use std::io;

use crate::identity::{pbi_start_quiet, ReadPurpose, Resolved, StartToken};

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
    let peeked = peek_raw(pid)?;
    // The start is read only when the peek says `Exit`, just before the consume: a `Running`
    // or `ECHILD` reads none, so a reusing process of another user never provokes the same-user
    // `EPERM` (`proc_info.c:2197-2212`).
    let (Peek::Exit(_), Some(start)) = (peeked, start) else {
        return Ok(peeked);
    };
    match check_start(pid, start, ReadPurpose::Peek) {
        StartCheck::Matches => Ok(peeked),
        StartCheck::Other => Ok(Peek::Foreign(Foreign::Other)),
        StartCheck::Gone => Ok(Peek::Foreign(Foreign::Gone)),
        // Unreadable start: the caller gets the start-less peek's answer. `Unassessable` is a
        // later unit's; a start that cannot be read is never taken as a mismatch.
        StartCheck::Unreadable => Ok(peeked),
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
        // reuse of the pid by a child that is still running, finds nothing.
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
    if let Some(start) = start {
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
    }
    match consume(pid) {
        Ok(_) => {}
        Err(e) if is_echild(&e) => log::debug!("second reap of pid {pid}: already reaped elsewhere"),
        Err(e) => log::warn!("second reap of pid {pid} failed ({e}); a zombie may be left"),
    }
}
