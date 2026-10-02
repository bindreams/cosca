//! macOS `exit_only`: `waitid(P_PID, ...)` by number, on a child that is this process's own and
//! unreaped. Never `waitpid`: XNU's `wait4` reports a stopped child to its tracer as if
//! `WUNTRACED` were set (`kern_exit.c:3028-3041`), while `waitid` reports stops only under
//! `WSTOPPED` (`:3270-3277`).

use std::io;

use crate::identity::{held_by, uniq_info, Held, ReadPurpose, UniqRead, LAUNCHD};

use super::{is_exit_record, reaped_from_record, Foreign, Peek, Reap, Record, Target};

fn pid_and_unique(target: &Target<'_>) -> (u32, Option<u64>) {
    match target {
        Target::Pid { pid, unique, .. } => (*pid, *unique),
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

/// Whether `pid`'s unique id, read for `purpose`, is `unique`.
enum IdCheck {
    Matches,
    Other,
    Gone,
    /// The read failed with this errno (a MACF denial).
    Unreadable(i32),
}

fn check_unique(pid: u32, unique: u64, purpose: ReadPurpose) -> IdCheck {
    match uniq_info(pid, purpose) {
        UniqRead::Found(now) if now.unique_id == unique => IdCheck::Matches,
        UniqRead::Found(_) => IdCheck::Other,
        UniqRead::Gone => IdCheck::Gone,
        UniqRead::Refused(errno) => IdCheck::Unreadable(errno),
    }
}

pub(super) fn peek(target: &Target<'_>) -> io::Result<Peek> {
    peek_with(target, false)
}

/// [`peek`]; with `verified`, a `Running` child whose id cannot be read is an error.
pub(super) fn peek_with(target: &Target<'_>, verified: bool) -> io::Result<Peek> {
    let (pid, unique) = pid_and_unique(target);
    let peeked = peek_raw(pid)?;
    let Some(unique) = unique else { return Ok(peeked) };
    match peeked {
        Peek::Exit(_) => match check_unique(pid, unique, ReadPurpose::Peek) {
            IdCheck::Matches => Ok(peeked),
            IdCheck::Other => Ok(Peek::Foreign(Foreign::Other)),
            IdCheck::Gone => Ok(Peek::Foreign(Foreign::Gone)),
            // The read was refused (a MACF denial): an exit that cannot be tied to the child is not
            // consumed by a bare pid. The errno stays in the error, so `EPERM` stays
            // `PermissionDenied`.
            IdCheck::Unreadable(errno) => Err(io::Error::new(
                io::Error::from_raw_os_error(errno).kind(),
                format!("pid {pid}: its identity could not be read (errno {errno}); its exit was not consumed"),
            )),
        },
        // `waitid` found a child of ours that has not exited. A foreign reap followed by a reuse
        // of the pid by another child of ours also looks like this, so the id decides.
        Peek::Running => match check_unique(pid, unique, ReadPurpose::Running) {
            IdCheck::Other => Ok(Peek::Foreign(Foreign::Other)),
            // `waitid` found the child running and the id read finds no such process: it was
            // reaped in between, so nothing is left to call running.
            IdCheck::Gone => Ok(Peek::Foreign(Foreign::Gone)),
            IdCheck::Matches => Ok(peeked),
            IdCheck::Unreadable(_) if !verified => Ok(peeked),
            IdCheck::Unreadable(errno) => Err(io::Error::new(
                io::Error::from_raw_os_error(errno).kind(),
                format!("pid {pid}: its identity could not be read (errno {errno}); it cannot be shown to be ours"),
            )),
        },
        // `ECHILD` is not proof of a reap: while a tracer holds our child the parent's `waitid`
        // answers `ECHILD` (`src/test_support/tracer.rs`), and the tracer's hand-back re-sends
        // `NOTE_EXIT`. The pid names our child and a live process other than launchd holds it:
        // running. A child held by launchd is a zombie (or a child mid-exit) whose tracer died:
        // XNU reparents it to launchd and keeps `p_oppid` naming us (xnu-12377.121.6
        // `kern_exit.c:2612-2613` and `:2748`, which sends the `SIGCHLD` to launchd). It comes
        // back to us only if launchd waits on it: `reap_child_locked` then finds `p_oppid`, hands
        // it back and re-sends `NOTE_EXIT` (`:2864-2912`). On CI launchd never did, in a 30 s
        // window, so this is taken for reaped. The sync child's later `wait` or `try_wait` still
        // reaps the zombie if that hand-back ever comes; the tokio backend forgets it.
        Peek::Foreign(Foreign::Gone) => match held_by(pid, unique, ReadPurpose::Echild) {
            Held::Other => Ok(Peek::Foreign(Foreign::Other)),
            Held::Parent(ppid) if ppid == LAUNCHD => Ok(peeked),
            Held::Parent(_) => Ok(Peek::Running),
            // `ESRCH` with `arg = 1` is a reap: a process resolves from `P_REF_DEAD` until then.
            Held::Gone => Ok(peeked),
            // A MACF denial: not ours to see.
            Held::Refused(_) => Ok(peeked),
        },
        Peek::Foreign(Foreign::Other) => Ok(peeked),
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
    let (pid, unique) = pid_and_unique(target);
    match peek(target)? {
        Peek::Exit(_) => {}
        Peek::Running => return Ok(Reap::Running),
        Peek::Foreign(f) => return Ok(Reap::Foreign(f)),
    }
    // Our own zombie's unique id, read before the first reap: the first reap does not change it
    // (`proc_reparentlocked` returns early when the parent is unchanged, `kern_exit.c:3411`),
    // and the second peek checks it.
    let second_unique = unique.or_else(|| match uniq_info(pid, ReadPurpose::PreReap) {
        UniqRead::Found(now) => Some(now.unique_id),
        UniqRead::Gone | UniqRead::Refused(_) => None,
    });
    let first = match consume(pid) {
        Ok(Some(record)) => reaped_from_record(record),
        // A by-pid consume is never pinned: a foreign reap between the peek and here, then a
        // reuse of the pid by a child that is still running, finds nothing. A reuser that is our
        // own child and already a zombie has its exit record consumed instead: the id check above
        // is a check, not a pin.
        Ok(None) => return Ok(Reap::Foreign(Foreign::Gone)),
        Err(e) if is_echild(&e) => return Ok(Reap::Foreign(Foreign::Gone)),
        Err(e) => return Err(e),
    };
    second_reap(pid, second_unique);
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
pub(crate) fn second_reap(pid: u32, unique: Option<u64>) {
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
    let Some(unique) = unique else {
        log::warn!("second reap of pid {pid}: no identity to check it against; a zombie may be left");
        return;
    };
    match check_unique(pid, unique, ReadPurpose::SecondPeek) {
        IdCheck::Matches => {}
        IdCheck::Other | IdCheck::Gone => {
            log::debug!("second reap of pid {pid}: the pid names another process now");
            return;
        }
        IdCheck::Unreadable(_) => {
            log::warn!("second reap of pid {pid}: its identity could not be read; a zombie may be left");
            return;
        }
    }
    match consume(pid) {
        Ok(_) => {}
        Err(e) if is_echild(&e) => log::debug!("second reap of pid {pid}: already reaped elsewhere"),
        Err(e) => log::warn!("second reap of pid {pid} failed ({e}); a zombie may be left"),
    }
}
