//! `SharedChild` against a child traced by a process that is not its parent, as `gdb -p` does
//! (`TRACER` group; needs `COSCA_TEST_TRACER_CONSENT=1`).
//!
//! A tracee that dies while a foreign tracer holds it is a zombie the tracer alone can see: its
//! pidfd is readable, the parent's `waitid` finds no record, and the parent's own record appears
//! only after the tracer hands the zombie back: by reaping it with `waitpid`, or by exiting
//! (`exit_ptrace` detaches it; a debugger that quits). Both are tested, for the unbounded `wait`
//! and, for the reap, for a bounded `wait_deadline`. A tracee the tracer merely stops is no exit
//! either. The tracer here is a re-exec of this test binary ([`foreign_tracer_helper`]); the
//! tracee allows it with `PR_SET_PTRACER`, which Yama's scope 1 requires of a tracer that is no
//! ancestor.

use std::cell::Cell;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::Arc;

use super::fixtures::Blocker;
use crate::test_support::require_group;
use crate::wait::exit_only::seams::{self as exit_seams, HolderStep};
use crate::wait::exit_only::Target;

/// Marks the helper re-exec; the value is the driver's pid.
const MARKER: &str = "COSCA_TEST_SHARED_FOREIGN_TRACER";

const PID_ENV: &str = "COSCA_TEST_SHARED_FOREIGN_TRACER_PID";

/// The go bytes. `STOP` makes the helper stop the tracee and report it; `REAP` and `EXIT` hand the
/// zombie back.
const STOP: u8 = b's';
const REAP: u8 = b'r';
const EXIT: u8 = b'x';

fn say(line: &str) {
    // Not `println!`: it panics on a write error, and this write must fail naming the driver.
    writeln!(std::io::stdout(), "@@{line}@@").expect("write to the driver");
}

/// `waitpid(pid, __WALL)`, past `EINTR`.
fn waitpid_status(pid: libc::pid_t) -> libc::c_int {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if r != -1 {
            return status;
        }
        let e = std::io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(libc::EINTR), "waitpid: {e}");
    }
}

/// The foreign tracer: seize the pid in [`PID_ENV`], report, and act on each go byte from stdin:
/// `STOP` interrupts the tracee and reports the stop, `REAP` reaps the zombie with `waitpid` and
/// reports, `EXIT` exits without reaping. A no-op unless it is the re-exec the driver started.
///
/// It seizes with no options, so no `PTRACE_O_TRACEEXIT`: the kill is not delayed by an exit stop,
/// and the pidfd turns readable at the zombie.
#[skuld::test]
fn foreign_tracer_helper() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return;
    }
    let pid: libc::pid_t = std::env::var(PID_ENV)
        .expect("the tracee's pid")
        .parse()
        .expect("a pid");
    // SAFETY: a ptrace request on a pid; variadic `addr`/`data` are read as pointers: typed nulls.
    let null = std::ptr::null_mut::<libc::c_void>;
    let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, null(), null()) };
    assert_eq!(rc, 0, "PTRACE_SEIZE: {}", std::io::Error::last_os_error());
    say("seized");
    loop {
        let mut go = [0u8; 1];
        std::io::stdin().read_exact(&mut go).expect("the driver's go byte");
        match go[0] {
            EXIT => return,
            STOP => {
                // SAFETY: as above.
                let rc = unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, pid, null(), null()) };
                assert_eq!(rc, 0, "PTRACE_INTERRUPT: {}", std::io::Error::last_os_error());
                let status = waitpid_status(pid);
                assert!(libc::WIFSTOPPED(status), "waitpid: not a stop: {status:#x}");
                say("stopped");
            }
            REAP => {
                // The driver saw the pidfd readable, so the tracee is a zombie, which `waitpid`
                // reports before any stop.
                let status = waitpid_status(pid);
                assert!(
                    libc::WIFEXITED(status) || libc::WIFSIGNALED(status),
                    "waitpid: not an exit: {status:#x}"
                );
                say("reaped");
                return;
            }
            other => panic!("an unknown go byte {other:#x}"),
        }
    }
}

/// Ends the helper when the driver leaves, whatever the way.
struct Helper(std::process::Child);

impl Drop for Helper {
    fn drop(&mut self) {
        _ = self.0.kill();
        _ = self.0.wait();
    }
}

/// What the waiting thread reports.
enum Msg {
    /// The holder, thread `tid`, is about to block, unlocked, in `waitid`.
    AtBlockingWaitid(libc::pid_t),
    /// A deadline holder is about to back off a second time: its first peek found the zombie held.
    AtBackoff,
    /// The holder polls instead of blocking or backing off.
    Spun(String),
    /// `wait` returned, with the holder's steps.
    Done(std::io::Result<Option<std::process::ExitStatus>>, Vec<HolderStep>),
}

/// The next line of the helper's stdout that ends in `@@<expected>@@`: skuld's own output, which
/// the helper shares, may precede it on the same line.
fn expect_line(lines: &mut impl Iterator<Item = std::io::Result<String>>, expected: &str) {
    let want = format!("@@{expected}@@");
    for line in lines {
        if line.expect("read the helper's stdout").ends_with(&want) {
            return;
        }
    }
    panic!("the helper ended without reporting {expected:?}");
}

#[derive(Debug, PartialEq, Eq)]
enum Holder {
    /// Asleep in a `waitid` that waits.
    Blocked,
    Finished,
}

/// Re-reads `/proc/self/task/<tid>/syscall` until the thread sleeps in a `waitid` without
/// `WNOHANG`, or is gone. Both are conditions the holder reaches by itself, so the only exit is
/// the condition; the pauses between reads are a backoff, not a bound. Any other shape of the
/// file than `running` or `<nr> ...` panics with its text.
fn await_blocked_or_finished(tid: libc::pid_t) -> Holder {
    let path = format!("/proc/self/task/{tid}/syscall");
    let mut pause = std::time::Duration::from_micros(50);
    loop {
        match std::fs::read_to_string(&path) {
            Ok(text) if text.trim() == "running" => {}
            // `<nr> <a0> <a1> <a2> <a3> <a4> <a5> <sp> <pc>`, or `-1 <sp> <pc>`.
            Ok(text) => {
                let mut fields = text.split_whitespace();
                let nr: libc::c_long = fields
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or_else(|| panic!("{path}: no syscall number in {text:?}"));
                if nr == libc::SYS_waitid {
                    // `waitid(idtype, id, infop, options, rusage)`: `options` is argument 4.
                    let options = fields
                        .nth(3)
                        .and_then(|o| u64::from_str_radix(o.trim_start_matches("0x"), 16).ok())
                        .unwrap_or_else(|| panic!("{path}: no waitid options in {text:?}"));
                    if options & libc::WNOHANG as u64 == 0 {
                        return Holder::Blocked;
                    }
                }
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => return Holder::Finished,
            Err(e) => panic!("read {path}: {e}"),
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(std::time::Duration::from_millis(5));
    }
}

/// How the driver waits on the held zombie.
#[derive(Clone, Copy)]
enum Wait {
    /// `wait`, which blocks in `waitid`.
    Unbounded,
    /// `wait_deadline` far in the future, which backs off.
    Deadline,
}

/// A zombie held by a foreign tracer is running to `try_wait`; `wait` blocks, unlocked, in
/// `waitid` (no polling, no `WNOHANG`) until the tracer reaps it, then returns the kill.
#[skuld::test]
fn a_zombie_held_by_a_foreign_tracer_is_handed_back_to_a_blocked_wait() {
    hand_back(REAP, Wait::Unbounded, false);
}

/// As [`a_zombie_held_by_a_foreign_tracer_is_handed_back_to_a_blocked_wait`], but the tracer lets
/// go by exiting without reaping, as a debugger that quits does.
#[skuld::test]
fn a_zombie_held_by_a_foreign_tracer_that_exits_is_handed_back_to_a_blocked_wait() {
    hand_back(EXIT, Wait::Unbounded, false);
}

/// A tracee the foreign tracer has stopped is no exit: `try_wait` and a short `wait_deadline` find
/// it running. The kill and the hand-back then go as above.
///
/// Mutant: a peek that finds no record reads as an exit (the holder goes on to reap).
#[skuld::test]
fn a_tracee_stopped_by_a_foreign_tracer_is_not_an_exit() {
    hand_back(REAP, Wait::Unbounded, true);
}

/// A bounded `wait_deadline` over the held zombie backs off and re-peeks, and returns the kill once
/// the tracer reaps it. The tracer lets go only after a second round of backoff, so a first peek
/// that found no record has to have been read as "still running".
///
/// Mutants: a deadline holder that re-polls, or reads the missing record as the child gone.
#[skuld::test]
fn a_deadline_wait_on_a_zombie_held_by_a_foreign_tracer_is_handed_back() {
    hand_back(REAP, Wait::Deadline, false);
}

fn hand_back(go_byte: u8, wait: Wait, stop_first: bool) {
    if !require_group("TRACER") {
        return;
    }
    let b = Blocker::spawn_with(|cmd| {
        // SAFETY: `set_ptracer` is a raw `prctl` syscall, async-signal-safe, and touches only the
        // forked child.
        unsafe {
            cmd.pre_exec(|| match rustix::process::set_ptracer(rustix::process::PTracer::Any) {
                // `INVAL`: no Yama, so nothing restricts a tracer and nothing needs allowing.
                Ok(()) | Err(rustix::io::Errno::INVAL) => Ok(()),
                Err(e) => Err(e.into()),
            });
        }
    });
    let pid = b.shared.id();
    let mut cmd = crate::test_child::fixture_command(crate::test_child::fixture_path!(foreign_tracer_helper));
    cmd.env(MARKER, std::process::id().to_string())
        .env(PID_ENV, pid.to_string())
        .env_remove("RUST_TEST_NOCAPTURE")
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    let mut helper = Helper(crate::test_spawn::spawn(&mut cmd).expect("spawn the foreign tracer"));
    let mut go = helper.0.stdin.take().expect("piped stdin");
    let mut lines = BufReader::new(helper.0.stdout.take().expect("piped stdout")).lines();
    expect_line(&mut lines, "seized");

    if stop_first {
        go.write_all(&[STOP]).expect("tell the helper to stop the tracee");
        expect_line(&mut lines, "stopped");
        assert_eq!(b.shared.try_wait().expect("try_wait"), None, "a stop is no exit");
        // The wait ends at its deadline with one final peek; a peek that read the stop as an exit
        // would go on to reap.
        exit_seams::holder_steps();
        let _no_reap = exit_seams::on_holder_step(HolderStep::Reap, || {
            panic!("the holder went to reap a tracee that is only stopped")
        });
        let soon = std::time::Instant::now() + std::time::Duration::from_millis(20);
        assert_eq!(
            b.shared.wait_deadline(soon).expect("wait_deadline"),
            None,
            "a stop is no exit"
        );
    }

    b.shared.kill().expect("kill");
    // The exit, which the tracer alone can see: the pidfd turns readable.
    let Some(Target::PidFd(fd)) = b.shared.target() else {
        panic!("a pidfd");
    };
    let mut fds = [libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    loop {
        // SAFETY: `fds` is one valid `pollfd`.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 1, -1) };
        if r == 1 {
            break;
        }
        let e = std::io::Error::last_os_error();
        assert!(r == -1 && e.raw_os_error() == Some(libc::EINTR), "poll: {e}");
    }
    assert_eq!(
        b.shared.try_wait().expect("try_wait"),
        None,
        "the tracer still holds it"
    );

    let (tx, rx) = mpsc::channel();
    let waiter = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            exit_seams::holder_steps();
            // Set when the holder reaches the wait this test is about: from then on a poll is a
            // spin no more.
            let waiting = Rc::new(Cell::new(false));
            let spin = |step| {
                let spun = tx.clone();
                let waiting = Rc::clone(&waiting);
                move || {
                    if !waiting.get() {
                        _ = spun.send(Msg::Spun(format!("a second {step:?}")));
                    }
                }
            };
            // Hooks fire in registration order: the first of each passes, a second is a spin.
            let reaped = Rc::new(Cell::new(false));
            let first_reap = Rc::clone(&reaped);
            let _first_poll = exit_seams::on_holder_step(HolderStep::Poll, || {});
            let _first_reap = exit_seams::on_holder_step(HolderStep::Reap, move || first_reap.set(true));
            let _second_poll = exit_seams::on_holder_step(HolderStep::Poll, spin(HolderStep::Poll));
            let _second_reap = exit_seams::on_holder_step(HolderStep::Reap, spin(HolderStep::Reap));
            // The first reap peeks once. Any other `waitid` before the blocking one is a poll with
            // no step, and the first after `BlockingWaitid` must wait: failing there beats hanging.
            let peeks = Cell::new(0u32);
            let waited = Cell::new(false);
            let (seen, armed, spun) = (Rc::clone(&reaped), Rc::clone(&waiting), tx.clone());
            let _observer = matches!(wait, Wait::Unbounded).then(|| {
                exit_seams::observe_waitid(move |options| {
                    if armed.get() {
                        if !waited.replace(true) {
                            assert_eq!(
                                options & libc::WNOHANG as u32,
                                0,
                                "the visible-exit wait made a WNOHANG waitid ({options:#x}) instead of blocking in its first"
                            );
                        }
                    } else if seen.get() {
                        peeks.set(peeks.get() + 1);
                        if peeks.get() > 1 {
                            _ = spun.send(Msg::Spun("a second non-blocking waitid before blocking".into()));
                        }
                    }
                })
            });
            let _first_backoff = exit_seams::on_holder_step(HolderStep::Backoff, || {});
            let at = tx.clone();
            let _hook = match wait {
                Wait::Unbounded => exit_seams::on_holder_step(HolderStep::BlockingWaitid, move || {
                    waiting.set(true);
                    _ = at.send(Msg::AtBlockingWaitid(rustix::thread::gettid().as_raw_nonzero().get()));
                }),
                // The second round: the first peek has found the zombie held and the holder loops.
                Wait::Deadline => exit_seams::on_holder_step(HolderStep::Backoff, move || {
                    waiting.set(true);
                    _ = at.send(Msg::AtBackoff);
                }),
            };
            let result = match wait {
                Wait::Unbounded => shared.wait().map(Some),
                Wait::Deadline => {
                    shared.wait_deadline(std::time::Instant::now() + std::time::Duration::from_secs(3600))
                }
            };
            _ = tx.send(Msg::Done(result, exit_seams::holder_steps()));
        }
    });
    match rx.recv().expect("the waiter reports") {
        Msg::AtBlockingWaitid(tid) => {
            // The tracer keeps the zombie until the holder sleeps in `waitid`, so a `waitid` that
            // does not block has nothing to return.
            if await_blocked_or_finished(tid) == Holder::Finished {
                match waiter.join() {
                    Err(panic) => std::panic::resume_unwind(panic),
                    Ok(()) => panic!("the holder finished while the tracer still held the zombie"),
                }
            }
            let printed = format!("{:?}", b.shared);
            assert!(printed.contains("W {"), "the holder is in W: {printed}");
        }
        Msg::AtBackoff => {}
        Msg::Spun(what) => panic!("the holder polled instead of waiting: {what}"),
        Msg::Done(result, steps) => {
            panic!("wait returned {result:?} ({steps:?}) while the tracer still held the zombie")
        }
    }
    go.write_all(&[go_byte])
        .expect("tell the helper to hand the zombie back");
    if go_byte == REAP {
        expect_line(&mut lines, "reaped");
    }
    let Msg::Done(result, steps) = rx.recv().expect("the waiter reports") else {
        panic!("the waiter reported a step twice");
    };
    waiter.join().expect("the waiter");
    let status = result.expect("wait").expect("the exit");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    match wait {
        Wait::Unbounded => assert_eq!(
            steps,
            [
                HolderStep::Poll,
                HolderStep::Reap,
                HolderStep::BlockingWaitid,
                HolderStep::Reap
            ]
        ),
        // The backoff re-peeks until the tracer has reaped, so it may repeat.
        Wait::Deadline => {
            let (first, rest) = steps.split_at(2);
            assert_eq!(first, [HolderStep::Poll, HolderStep::Reap]);
            let (last, backoffs) = rest.split_last().expect("the final reap");
            assert_eq!(*last, HolderStep::Reap, "{steps:?}");
            assert!(
                !backoffs.is_empty() && backoffs.iter().all(|s| *s == HolderStep::Backoff),
                "{steps:?}"
            );
        }
    }
    assert_eq!(
        b.shared.try_wait().expect("try_wait").and_then(|s| s.signal()),
        Some(libc::SIGKILL)
    );
    drop(go);
    let status = helper.0.wait().expect("the helper exits");
    assert!(status.success(), "{status:?}");
}
