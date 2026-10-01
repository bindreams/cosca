//! `SharedChild` against a child traced by a process that is not its parent, as `gdb -p` does
//! (`TRACER` group; needs `COSCA_TEST_TRACER_CONSENT=1`).
//!
//! A tracee that dies while a foreign tracer holds it is a zombie the tracer alone can see: its
//! pidfd is readable, the parent's `waitid` finds no record, and the parent's own record appears
//! only after the tracer hands the zombie back: by reaping it with `waitpid`, or by exiting
//! (`exit_ptrace` detaches it; a debugger that quits). Both are tested. The tracer here is a
//! re-exec of this test binary ([`foreign_tracer_helper`]); the tracee allows it with
//! `PR_SET_PTRACER`, which Yama's scope 1 requires of a tracer that is no ancestor.

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

/// Holds the driver's pid in a fixture re-exec of this test.
const MARKER: &str = "COSCA_TEST_SHARED_FOREIGN_TRACER";

/// The tracee's pid, for the helper.
const PID_ENV: &str = "COSCA_TEST_SHARED_FOREIGN_TRACER_PID";

/// The go bytes: how the helper hands the zombie back.
const REAP: u8 = b'r';
const EXIT: u8 = b'x';

fn say(line: &str) {
    // Not `println!`: libtest captures that.
    writeln!(std::io::stdout(), "@@{line}@@").expect("write to the driver");
}

/// The foreign tracer: seize the pid in [`PID_ENV`], report, and once told (a byte on stdin) hand
/// the zombie back: `REAP` reaps it with `waitpid` and reports again, `EXIT` exits without
/// reaping. A no-op unless it is the re-exec the driver started.
///
/// It seizes with no options, so no `PTRACE_O_TRACEEXIT`: the kill is not delayed by an exit stop,
/// and the pidfd turns readable at the zombie.
#[test]
fn foreign_tracer_helper() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return;
    }
    let pid: libc::pid_t = std::env::var(PID_ENV)
        .expect("the tracee's pid")
        .parse()
        .expect("a pid");
    // SAFETY: a plain ptrace request on the driver's child.
    // `ptrace` is variadic, and glibc reads `addr` and `data` as pointers.
    let null = std::ptr::null_mut::<libc::c_void>;
    let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, null(), null()) };
    assert_eq!(rc, 0, "PTRACE_SEIZE: {}", std::io::Error::last_os_error());
    say("seized");
    let mut go = [0u8; 1];
    std::io::stdin().read_exact(&mut go).expect("the driver's go byte");
    if go[0] == EXIT {
        return;
    }
    assert_eq!(go[0], REAP, "an unknown go byte");
    let status = loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if r != -1 {
            break status;
        }
        let e = std::io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(libc::EINTR), "waitpid: {e}");
    };
    // The driver saw the pidfd readable, so the tracee is a zombie, which `waitpid` reports before
    // any stop.
    assert!(
        libc::WIFEXITED(status) || libc::WIFSIGNALED(status),
        "waitpid: not an exit: {status:#x}"
    );
    say("reaped");
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
    /// The holder took a second `step` before blocking: it spins instead of blocking.
    Spun(HolderStep),
    /// `wait` returned, with the holder's steps.
    Done(std::io::Result<std::process::ExitStatus>, Vec<HolderStep>),
}

/// The next line of the helper's stdout that ends in `@@<expected>@@`: libtest's own output, which
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

/// Where the holder thread is.
#[derive(Debug, PartialEq, Eq)]
enum Holder {
    /// Asleep in a `waitid` that waits.
    Blocked,
    /// The thread is gone.
    Finished,
}

/// Re-reads `/proc/self/task/<tid>/syscall` until the thread sleeps in a `waitid` without
/// `WNOHANG`, or is gone. Both are conditions the holder reaches by itself, so the only exit is
/// the condition; the pauses between reads are a backoff, not a bound.
fn await_blocked_or_finished(tid: libc::pid_t) -> Holder {
    let path = format!("/proc/self/task/{tid}/syscall");
    let mut pause = std::time::Duration::from_micros(50);
    loop {
        match std::fs::read_to_string(&path) {
            // `<nr> <a0> <a1> <a2> <a3> <a4> <a5> <sp> <pc>`, or `running`, or `-1 <sp> <pc>`.
            Ok(text) => {
                let mut fields = text.split_whitespace();
                let nr = fields.next().and_then(|n| n.parse::<libc::c_long>().ok());
                // `waitid(idtype, id, infop, options, rusage)`: `options` is the fourth argument.
                let options = fields
                    .nth(3)
                    .and_then(|o| u64::from_str_radix(o.trim_start_matches("0x"), 16).ok());
                if nr == Some(libc::SYS_waitid) && options.is_some_and(|o| o & libc::WNOHANG as u64 == 0) {
                    return Holder::Blocked;
                }
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => return Holder::Finished,
            Err(e) => panic!("read {path}: {e}"),
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(std::time::Duration::from_millis(5));
    }
}

/// A zombie held by a foreign tracer is running to `try_wait`; `wait` blocks, unlocked, in
/// `waitid` rather than re-polling the readable pidfd until the tracer lets go, and then returns
/// the kill. The tracer lets go by reaping it.
///
/// Mutants: a `waitid` that finds no record read as the child being gone (`try_wait` fails); a
/// holder that spins instead of blocking, whether by re-polling, by looping on the reap, or by a
/// non-blocking peek in place of the blocking `waitid` (a second `Poll` or `Reap` is reported
/// before any `BlockingWaitid`, so the driver fails instead of waiting for one); a blocking
/// `waitid` that is `WNOHANG` (the holder asserts `si_pid`, as the tracee is still held, and the
/// driver sees the thread gone); a blocking `waitid` under the lock; a `wait` that returns before
/// the tracer's reap.
#[test]
fn a_zombie_held_by_a_foreign_tracer_is_handed_back_to_a_blocked_wait() {
    hand_back(REAP);
}

/// As [`a_zombie_held_by_a_foreign_tracer_is_handed_back_to_a_blocked_wait`], but the tracer lets
/// go by exiting without reaping, as a debugger that quits does.
#[test]
fn a_zombie_held_by_a_foreign_tracer_that_exits_is_handed_back_to_a_blocked_wait() {
    hand_back(EXIT);
}

fn hand_back(go_byte: u8) {
    if !require_group("TRACER") {
        return;
    }
    let b = Blocker::spawn_with(|cmd| {
        // SAFETY: `prctl` is async-signal-safe and touches only the forked child.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(
                    libc::PR_SET_PTRACER,
                    libc::PR_SET_PTRACER_ANY,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) != 0
                {
                    let e = std::io::Error::last_os_error();
                    // `EINVAL`: no Yama, so nothing restricts a tracer and nothing needs allowing.
                    if e.raw_os_error() != Some(libc::EINVAL) {
                        return Err(e);
                    }
                }
                Ok(())
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
            let blocked = Rc::new(Cell::new(false));
            let spin = |step| {
                let spun = tx.clone();
                let blocked = Rc::clone(&blocked);
                move || {
                    if !blocked.get() {
                        _ = spun.send(Msg::Spun(step));
                    }
                }
            };
            // Hooks fire in registration order: the first of each passes, a second is a spin.
            let _first_poll = exit_seams::on_holder_step(HolderStep::Poll, || {});
            let _first_reap = exit_seams::on_holder_step(HolderStep::Reap, || {});
            let _second_poll = exit_seams::on_holder_step(HolderStep::Poll, spin(HolderStep::Poll));
            let _second_reap = exit_seams::on_holder_step(HolderStep::Reap, spin(HolderStep::Reap));
            let at_block = tx.clone();
            let _hook = exit_seams::on_holder_step(HolderStep::BlockingWaitid, move || {
                blocked.set(true);
                _ = at_block.send(Msg::AtBlockingWaitid(rustix::thread::gettid().as_raw_nonzero().get()));
            });
            let result = shared.wait();
            _ = tx.send(Msg::Done(result, exit_seams::holder_steps()));
        }
    });
    match rx.recv().expect("the waiter reports") {
        Msg::AtBlockingWaitid(tid) => {
            // The tracee stays alive, held by the tracer, until the holder is asleep in the
            // blocking `waitid` or has finished: a `waitid` that did not block then has nothing
            // to answer with.
            if await_blocked_or_finished(tid) == Holder::Finished {
                match waiter.join() {
                    Err(panic) => std::panic::resume_unwind(panic),
                    Ok(()) => panic!("the holder finished while the tracer still held the zombie"),
                }
            }
        }
        Msg::Spun(step) => panic!("the holder took a second {step:?} instead of blocking in waitid"),
        Msg::Done(result, steps) => {
            panic!("wait returned {result:?} ({steps:?}) while the tracer still held the zombie")
        }
    }
    // The holder gave up the lock before it blocked, and is asleep in `waitid`.
    let printed = format!("{:?}", b.shared);
    assert!(printed.contains("W {"), "the holder is in W: {printed}");
    assert!(
        !printed.contains("locked"),
        "the blocking waitid must hold no lock: {printed}"
    );
    go.write_all(&[go_byte])
        .expect("tell the helper to hand the zombie back");
    if go_byte == REAP {
        expect_line(&mut lines, "reaped");
    }
    let Msg::Done(result, steps) = rx.recv().expect("the waiter reports") else {
        panic!("the waiter reported a step twice");
    };
    waiter.join().expect("the waiter");
    assert_eq!(result.expect("wait").signal(), Some(libc::SIGKILL));
    assert_eq!(
        steps,
        [
            HolderStep::Poll,
            HolderStep::Reap,
            HolderStep::BlockingWaitid,
            HolderStep::Reap
        ]
    );
    assert_eq!(
        b.shared.try_wait().expect("try_wait").and_then(|s| s.signal()),
        Some(libc::SIGKILL)
    );
    drop(go);
    let status = helper.0.wait().expect("the helper exits");
    assert!(status.success(), "{status:?}");
}
