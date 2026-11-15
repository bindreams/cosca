use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use rustix::event::{PollFd, PollFlags};
use rustix::process::{pidfd_send_signal, waitid, Signal, WaitId, WaitIdOptions};

use super::{
    channel, spawn, Failure, Program, Progress, Record, RefusalKind, SpawnError, Spawned, Status, StepFailure,
};
use crate::child::spawn::spawn_lock;
use crate::os_process::linux::fork::{
    clone_with_pidfd, fails_with, fallback, fork_with_pidfd, CloneKind, Fork, ForkFn, NewChild,
};

type Steps<'a> = &'a dyn Fn() -> Result<(), StepFailure>;

fn program(candidate: &str, argv: &[&str], env: &[(&str, &str)]) -> Program {
    let argv: Vec<&OsStr> = argv.iter().map(OsStr::new).collect();
    let env = env.iter().map(|(k, v)| (OsString::from(k), OsString::from(v)));
    Program::new(&[OsString::from(candidate)], &argv, env).expect("no NUL")
}

fn tool(candidate: &str) -> Program {
    program(candidate, &[candidate], &[])
}

/// The exit code of a child whose step failed, as these tests give it to `spawn`: not the 127 of a
/// failed `execve`.
const STEP_EXIT: i32 = 117;

/// A spawn of `program` through `fork`, under `spawn_lock`.
fn start(kind: CloneKind, fork: ForkFn, program: &Program, steps: Steps<'_>) -> Result<Spawned, SpawnError> {
    let _lock = spawn_lock();
    // SAFETY: this thread holds `spawn_lock`, and every `steps` of these tests makes raw system calls
    // only.
    unsafe { spawn(kind, fork, program, &[], &mut || steps(), STEP_EXIT) }
}

fn started(kind: CloneKind, program: &Program, steps: Steps<'_>) -> Spawned {
    start(kind, fork_with_pidfd, program, steps)
        .unwrap_or_else(|e| panic!("the spawn of a {kind:?} child failed: {e:?}"))
}

/// Blocks until the status has said all it will: a failure record, or the end. Waits on the real
/// condition (the descriptor's readiness) each round.
fn settled(status: &mut Status) -> Progress {
    loop {
        match status.progress().expect("the status pipe reads") {
            Progress::Pending | Progress::Ready => {
                let fd = status.as_fd();
                let mut fds = [PollFd::new(&fd, PollFlags::IN)];
                crate::wait::poll_ready(&mut fds).expect("poll the status pipe");
            }
            settled => return settled,
        }
    }
}

/// The exit status of `child`, reaped through its pidfd.
fn exit_status(child: &NewChild) -> i32 {
    let done = waitid(WaitId::PidFd(child.pidfd.as_fd()), WaitIdOptions::EXITED)
        .expect("waitid on the pidfd")
        .expect("a blocking wait returns a status");
    done.exit_status().unwrap_or_else(|| {
        panic!(
            "the child did not exit: it died of signal {:?}",
            done.terminating_signal()
        )
    }) as i32
}

/// The signal the child died of, reaped through its pidfd.
fn terminating_signal(child: &NewChild) -> Option<i32> {
    let done = waitid(WaitId::PidFd(child.pidfd.as_fd()), WaitIdOptions::EXITED)
        .expect("waitid on the pidfd")
        .expect("a blocking wait returns a status");
    done.terminating_signal()
}

// Status ---------------------------------------------------------------------------------------

fn write_record(writer: &OwnedFd, record: Record) {
    let written = rustix::io::write(writer, &record.encode()).expect("write a record");
    assert_eq!(written, 4);
}

/// The status read end must not block, so that a read of a pipe with nothing in it answers at once. A
/// blocking one would wait for a record, or for the end, which another thread's fork-without-exec can
/// keep from coming; this fails first, before any read can hang.
fn assert_nonblocking(status: &Status) {
    let flags = rustix::fs::fcntl_getfl(status.as_fd()).unwrap();
    assert!(
        flags.contains(rustix::fs::OFlags::NONBLOCK),
        "the status read end must not block"
    );
}

/// The records come out in the order they went in, a failure ends the reading and stays the answer,
/// and the pipe's end says whether a ready record came first.
///
/// Mutants: a record is decoded as another; a failure is forgotten by the next read; the end ignores
/// the ready record; the read end blocks.
#[skuld::test]
fn the_status_reads_records_in_order_and_a_failure_sticks() {
    let (mut status, writer) = channel(CloneKind::Plain, &[]).expect("a channel");
    assert_nonblocking(&status);
    assert_eq!(status.progress().unwrap(), Progress::Pending);
    write_record(&writer, Record::Ready);
    assert_eq!(status.progress().unwrap(), Progress::Ready);
    assert_eq!(status.progress().unwrap(), Progress::Ready);
    write_record(&writer, Record::Failed(Failure::Exec(libc::ENOENT)));
    let failed = Progress::Failed(Failure::Exec(libc::ENOENT));
    assert_eq!(status.progress().unwrap(), failed);
    assert_eq!(status.progress().unwrap(), failed, "a failure is the answer for good");

    let (mut status, writer) = channel(CloneKind::Plain, &[]).expect("a channel");
    write_record(&writer, Record::Ready);
    write_record(
        &writer,
        Record::Failed(Failure::Step(StepFailure {
            kind: 3,
            value: libc::EACCES as u16,
        })),
    );
    assert_eq!(
        status.progress().unwrap(),
        Progress::Failed(Failure::Step(StepFailure {
            kind: 3,
            value: libc::EACCES as u16
        })),
        "both records are in the pipe: the failure is the answer"
    );

    let (mut status, writer) = channel(CloneKind::Plain, &[]).expect("a channel");
    drop(writer);
    assert_eq!(status.progress().unwrap(), Progress::Ended { ready: false });
    let (mut status, writer) = channel(CloneKind::Plain, &[]).expect("a channel");
    write_record(&writer, Record::Ready);
    drop(writer);
    assert_eq!(status.progress().unwrap(), Progress::Ended { ready: true });
}

/// `garbage` written to a channel is a bug in debug builds and an error without them, and the channel
/// is unusable for good: a whole record written after it is not decoded.
fn assert_garbage_ends_the_channel(garbage: &[u8]) {
    let (mut status, writer) = channel(CloneKind::Plain, &[]).expect("a channel");
    rustix::io::write(&writer, garbage).unwrap();
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| status.progress()));
    if cfg!(debug_assertions) {
        assert!(first.is_err(), "{garbage:?} is a bug in debug builds");
    } else {
        assert_eq!(first.unwrap().unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }
    write_record(&writer, Record::Ready);
    assert_eq!(
        status.progress().unwrap_err().kind(),
        std::io::ErrorKind::InvalidData,
        "a whole record after {garbage:?} is not decoded"
    );
    assert!(status.could_have_started().is_err());
}

/// The child writes each record in one write of four bytes, which a pipe keeps whole, so a short read
/// means something else wrote to the channel, and the bytes after it cannot be told from a record.
///
/// Mutant: a read after a short one decodes what follows it.
#[skuld::test]
fn a_short_status_read_ends_the_channel_as_an_error() {
    assert_garbage_ends_the_channel(&[1, 2]);
}

/// A record whose kind is neither one the core reserves nor a step kind (a `u8`) is not the child's
/// either: it ends the channel as an error, not as a failure of some kind.
///
/// Mutant: an out-of-range kind is decoded as a step failure, its kind cut to eight bits.
#[skuld::test]
fn a_record_of_no_kind_ends_the_channel_as_an_error() {
    assert_garbage_ends_the_channel(&(0x0100u32 << 16 | 7).to_ne_bytes());
}

// Spawn ----------------------------------------------------------------------------------------

/// A program that does not exist ends in an exec failure record carrying the errno, whichever the
/// kind, and the child is gone with exit status 127. For the vfork kind the record is in the pipe when
/// the spawn returns.
///
/// Mutants: the errno is not the exec's; the failure is not written; the record is read before the
/// child has written it (vfork: not suspended, see the next test).
#[skuld::test]
fn an_exec_that_fails_gives_its_errno_record() {
    let missing = tool("/nonexistent/cosca-b5-core");
    for kind in [CloneKind::Vfork, CloneKind::Plain] {
        let mut spawned = started(kind, &missing, &|| Ok(()));
        let progress = if kind == CloneKind::Vfork {
            spawned.status.progress().unwrap()
        } else {
            settled(&mut spawned.status)
        };
        assert_eq!(progress, Progress::Failed(Failure::Exec(libc::ENOENT)), "{kind:?}");
        assert!(!spawned.status.could_have_started().unwrap(), "{kind:?}");
        assert_eq!(exit_status(&spawned.child), 127, "{kind:?}");
    }
}

/// A step that fails ends the child before the program, with its own record and the exit code the
/// caller gave, which is not an exec failure's 127.
///
/// Mutants: the step's failure is written as an exec failure; the exec runs after a failed step; the
/// child exits 127 after a failed step.
#[skuld::test]
fn a_step_that_fails_gives_its_record_and_the_program_never_runs() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let ran = program(
        "/bin/sh",
        &["sh", "-c", "echo > \"$1\"", "sh", marker.to_str().unwrap()],
        &[],
    );
    let failure = StepFailure {
        kind: 9,
        value: libc::EACCES as u16,
    };
    for kind in [CloneKind::Vfork, CloneKind::Plain] {
        let mut spawned = started(kind, &ran, &|| Err(failure));
        assert_eq!(
            settled(&mut spawned.status),
            Progress::Failed(Failure::Step(failure)),
            "{kind:?}"
        );
        assert_eq!(
            exit_status(&spawned.child),
            STEP_EXIT,
            "{kind:?}: a failed step ends the child with the caller's code, not an exec failure's 127"
        );
        assert!(!marker.exists(), "{kind:?}: the program ran");
    }
}

/// A child that ends before its ready record did not start the program. For the vfork kind the spawn
/// has returned by then, and the pipe may or may not have closed yet: either way it is "not started".
///
/// Mutant: the absence of a ready record reads as "started".
#[skuld::test]
fn a_child_that_dies_before_ready_is_not_started() {
    let program = tool("/bin/true");
    let mut spawned = started(CloneKind::Vfork, &program, &|| {
        // SAFETY: a plain system call.
        unsafe { libc::_exit(5) }
    });
    let progress = spawned.status.progress().unwrap();
    assert!(
        matches!(progress, Progress::Pending | Progress::Ended { ready: false }),
        "{progress:?}"
    );
    assert!(!spawned.status.could_have_started().unwrap(), "{progress:?}");
    assert_eq!(exit_status(&spawned.child), 5);
    assert_eq!(settled(&mut spawned.status), Progress::Ended { ready: false });
}

/// A child that wrote its ready record and execed is started, and the program ran: it exits with its
/// own status, which the pipe's end does not carry.
///
/// Mutants: the ready record is not written; the exec is not attempted.
#[skuld::test]
fn a_child_that_was_ready_and_execed_is_started() {
    let exits_3 = program("/bin/sh", &["sh", "-c", "exit 3"], &[]);
    for kind in [CloneKind::Vfork, CloneKind::Plain] {
        let mut spawned = started(kind, &exits_3, &|| Ok(()));
        let progress = settled(&mut spawned.status);
        assert_eq!(progress, Progress::Ended { ready: true }, "{kind:?}");
        assert!(spawned.status.could_have_started().unwrap(), "{kind:?}");
        assert_eq!(exit_status(&spawned.child), 3, "{kind:?}");
    }
}

/// The `clone(2)` fallback of [`fork_with_pidfd`], on its own: the path of a kernel without `clone3`.
unsafe fn clone_fallback(kind: CloneKind) -> Result<Fork, i32> {
    // SAFETY: the caller's contract; the first clone is refused without making a child.
    unsafe { fallback(|_| fails_with(libc::ENOSYS), clone_with_pidfd, kind) }
}

/// The vfork kind returns only after the child has run its steps and execed, so what the steps wrote
/// is already there: no wait, no timing. The kernel suspends the parent until the child's exec. The
/// plain kind does not: its parent returns while the child is held in its steps, before it wrote.
/// Both on `clone3` and on the `clone(2)` fallback.
///
/// Mutants: the vfork kind clones without `CLONE_VFORK` (the byte is missing at return in nearly every
/// run), or with `CLONE_VM` (the child runs on the parent's stack, and the test process dies of
/// `SIGSEGV`), on either path. The plain kind cloned with `CLONE_VFORK` never returns: the child is
/// held for a release only the returned parent gives.
#[skuld::test]
fn the_vfork_kind_returns_only_after_the_child_ran_its_steps() {
    let nonblocking_pipe = || {
        let (read, write) = std::io::pipe().unwrap();
        let flags = rustix::fs::fcntl_getfl(&read).unwrap() | rustix::fs::OFlags::NONBLOCK;
        rustix::fs::fcntl_setfl(&read, flags).unwrap();
        (read, write)
    };
    let program = tool("/bin/true");
    for (path, fork) in [
        ("clone3", fork_with_pidfd as ForkFn),
        ("clone(2)", clone_fallback as ForkFn),
    ] {
        let (witness_read, witness_write) = nonblocking_pipe();
        let w = witness_write.as_raw_fd();
        let spawned = start(CloneKind::Vfork, fork, &program, &move || {
            // SAFETY: a one-byte write of a valid buffer.
            unsafe { libc::write(w, b"x".as_ptr().cast(), 1) };
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{path}: the vfork spawn failed: {e:?}"));
        let mut byte = [0u8; 1];
        assert_eq!(
            rustix::io::read(&witness_read, &mut byte),
            Ok(1),
            "{path}: the spawn returned before the child ran its steps"
        );
        exit_status(&spawned.child);

        let (witness_read, witness_write) = nonblocking_pipe();
        let w = witness_write.as_raw_fd();
        let (release_read, release_write) = std::io::pipe().unwrap();
        let held = held_until_released(&release_read, &release_write);
        let spawned = start(CloneKind::Plain, fork, &program, &move || {
            held()?;
            // SAFETY: a one-byte write of a valid buffer.
            unsafe { libc::write(w, b"x".as_ptr().cast(), 1) };
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{path}: the plain spawn failed: {e:?}"));
        assert_eq!(
            rustix::io::read(&witness_read, &mut byte),
            Err(rustix::io::Errno::AGAIN),
            "{path}: the plain child ran its steps past the hold before the parent released it"
        );
        drop(release_write);
        assert_eq!(exit_status(&spawned.child), 0, "{path}");
        assert_eq!(rustix::io::read(&witness_read, &mut byte), Ok(1), "{path}");
    }
}

thread_local! {
    static HOLDER: RefCell<Option<NewChild>> = const { RefCell::new(None) };
}

/// A fork that first makes a child which never execs and holds a copy of every descriptor the spawn
/// has made so far, the status pipe's write end among them: another thread's fork-without-exec.
unsafe fn holder_then_fork(kind: CloneKind) -> Result<Fork, i32> {
    // SAFETY: the caller's contract; the holder pauses for ever, which is async-signal-safe.
    match unsafe { fork_with_pidfd(CloneKind::Plain) }? {
        Fork::Child => loop {
            // SAFETY: a plain system call.
            unsafe { libc::pause() };
        },
        Fork::Parent(holder) => HOLDER.with(|h| *h.borrow_mut() = Some(holder)),
    }
    // SAFETY: the caller's contract.
    unsafe { fork_with_pidfd(kind) }
}

/// Ends the holder when the test does.
struct Holder;

impl Drop for Holder {
    fn drop(&mut self) {
        if let Some(holder) = HOLDER.with(|h| h.borrow_mut().take()) {
            pidfd_send_signal(&holder.pidfd, Signal::KILL).expect("kill the holder");
            exit_status_or_signal(&holder);
        }
    }
}

fn exit_status_or_signal(child: &NewChild) {
    waitid(WaitId::PidFd(child.pidfd.as_fd()), WaitIdOptions::EXITED)
        .expect("waitid on the pidfd")
        .expect("a blocking wait returns a status");
}

/// A copy of the status pipe's write end in a process that never execs keeps the pipe from ending, so
/// the spawn does not wait for the end: it reads what is there, without blocking. The ready record is
/// there, and that is "started".
///
/// Mutants: the status read end is blocking (this fails by assertion before it can hang); the ready
/// record is not written. A read that waits for the pipe's end would hang here, and no assertion can
/// say that: the non-blocking read end is what the test pins.
#[skuld::test]
fn a_fork_without_exec_holding_the_channel_does_not_hold_the_return() {
    let _holder = Holder;
    let program = tool("/bin/true");
    let mut spawned = start(CloneKind::Vfork, holder_then_fork, &program, &|| Ok(())).expect("the vfork spawn returns");
    assert_nonblocking(&spawned.status);
    let progress = spawned.status.progress().unwrap();
    assert_eq!(
        progress,
        Progress::Ready,
        "the pipe has a second writer, so it has not ended"
    );
    assert!(spawned.status.could_have_started().unwrap());
    exit_status(&spawned.child);
}

unsafe fn both_refused(kind: CloneKind) -> Result<Fork, i32> {
    // SAFETY: neither stand-in makes a child.
    unsafe { fallback(|_| fails_with(libc::ENOSYS), |_| fails_with(libc::EPERM), kind) }
}

unsafe fn eagain(_: CloneKind) -> Result<Fork, i32> {
    fails_with(libc::EAGAIN)
}

/// A clone refused on both paths means the kernel or its filter cannot make a child with a pidfd:
/// `Unsupported`. Any other errno is the fork's own.
///
/// Mutants: a refusal on both paths is `Fork`; every errno is `Unsupported`.
#[skuld::test]
fn a_clone_refused_on_both_paths_is_unsupported() {
    let program = tool("/bin/true");
    for kind in [CloneKind::Vfork, CloneKind::Plain] {
        let refused = start(kind, both_refused, &program, &|| Ok(())).err();
        assert!(
            matches!(refused, Some(SpawnError::Unsupported(RefusalKind::Eperm))),
            "{kind:?}: {refused:?}"
        );
        let other = start(kind, eagain, &program, &|| Ok(())).err();
        assert!(
            matches!(other, Some(SpawnError::Fork(libc::EAGAIN))),
            "{kind:?}: {other:?}"
        );
    }
}

/// The child's environment is exactly the block the parent built: what the child reads from
/// `/proc/<pid>/environ` is that block, with none of the parent's variables.
///
/// Mutants: the child inherits the parent's environment; a variable is dropped or reordered.
#[skuld::test]
fn the_child_gets_exactly_the_env_block_built_in_the_parent() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("environ");
    let dump = program(
        "/bin/sh",
        &["sh", "-c", "cat /proc/$$/environ > \"$1\"", "sh", out.to_str().unwrap()],
        &[("COSCA_B5_ONE", "1"), ("COSCA_B5_TWO", "two words")],
    );
    let spawned = started(CloneKind::Vfork, &dump, &|| Ok(()));
    assert_eq!(exit_status(&spawned.child), 0);
    assert_eq!(
        std::fs::read(&out).unwrap(),
        b"COSCA_B5_ONE=1\0COSCA_B5_TWO=two words\0"
    );
}

/// With no descriptor to spare the channel cannot be made, and that is its own answer: no child
/// exists, and the errno is the pipe's.
///
/// Mutant: the pipe's failure is reported as a fork failure.
#[skuld::test]
fn a_full_fd_table_is_a_pipe_error() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_full_fd_table_is_a_pipe_error),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let program = tool("/bin/true");
    let _restore = crate::test_child::exhaust_fds(&done);
    let refused = start(CloneKind::Plain, fork_with_pidfd, &program, &|| Ok(())).err();
    assert!(matches!(refused, Some(SpawnError::Pipe(libc::EMFILE))), "{refused:?}");
}

/// The signal a program died of reaches the pidfd's `waitid`, not the status pipe: a program killed
/// after its exec has a ready record and an end, and no failure.
///
/// Mutant: a child's death by signal is reported as a failure record.
#[skuld::test]
fn a_program_killed_after_its_exec_is_started_and_not_failed() {
    let suicidal = program("/bin/sh", &["sh", "-c", "kill -KILL $$"], &[]);
    let mut spawned = started(CloneKind::Plain, &suicidal, &|| Ok(()));
    assert_eq!(settled(&mut spawned.status), Progress::Ended { ready: true });
    assert_eq!(terminating_signal(&spawned.child), Some(libc::SIGKILL));
}

/// A plain-cloned child holds at a read of `release` until the test drops the write end: its steps
/// close their copy of the write end first, so the drop is the end of the pipe.
fn held_until_released(
    release_read: &std::io::PipeReader,
    release_write: &std::io::PipeWriter,
) -> impl Fn() -> Result<(), StepFailure> {
    let (r, w) = (release_read.as_raw_fd(), release_write.as_raw_fd());
    move || {
        // SAFETY: `close` and a one-byte `read` into a valid buffer.
        unsafe {
            libc::close(w);
            let mut byte = 0u8;
            libc::read(r, (&mut byte as *mut u8).cast(), 1);
        }
        Ok(())
    }
}

/// After a plain clone the child runs beside the parent, so a channel with nothing in it shows nothing
/// yet: the program could still start, and "not started" would be wrong. After a vfork clone the same
/// channel is "not started" (`a_child_that_dies_before_ready_is_not_started`).
///
/// Mutant: an empty channel is "not started" whatever the clone.
#[skuld::test]
fn after_a_plain_clone_an_empty_channel_could_still_start() {
    let (release_read, release_write) = std::io::pipe().unwrap();
    let steps = held_until_released(&release_read, &release_write);
    let mut spawned = started(CloneKind::Plain, &tool("/bin/true"), &steps);
    assert_eq!(spawned.status.progress().unwrap(), Progress::Pending);
    assert!(spawned.status.could_have_started().unwrap());
    drop(release_write);
    assert_eq!(settled(&mut spawned.status), Progress::Ended { ready: true });
    assert_eq!(exit_status(&spawned.child), 0);
}

/// `SIGPIPE`'s bit in the masks of `/proc/<pid>/status`.
const SIGPIPE_BIT: u64 = 1 << (libc::SIGPIPE - 1);

/// A program that writes its own `/proc/<pid>/status` to its stdout, which shows the signals pending
/// for it and blocked in it as the child left them at its `execve`. It is the shell reading the file
/// with its `read` builtin, not `cat`: where `/bin/cat` is a Rust program (uutils, the default on
/// Ubuntu 26.04) its runtime sets `SIGPIPE` to ignored at startup, and that discards a blocked
/// `SIGPIPE` pending for it, which is the very signal these tests look for. The shell reads its own
/// status through `$$`, because a child process would be a different process.
fn status_dump() -> Program {
    program(
        "/bin/sh",
        &[
            "sh",
            "-c",
            "while IFS= read -r line; do printf '%s\\n' \"$line\"; done < /proc/$$/status",
        ],
        &[],
    )
}

/// The mask `field` (`SigPnd:` or `SigBlk:`) of a `/proc/<pid>/status` dump.
fn signal_mask(dump: &str, field: &str) -> u64 {
    let hex = dump
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap_or_else(|| panic!("no {field} line in the program's status"));
    u64::from_str_radix(hex.trim(), 16).expect("a hexadecimal mask")
}

/// Runs a plain-cloned child through `steps` and then the record writes with the status read end
/// already dropped (the write of each record is a broken pipe), and returns the program's
/// `/proc/<pid>/status`. The child holds before its record writes until the read end is gone.
fn status_of_a_program_whose_parent_stopped_reading(steps: impl Fn() + 'static) -> String {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("status");
    let out_c = std::ffi::CString::new(out.to_str().unwrap()).unwrap();
    let dump = status_dump();
    let (release_read, release_write) = std::io::pipe().unwrap();
    let hold = held_until_released(&release_read, &release_write);
    let Spawned { child, status } = started(CloneKind::Plain, &dump, &move || {
        // SAFETY: `open`, `dup2` and `close` on a prebuilt path and a descriptor it returned.
        unsafe {
            let file = libc::open(out_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644);
            libc::dup2(file, 1);
            libc::close(file);
        }
        steps();
        hold()
    });
    // The child closed its copy of the read end before its steps, so this is the last one.
    drop(status);
    drop(release_write);
    assert_eq!(exit_status(&child), 0);
    std::fs::read_to_string(out).unwrap()
}

/// A child step that sets `SIGPIPE` to its default disposition, as a host that did not ignore it (Rust's
/// runtime does) leaves it, and blocks it.
fn block_sigpipe() {
    // SAFETY: `sigaction` and `sigprocmask` on valid, zeroed records.
    unsafe {
        let mut default: libc::sigaction = std::mem::zeroed();
        default.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGPIPE, &default, std::ptr::null_mut());
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigaddset(&mut set, libc::SIGPIPE);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

/// A parent that dropped the read end must not cost the child its `execve`, and the child's record
/// writes leave the program's signal state as the child inherited it: no `SIGPIPE` pending and none
/// blocked that the child did not block.
///
/// Mutants: the record writes run with `SIGPIPE` as inherited, and the child dies of it before its
/// `execve`; the mask is not put back.
#[skuld::test]
fn a_child_whose_parent_stopped_reading_still_execs_with_its_signals_as_inherited() {
    let dump = status_of_a_program_whose_parent_stopped_reading(|| {
        // SAFETY: `sigaction` on a valid, zeroed record.
        unsafe {
            let mut default: libc::sigaction = std::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGPIPE, &default, std::ptr::null_mut());
        }
    });
    assert_eq!(signal_mask(&dump, "SigPnd:") & SIGPIPE_BIT, 0, "{dump}");
    assert_eq!(signal_mask(&dump, "SigBlk:") & SIGPIPE_BIT, 0, "{dump}");
}

/// A child whose mask blocks `SIGPIPE` hands its program the same mask, and the `SIGPIPE` its record
/// write raised is not left pending: the program that unblocks `SIGPIPE` is not killed by a write the
/// child made.
///
/// Mutant: the record writes ignore `SIGPIPE` for their duration, which a blocked signal is not
/// discarded by: it is queued, and survives the `execve`.
#[skuld::test]
fn a_blocked_sigpipe_raised_by_a_record_write_is_not_left_pending_for_the_program() {
    let dump = status_of_a_program_whose_parent_stopped_reading(block_sigpipe);
    assert_eq!(signal_mask(&dump, "SigPnd:") & SIGPIPE_BIT, 0, "{dump}");
    assert_ne!(
        signal_mask(&dump, "SigBlk:") & SIGPIPE_BIT,
        0,
        "the mask the child inherited is back: {dump}"
    );
}

/// A `SIGPIPE` pending for the child before its record write is the program's to receive: the write's
/// own is consumed, that one is not.
///
/// Mutant: a broken pipe consumes the `SIGPIPE` pending whether the write raised it or not.
#[skuld::test]
fn a_sigpipe_pending_before_the_record_writes_still_reaches_the_program() {
    let dump = status_of_a_program_whose_parent_stopped_reading(|| {
        block_sigpipe();
        // SAFETY: raw system calls: this thread's own `tgkill`.
        unsafe {
            let pid = libc::syscall(libc::SYS_getpid);
            let tid = libc::syscall(libc::SYS_gettid);
            libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGPIPE);
        }
    });
    assert_ne!(
        signal_mask(&dump, "SigPnd:") & SIGPIPE_BIT,
        0,
        "the signal pending before the writes is gone: {dump}"
    );
    assert_ne!(signal_mask(&dump, "SigBlk:") & SIGPIPE_BIT, 0, "{dump}");
}

/// A child whose ready record could not be written for a reason other than a broken pipe does not exec:
/// with no ready record the program must not have started, and a program that ran would contradict it.
/// The child ends with the caller's step code. (The steps here close every descriptor, the channel's
/// write end among them, which the contract forbids a real caller; the write is then `EBADF`.)
///
/// Mutants: a failed ready write is ignored and the program runs; the child exits 127.
#[skuld::test]
fn a_ready_record_that_cannot_be_written_stops_the_child_before_its_exec() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let ran = program(
        "/bin/sh",
        &["sh", "-c", "echo > \"$1\"", "sh", marker.to_str().unwrap()],
        &[],
    );
    let mut spawned = started(CloneKind::Plain, &ran, &|| {
        // SAFETY: a raw `close_range` of every descriptor above stdio; where the kernel has none (it is
        // Linux 5.9, above the floor), a `close` of every number below the descriptor limit.
        unsafe {
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == -1 {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
                for fd in 3..limit.rlim_cur.min(libc::c_int::MAX as u64) as libc::c_int {
                    libc::close(fd);
                }
            }
        }
        Ok(())
    });
    assert_eq!(exit_status(&spawned.child), STEP_EXIT);
    assert_eq!(settled(&mut spawned.status), Progress::Ended { ready: false });
    assert!(!marker.exists(), "the program ran with no ready record written");
}
