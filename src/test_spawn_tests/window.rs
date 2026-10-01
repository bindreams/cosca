//! The spawn window: what a fork that follows the crate rule (fork under `spawn_lock`) sees of a
//! raw spawn that is still in flight.
//!
//! A raw spawn with a `Stdio::piped()` stdout holds the child-side write end of that pipe in the
//! parent until `spawn` returns. The raw child is parked in `pre_exec`, so the spawn is
//! mid-flight. The forker then reports how many write ends of that pipe its own forked child
//! holds, found by the pipe's inode, which the raw child reports from its own stdout.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

use crate::containment::cgroup::test_support::block_on;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Contended,
    Forked,
}

#[derive(Debug)]
struct Outcome {
    first: Event,
    writers: u8,
    /// Whether the raw child's fork ran under `spawn_lock`, as its own `pre_exec` saw it. The
    /// forker's `Contended` alone cannot show this: another test's spawn can hold the lock too.
    raw_forked_under_the_lock: bool,
}

/// Open FIFOs in this process whose (st_dev, st_ino) equals `identity`.
fn pipe_fds(identity: [u64; 2]) -> Vec<RawFd> {
    std::fs::read_dir("/proc/self/fd")
        .expect("list /proc/self/fd")
        .filter_map(|entry| {
            entry
                .expect("read a /proc/self/fd entry")
                .file_name()
                .to_str()?
                .parse::<RawFd>()
                .ok()
        })
        .filter(|&fd| {
            // SAFETY: `fstat` on an fd number writes only into `st`.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                // Only the `read_dir` handle's own fd, closed by now, can fail.
                debug_assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
                return false;
            }
            (st.st_mode & libc::S_IFMT) == libc::S_IFIFO && [st.st_dev, st.st_ino] == identity
        })
        .collect()
}

/// Fork a child that counts the write ends among `fds`, reports the count to `seen_fd`, and
/// blocks on `hold_fd` until the test lets it go. Returns its pid.
fn fork_counting_writers(fds: &[RawFd], seen_fd: RawFd, hold_fd: RawFd) -> libc::pid_t {
    // SAFETY: the child runs only `fcntl`, `write` and `block_on` (async-signal-safe), reading
    // `fds` without allocating or dropping it, then `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let mut writers = 0u8;
        for &fd in fds {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags != -1 && (flags & libc::O_ACCMODE) == libc::O_WRONLY {
                writers += 1;
            }
        }
        unsafe { libc::write(seen_fd, (&raw const writers).cast(), 1) };
        block_on(hold_fd);
        unsafe { libc::_exit(0) };
    }
    pid
}

/// How the raw child is spawned.
#[derive(Clone, Copy)]
enum Spawner {
    /// A plain `Command::spawn`, the unlocked control.
    Unlocked,
    /// [`crate::test_spawn::spawn`].
    TestSpawn,
    /// `spawn_locked` from `tests/common/locked.rs`.
    Common,
}

fn run(spawner: Spawner) -> Outcome {
    let spawn_under_the_lock = !matches!(spawner, Spawner::Unlocked);
    use std::os::unix::process::CommandExt;

    let (mut report_read, report_write) = std::io::pipe().expect("report pipe");
    let (gate_read, gate_write) = std::io::pipe().expect("gate pipe");
    let (mut seen_read, seen_write) = std::io::pipe().expect("seen pipe");
    let (hold_read, mut hold_write) = std::io::pipe().expect("hold pipe");
    let (seen_fd, hold_fd, gate_fd, report_fd) = (
        seen_write.as_raw_fd(),
        hold_read.as_raw_fd(),
        gate_read.as_raw_fd(),
        report_write.as_raw_fd(),
    );

    // The raw spawn. Its child reports the identity of its own stdout pipe, then parks until the
    // test opens the gate. `report_write` moves in, so a spawn that fails before reporting closes
    // the pipe and the test's read below fails instead of hanging.
    let raw_spawn = std::thread::spawn(move || -> Child {
        let _report_write = report_write;
        let mut cmd = Command::new("/bin/true");
        cmd.stdout(Stdio::piped());
        // SAFETY: `fstat`, `write`, `held_by_this_thread` (a const-initialised thread-local read)
        // and `block_on` are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                let mut st: libc::stat = std::mem::zeroed();
                libc::fstat(1, &mut st);
                let report: [u64; 3] = [st.st_dev, st.st_ino, crate::test_spawn::held_by_this_thread().into()];
                libc::write(report_fd, report.as_ptr().cast(), 24);
                block_on(gate_fd);
                Ok(())
            });
        }
        match spawner {
            Spawner::Unlocked => crate::test_spawn::spawn_unlocked(&mut cmd),
            Spawner::TestSpawn => crate::test_spawn::spawn(&mut cmd),
            Spawner::Common => super::locked::spawn_locked(&mut cmd),
        }
        .expect("raw spawn")
    });

    let mut report = [0u8; 24];
    report_read
        .read_exact(&mut report)
        .expect("the raw child must report its stdout pipe's identity");
    let word = |i: usize| u64::from_ne_bytes(report[i * 8..(i + 1) * 8].try_into().unwrap());
    let (identity, raw_forked_under_the_lock) = ([word(0), word(1)], word(2) == 1);

    let (events, events_rx) = mpsc::channel::<Event>();
    let forker = std::thread::spawn(move || {
        // The unlocked control runs in a process of its own, so no other test's spawn holds the
        // lock while its raw child is parked.
        let guard = crate::child::spawn::spawn_lock_tracked(|| {
            _ = events.send(Event::Contended);
        });
        let pid = fork_counting_writers(&pipe_fds(identity), seen_fd, hold_fd);
        drop(guard);
        _ = events.send(Event::Forked);
        pid
    });

    let mut gate_write = Some(gate_write);
    let mut first = None;
    loop {
        let event = events_rx.recv().expect("the forker must report");
        let forked = event == Event::Forked;
        first.get_or_insert(event);
        // A forker blocked behind a locked spawn can only proceed once the raw child is released.
        // An unlocked spawn never blocks it, so its fork happens with the gate still shut.
        if forked || spawn_under_the_lock {
            if let Some(mut gate) = gate_write.take() {
                gate.write_all(&[1]).expect("open the gate");
            }
        }
        if forked {
            break;
        }
    }

    let mut writers = [0u8; 1];
    seen_read.read_exact(&mut writers).expect("the forked child reports");
    hold_write.write_all(&[1]).expect("release the forked child");
    let forked_pid = forker.join().expect("forker");
    let mut status = 0;
    // SAFETY: `forked_pid` is our own child, reaped once.
    assert_eq!(unsafe { libc::waitpid(forked_pid, &mut status, 0) }, forked_pid);
    raw_spawn
        .join()
        .expect("raw spawn thread")
        .wait()
        .expect("wait for the raw child");

    Outcome {
        first: first.expect("at least one event"),
        writers: writers[0],
        raw_forked_under_the_lock,
    }
}

/// A raw spawn that skips `spawn_lock` lets a lock-respecting fork happen mid-spawn, and that
/// fork's child inherits the raw child's `Stdio::piped()` write end. A reader of that pipe would
/// wait for the fork to exit as well.
///
/// Its two unlocked forks run in a process of their own: here they would also copy every other
/// test's open descriptors.
#[test]
fn an_unlocked_raw_spawn_leaks_its_piped_end_into_a_concurrent_fork() {
    use crate::test_own_process::{own_process, test_path};
    let Some(_alone) = own_process(
        test_path!(an_unlocked_raw_spawn_leaks_its_piped_end_into_a_concurrent_fork),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let outcome = run(Spawner::Unlocked);
    assert!(!outcome.raw_forked_under_the_lock, "the control spawn takes no lock");
    assert_eq!(outcome.first, Event::Forked, "this forker never waits on the lock");
    assert!(
        outcome.writers >= 1,
        "the fork inside the spawn window must inherit the child-side write end, got {outcome:?}"
    );
}

fn assert_fork_waits_out_the_spawn(spawner: Spawner) {
    let outcome = run(spawner);
    assert!(
        outcome.raw_forked_under_the_lock,
        "the raw spawn must hold spawn_lock through its fork, got {outcome:?}"
    );
    assert_eq!(
        outcome.first,
        Event::Contended,
        "the forker must find the lock held by the spawn and wait"
    );
    assert_eq!(
        outcome.writers, 0,
        "a fork that waited for the spawn must not inherit its piped end, got {outcome:?}"
    );
}

/// Locked helper: a fork under the lock waits out the spawn and inherits nothing.
#[test]
fn a_locked_raw_spawn_keeps_a_concurrent_fork_out_of_its_window() {
    assert_fork_waits_out_the_spawn(Spawner::TestSpawn);
}

/// The same for the integration tests' `spawn_locked`, compiled from its real source.
#[test]
fn a_spawn_locked_raw_spawn_keeps_a_concurrent_fork_out_of_its_window() {
    assert_fork_waits_out_the_spawn(Spawner::Common);
}
