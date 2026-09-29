//! The spawn window: what a fork that follows the crate rule (fork under `spawn_lock`) sees of a
//! raw spawn that is still in flight.
//!
//! A raw spawn with a `Stdio::piped()` stdout holds the child-side write end of that pipe in the
//! parent until `spawn` returns. The raw child is parked in `pre_exec`, so the spawn is
//! provably mid-flight. The forker then reports how many write ends of that pipe its own forked
//! child holds, found by the pipe's inode, which the raw child reports from its own stdout.
//! Nothing here waits on a duration.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

use crate::containment::cgroup::test_support::block_on;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    /// The forker found the lock held and is about to block on it.
    Contended,
    /// The forker has forked.
    Forked,
}

#[derive(Debug)]
struct Outcome {
    /// The first event the forker reported.
    first: Event,
    /// Write ends of the raw child's stdout pipe open in the forker's child.
    writers: u8,
}

/// The `(st_dev, st_ino)` of every open FIFO in this process matching `identity`.
fn pipe_fds(identity: [u64; 2]) -> Vec<RawFd> {
    std::fs::read_dir("/proc/self/fd")
        .expect("list /proc/self/fd")
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<RawFd>().ok())
        .filter(|&fd| {
            // SAFETY: `fstat` on an fd number writes only into `st`; a closed fd just fails.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
            ok && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO && [st.st_dev, st.st_ino] == identity
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

fn run(spawn_under_the_lock: bool) -> Outcome {
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
        // SAFETY: `fstat`, `write` and `block_on` are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                let mut st: libc::stat = std::mem::zeroed();
                libc::fstat(1, &mut st);
                let identity = [st.st_dev, st.st_ino];
                libc::write(report_fd, identity.as_ptr().cast(), 16);
                block_on(gate_fd);
                Ok(())
            });
        }
        if spawn_under_the_lock {
            super::super::spawn(&mut cmd)
        } else {
            cmd.spawn()
        }
        .expect("raw spawn")
    });

    let mut identity = [0u8; 16];
    report_read
        .read_exact(&mut identity)
        .expect("the raw child must report its stdout pipe's identity");
    let identity: [u64; 2] = [
        u64::from_ne_bytes(identity[..8].try_into().unwrap()),
        u64::from_ne_bytes(identity[8..].try_into().unwrap()),
    ];

    let (events, events_rx) = mpsc::channel::<Event>();
    let forker = std::thread::spawn(move || {
        // The unlocked case forks without the lock. A fork that waited for it could deadlock with
        // any other test's locked spawn: the unlocked raw child parked in `pre_exec` holds that
        // spawn's exec-error pipe open, and this test opens its gate only after the fork.
        let guard = spawn_under_the_lock.then(|| {
            crate::child::spawn::spawn_lock_tracked(|| {
                _ = events.send(Event::Contended);
            })
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
    }
}

/// A raw spawn that skips `spawn_lock` lets a lock-respecting fork happen mid-spawn, and that
/// fork's child inherits the raw child's `Stdio::piped()` write end. A reader of that pipe would
/// wait for the fork to exit as well. This is the hazard the helper exists for; it also shows the
/// next test's zero is a real measurement.
#[test]
fn an_unlocked_raw_spawn_leaks_its_piped_end_into_a_concurrent_fork() {
    let outcome = run(false);
    assert_eq!(outcome.first, Event::Forked, "this forker never waits on the lock");
    assert!(
        outcome.writers >= 1,
        "the fork inside the spawn window must inherit the child-side write end, got {outcome:?}"
    );
}

/// The helper holds the lock through the whole window, so a fork under the lock waits for the
/// spawn to finish and inherits nothing of it.
#[test]
fn a_locked_raw_spawn_keeps_a_concurrent_fork_out_of_its_window() {
    let outcome = run(true);
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
