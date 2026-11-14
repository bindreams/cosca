//! A process whose leader thread has exited while another thread runs, as a process of its own: the
//! lib's test binary re-run with [`argv`], dispatched from `main` before the runner starts so it is
//! single-threaded. It spawns a `cat` on its own stdin, prints the `cat`'s pid, starts a thread that
//! blocks on the stdin, and ends the leader thread alone (`SYS_exit`, not `pthread_exit`, which would
//! unwind through Rust's frames). The kernel then shows the process as a zombie (`Z`) that still has a
//! live thread, and keeps the `cat`'s parent number at the process's. The thread prints `exited` once
//! the kernel reports the leader's end (see [`LEADER_TID`]), then blocks on the stdin. Closing the
//! stdin ends the thread and the `cat`, and with them the process.

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const FLAG: &str = "--cosca-zombie-leader-root";

/// The leader thread's `clear_child_tid` word: its tid while it runs, and the kernel zeroes it and
/// wakes its waiters as the thread exits. That is a step of the exit, taken before the kernel marks the
/// thread a zombie.
static LEADER_TID: AtomicU32 = AtomicU32::new(0);

/// Blocks until the leader thread has begun to exit: the word reads zero. The futex wait has no
/// timeout, and is woken by the exit this thread's process is about to make.
fn wait_for_the_leader_to_exit() {
    loop {
        let tid = LEADER_TID.load(Ordering::SeqCst);
        if tid == 0 {
            return;
        }
        // SAFETY: `LEADER_TID` is a static word; the wait reads it and sleeps while it still holds `tid`.
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                LEADER_TID.as_ptr(),
                libc::FUTEX_WAIT,
                tid,
                std::ptr::null::<libc::timespec>(),
            )
        };
    }
}

/// Runs the root and ends its leader thread, if this process was started as one.
pub(crate) fn run_if_requested() {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).is_none_or(|a| a != FLAG) {
        return;
    }
    run();
}

pub(crate) fn argv() -> [&'static str; 1] {
    [FLAG]
}

fn run() -> ! {
    #[allow(
        clippy::disallowed_methods,
        reason = "this process is single-threaded: nothing else forks, so there is no lock to hold"
    )]
    let cat = Command::new("cat")
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn the cat");
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", cat.id()).expect("report the cat's pid");
    out.flush().expect("report the cat's pid");
    drop(out);

    // SAFETY: registers the static word as the leader thread's `clear_child_tid`; it returns the tid.
    let tid = unsafe { libc::syscall(libc::SYS_set_tid_address, LEADER_TID.as_ptr()) };
    LEADER_TID.store(u32::try_from(tid).expect("a thread's tid"), Ordering::SeqCst);
    let blocked = std::thread::spawn(|| {
        wait_for_the_leader_to_exit();
        let mut out = std::io::stdout().lock();
        writeln!(out, "exited").expect("report the leader's exit");
        out.flush().expect("report the leader's exit");
        drop(out);
        _ = std::io::stdin().read(&mut [0u8; 1]);
    });
    // Nothing is dropped after this: the leader thread's end runs no destructor.
    std::mem::forget((cat, blocked));
    // SAFETY: `SYS_exit` ends the calling thread only, which is the leader; the other thread runs on.
    unsafe { libc::syscall(libc::SYS_exit, 0) };
    unreachable!("SYS_exit does not return");
}
