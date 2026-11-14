//! A process whose leader thread has exited while another thread runs, as a process of its own: the
//! lib's test binary re-run with [`argv`], dispatched from `main` before the runner starts so it is
//! single-threaded. It spawns a `cat` on its own stdin, prints the `cat`'s pid, starts a thread that
//! blocks on the stdin, and ends the leader thread alone (`SYS_exit`, not `pthread_exit`, which would
//! unwind through Rust's frames). The kernel then shows the process as a zombie (`Z`) that still has a
//! live thread, and keeps the `cat`'s parent number at the process's. Closing the stdin ends the
//! thread and the `cat`, and with them the process.

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};

const FLAG: &str = "--cosca-zombie-leader-root";

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

    let blocked = std::thread::spawn(|| _ = std::io::stdin().read(&mut [0u8; 1]));
    // Nothing is dropped after this: the leader thread's end runs no destructor.
    std::mem::forget((cat, blocked));
    // SAFETY: `SYS_exit` ends the calling thread only, which is the leader; the other thread runs on.
    unsafe { libc::syscall(libc::SYS_exit, 0) };
    unreachable!("SYS_exit does not return");
}
