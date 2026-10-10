use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
static DELIVERED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn delivered(_: libc::c_int) {
    DELIVERED.store(true, Ordering::Relaxed);
}

/// The calling thread's `SIGPIPE` handler runs before `pthread_sigmask` returns, if one is pending.
#[cfg(target_os = "linux")]
fn unblock_sigpipe() {
    // SAFETY: all-zero sets are valid out-parameters; `sigemptyset` and `sigaddset` initialise `set`.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGPIPE);
        assert_eq!(libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()), 0);
    }
}

/// Linux raises the signal at the writing thread, before the write returns. Elsewhere it is aimed at
/// the process and may be taken by another thread, so the test cannot see it; the shim runs on Linux.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_closed_stderr_raises_no_sigpipe() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_closed_stderr_raises_no_sigpipe),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    // SAFETY: an all-zero `sigaction` is valid, and the handler only stores to an atomic.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = delivered as *const () as usize;
        assert_eq!(libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut()), 0);
    }
    let original = rustix::io::dup(std::io::stderr().as_fd()).expect("a copy of stderr");
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    rustix::stdio::dup2_stderr(&writer).expect("stderr is the broken pipe");

    // Control: a plain write to this stderr raises the signal, so the line below proves something.
    let plain = rustix::io::write(std::io::stderr().as_fd(), b"x");
    let plain_raised = DELIVERED.swap(false, Ordering::Relaxed);

    super::line(format_args!("a line for a closed pipe"));
    let line_raised = DELIVERED.load(Ordering::Relaxed);
    unblock_sigpipe();
    let line_raised_on_unblock = DELIVERED.load(Ordering::Relaxed);

    rustix::stdio::dup2_stderr(&original).expect("stderr is back");
    assert_eq!(plain, Err(rustix::io::Errno::PIPE), "the pipe has no reader");
    assert!(plain_raised, "a plain write to a broken pipe raises SIGPIPE here");
    assert!(!line_raised, "the line raised SIGPIPE");
    assert!(!line_raised_on_unblock, "the line left a SIGPIPE pending");
}

#[skuld::test]
fn a_line_to_a_working_stderr_is_written() {
    // The shim's stderr lines are the front's only report of a refusal before hello.
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_line_to_a_working_stderr_is_written),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let (reader, writer) = std::io::pipe().expect("a pipe");
    let original = rustix::io::dup(std::io::stderr().as_fd()).expect("a copy of stderr");
    rustix::stdio::dup2_stderr(&writer).expect("stderr is the pipe");
    super::line(format_args!("exit {}", 7));
    rustix::stdio::dup2_stderr(&original).expect("stderr is back");
    drop(writer);
    let mut text = String::new();
    std::io::Read::read_to_string(&mut &reader, &mut text).expect("the line");
    assert_eq!(text, "cosca-elevation-shim: exit 7\n");
}
