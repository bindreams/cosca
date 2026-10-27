//! A tracer that is this test thread, for a child the test spawned: it seizes the child with
//! `ptrace` (`TRACER` group; needs `COSCA_TEST_TRACER_CONSENT=1`). Yama allows it: the child is a
//! descendant. The thread that seizes is the one that must make every later request and wait.

/// Seizes `pid`, this test's own child, interrupts it, and returns once its stop is there, seen
/// without consuming it.
pub(crate) fn seize_and_stop(pid: libc::pid_t) {
    // `ptrace` is variadic, and glibc reads `addr` and `data` as pointers.
    let null = std::ptr::null_mut::<libc::c_void>;
    // SAFETY: plain ptrace requests on this test's own child, from the thread that waits below.
    unsafe {
        assert_eq!(
            libc::ptrace(libc::PTRACE_SEIZE, pid, null(), null()),
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::ptrace(libc::PTRACE_INTERRUPT, pid, null(), null()),
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }
    // The stop, or an exit that would mean no stop is coming, seen without consuming it.
    // SAFETY: an all-zero `siginfo_t` is valid and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WSTOPPED | libc::WEXITED | libc::WNOWAIT | libc::__WALL,
        )
    };
    assert_eq!(r, 0, "waitid: {}", std::io::Error::last_os_error());
    assert_eq!(
        info.si_code,
        libc::CLD_TRAPPED,
        "the tracee did not stop (si_code {}, si_status {})",
        info.si_code,
        // SAFETY: a `waitid` record's `si_status` is valid for these `si_code`s.
        unsafe { info.si_status() }
    );
}

/// Resumes the stopped `pid` (`PTRACE_CONT`, no signal), unless it is already dying: a `SIGKILL`
/// sent before this call has woken it, and the request answers `ESRCH`.
pub(crate) fn resume_unless_dying(pid: libc::pid_t) {
    // SAFETY: a plain ptrace request on this test's own child; `ptrace` is variadic and glibc reads
    // `addr` and `data` as pointers.
    let resumed = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if resumed != 0 {
        let e = std::io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(libc::ESRCH), "PTRACE_CONT: {e}");
    }
}
